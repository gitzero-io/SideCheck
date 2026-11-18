package com.bastionsecurity.sidecheck.ui.apk

import com.bastionsecurity.sidecheck.data.DeviceModeStore
import androidx.core.content.pm.PackageInfoCompat
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bastionsecurity.sidecheck.AppContainer
import com.bastionsecurity.sidecheck.engine.model.AppReport
import com.bastionsecurity.sidecheck.install.ApkStaging
import com.bastionsecurity.sidecheck.install.InstallHandoff
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** What we know about a version of this app that's already on the TV. */
data class ExistingInstall(
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    /** null if either signature couldn't be read. */
    val sameSigner: Boolean?,
)

sealed interface ApkCheckState {
    /** Opened without a file: explain how to send one. */
    data object NoFile : ApkCheckState
    data class Working(val message: String) : ApkCheckState
    data class Ready(
        val report: AppReport,
        val file: File,
        val fileName: String,
        val existing: ExistingInstall?,
        /** True after "Install anyway" when SideCheck isn't yet allowed to install apps. */
        val needsInstallPermission: Boolean = false,
    ) : ApkCheckState
    data class Installed(val label: String, val packageName: String) : ApkCheckState
    data class Failed(val title: String, val body: String) : ApkCheckState
}

class ApkCheckViewModel(private val c: AppContainer) : ViewModel() {
    private val staging = ApkStaging(c.app)
    private val handoff = InstallHandoff(c.app)

    /** "TV" or "device", for messages. */
    private val noun get() = DeviceModeStore.noun(c.app)

    private val _state = MutableStateFlow<ApkCheckState>(ApkCheckState.NoFile)
    val state: StateFlow<ApkCheckState> = _state.asStateFlow()

    /** One-shot: an intent the screen should start (the system installer or a Settings page). */
    private val _launch = MutableStateFlow<Intent?>(null)
    val launch: StateFlow<Intent?> = _launch.asStateFlow()

    private var handedOffAt = 0L
    private var started = false

    /** Call once with the incoming VIEW uri (null = opened without a file). */
    fun start(uri: Uri?) {
        if (started) return
        started = true
        if (uri != null) check(uri)
    }

    fun onNewFile(uri: Uri) = check(uri)

    private fun check(uri: Uri) {
        viewModelScope.launch {
            _state.value = ApkCheckState.Working("Reading the file…")
            val staged = withContext(Dispatchers.IO) { staging.stage(uri) }
            when (staged) {
                is ApkStaging.Result.Failed -> _state.value = failure(staged)
                is ApkStaging.Result.Ok -> {
                    _state.value = ApkCheckState.Working("Checking what this app does…")
                    try {
                        val facts = withContext(Dispatchers.IO) { c.collector.collectArchive(staged.file) }
                        if (facts == null) {
                            staging.cleanup(keep = null)
                            _state.value = ApkCheckState.Failed(
                                "We couldn't read this app",
                                "The file may be damaged or only partly downloaded. Try downloading it again.",
                            )
                            return@launch
                        }
                        val report = c.analyzer.analyze(facts, c.platform())
                        _state.value = ApkCheckState.Ready(report, staged.file, staged.displayName, existing(report))
                    } catch (e: Exception) {
                        Log.e(TAG, "APK check failed", e)
                        staging.cleanup(keep = null)
                        _state.value = ApkCheckState.Failed("Something went wrong", "We couldn't finish checking this file (${e.javaClass.simpleName}).")
                    }
                }
            }
        }
    }

    fun installAnyway() {
        val s = _state.value as? ApkCheckState.Ready ?: return
        if (!handoff.canInstall()) {
            _state.value = s.copy(needsInstallPermission = true)
            return
        }
        val intent = handoff.installIntent(s.file)
        if (intent == null) {
            _state.value = ApkCheckState.Failed("No installer found", "This $noun doesn't have Android's app installer available.")
            return
        }
        handedOffAt = System.currentTimeMillis()
        _launch.value = intent
    }

    fun openInstallPermissionSettings() { _launch.value = handoff.allowInstallsIntent() }

    fun launched() { _launch.value = null }

    /** When we come back from the installer or Settings. */
    fun onResume() {
        val s = _state.value as? ApkCheckState.Ready ?: return
        if (s.needsInstallPermission && handoff.canInstall()) {
            _state.value = s.copy(needsInstallPermission = false)
        }
        if (handedOffAt == 0L) return
        val pkg = s.report.facts.packageName
        val pi = packageInfo(pkg) ?: return
        if (pi.lastUpdateTime >= handedOffAt - 5_000 && PackageInfoCompat.getLongVersionCode(pi) == s.report.facts.versionCode) {
            staging.cleanup(keep = null)
            _state.value = ApkCheckState.Installed(s.report.facts.label, pkg)
            viewModelScope.launch { c.repository.rescan(pkg) }
        }
    }

    /** "Don't install" / leaving: delete the copy we made. */
    fun discard() = staging.cleanup(keep = null)

    private fun existing(r: AppReport): ExistingInstall? {
        val pi = packageInfo(r.facts.packageName) ?: return null
        val installed = c.collector.collectInstalledSignersOnly(r.facts.packageName)
        val newSigners = r.facts.signers.map { it.sha256 }.toSet()
        val same = if (installed.isEmpty() || newSigners.isEmpty()) null else installed.any { it in newSigners }
        val label = runCatching { c.app.packageManager.getApplicationLabel(pi.applicationInfo!!).toString() }.getOrDefault(r.facts.label)
        return ExistingInstall(label, pi.versionName, PackageInfoCompat.getLongVersionCode(pi), same)
    }

    private fun packageInfo(pkg: String): PackageInfo? = try {
        val pm = c.app.packageManager
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
        else @Suppress("DEPRECATION") pm.getPackageInfo(pkg, 0)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun failure(f: ApkStaging.Result.Failed): ApkCheckState.Failed = when (f.reason) {
        ApkStaging.Reason.CANT_READ -> ApkCheckState.Failed(
            "We couldn't open that file",
            "The app that sent it didn't let us read it. Try opening the file from a different file manager or from Downloader.",
        )
        ApkStaging.Reason.TOO_BIG -> ApkCheckState.Failed("This file is too big", "We only check files up to 1 GB to keep your $noun running smoothly.")
        ApkStaging.Reason.NOT_ENOUGH_SPACE -> ApkCheckState.Failed(
            "Not enough free space",
            "Your $noun needs more free storage to check this file. Try removing apps or files you don't use.",
        )
        ApkStaging.Reason.BUNDLE -> ApkCheckState.Failed(
            "This is an app bundle, not a single app file",
            "Files ending in .apks, .xapk, or .apkm hold several app files. SideCheck can only check single .apk files for now.",
        )
        ApkStaging.Reason.NOT_AN_APK -> ApkCheckState.Failed("This isn't an app file", "The file isn't an Android app (.apk), or it's damaged.")
    }

    override fun onCleared() {
        // Keep the file only while the installer might still be reading it.
        if (_state.value !is ApkCheckState.Ready || handedOffAt == 0L) staging.cleanup(keep = null)
    }

    companion object { private const val TAG = "SideCheck" }
}
