package com.bastionsecurity.sidecheck.ui.detail

import android.app.Application
import android.content.pm.PackageManager
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.bastionsecurity.sidecheck.data.AppEntry
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.data.TrustStore
import com.bastionsecurity.sidecheck.engine.model.AppFacts
import com.bastionsecurity.sidecheck.engine.model.InstallerKind
import com.bastionsecurity.sidecheck.grants.Grant
import com.bastionsecurity.sidecheck.grants.GrantInspector
import com.bastionsecurity.sidecheck.grants.ShizukuBridge
import com.bastionsecurity.sidecheck.grants.ShizukuToggle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DetailViewModel(
    private val context: Application,
    val packageName: String,
    private val repo: ScanRepository,
    private val trust: TrustStore,
    private val watch: com.bastionsecurity.sidecheck.data.WatchState,
    private val grantsReader: GrantInspector,
    val shizuku: ShizukuBridge,
) : ViewModel() {

    val entry: StateFlow<AppEntry?> = repo.entries
        .map { list -> list.firstOrNull { it.packageName == packageName } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _grants = MutableStateFlow<List<Grant>?>(null)
    val grants: StateFlow<List<Grant>?> = _grants.asStateFlow()

    /** We couldn't read or check this app. */
    private val _failed = MutableStateFlow(false)
    val failed: StateFlow<Boolean> = _failed.asStateFlow()

    fun retry() = viewModelScope.launch {
        _failed.value = false
        when (repo.rescanResult(packageName)) {
            is ScanRepository.Rescan.Ok -> Unit
            ScanRepository.Rescan.NotInstalled -> _removed.value = true
            is ScanRepository.Rescan.Failed -> _failed.value = true
        }
    }

    private val _removed = MutableStateFlow(false)
    val removed: StateFlow<Boolean> = _removed.asStateFlow()

    /** Short status line after an action ("Turned off: Microphone"). */
    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    init {
        viewModelScope.launch { watch.acknowledge(packageName) }
        // Opened directly (e.g. from a notification) without a scan in memory: check just this app.
        viewModelScope.launch {
            if (repo.reports.value[packageName] == null) {
                when (repo.rescanResult(packageName)) {
                    is ScanRepository.Rescan.Ok -> Unit
                    ScanRepository.Rescan.NotInstalled -> _removed.value = true
                    is ScanRepository.Rescan.Failed -> _failed.value = true
                }
            }
        }
    }

    /** Called every time the screen comes back (e.g. from Settings or the uninstall dialog). */
    fun onResume() {
        viewModelScope.launch {
            if (!isInstalled()) {
                repo.remove(packageName)
                _removed.value = true
                return@launch
            }
            shizuku.refresh()
            loadGrants()
        }
    }

    private suspend fun loadGrants() {
        _grants.value = withContext(Dispatchers.IO) { runCatching { grantsReader.grantsFor(packageName) }.getOrDefault(emptyList()) }
    }

    fun setTrusted(trusted: Boolean) = viewModelScope.launch {
        val e = entry.value ?: return@launch
        trust.setTrusted(packageName, e.cert, trusted)
    }

    fun setKept(findingId: String, kept: Boolean) = viewModelScope.launch {
        val e = entry.value ?: return@launch
        trust.setKept(packageName, e.cert, findingId, kept)
    }

    fun toggle(grant: Grant) = viewModelScope.launch {
        val t = grant.shizukuToggle ?: return@launch
        val turnOn = grant.allowed != true
        _busy.value = true
        val result = when (t) {
            is ShizukuToggle.Runtime -> shizuku.grantRuntime(packageName, t.permission, turnOn)
            is ShizukuToggle.AppOp -> shizuku.setAppOp(packageName, t.op, turnOn)
        }
        _message.value = if (result.ok) {
            "${if (turnOn) "Turned on" else "Turned off"}: ${grant.title}"
        } else {
            "Couldn't change ${grant.title}. ${result.output.lineSequence().firstOrNull().orEmpty()}".trim()
        }
        loadGrants()
        _busy.value = false
    }

    fun requestShizuku() = shizuku.requestPermission()

    fun clearMessage() { _message.value = null }

    private fun isInstalled(): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    /** "Installed by Downloader", "From Google Play", "Installed from a computer or unknown source". */
    fun installSourceText(f: AppFacts): String {
        val inst = f.installSource.installerPackage ?: f.installSource.initiatingPackage
        val name = inst?.let { labelOf(it) }
        return when (f.installSource.kind) {
            InstallerKind.APP_STORE -> "From ${name ?: "an app store"}"
            InstallerKind.PREINSTALLED -> "Came with this device"
            InstallerKind.SIDELOADED, InstallerKind.UNKNOWN ->
                if (name != null && inst != "com.android.shell") "Installed by $name" else "Installed from a computer or unknown source"
        }
    }

    private fun labelOf(pkg: String): String? = try {
        val pm = context.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
    } catch (_: Exception) {
        null
    }
}
