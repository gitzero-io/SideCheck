package com.bastionsecurity.sidecheck.collect

import androidx.core.content.pm.PackageInfoCompat
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import com.bastionsecurity.sidecheck.engine.apk.ApkFileInspector
import com.bastionsecurity.sidecheck.engine.apk.ApkFileInspector.Companion.toHex
import com.bastionsecurity.sidecheck.engine.model.AppFacts
import com.bastionsecurity.sidecheck.engine.model.CertInfo
import com.bastionsecurity.sidecheck.engine.model.ComponentFacts
import com.bastionsecurity.sidecheck.engine.model.ComponentType
import com.bastionsecurity.sidecheck.engine.model.InstallSource
import com.bastionsecurity.sidecheck.engine.model.InstallerKind
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Turns PackageManager data (plus the APK file itself) into engine [AppFacts].
 * Blocking; call from a background dispatcher.
 */
class PackageCollector(
    private val pm: PackageManager,
    private val selfPackage: String,
    private val inspector: ApkFileInspector,
) {

    /** Installed apps the user added (not part of the system image), excluding SideCheck itself. */
    fun userPackages(): List<String> = userPackageTimes().map { it.packageName }

    data class InstallTimes(val packageName: String, val firstInstallTime: Long, val lastUpdateTime: Long)

    /** User apps with their install/update times (cheap: no APK reading). */
    fun userPackageTimes(): List<InstallTimes> =
        installedPackages(0)
            .filter { it.packageName != selfPackage }
            .filter { pi -> pi.applicationInfo?.let { !it.isSystem() } ?: false }
            .map { InstallTimes(it.packageName, it.firstInstallTime, it.lastUpdateTime) }

    fun collectInstalled(packageName: String): AppFacts? {
        val pi = packageInfo(packageName) ?: return null
        val ai = pi.applicationInfo ?: return null
        val files = buildList {
            add(File(ai.sourceDir))
            ai.splitSourceDirs?.forEach { add(File(it)) }
        }.filter { it.canRead() }
        return build(pi, ai, files, isArchive = false)
    }

    /** SHA-256 of the installed app's signing certificate(s); empty if not installed. */
    fun collectInstalledSignersOnly(packageName: String): List<String> =
        runCatching { signers(getInfo(packageName, signingFlag)).map { it.sha256 } }.getOrDefault(emptyList())

    /** For an APK file that isn't installed. [apk] must be a readable local file. */
    fun collectArchive(apk: File): AppFacts? {
        val pi = archiveInfo(apk) ?: return null
        val ai = pi.applicationInfo ?: return null
        // Needed so loadLabel/loadIcon can read resources from the archive.
        ai.sourceDir = apk.absolutePath
        ai.publicSourceDir = apk.absolutePath
        return build(pi, ai, listOf(apk), isArchive = true)
    }

    private fun build(pi: PackageInfo, ai: ApplicationInfo, files: List<File>, isArchive: Boolean): AppFacts {
        val static = if (files.isNotEmpty()) inspector.inspectAll(files) else null
        return AppFacts(
            packageName = pi.packageName,
            label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(pi.packageName),
            versionName = pi.versionName,
            versionCode = PackageInfoCompat.getLongVersionCode(pi),
            targetSdk = ai.targetSdkVersion,
            minSdk = ai.minSdkVersion,
            firstInstallTime = if (isArchive) null else pi.firstInstallTime,
            lastUpdateTime = if (isArchive) null else pi.lastUpdateTime,
            installSource = if (isArchive) InstallSource(null, null, InstallerKind.UNKNOWN) else installSource(pi.packageName, ai),
            isSystemApp = ai.isSystem(),
            isArchive = isArchive,
            permissions = pi.requestedPermissions?.toList().orEmpty(),
            signers = signers(pi),
            apkSha256 = static?.sha256,
            debuggable = ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            // Reflects android:usesCleartextTraffic (and its targetSdk default). A network security
            // config can narrow this per domain; we don't parse that in v1.
            cleartextTrafficAllowed = ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0,
            components = components(pi),
            hasLauncherEntry = if (isArchive) null else hasLauncherEntry(pi.packageName),
            appCategory = categoryName(ai.category),
            apkContents = static?.contents,
            dexScan = static?.dexScan,
            enabled = isArchive || isEnabled(pi.packageName, ai),
        )
    }

    // --- PackageManager calls ---------------------------------------------------------------

    private val signingFlag =
        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES

    private val fullFlags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
        PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
        PackageManager.MATCH_DISABLED_COMPONENTS or signingFlag

    private fun installedPackages(flags: Int): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
        }

    private fun getInfo(pkg: String, flags: Int): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getPackageInfo(pkg, flags)
        }

    /**
     * Asks for everything in one call. Apps with thousands of components can overflow the binder
     * buffer; then we fetch each component type separately and merge.
     */
    private fun packageInfo(pkg: String): PackageInfo? {
        return try {
            getInfo(pkg, fullFlags)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } catch (e: RuntimeException) {
            Log.w(TAG, "Full package info too large for $pkg, fetching in parts", e)
            try {
                val base = getInfo(pkg, PackageManager.GET_PERMISSIONS or signingFlag)
                fun part(flag: Int) = runCatching { getInfo(pkg, flag or PackageManager.MATCH_DISABLED_COMPONENTS) }.getOrNull()
                base.activities = part(PackageManager.GET_ACTIVITIES)?.activities
                base.services = part(PackageManager.GET_SERVICES)?.services
                base.receivers = part(PackageManager.GET_RECEIVERS)?.receivers
                base.providers = part(PackageManager.GET_PROVIDERS)?.providers
                base
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun archiveInfo(apk: File): PackageInfo? {
        val flags = fullFlags and PackageManager.MATCH_DISABLED_COMPONENTS.inv()
        val pi = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getPackageArchiveInfo(apk.absolutePath, flags)
        }
        // Some Android versions return no signingInfo for archives; retry with legacy signatures.
        if (pi != null && Build.VERSION.SDK_INT >= 28 && pi.signingInfo == null) {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.GET_SIGNATURES)?.signatures?.let {
                @Suppress("DEPRECATION")
                pi.signatures = it
            }
        }
        return pi
    }

    private fun installSource(pkg: String, ai: ApplicationInfo): InstallSource {
        var installer: String? = null
        var initiator: String? = null
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                val info = pm.getInstallSourceInfo(pkg)
                installer = info.installingPackageName
                initiator = info.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                installer = pm.getInstallerPackageName(pkg)
            }
        } catch (_: Exception) {
            // NameNotFound or SecurityException on some OEM builds — leave unknown.
        }
        val kind = when {
            ai.isSystem() -> InstallerKind.PREINSTALLED
            installer in APP_STORES -> InstallerKind.APP_STORE
            // Package installer, file managers, Downloader, adb (often null) all count as sideloaded.
            else -> InstallerKind.SIDELOADED
        }
        return InstallSource(installer, initiator, kind)
    }

    private fun signers(pi: PackageInfo): List<CertInfo> {
        val sigs: Array<Signature>? = if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null) {
            pi.signingInfo!!.apkContentsSigners
        } else {
            @Suppress("DEPRECATION") pi.signatures
        }
        return sigs.orEmpty().mapNotNull { certInfo(it) }
    }

    private fun certInfo(sig: Signature): CertInfo? = try {
        val bytes = sig.toByteArray()
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream()) as X509Certificate
        CertInfo(
            sha256 = MessageDigest.getInstance("SHA-256").digest(bytes).toHex(),
            subject = cert.subjectX500Principal.name,
            issuer = cert.issuerX500Principal.name,
        )
    } catch (_: Exception) {
        null
    }

    private fun components(pi: PackageInfo): List<ComponentFacts> = buildList {
        fun add(items: Array<out ComponentInfo>?, type: ComponentType, perm: (ComponentInfo) -> String?) {
            items?.forEach { ci -> add(ComponentFacts(ci.name, type, ci.exported, perm(ci), ci.enabled)) }
        }
        add(pi.activities, ComponentType.ACTIVITY) { (it as android.content.pm.ActivityInfo).permission }
        add(pi.services, ComponentType.SERVICE) { (it as android.content.pm.ServiceInfo).permission }
        add(pi.receivers, ComponentType.RECEIVER) { (it as android.content.pm.ActivityInfo).permission }
        add(pi.providers, ComponentType.PROVIDER) {
            val p = it as android.content.pm.ProviderInfo
            p.readPermission ?: p.writePermission
        }
    }

    private fun hasLauncherEntry(pkg: String): Boolean {
        fun query(category: String): Boolean {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(category).setPackage(pkg)
            val list = if (Build.VERSION.SDK_INT >= 33) {
                pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION") pm.queryIntentActivities(intent, 0)
            }
            return list.isNotEmpty()
        }
        return query(Intent.CATEGORY_LEANBACK_LAUNCHER) || query(Intent.CATEGORY_LAUNCHER)
    }

    private fun isEnabled(pkg: String, ai: ApplicationInfo): Boolean {
        val state = runCatching { pm.getApplicationEnabledSetting(pkg) }.getOrNull()
        return when (state) {
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED -> true
            PackageManager.COMPONENT_ENABLED_STATE_DEFAULT, null -> ai.enabled
            else -> false
        }
    }

    private fun categoryName(c: Int): String? = when (c) {
        ApplicationInfo.CATEGORY_GAME -> "GAME"
        ApplicationInfo.CATEGORY_AUDIO -> "AUDIO"
        ApplicationInfo.CATEGORY_VIDEO -> "VIDEO"
        ApplicationInfo.CATEGORY_IMAGE -> "IMAGE"
        ApplicationInfo.CATEGORY_SOCIAL -> "SOCIAL"
        ApplicationInfo.CATEGORY_NEWS -> "NEWS"
        ApplicationInfo.CATEGORY_MAPS -> "MAPS"
        ApplicationInfo.CATEGORY_PRODUCTIVITY -> "PRODUCTIVITY"
        else -> null
    }

    private fun ApplicationInfo.isSystem() =
        flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

    companion object {
        private const val TAG = "SideCheck"

        val APP_STORES = setOf(
            "com.android.vending", // Google Play
            "com.amazon.venezia", // Amazon Appstore
            "com.sec.android.app.samsungapps",
            "com.huawei.appmarket",
            "com.xiaomi.market",
        )
    }
}
