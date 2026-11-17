package com.bastionsecurity.sidecheck.engine.model

/**
 * Everything we know about one app, as plain data. Collected on-device by the Android layer
 * (or, later, on a server from an uploaded APK). The rules engine only ever looks at this.
 */
data class AppFacts(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val targetSdk: Int,
    val minSdk: Int?,
    val firstInstallTime: Long?,
    val lastUpdateTime: Long?,
    val installSource: InstallSource,
    val isSystemApp: Boolean,
    /** True when this came from an APK file that is not installed yet. */
    val isArchive: Boolean,
    val permissions: List<String>,
    val signers: List<CertInfo>,
    val apkSha256: String?,
    val debuggable: Boolean,
    /** Null when unknown (e.g. could not be read from an archive). */
    val cleartextTrafficAllowed: Boolean?,
    val components: List<ComponentFacts>,
    /**
     * Whether the app shows up on a launcher (phone or TV). Null when unknown — archives can't be
     * resolved against intent filters until they are installed.
     */
    val hasLauncherEntry: Boolean?,
    /** ApplicationInfo.category name (e.g. "VIDEO", "AUDIO"), or null. */
    val appCategory: String?,
    val apkContents: ApkContents?,
    val dexScan: DexScanResult?,
    /** False when the user (or system) has turned the app off. A disabled app can't run at all. */
    val enabled: Boolean = true,
) {
    val primarySigner: CertInfo? get() = signers.firstOrNull()

    fun hasPermission(name: String) = name in permissions

    fun servicesRequiring(permission: String) =
        components.filter { it.type == ComponentType.SERVICE && it.permission == permission }

    fun receiversRequiring(permission: String) =
        components.filter { it.type == ComponentType.RECEIVER && it.permission == permission }
}

enum class InstallerKind {
    /** Google Play, Amazon Appstore, a device-maker store, etc. */
    APP_STORE,
    /** The system package installer / a file manager / Downloader / ADB. */
    SIDELOADED,
    /** Preinstalled with the device. */
    PREINSTALLED,
    UNKNOWN,
}

data class InstallSource(
    val installerPackage: String?,
    val initiatingPackage: String?,
    val kind: InstallerKind,
)

data class CertInfo(
    val sha256: String,
    val subject: String,
    val issuer: String? = null,
) {
    val isAndroidDebugCert: Boolean
        get() = subject.contains("CN=Android Debug", ignoreCase = true)
}

enum class ComponentType { ACTIVITY, SERVICE, RECEIVER, PROVIDER }

data class ComponentFacts(
    val name: String,
    val type: ComponentType,
    val exported: Boolean,
    /** Permission another app must hold to use this component, if any. */
    val permission: String?,
    val enabled: Boolean = true,
)

data class ApkContents(
    val nativeLibs: List<String>,
    val abis: Set<String>,
    val packerLibs: List<String>,
    val dexCount: Int,
    val totalDexBytes: Long,
    val entryCount: Int,
)

data class DexScanResult(
    val dexFilesScanned: Int,
    val stringsScanned: Long,
    /** True when we stopped early because of a safety limit. Results are then partial. */
    val truncated: Boolean,
    val truncationReasons: List<String>,
    /** Tracker id -> one example class/string that matched. */
    val trackerHits: Map<String, String>,
    /** Which class loaders that can load extra code were referenced. */
    val dynamicCodeLoaders: Set<String>,
    val pathClassLoaderReferenced: Boolean,
    /** Strings that suggest code is downloaded and saved to a file (network client + .dex/.jar/.apk names). */
    val downloadToFileHints: Set<String>,
    val reflectionApis: Set<String>,
    val hiddenApiReflectionTargets: Set<String>,
    val runtimeExec: Boolean,
    val ipAddresses: Set<String>,
    val urls: Set<String>,
) {
    val reflectionHeavy: Boolean
        get() = reflectionApis.size >= 3 && hiddenApiReflectionTargets.size >= 2

    val pathClassLoaderWithDownload: Boolean
        get() = pathClassLoaderReferenced && downloadToFileHints.isNotEmpty()

    val cleartextUrls: Set<String>
        get() = urls.filter { it.startsWith("http://", ignoreCase = true) }.toSet()

    companion object {
        val EMPTY = DexScanResult(
            0, 0, false, emptyList(), emptyMap(), emptySet(), false, emptySet(),
            emptySet(), emptySet(), false, emptySet(), emptySet(),
        )
    }
}
