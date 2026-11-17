package com.bastionsecurity.sidecheck.engine.rules

import com.bastionsecurity.sidecheck.engine.impersonation.ImpersonationResult
import com.bastionsecurity.sidecheck.engine.model.AppFacts
import com.bastionsecurity.sidecheck.engine.model.ComponentType
import com.bastionsecurity.sidecheck.engine.model.ReputationResult
import com.bastionsecurity.sidecheck.engine.trackers.TrackerCatalog

/** Everything a signal may look at. */
class RuleContext(
    val facts: AppFacts,
    val impersonation: ImpersonationResult,
    val trackers: TrackerCatalog,
    val reputation: ReputationResult?,
)

/** A matched signal: technical evidence lines plus template parameters. */
data class SignalHit(
    val evidence: List<String>,
    val params: Map<String, String> = emptyMap(),
)

/**
 * Named facts about an app that rules can combine. Each returns null when it doesn't apply.
 *
 * Parameters provided (for templates):
 *  - trackersSome / trackersMany: {trackers}, {trackerCount}
 *  - impersonatesBrand: {brand}, {official}
 *  - signerMismatch: {brand}
 *  - systemLikeName: {name}
 *  - packed: {packers}
 *  - publicIps: {ips}, {ipCount}
 *  - exportedUnprotected: {count}
 *  - dangerousPermissions: {permissionList}
 *  - knownMalware: {source}, {malwareName}
 *  - partialScan: {reasons}
 *  - Always: {app}, {targetSdk}, {androidVersion}
 */
object Signals {

    private const val P = "android.permission."
    const val BIND_ACCESSIBILITY = "${P}BIND_ACCESSIBILITY_SERVICE"
    const val BIND_DEVICE_ADMIN = "${P}BIND_DEVICE_ADMIN"
    const val BIND_NOTIFICATION_LISTENER = "${P}BIND_NOTIFICATION_LISTENER_SERVICE"
    const val BIND_VPN = "${P}BIND_VPN_SERVICE"

    /** Permissions Android treats as "dangerous" (runtime-prompted on targetSdk >= 23). */
    val DANGEROUS_PERMISSIONS = setOf(
        "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE",
        "READ_PHONE_NUMBERS", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG", "ADD_VOICEMAIL",
        "USE_SIP", "PROCESS_OUTGOING_CALLS", "BODY_SENSORS", "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
        "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    ).map { P + it }.toSet()

    /** Services that are normal reasons for an app to have no launcher icon. */
    private val EXPECTED_HEADLESS_BINDINGS = setOf(
        "${P}BIND_INPUT_METHOD", "${P}BIND_WALLPAPER", "${P}BIND_TV_INPUT", "${P}BIND_DREAM_SERVICE",
        "${P}BIND_TEXT_SERVICE", "${P}BIND_PRINT_SERVICE", "${P}BIND_TV_INTERACTIVE_APP",
        "${P}BIND_SCREENING_SERVICE", "${P}BIND_AUTOFILL_SERVICE",
    )

    private val MEDIA_CATEGORIES = setOf("VIDEO", "AUDIO", "IMAGE")
    private val MEDIA_WORDS = listOf(
        "tv", "iptv", "stream", "player", "movie", "video", "media", "music", "film", "cinema",
        "live", "anime", "sport", "channel", "series", "kodi", "flix",
    ).map { it to Regex("(^|[^a-z])$it") }
    private val VPN_WORDS = listOf("vpn", "proxy", "tunnel", "wireguard", "openvpn")

    private fun hit(vararg evidence: String, params: Map<String, String> = emptyMap()) =
        SignalHit(evidence.toList(), params)

    private fun componentHit(what: String, names: List<String>) =
        if (names.isEmpty()) null else SignalHit(names.map { "$what: $it" }, mapOf("count" to names.size.toString()))

    val registry: Map<String, (RuleContext) -> SignalHit?> = mapOf(
        "accessibility" to { c ->
            componentHit("Accessibility service", c.facts.servicesRequiring(BIND_ACCESSIBILITY).map { it.name })
        },
        "deviceAdmin" to { c ->
            componentHit("Device admin receiver", c.facts.receiversRequiring(BIND_DEVICE_ADMIN).map { it.name })
        },
        "notificationListener" to { c ->
            componentHit("Notification listener", c.facts.servicesRequiring(BIND_NOTIFICATION_LISTENER).map { it.name })
        },
        "vpn" to { c -> componentHit("VPN service", c.facts.servicesRequiring(BIND_VPN).map { it.name }) },
        "vpnApp" to { c ->
            val text = (c.facts.label + " " + c.facts.packageName).lowercase()
            VPN_WORDS.firstOrNull { it in text }?.let { hit("Name contains \"$it\"") }
        },
        "boot" to { c ->
            if (c.facts.hasPermission("${P}RECEIVE_BOOT_COMPLETED")) hit("Permission: ${P}RECEIVE_BOOT_COMPLETED") else null
        },
        "overlay" to { c ->
            if (c.facts.hasPermission("${P}SYSTEM_ALERT_WINDOW")) hit("Permission: ${P}SYSTEM_ALERT_WINDOW") else null
        },
        "installPackages" to { c ->
            listOf("${P}REQUEST_INSTALL_PACKAGES", "${P}INSTALL_PACKAGES").filter { c.facts.hasPermission(it) }
                .takeIf { it.isNotEmpty() }?.let { SignalHit(it.map { p -> "Permission: $p" }) }
        },
        "mediaApp" to { c ->
            val cat = c.facts.appCategory
            if (cat != null && cat in MEDIA_CATEGORIES) {
                hit("App category: $cat")
            } else {
                val text = (c.facts.label + " " + c.facts.packageName).lowercase()
                MEDIA_WORDS.firstOrNull { it.second.containsMatchIn(text) }
                    ?.let { hit("Name suggests a media app (\"${it.first}\")") }
            }
        },
        "debugCert" to { c ->
            c.facts.signers.firstOrNull { it.isAndroidDebugCert }?.let {
                hit("Signing certificate subject: ${it.subject}", "Certificate SHA-256: ${it.sha256}")
            }
        },
        "unsigned" to { c -> if (c.facts.signers.isEmpty()) hit("No signing certificate could be read") else null },
        "debuggable" to { c -> if (c.facts.debuggable) hit("android:debuggable=\"true\"") else null },
        "cleartext" to { c ->
            if (c.facts.cleartextTrafficAllowed == true) hit("Cleartext (http://) traffic is allowed (usesCleartextTraffic)") else null
        },
        "cleartextUrls" to { c ->
            val urls = c.facts.dexScan?.cleartextUrls.orEmpty()
            if (urls.isEmpty()) null else SignalHit(urls.take(8).map { "Unencrypted address in code: $it" })
        },
        "packed" to { c ->
            val libs = c.facts.apkContents?.packerLibs.orEmpty()
            if (libs.isEmpty()) null else SignalHit(libs.map { "Protector library: $it" }, mapOf("packers" to libs.joinToString(", ")))
        },
        "hiddenApp" to { c -> hiddenApp(c.facts) },
        "dynamicCode" to { c ->
            val loaders = c.facts.dexScan?.dynamicCodeLoaders.orEmpty()
            if (loaders.isEmpty()) null else SignalHit(loaders.map { "Code references $it" })
        },
        "pathLoaderDownload" to { c ->
            val d = c.facts.dexScan
            if (d != null && d.pathClassLoaderWithDownload) {
                SignalHit(listOf("Code references dalvik.system.PathClassLoader") + d.downloadToFileHints.map { "Related string: $it" })
            } else {
                null
            }
        },
        "runtimeExec" to { c ->
            if (c.facts.dexScan?.runtimeExec == true) hit("Code references java.lang.Runtime and exec()") else null
        },
        "reflectionHeavy" to { c ->
            val d = c.facts.dexScan
            if (d != null && d.reflectionHeavy) {
                SignalHit(
                    d.reflectionApis.map { "Reflection API: $it" } +
                        d.hiddenApiReflectionTargets.map { "Internal Android name: $it" },
                )
            } else {
                null
            }
        },
        "publicIps" to { c ->
            val ips = c.facts.dexScan?.ipAddresses.orEmpty()
            if (ips.isEmpty()) {
                null
            } else {
                SignalHit(
                    ips.take(10).map { "IP address in code: $it" },
                    mapOf("ips" to ips.take(3).joinToString(", "), "ipCount" to ips.size.toString()),
                )
            }
        },
        "trackersSome" to { c -> trackers(c, 1..4) },
        "trackersMany" to { c -> trackers(c, 5..Int.MAX_VALUE) },
        "impersonatesBrand" to { c ->
            (c.impersonation as? ImpersonationResult.BrandMismatch)?.let {
                hit(
                    "Label: \"${c.facts.label}\"",
                    "Package: ${c.facts.packageName}",
                    "Official package(s) for ${it.brand}: ${it.officialPackages.joinToString()}",
                    params = mapOf("brand" to it.brand, "official" to it.officialPackages.first()),
                )
            }
        },
        "signerMismatch" to { c ->
            (c.impersonation as? ImpersonationResult.SignerMismatch)?.let {
                hit(
                    "Package: ${c.facts.packageName}",
                    "Signed by: ${it.actual}",
                    "Official signer(s): ${it.expected.joinToString()}",
                    params = mapOf("brand" to it.brand),
                )
            }
        },
        "systemLikeName" to { c ->
            (c.impersonation as? ImpersonationResult.SystemLike)?.let {
                hit("Label: \"${it.name}\"", "Package: ${c.facts.packageName}", params = mapOf("name" to it.name))
            }
        },
        "exportedUnprotected" to { c ->
            val open = c.facts.components.filter {
                it.exported && it.permission == null && it.type != ComponentType.ACTIVITY
            }
            if (open.size >= 3) {
                SignalHit(open.take(15).map { "${it.type.name.lowercase()}: ${it.name}" }, mapOf("count" to open.size.toString()))
            } else {
                null
            }
        },
        "dangerousPermissions" to { c ->
            val perms = c.facts.permissions.filter { it in DANGEROUS_PERMISSIONS }
            if (perms.isEmpty()) {
                null
            } else {
                SignalHit(
                    perms.map { "Permission: $it" },
                    mapOf("permissionList" to PermissionNames.describe(perms)),
                )
            }
        },
        "knownMalware" to { c ->
            c.reputation?.takeIf { it.knownMalicious }?.let {
                hit(
                    "Reputation source: ${it.source}",
                    "Label: ${it.label ?: "unknown"}",
                    params = mapOf("source" to it.source, "malwareName" to (it.label ?: "known malware")),
                )
            }
        },
        "partialScan" to { c ->
            val d = c.facts.dexScan
            if (d != null && d.truncated) {
                SignalHit(d.truncationReasons.map { "Scan limit: $it" }, mapOf("reasons" to d.truncationReasons.joinToString("; ")))
            } else {
                null
            }
        },
    )

    private fun trackers(c: RuleContext, range: IntRange): SignalHit? {
        val hits = c.facts.dexScan?.trackerHits.orEmpty()
        if (hits.size !in range) return null
        val byId = c.trackers.trackers.associateBy { it.id }
        val names = hits.keys.map { byId[it]?.name ?: it }
        return SignalHit(
            hits.map { (id, sample) -> "${byId[id]?.name ?: id}: found $sample" },
            mapOf("trackers" to names.joinToString(", "), "trackerCount" to hits.size.toString()),
        )
    }

    private fun hiddenApp(f: AppFacts): SignalHit? {
        if (f.hasLauncherEntry != false) return null // unknown or has an icon
        if (!f.enabled) return null // turned off: Android hides its icon, and it can't run either
        val bindings = f.components.mapNotNull { it.permission }.toSet()
        if (bindings.any { it in EXPECTED_HEADLESS_BINDINGS }) return null
        val active = f.components.filter {
            it.exported && (it.type == ComponentType.SERVICE || it.type == ComponentType.RECEIVER)
        }
        val boot = f.hasPermission("${P}RECEIVE_BOOT_COMPLETED")
        if (active.isEmpty() && !boot) return null
        return SignalHit(
            listOf("No launcher (home screen) entry") +
                (if (boot) listOf("Starts at boot (RECEIVE_BOOT_COMPLETED)") else emptyList()) +
                active.take(10).map { "Exported ${it.type.name.lowercase()}: ${it.name}" },
        )
    }

    /** Android version name for an API level, for plain-language text. */
    fun androidVersion(api: Int): String = when {
        api <= 0 -> "an unknown version"
        api < 14 -> "Android 3 or older"
        api < 16 -> "Android 4.0"
        api < 19 -> "Android 4.1–4.3"
        api < 21 -> "Android 4.4"
        api < 23 -> "Android 5"
        api < 24 -> "Android 6"
        api < 26 -> "Android 7"
        api < 28 -> "Android 8"
        api < 32 -> "Android ${api - 19}"
        api == 32 -> "Android 12L"
        else -> "Android ${api - 20}"
    }
}

/** Plain-language names for permissions, for use in sentences. */
object PermissionNames {
    private val NAMES = mapOf(
        "READ_CALENDAR" to "your calendar", "WRITE_CALENDAR" to "your calendar",
        "CAMERA" to "the camera", "READ_CONTACTS" to "your contacts", "WRITE_CONTACTS" to "your contacts",
        "GET_ACCOUNTS" to "your account list", "ACCESS_FINE_LOCATION" to "your exact location",
        "ACCESS_COARSE_LOCATION" to "your rough location", "RECORD_AUDIO" to "the microphone",
        "READ_PHONE_STATE" to "phone details", "READ_PHONE_NUMBERS" to "phone numbers",
        "CALL_PHONE" to "making calls", "READ_CALL_LOG" to "your call history", "WRITE_CALL_LOG" to "your call history",
        "ADD_VOICEMAIL" to "voicemail", "USE_SIP" to "internet calls", "PROCESS_OUTGOING_CALLS" to "outgoing calls",
        "BODY_SENSORS" to "body sensors", "SEND_SMS" to "sending texts", "RECEIVE_SMS" to "your text messages",
        "READ_SMS" to "your text messages", "RECEIVE_WAP_PUSH" to "your text messages",
        "RECEIVE_MMS" to "your text messages", "READ_EXTERNAL_STORAGE" to "your files",
        "WRITE_EXTERNAL_STORAGE" to "your files",
    )

    fun describe(permissions: List<String>): String {
        val names = permissions.mapNotNull { NAMES[it.substringAfterLast('.')] }.distinct()
        return when (names.size) {
            0 -> "sensitive data"
            1 -> names[0]
            else -> names.dropLast(1).joinToString(", ") + " and " + names.last()
        }
    }
}
