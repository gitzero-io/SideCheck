package com.bastionsecurity.sidecheck.engine.providers

import com.bastionsecurity.sidecheck.engine.impersonation.KnownAppsCatalog
import com.bastionsecurity.sidecheck.engine.malware.MalwareDb
import com.bastionsecurity.sidecheck.engine.model.ReputationResult
import com.bastionsecurity.sidecheck.engine.rules.RuleSet
import com.bastionsecurity.sidecheck.engine.trackers.TrackerCatalog
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Future: look up an APK / signer hash with a reputation service (own backend, MalwareBazaar,
 * VirusTotal). v1 ships only [NoOpReputationProvider] — the app has no INTERNET permission.
 */
interface ReputationProvider {
    val name: String

    /** Returns null when the service has no opinion. Must not throw for "not found". */
    suspend fun lookup(apkSha256: String?, packageName: String, signerSha256s: List<String>): ReputationResult?
}

object NoOpReputationProvider : ReputationProvider {
    override val name = "none"
    override suspend fun lookup(apkSha256: String?, packageName: String, signerSha256s: List<String>): ReputationResult? = null
}

@Serializable
data class PackerList(val version: Int, val libraries: List<PackerLib>)

@Serializable
data class PackerLib(val glob: String, val vendor: String)

/** Everything the engine needs that can change without an app update. */
data class RuleBundle(
    val rules: RuleSet,
    val trackers: TrackerCatalog,
    val knownApps: KnownAppsCatalog,
    val packers: PackerList,
    val malware: MalwareDb,
)

/**
 * Where rules, tracker lists, known apps and packer signatures come from. v1 only bundles them.
 * A future implementation can download a signed bundle, cache it, and fall back to the bundled one.
 */
interface RuleSetProvider {
    suspend fun load(): RuleBundle
}

/** Loads the JSON files shipped inside the engine jar under /sidecheck/. */
class BundledRuleSetProvider : RuleSetProvider {
    override suspend fun load(): RuleBundle = loadBlocking()

    fun loadBlocking(): RuleBundle = RuleBundle(
        rules = json.decodeFromString(resource("rules.json")),
        trackers = json.decodeFromString(resource("trackers.json")),
        knownApps = json.decodeFromString(resource("known_apps.json")),
        packers = json.decodeFromString(resource("packers.json")),
        malware = json.decodeFromString(resource("malware_db.json")),
    )

    private fun resource(name: String): String =
        (javaClass.getResourceAsStream("/sidecheck/$name") ?: error("Missing bundled resource $name"))
            .bufferedReader().use { it.readText() }

    companion object {
        val json = Json { ignoreUnknownKeys = true }
    }
}

enum class PremiumFeature {
    /** Hash lookups against a cloud reputation service. */
    CLOUD_REPUTATION,
    /** Rules / tracker lists updated from the server between app releases. */
    LIVE_RULE_UPDATES,
}

/** Gate for the future paid tier. v1 is free only. */
interface PremiumFeatures {
    val isPremium: Boolean
    fun isEnabled(feature: PremiumFeature): Boolean
}

object FreeTier : PremiumFeatures {
    /** Flip only when the paid tier and its backend exist. */
    const val PREMIUM_AVAILABLE = false

    override val isPremium = false
    override fun isEnabled(feature: PremiumFeature) = false
}
