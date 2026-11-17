package com.bastionsecurity.sidecheck.engine.impersonation

import com.bastionsecurity.sidecheck.engine.model.AppFacts
import kotlinx.serialization.Serializable

@Serializable
data class KnownAppsCatalog(
    val version: Int,
    val apps: List<KnownApp>,
    /** Names that only Android itself should use ("Android System", "System Update"...). */
    val systemLikeLabels: List<String> = emptyList(),
)

@Serializable
data class KnownApp(
    val brand: String,
    /** Names this app is shown as. Matching ignores case, spaces and punctuation. */
    val aliases: List<String>,
    val officialPackages: List<String>,
    /**
     * SHA-256 of the official signing certificate(s), lowercase hex, no colons.
     *
     * TODO(bastion): fill these in with VERIFIED values only — e.g. from `apksigner verify
     *  --print-certs` on an APK pulled from a device that installed it from Google Play.
     *  Until filled in, a matching package name is trusted without a certificate check, so a
     *  modified copy that keeps the official package name is NOT flagged by this check.
     */
    val signingCertSha256: List<String> = emptyList(),
)

sealed interface ImpersonationResult {
    data object None : ImpersonationResult

    /** Uses a known brand's name, but isn't that brand's package. */
    data class BrandMismatch(val brand: String, val officialPackages: List<String>) : ImpersonationResult

    /** Uses the official package name, but is signed by someone else. Only possible once hashes are filled in. */
    data class SignerMismatch(val brand: String, val expected: List<String>, val actual: String?) : ImpersonationResult

    /** Uses a name that only Android itself should use. */
    data class SystemLike(val name: String) : ImpersonationResult
}

class ImpersonationCheck(private val catalog: KnownAppsCatalog) {

    private val byAlias: Map<String, KnownApp> = buildMap {
        for (app in catalog.apps) for (alias in app.aliases + app.brand) put(normalize(alias), app)
    }
    private val byPackage: Map<String, KnownApp> = buildMap {
        for (app in catalog.apps) for (p in app.officialPackages) put(p, app)
    }
    private val systemLike = catalog.systemLikeLabels.map(::normalize).toSet()

    fun check(facts: AppFacts): ImpersonationResult {
        val official = byPackage[facts.packageName]
        if (official != null) {
            val expected = official.signingCertSha256.map { it.lowercase().replace(":", "") }
            val actual = facts.primarySigner?.sha256?.lowercase()
            if (expected.isNotEmpty() && actual != null && facts.signers.none { it.sha256.lowercase() in expected }) {
                return ImpersonationResult.SignerMismatch(official.brand, expected, actual)
            }
            return ImpersonationResult.None
        }

        val label = normalize(facts.label)
        if (label.isEmpty()) return ImpersonationResult.None

        matchBrand(label)?.let { return ImpersonationResult.BrandMismatch(it.brand, it.officialPackages) }

        if (!facts.isSystemApp && label in systemLike && !isPlatformPackage(facts.packageName)) {
            return ImpersonationResult.SystemLike(facts.label)
        }
        return ImpersonationResult.None
    }

    /** Exact alias, or alias followed only by filler words ("Netflix TV", "Netflix 4K Mod"). */
    private fun matchBrand(label: String): KnownApp? {
        byAlias[label]?.let { return it }
        for ((alias, app) in byAlias) {
            if (alias.length < 3 || !label.startsWith(alias)) continue
            var rest = label.substring(alias.length)
            var changed = true
            while (rest.isNotEmpty() && changed) {
                changed = false
                for (w in FILLER) {
                    if (rest.startsWith(w)) {
                        rest = rest.substring(w.length)
                        changed = true
                        break
                    }
                }
            }
            if (rest.isEmpty()) return app
        }
        return null
    }

    private fun isPlatformPackage(pkg: String) =
        pkg == "android" || pkg.startsWith("com.android.") || pkg.startsWith("com.google.android.")

    companion object {
        /** Words that commonly get tacked onto a cloned brand name. Already normalized. */
        private val FILLER = listOf(
            "androidtv", "googletv", "fortv", "tv", "hd", "4k", "uhd", "app", "premium", "pro", "mod",
            "modded", "free", "plus", "lite", "official", "new", "apk", "cracked", "unlocked", "vip",
        ).sortedByDescending { it.length }

        fun normalize(s: String): String =
            s.lowercase()
                .replace("+", "plus")
                .replace("&", "and")
                .filter { it.isLetterOrDigit() }
    }
}
