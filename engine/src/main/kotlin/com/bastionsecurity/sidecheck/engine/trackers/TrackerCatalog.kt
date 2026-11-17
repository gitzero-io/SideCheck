package com.bastionsecurity.sidecheck.engine.trackers

import kotlinx.serialization.Serializable

/**
 * A list of known tracker / ad SDKs, identified by Java package prefixes found in the app's code.
 *
 * The shape deliberately mirrors the Exodus Privacy tracker list (name, code signature, categories,
 * website) so it can be swapped in later. Exodus publishes `code_signature` as a regex of package
 * names joined by "|" (e.g. "com.facebook.ads|com.facebook.audiencenetwork"); an adapter only has to
 * split on "|" and strip regex escapes to produce [codeSignatures].
 */
@Serializable
data class TrackerCatalog(
    val version: Int,
    val source: String,
    val trackers: List<TrackerDef>,
)

@Serializable
data class TrackerDef(
    val id: String,
    val name: String,
    /** e.g. "Advertisement", "Analytics", "Profiling", "Crash reporting". Same vocabulary as Exodus. */
    val categories: List<String>,
    /** Java package prefixes, dotted form, e.g. "com.facebook.ads". */
    val codeSignatures: List<String>,
    val website: String? = null,
)

/**
 * Fast prefix matcher over class names. Accepts both dex type descriptors ("Lcom/foo/Bar;") and
 * dotted names ("com.foo.Bar") and matches on whole package segments only.
 */
class TrackerMatcher(catalog: TrackerCatalog) {

    private class Entry(val prefix: String, val trackerId: String)

    /** Index by the first two package segments ("com.facebook") so each lookup checks few entries. */
    private val index: Map<String, List<Entry>>

    init {
        val map = HashMap<String, MutableList<Entry>>()
        for (t in catalog.trackers) {
            for (sig in t.codeSignatures) {
                val prefix = sig.trim().trimEnd('.')
                if (prefix.isEmpty()) continue
                map.getOrPut(keyOf(prefix)) { mutableListOf() }.add(Entry(prefix, t.id))
            }
        }
        index = map
    }

    /** Returns the tracker id that [raw] belongs to, or null. */
    fun match(raw: String): String? {
        val name = normalize(raw) ?: return null
        val candidates = index[keyOf(name)] ?: return null
        for (e in candidates) {
            if (name.length == e.prefix.length) {
                if (name == e.prefix) return e.trackerId
            } else if (name.length > e.prefix.length && name.startsWith(e.prefix) && name[e.prefix.length] == '.') {
                return e.trackerId
            }
        }
        return null
    }

    private fun keyOf(dotted: String): String {
        val first = dotted.indexOf('.')
        if (first < 0) return dotted
        val second = dotted.indexOf('.', first + 1)
        return if (second < 0) dotted else dotted.substring(0, second)
    }

    private fun normalize(s: String): String? {
        if (s.length < 3) return null
        if (s[0] == 'L' && s.endsWith(";") && s.indexOf('/') > 0) {
            return s.substring(1, s.length - 1).replace('/', '.')
        }
        // Dotted names used with reflection, e.g. "com.facebook.ads.AdView".
        if (s.indexOf('.') > 0 && s.none { it == ' ' || it == '/' }) return s
        return null
    }
}
