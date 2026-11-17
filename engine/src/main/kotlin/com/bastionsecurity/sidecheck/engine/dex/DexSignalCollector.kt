package com.bastionsecurity.sidecheck.engine.dex

import com.bastionsecurity.sidecheck.engine.model.DexScanResult
import com.bastionsecurity.sidecheck.engine.trackers.TrackerMatcher

/**
 * Looks at each dex string once and records anything interesting. Keeps only small, capped sets.
 * One collector is shared across all dex files of an APK.
 */
class DexSignalCollector(
    private val trackers: TrackerMatcher,
    private val limits: DexScanLimits = DexScanLimits(),
) {
    private val trackerHits = LinkedHashMap<String, String>()
    private val dynamicLoaders = LinkedHashSet<String>()
    private var pathClassLoader = false
    private val networkClients = LinkedHashSet<String>()
    private val codeFileNames = LinkedHashSet<String>()
    private val reflectionApis = LinkedHashSet<String>()
    private val hiddenTargets = LinkedHashSet<String>()
    private var sawRuntime = false
    private var sawExec = false
    private val ips = LinkedHashSet<String>()
    private val urls = LinkedHashSet<String>()

    var dexFiles = 0
    var strings = 0L
    val truncationReasons = mutableListOf<String>()

    fun visit(s: String) {
        strings++
        if (s.isEmpty()) return

        trackers.match(s)?.let { id -> if (id !in trackerHits) trackerHits[id] = s }

        when (s) {
            in DYNAMIC_LOADERS -> dynamicLoaders += s
            in PATH_CLASS_LOADER -> pathClassLoader = true
            in NETWORK_CLIENTS -> networkClients += s
            in REFLECTION_APIS -> reflectionApis += s
            in HIDDEN_API_TARGETS -> hiddenTargets += s
            "Ljava/lang/Runtime;" -> sawRuntime = true
            "exec" -> sawExec = true
        }

        if (s.length in 5..200 && codeFileNames.size < 10 && ' ' !in s) {
            val lower = s.lowercase()
            if (lower.endsWith(".dex") || lower.endsWith(".jar") || lower.endsWith(".apk")) codeFileNames += s
        }

        if (s.length >= 10 && (s.contains("http://") || s.contains("https://"))) {
            extractUrls(s)
        } else if (s.length in 7..21 && s[0].isDigit()) {
            NetworkStrings.publicIpv4(s, fromUrl = false)?.let { if (ips.size < limits.maxIps) ips += it }
        }
    }

    private fun extractUrls(s: String) {
        var start = s.indexOf("http")
        while (start >= 0 && urls.size < limits.maxUrls) {
            if (s.startsWith("http://", start) || s.startsWith("https://", start)) {
                var end = start
                while (end < s.length && !s[end].isWhitespace() && s[end] != '"' && s[end] != '\'' && s[end] != '<') end++
                val url = s.substring(start, minOf(end, start + 300))
                val host = NetworkStrings.hostOf(url)
                if (host != null && !NetworkStrings.isIgnorableHost(host)) {
                    urls += url
                    NetworkStrings.publicIpv4(host, fromUrl = true)?.let { if (ips.size < limits.maxIps) ips += it }
                }
                start = s.indexOf("http", end)
            } else {
                start = s.indexOf("http", start + 4)
            }
        }
    }

    fun result(): DexScanResult = DexScanResult(
        dexFilesScanned = dexFiles,
        stringsScanned = strings,
        truncated = truncationReasons.isNotEmpty(),
        truncationReasons = truncationReasons.toList(),
        trackerHits = trackerHits.toMap(),
        dynamicCodeLoaders = dynamicLoaders.toSet(),
        pathClassLoaderReferenced = pathClassLoader,
        downloadToFileHints = if (networkClients.isNotEmpty() && codeFileNames.isNotEmpty()) {
            (networkClients.take(2) + codeFileNames.take(5)).toSet()
        } else {
            emptySet()
        },
        reflectionApis = reflectionApis.toSet(),
        hiddenApiReflectionTargets = hiddenTargets.toSet(),
        runtimeExec = sawRuntime && sawExec,
        ipAddresses = ips.toSet(),
        urls = urls.toSet(),
    )

    companion object {
        val DYNAMIC_LOADERS = setOf(
            "Ldalvik/system/DexClassLoader;",
            "Ldalvik/system/InMemoryDexClassLoader;",
            "dalvik.system.DexClassLoader",
            "dalvik.system.InMemoryDexClassLoader",
        )
        val PATH_CLASS_LOADER = setOf("Ldalvik/system/PathClassLoader;", "dalvik.system.PathClassLoader")
        val NETWORK_CLIENTS = setOf(
            "Ljava/net/HttpURLConnection;",
            "Ljavax/net/ssl/HttpsURLConnection;",
            "Lokhttp3/OkHttpClient;",
            "Lcom/android/volley/RequestQueue;",
        )
        val REFLECTION_APIS = setOf(
            "getDeclaredMethod", "getDeclaredField", "setAccessible", "forName",
            "Ljava/lang/reflect/Method;", "Ljava/lang/reflect/Field;",
        )

        /** Internal Android names that apps only touch to rewire how they load or run. */
        val HIDDEN_API_TARGETS = setOf(
            "android.app.ActivityThread", "android.app.LoadedApk", "currentActivityThread",
            "mBoundApplication", "mInitialApplication", "mAllApplications", "mClassLoader",
            "mPackages", "dalvik.system.DexPathList", "dexElements",
        )
    }
}

internal object NetworkStrings {
    /** Hosts that show up as XML namespaces / spec links, not as places an app connects to. */
    private val IGNORABLE_HOSTS = setOf(
        "schemas.android.com", "www.w3.org", "w3.org", "ns.adobe.com", "xmlpull.org", "www.xmlpull.org",
        "xml.org", "www.apache.org", "apache.org", "json-schema.org", "purl.org", "schemas.xmlsoap.org",
        "schemas.microsoft.com", "localhost", "127.0.0.1", "example.com", "www.example.com",
    )

    fun isIgnorableHost(host: String) = host.lowercase() in IGNORABLE_HOSTS

    fun hostOf(url: String): String? {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return null
        var start = schemeEnd + 3
        val at = url.indexOf('@', start)
        val slash = url.indexOf('/', start).let { if (it < 0) url.length else it }
        if (at in start until slash) start = at + 1
        var end = start
        while (end < url.length && url[end] != '/' && url[end] != ':' && url[end] != '?' && url[end] != '#') end++
        val host = url.substring(start, end)
        return host.ifEmpty { null }
    }

    /**
     * Returns [s] if it is a public IPv4 address. Bare strings that look like version numbers
     * (every part under 10, e.g. "1.2.0.4") are ignored unless they came from a URL.
     */
    fun publicIpv4(s: String, fromUrl: Boolean): String? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val octets = IntArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it.isDigit() }) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            octets[i] = v
        }
        val (a, b) = octets[0] to octets[1]
        val private = a == 0 || a == 10 || a == 127 || a >= 224 ||
            (a == 172 && b in 16..31) || (a == 192 && b == 168) || (a == 169 && b == 254) ||
            (a == 100 && b in 64..127)
        if (private) return null
        if (!fromUrl && octets.all { it < 10 }) return null
        return s
    }
}
