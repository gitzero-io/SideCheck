package com.bastionsecurity.sidecheck.engine.apk

import com.bastionsecurity.sidecheck.engine.dex.DexFormatException
import com.bastionsecurity.sidecheck.engine.dex.DexScanLimits
import com.bastionsecurity.sidecheck.engine.dex.DexSignalCollector
import com.bastionsecurity.sidecheck.engine.dex.DexStringReader
import com.bastionsecurity.sidecheck.engine.model.ApkContents
import com.bastionsecurity.sidecheck.engine.model.DexScanResult
import com.bastionsecurity.sidecheck.engine.trackers.TrackerMatcher
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.zip.ZipFile

data class ApkStaticFacts(
    val contents: ApkContents,
    val dexScan: DexScanResult,
    val sha256: String?,
)

/** Packer / protector native library names, as simple globs ("libjiagu*.so"). */
class PackerSignatures(globs: List<String>) {
    private val patterns = globs.map { glob ->
        Regex(glob.split('*').joinToString(".*") { Regex.escape(it) }, RegexOption.IGNORE_CASE)
    }

    fun matches(fileName: String) = patterns.any { it.matches(fileName) }
}

/**
 * Reads what it can from an APK file without installing it: native libs, packer libs, dex count,
 * and a streaming dex string scan. Pure JVM — works on device and on a server.
 *
 * For split APKs, call [inspect] once per split and merge, or pass all paths to [inspectAll].
 */
class ApkFileInspector(
    private val trackers: TrackerMatcher,
    private val packers: PackerSignatures,
    private val limits: DexScanLimits = DexScanLimits(),
) {
    fun inspectAll(apks: List<File>, hashFirst: Boolean = true): ApkStaticFacts {
        val deadline = System.nanoTime() + limits.maxMillisPerApk * 1_000_000
        val collector = DexSignalCollector(trackers, limits)
        val libs = mutableListOf<String>()
        val abis = linkedSetOf<String>()
        val packerLibs = mutableListOf<String>()
        var dexCount = 0
        var dexBytes = 0L
        var entries = 0

        for (apk in apks) {
            try {
                ZipFile(apk).use { zip ->
                    val zipEntries = zip.entries()
                    while (zipEntries.hasMoreElements()) {
                        val e = zipEntries.nextElement()
                        entries++
                        if (entries > MAX_ZIP_ENTRIES) {
                            collector.truncationReasons += "APK has more than $MAX_ZIP_ENTRIES files; stopped listing"
                            break
                        }
                        if (e.isDirectory) continue
                        val name = e.name
                        if (name.startsWith("lib/") && name.endsWith(".so")) {
                            val parts = name.split('/')
                            if (parts.size >= 3) abis += parts[1]
                            val file = parts.last()
                            if (libs.size < MAX_LIBS_LISTED) libs += name
                            if (packers.matches(file) && file !in packerLibs) packerLibs += file
                        } else if (DEX_NAME.matches(name)) {
                            dexCount++
                            if (e.size > 0) dexBytes += e.size
                            scanDex(zip, e, collector, deadline)
                        }
                    }
                }
            } catch (ex: IOException) {
                collector.truncationReasons += "could not open ${apk.name} as a zip: ${ex.message}"
            }
        }

        val sha = if (hashFirst) apks.firstOrNull()?.let { runCatching { sha256(it) }.getOrNull() } else null
        return ApkStaticFacts(
            contents = ApkContents(libs, abis, packerLibs, dexCount, dexBytes, entries),
            dexScan = collector.result(),
            sha256 = sha,
        )
    }

    fun inspect(apk: File) = inspectAll(listOf(apk))

    private fun scanDex(zip: ZipFile, entry: java.util.zip.ZipEntry, collector: DexSignalCollector, deadline: Long) {
        if (collector.dexFiles >= limits.maxDexFiles) {
            if (collector.truncationReasons.none { it.startsWith("more than") }) {
                collector.truncationReasons += "more than ${limits.maxDexFiles} code files; scanned the first ${limits.maxDexFiles}"
            }
            return
        }
        if (System.nanoTime() > deadline) {
            if ("ran out of time" !in collector.truncationReasons) collector.truncationReasons += "ran out of time"
            return
        }
        collector.dexFiles++
        try {
            zip.getInputStream(entry).use { input ->
                val stats = DexStringReader.read(input, limits, deadline) { collector.visit(it) }
                stats.truncatedReason?.let { collector.truncationReasons += "${entry.name}: $it" }
            }
        } catch (ex: DexFormatException) {
            collector.truncationReasons += "${entry.name}: ${ex.message}"
        } catch (ex: IOException) {
            collector.truncationReasons += "${entry.name}: read error (${ex.message})"
        }
    }

    companion object {
        private val DEX_NAME = Regex("^classes\\d*\\.dex$")
        private const val MAX_ZIP_ENTRIES = 100_000
        private const val MAX_LIBS_LISTED = 200

        fun sha256(file: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().buffered(64 * 1024).use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                }
            }
            return md.digest().toHex()
        }

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    }
}
