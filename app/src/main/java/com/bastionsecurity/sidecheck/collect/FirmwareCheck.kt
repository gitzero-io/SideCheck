package com.bastionsecurity.sidecheck.collect

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.edit
import com.bastionsecurity.sidecheck.engine.apk.ApkFileInspector
import com.bastionsecurity.sidecheck.engine.malware.MalwareMatch
import com.bastionsecurity.sidecheck.engine.malware.MalwareMatcher
import com.bastionsecurity.sidecheck.engine.malware.MatchType
import java.io.File

/** A preinstalled (firmware) app that matches the known-malware list. */
data class FirmwareMatch(
    val packageName: String,
    val label: String,
    val family: String,
    val source: String,
    val sourceUrl: String,
    val bySigner: Boolean,
    val enabled: Boolean,
)

/**
 * Checks apps that came with the device against the known-malware list ONLY (no grading).
 * Botnets such as BadBox 2.0 and Vo1d often ship inside cheap TV boxes' firmware.
 *
 * Cost control: signers are cheap to read. Whole-APK hashes are only computed if the list has
 * file hashes, only for files up to [MAX_HASH_BYTES], and are cached by path + size + date.
 */
class FirmwareCheck(
    private val context: Context,
    private val matcher: MalwareMatcher,
    private val collector: () -> PackageCollector,
) {
    private val cache = context.getSharedPreferences("apk_hash_cache", Context.MODE_PRIVATE)

    /** Blocking; call on a background thread. */
    fun run(): List<FirmwareMatch> {
        if (matcher.isEmpty) return emptyList()
        val pm = context.packageManager
        val c = collector()
        val out = mutableListOf<FirmwareMatch>()
        for (ai in systemApps(pm)) {
            val pkg = ai.packageName
            val signers = c.collectInstalledSignersOnly(pkg)
            val apkHash = if (matcher.hasApkHashes) hashOf(File(ai.sourceDir)) else null
            val m: MalwareMatch = matcher.match(apkHash, signers) ?: continue
            out += FirmwareMatch(
                packageName = pkg,
                label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(pkg),
                family = m.entry.family,
                source = m.entry.source,
                sourceUrl = m.entry.sourceUrl,
                bySigner = m.entry.type == MatchType.CERT_SHA256,
                enabled = ai.enabled,
            )
        }
        Log.i(TAG, "Firmware check: ${out.size} match(es)")
        return out
    }

    private fun systemApps(pm: PackageManager): List<ApplicationInfo> {
        val flags = PackageManager.MATCH_DISABLED_COMPONENTS
        val apps = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getInstalledApplications(flags)
        }
        return apps.filter { it.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0 }
    }

    private fun hashOf(f: File): String? {
        if (!f.canRead() || f.length() > MAX_HASH_BYTES) return null
        val key = f.absolutePath
        val stamp = "${f.length()}|${f.lastModified()}"
        cache.getString(key, null)?.let { v ->
            if (v.startsWith("$stamp|")) return v.substringAfterLast('|')
        }
        val h = runCatching { ApkFileInspector.sha256(f) }.getOrNull() ?: return null
        cache.edit { putString(key, "$stamp|$h") }
        return h
    }

    companion object {
        private const val TAG = "SideCheck"
        /** Botnet payload APKs are small; skip huge system apps (e.g. Play services) to save time. */
        private const val MAX_HASH_BYTES = 128L * 1024 * 1024
    }
}
