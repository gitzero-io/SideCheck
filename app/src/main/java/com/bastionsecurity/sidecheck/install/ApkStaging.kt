package com.bastionsecurity.sidecheck.install

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.io.IOException
import java.util.zip.ZipFile

/**
 * Copies an APK the user handed us (from a file manager, Downloader, or the document picker) into
 * our private cache so it can be inspected and later handed to the system installer.
 *
 * The copy streams in 64 KB chunks, so even large APKs don't need much memory.
 */
class ApkStaging(private val context: Context) {

    sealed interface Result {
        data class Ok(val file: File, val displayName: String) : Result
        data class Failed(val reason: Reason, val detail: String? = null) : Result
    }

    enum class Reason {
        /** We weren't allowed to read the file (e.g. an old-style file:// link). */
        CANT_READ,
        TOO_BIG,
        NOT_ENOUGH_SPACE,
        /** .apks / .xapk / .apkm bundles: several APKs zipped together. */
        BUNDLE,
        NOT_AN_APK,
    }

    val dir: File get() = File(context.cacheDir, DIR).apply { mkdirs() }

    fun stage(uri: Uri): Result {
        cleanup(keep = null)
        val name = displayName(uri) ?: uri.lastPathSegment ?: "app.apk"
        val size = sizeOf(uri)
        if (size != null && size > MAX_BYTES) return Result.Failed(Reason.TOO_BIG)
        val needed = (size ?: 0L) + SPACE_MARGIN
        if (dir.usableSpace < needed) return Result.Failed(Reason.NOT_ENOUGH_SPACE)

        val out = File(dir, "check-${System.currentTimeMillis()}.apk")
        try {
            val input = try {
                context.contentResolver.openInputStream(uri)
            } catch (e: SecurityException) {
                return Result.Failed(Reason.CANT_READ, e.message)
            } ?: return Result.Failed(Reason.CANT_READ)
            input.use { inp ->
                out.outputStream().use { o ->
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val n = inp.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_BYTES) {
                            o.close(); out.delete()
                            return Result.Failed(Reason.TOO_BIG)
                        }
                        o.write(buf, 0, n)
                    }
                }
            }
        } catch (e: IOException) {
            out.delete()
            return Result.Failed(Reason.CANT_READ, e.message)
        }

        classify(out)?.let { reason ->
            out.delete()
            return Result.Failed(reason)
        }
        return Result.Ok(out, name)
    }

    /** Null if it looks like a normal APK. */
    private fun classify(f: File): Reason? = try {
        ZipFile(f).use { zip ->
            var hasManifest = false
            var hasInnerApk = false
            val entries = zip.entries()
            var seen = 0
            while (entries.hasMoreElements() && seen < 50_000) {
                val name = entries.nextElement().name
                seen++
                if (name == "AndroidManifest.xml") hasManifest = true
                if (name.endsWith(".apk", ignoreCase = true)) hasInnerApk = true
            }
            when {
                hasManifest -> null
                hasInnerApk -> Reason.BUNDLE
                else -> Reason.NOT_AN_APK
            }
        }
    } catch (_: IOException) {
        Reason.NOT_AN_APK
    }

    /** Deletes staged files except [keep]. Called before each new check and when leaving. */
    fun cleanup(keep: File?) {
        dir.listFiles()?.forEach { if (it != keep) it.delete() }
    }

    private fun displayName(uri: Uri): String? = query(uri, OpenableColumns.DISPLAY_NAME) { it.getString(0) }
        ?: if (uri.scheme == ContentResolver.SCHEME_FILE) uri.lastPathSegment else null

    private fun sizeOf(uri: Uri): Long? = query(uri, OpenableColumns.SIZE) { if (it.isNull(0)) null else it.getLong(0) }

    private fun <T> query(uri: Uri, column: String, read: (android.database.Cursor) -> T?): T? =
        if (uri.scheme != ContentResolver.SCHEME_CONTENT) {
            null
        } else {
            runCatching {
                context.contentResolver.query(uri, arrayOf(column), null, null, null)?.use { c ->
                    if (c.moveToFirst()) read(c) else null
                }
            }.getOrNull()
        }

    companion object {
        const val DIR = "apk-check"
        /** TV apps are rarely over a few hundred MB; this keeps cheap boxes from filling up. */
        const val MAX_BYTES = 1024L * 1024 * 1024
        private const val SPACE_MARGIN = 100L * 1024 * 1024
    }
}
