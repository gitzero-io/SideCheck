package com.bastionsecurity.sidecheck.engine.apk

import com.bastionsecurity.sidecheck.engine.DexFixture
import com.bastionsecurity.sidecheck.engine.Fixtures
import com.bastionsecurity.sidecheck.engine.trackers.TrackerMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkFileInspectorTest {
    @get:Rule val tmp = TemporaryFolder()

    private val inspector = ApkFileInspector(
        TrackerMatcher(Fixtures.bundle.trackers),
        PackerSignatures(Fixtures.bundle.packers.libraries.map { it.glob }),
    )

    private fun apk(entries: Map<String, ByteArray>): File {
        val f = tmp.newFile("test.apk")
        ZipOutputStream(f.outputStream()).use { zip ->
            for ((name, bytes) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return f
    }

    @Test
    fun `reads libs, packers, dex count and dex strings`() {
        val f = apk(
            mapOf(
                "AndroidManifest.xml" to ByteArray(10),
                "classes.dex" to DexFixture.build(listOf("Lcom/unity3d/ads/UnityAds;", "Lcom/example/Main;")),
                "classes2.dex" to DexFixture.build(listOf("Ldalvik/system/InMemoryDexClassLoader;")),
                "assets/classes3.dex" to ByteArray(4), // not a root dex; must be ignored
                "lib/arm64-v8a/libjiagu_a64.so" to ByteArray(4),
                "lib/armeabi-v7a/libfoo.so" to ByteArray(4),
            ),
        )
        val r = inspector.inspect(f)
        assertEquals(2, r.contents.dexCount)
        assertEquals(setOf("arm64-v8a", "armeabi-v7a"), r.contents.abis)
        assertEquals(listOf("libjiagu_a64.so"), r.contents.packerLibs)
        assertEquals(setOf("unity_ads"), r.dexScan.trackerHits.keys)
        assertEquals(setOf("Ldalvik/system/InMemoryDexClassLoader;"), r.dexScan.dynamicCodeLoaders)
        assertEquals(2, r.dexScan.dexFilesScanned)
        assertEquals(64, r.sha256!!.length)
    }

    @Test
    fun `bad dex is reported, not thrown`() {
        val f = apk(mapOf("classes.dex" to ByteArray(200)))
        val r = inspector.inspect(f)
        assertTrue(r.dexScan.truncated)
    }

    @Test
    fun `not a zip is reported, not thrown`() {
        val f = tmp.newFile("bad.apk").apply { writeText("hello") }
        val r = inspector.inspect(f)
        assertTrue(r.dexScan.truncated)
        assertEquals(0, r.contents.dexCount)
    }

    @Test
    fun `packer globs`() {
        val p = PackerSignatures(Fixtures.bundle.packers.libraries.map { it.glob })
        assertTrue(p.matches("libjiagu.so"))
        assertTrue(p.matches("libDexHelper-x86.so"))
        assertTrue(p.matches("libshella-2.10.so"))
        assertTrue(p.matches("libsecexe.so"))
        assertTrue(!p.matches("libsecexe2.so"))
        assertTrue(!p.matches("libc++_shared.so"))
    }
}
