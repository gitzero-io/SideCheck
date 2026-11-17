package com.bastionsecurity.sidecheck.engine.dex

import com.bastionsecurity.sidecheck.engine.DexFixture
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class DexStringReaderTest {

    private val farFuture = Long.MAX_VALUE

    private fun readAll(bytes: ByteArray, limits: DexScanLimits = DexScanLimits()): Pair<List<String>, DexReadStats> {
        val seen = mutableListOf<String>()
        val stats = DexStringReader.read(ByteArrayInputStream(bytes), limits, farFuture) { seen += it }
        return seen to stats
    }

    @Test
    fun `reads every string even when data is out of order`() {
        val strings = listOf("Landroid/app/Activity;", "Lcom/example/Main;", "onCreate", "hello world")
        val (seen, stats) = readAll(DexFixture.build(strings))
        assertEquals(strings.toSet(), seen.toSet())
        assertEquals(4L, stats.stringsRead)
        assertNull(stats.truncatedReason)
    }

    @Test
    fun `decodes modified utf8 including nul and surrogate pairs`() {
        val strings = listOf("café", "a\u0000b", "日本語", "😀 smile")
        val (seen, _) = readAll(DexFixture.build(strings))
        assertEquals(strings.toSet(), seen.toSet())
    }

    @Test
    fun `nul char is encoded as two bytes`() {
        val enc = DexFixture.mutf8("\u0000")
        assertEquals(2, enc.size)
        assertEquals("\u0000", Mutf8.decode(enc, enc.size))
    }

    @Test
    fun `empty string table is fine`() {
        val (seen, stats) = readAll(DexFixture.build(emptyList()))
        assertTrue(seen.isEmpty())
        assertEquals(0L, stats.stringsRead)
    }

    @Test(expected = DexFormatException::class)
    fun `rejects non dex input`() {
        readAll(ByteArray(0x70) { 'x'.code.toByte() })
    }

    @Test
    fun `caps number of strings`() {
        val strings = (0 until 100).map { "s$it" }
        val (seen, stats) = readAll(DexFixture.build(strings), DexScanLimits(maxStringsPerDex = 10))
        assertEquals(10, seen.size)
        assertNotNull(stats.truncatedReason)
    }

    @Test
    fun `skips strings longer than the cap without failing`() {
        val long = "x".repeat(5000)
        val (seen, _) = readAll(DexFixture.build(listOf("short", long, "after")), DexScanLimits(maxStringBytes = 100))
        assertEquals(setOf("short", "after"), seen.toSet())
    }

    @Test
    fun `stops at byte limit`() {
        val strings = (0 until 2000).map { "string-number-$it" }
        val (seen, stats) = readAll(DexFixture.build(strings), DexScanLimits(maxBytesPerDex = 12_000))
        assertTrue(seen.size in 1 until 2000)
        assertNotNull(stats.truncatedReason)
    }

    @Test
    fun `handles truncated file`() {
        val full = DexFixture.build(listOf("alpha", "beta", "gamma"))
        val cut = full.copyOf(full.size - 4)
        val (_, stats) = readAll(cut)
        assertNotNull(stats.truncatedReason)
    }

    @Test
    fun `respects deadline`() {
        val strings = (0 until 10_000).map { "s$it" }
        val stats = DexStringReader.read(ByteArrayInputStream(DexFixture.build(strings)), DexScanLimits(), 0L) {}
        assertEquals("ran out of time", stats.truncatedReason)
    }
}
