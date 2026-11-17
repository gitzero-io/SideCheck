package com.bastionsecurity.sidecheck.engine.dex

import java.io.EOFException
import java.io.InputStream

/**
 * Safety limits for scanning. Defaults are tuned for cheap 2 GB TV boxes.
 */
data class DexScanLimits(
    /** Stop after this many dex files in one APK. */
    val maxDexFiles: Int = 40,
    /** Read at most this many string ids per dex (the offset table costs 4 bytes each). */
    val maxStringsPerDex: Int = 600_000,
    /** Don't read past this byte offset in a single dex. */
    val maxBytesPerDex: Long = 96L * 1024 * 1024,
    /** Strings longer than this (in encoded bytes) are skipped, not decoded. */
    val maxStringBytes: Int = 2048,
    /** Total wall-clock budget for one APK's dex scan. */
    val maxMillisPerApk: Long = 25_000,
    val maxUrls: Int = 150,
    val maxIps: Int = 50,
)

class DexFormatException(message: String) : Exception(message)

data class DexReadStats(
    val stringsRead: Long,
    val truncatedReason: String?,
)

/**
 * Reads the string table of a single .dex file from a forward-only stream.
 *
 * Why forward-only: dex files inside an APK are usually compressed, so random access means
 * extracting to disk first. Instead we:
 *  1. read the 0x70-byte header to get string_ids_size / string_ids_off,
 *  2. read the string_ids offset table into an IntArray (4 bytes per string, capped),
 *  3. sort those offsets and walk forward through the stream, skipping to each string_data_item,
 *     decoding the uleb128 length + MUTF-8 bytes, and handing each string to [visitor].
 *
 * Memory use is the offset table plus one small reusable buffer. No string is retained here.
 */
object DexStringReader {

    private const val HEADER_SIZE = 0x70
    private const val ENDIAN_CONSTANT = 0x12345678

    fun read(
        input: InputStream,
        limits: DexScanLimits,
        deadlineNanos: Long,
        visitor: (String) -> Unit,
    ): DexReadStats {
        val stream = PositionedStream(input)
        val header = ByteArray(HEADER_SIZE)
        stream.readFully(header)

        if (header[0] != 'd'.code.toByte() || header[1] != 'e'.code.toByte() ||
            header[2] != 'x'.code.toByte() || header[3] != '\n'.code.toByte()
        ) {
            throw DexFormatException("Not a dex file (bad magic)")
        }
        val endian = le32(header, 0x28)
        if (endian != ENDIAN_CONSTANT) throw DexFormatException("Unsupported endian tag ${endian.toString(16)}")

        val fileSize = le32(header, 0x20).toLong() and 0xFFFFFFFFL
        val stringIdsSize = le32(header, 0x38).toLong() and 0xFFFFFFFFL
        val stringIdsOff = le32(header, 0x3C).toLong() and 0xFFFFFFFFL

        if (stringIdsSize == 0L) return DexReadStats(0, null)
        if (stringIdsOff < HEADER_SIZE) throw DexFormatException("string_ids_off points inside header")

        var truncated: String? = null
        val count = if (stringIdsSize > limits.maxStringsPerDex) {
            truncated = "string table has $stringIdsSize entries; read first ${limits.maxStringsPerDex}"
            limits.maxStringsPerDex
        } else {
            stringIdsSize.toInt()
        }
        if (stringIdsOff + count * 4L > limits.maxBytesPerDex) {
            return DexReadStats(0, "string table is beyond the ${limits.maxBytesPerDex}-byte limit")
        }

        stream.skipTo(stringIdsOff)
        val offsets = IntArray(count)
        val chunk = ByteArray(16 * 1024)
        var filled = 0
        while (filled < count) {
            val n = minOf(chunk.size / 4, count - filled)
            stream.readFully(chunk, n * 4)
            for (i in 0 until n) offsets[filled + i] = le32(chunk, i * 4)
            filled += n
        }

        // Offsets are unsigned 32-bit; anything that doesn't fit in a positive Int is far past our
        // byte limit anyway, so treat it as out of range.
        offsets.sort()

        val buf = ByteArray(limits.maxStringBytes)
        var read = 0L
        var previous = -1
        for (i in 0 until count) {
            val off = offsets[i]
            if (off < 0 || off == previous) continue
            previous = off
            if (off.toLong() >= limits.maxBytesPerDex) {
                truncated = truncated ?: "stopped at the ${limits.maxBytesPerDex}-byte limit"
                break
            }
            if (fileSize > 0 && off.toLong() >= fileSize) continue
            if (off < stream.position) continue // overlapping/corrupt entry; skip rather than rewind
            if ((i and 0xFFF) == 0 && System.nanoTime() > deadlineNanos) {
                truncated = "ran out of time"
                break
            }
            stream.skipTo(off.toLong())
            try {
                readUleb128(stream) // utf16 length; we rely on the 0 terminator instead
                var len = 0
                var tooLong = false
                while (true) {
                    val b = stream.read()
                    if (b < 0) throw EOFException()
                    if (b == 0) break
                    if (len < buf.size) buf[len++] = b.toByte() else tooLong = true
                }
                if (!tooLong) {
                    visitor(Mutf8.decode(buf, len))
                    read++
                }
            } catch (_: EOFException) {
                truncated = truncated ?: "dex file ended early"
                break
            }
        }
        return DexReadStats(read, truncated)
    }

    internal fun readUleb128(stream: PositionedStream): Int {
        var result = 0
        var shift = 0
        while (shift < 35) {
            val b = stream.read()
            if (b < 0) throw EOFException()
            result = result or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw DexFormatException("uleb128 too long")
    }

    internal fun le32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or
            ((b[off + 3].toInt() and 0xFF) shl 24)
}

/** Forward-only stream that tracks its byte position. Not thread-safe. */
internal class PositionedStream(private val input: InputStream) {
    private val buffer = ByteArray(64 * 1024)
    private var bufPos = 0
    private var bufLen = 0
    var position = 0L
        private set

    private fun fill(): Boolean {
        bufLen = input.read(buffer, 0, buffer.size)
        bufPos = 0
        if (bufLen <= 0) {
            bufLen = 0
            return false
        }
        return true
    }

    fun read(): Int {
        if (bufPos >= bufLen && !fill()) return -1
        position++
        return buffer[bufPos++].toInt() and 0xFF
    }

    fun readFully(dest: ByteArray, length: Int = dest.size) {
        var done = 0
        while (done < length) {
            if (bufPos >= bufLen && !fill()) throw EOFException()
            val n = minOf(length - done, bufLen - bufPos)
            System.arraycopy(buffer, bufPos, dest, done, n)
            bufPos += n
            done += n
            position += n
        }
    }

    fun skipTo(target: Long) {
        var remaining = target - position
        require(remaining >= 0) { "cannot seek backwards" }
        while (remaining > 0) {
            if (bufPos >= bufLen && !fill()) throw EOFException()
            val n = minOf(remaining, (bufLen - bufPos).toLong()).toInt()
            bufPos += n
            position += n
            remaining -= n
        }
    }
}

/** Decoder for the "modified UTF-8" used in dex string data. */
object Mutf8 {
    fun decode(bytes: ByteArray, length: Int): String {
        val out = CharArray(length)
        var i = 0
        var o = 0
        while (i < length) {
            val a = bytes[i++].toInt() and 0xFF
            when {
                a < 0x80 -> out[o++] = a.toChar()
                a and 0xE0 == 0xC0 && i < length -> {
                    val b = bytes[i++].toInt() and 0xFF
                    out[o++] = (((a and 0x1F) shl 6) or (b and 0x3F)).toChar()
                }
                a and 0xF0 == 0xE0 && i + 1 < length -> {
                    val b = bytes[i++].toInt() and 0xFF
                    val c = bytes[i++].toInt() and 0xFF
                    out[o++] = (((a and 0x0F) shl 12) or ((b and 0x3F) shl 6) or (c and 0x3F)).toChar()
                }
                else -> out[o++] = '�'
            }
        }
        return String(out, 0, o)
    }
}
