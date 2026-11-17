package com.bastionsecurity.sidecheck.engine

import com.bastionsecurity.sidecheck.engine.model.AppFacts
import com.bastionsecurity.sidecheck.engine.model.CertInfo
import com.bastionsecurity.sidecheck.engine.model.ComponentFacts
import com.bastionsecurity.sidecheck.engine.model.ComponentType
import com.bastionsecurity.sidecheck.engine.model.DexScanResult
import com.bastionsecurity.sidecheck.engine.model.InstallSource
import com.bastionsecurity.sidecheck.engine.model.InstallerKind
import com.bastionsecurity.sidecheck.engine.providers.BundledRuleSetProvider
import java.io.ByteArrayOutputStream

object Fixtures {
    val bundle by lazy { BundledRuleSetProvider().loadBlocking() }

    const val P = "android.permission."

    val releaseCert = CertInfo("ab".repeat(32), "CN=Example Media, O=Example, C=US")
    val debugCert = CertInfo("cd".repeat(32), "C=US, O=Android, CN=Android Debug")

    /** A clean, sideloaded TV app. Tests change only what they care about. */
    fun facts(
        packageName: String = "com.example.player",
        label: String = "Example Player",
        targetSdk: Int = 34,
        permissions: List<String> = listOf("${P}INTERNET"),
        signers: List<CertInfo> = listOf(releaseCert),
        components: List<ComponentFacts> = emptyList(),
        hasLauncherEntry: Boolean? = true,
        debuggable: Boolean = false,
        cleartext: Boolean? = false,
        isSystemApp: Boolean = false,
        dexScan: DexScanResult? = DexScanResult.EMPTY,
        packerLibs: List<String> = emptyList(),
    ) = AppFacts(
        packageName = packageName,
        label = label,
        versionName = "1.0",
        versionCode = 1,
        targetSdk = targetSdk,
        minSdk = 21,
        firstInstallTime = 0,
        lastUpdateTime = 0,
        installSource = InstallSource("com.android.packageinstaller", null, InstallerKind.SIDELOADED),
        isSystemApp = isSystemApp,
        isArchive = false,
        permissions = permissions,
        signers = signers,
        apkSha256 = "00".repeat(32),
        debuggable = debuggable,
        cleartextTrafficAllowed = cleartext,
        components = components,
        hasLauncherEntry = hasLauncherEntry,
        appCategory = null,
        apkContents = com.bastionsecurity.sidecheck.engine.model.ApkContents(
            nativeLibs = packerLibs.map { "lib/arm64-v8a/$it" },
            abis = if (packerLibs.isEmpty()) emptySet() else setOf("arm64-v8a"),
            packerLibs = packerLibs,
            dexCount = 1,
            totalDexBytes = 1000,
            entryCount = 10,
        ),
        dexScan = dexScan,
    )

    fun service(name: String, permission: String?, exported: Boolean = true) =
        ComponentFacts(name, ComponentType.SERVICE, exported, permission)

    fun receiver(name: String, permission: String?, exported: Boolean = true) =
        ComponentFacts(name, ComponentType.RECEIVER, exported, permission)
}

/**
 * Builds a minimal but valid-enough .dex: header, string_ids, string_data. String data is written
 * in REVERSE order so the reader's offset sorting is exercised.
 */
object DexFixture {
    fun build(strings: List<String>, version: String = "035"): ByteArray {
        val headerSize = 0x70
        val idsOff = headerSize
        val dataStart = idsOff + strings.size * 4

        val data = ByteArrayOutputStream()
        val offsets = IntArray(strings.size)
        for (i in strings.indices.reversed()) {
            offsets[i] = dataStart + data.size()
            val s = strings[i]
            writeUleb128(data, s.length)
            data.write(mutf8(s))
            data.write(0)
        }
        val total = dataStart + data.size()
        val out = ByteArray(total)
        "dex\n$version\u0000".toByteArray(Charsets.ISO_8859_1).copyInto(out, 0)
        putLe32(out, 0x20, total)
        putLe32(out, 0x24, headerSize)
        putLe32(out, 0x28, 0x12345678)
        putLe32(out, 0x38, strings.size)
        putLe32(out, 0x3C, idsOff)
        offsets.forEachIndexed { i, off -> putLe32(out, idsOff + i * 4, off) }
        data.toByteArray().copyInto(out, dataStart)
        return out
    }

    fun mutf8(s: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (c in s) {
            val v = c.code
            when {
                v in 1..0x7F -> out.write(v)
                v < 0x800 -> { out.write(0xC0 or (v shr 6)); out.write(0x80 or (v and 0x3F)) }
                else -> {
                    out.write(0xE0 or (v shr 12))
                    out.write(0x80 or ((v shr 6) and 0x3F))
                    out.write(0x80 or (v and 0x3F))
                }
            }
        }
        return out.toByteArray()
    }

    private fun writeUleb128(out: ByteArrayOutputStream, value: Int) {
        var v = value
        do {
            var b = v and 0x7F
            v = v ushr 7
            if (v != 0) b = b or 0x80
            out.write(b)
        } while (v != 0)
    }

    private fun putLe32(b: ByteArray, off: Int, v: Int) {
        b[off] = v.toByte(); b[off + 1] = (v shr 8).toByte(); b[off + 2] = (v shr 16).toByte(); b[off + 3] = (v shr 24).toByte()
    }
}
