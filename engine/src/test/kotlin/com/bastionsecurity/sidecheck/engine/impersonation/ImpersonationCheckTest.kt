package com.bastionsecurity.sidecheck.engine.impersonation

import com.bastionsecurity.sidecheck.engine.Fixtures
import com.bastionsecurity.sidecheck.engine.Fixtures.facts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ImpersonationCheckTest {
    private val check = ImpersonationCheck(Fixtures.bundle.knownApps)

    @Test
    fun `official package is not flagged`() {
        assertEquals(ImpersonationResult.None, check.check(facts(packageName = "com.netflix.ninja", label = "Netflix")))
    }

    @Test
    fun `brand name with other package is flagged`() {
        val r = check.check(facts(packageName = "com.free.netflix", label = "Netflix"))
        assertTrue(r is ImpersonationResult.BrandMismatch)
        assertEquals("Netflix", (r as ImpersonationResult.BrandMismatch).brand)
    }

    @Test
    fun `filler words still match`() {
        assertTrue(check.check(facts(packageName = "x.y", label = "Netflix 4K MOD")) is ImpersonationResult.BrandMismatch)
        assertTrue(check.check(facts(packageName = "x.y", label = "Disney Plus TV")) is ImpersonationResult.BrandMismatch)
        assertTrue(check.check(facts(packageName = "x.y", label = "disney+")) is ImpersonationResult.BrandMismatch)
    }

    @Test
    fun `different products sharing a prefix are not flagged`() {
        assertEquals(ImpersonationResult.None, check.check(facts(packageName = "x.y", label = "Netflix Party Helper")))
        assertEquals(ImpersonationResult.None, check.check(facts(packageName = "x.y", label = "My Player")))
    }

    @Test
    fun `youtube kids is its own brand`() {
        val r = check.check(facts(packageName = "x.y", label = "YouTube Kids"))
        assertEquals("YouTube Kids", (r as ImpersonationResult.BrandMismatch).brand)
    }

    @Test
    fun `system like names`() {
        assertTrue(check.check(facts(packageName = "com.evil.upd", label = "System Update")) is ImpersonationResult.SystemLike)
        assertEquals(
            ImpersonationResult.None,
            check.check(facts(packageName = "com.vendor.ota", label = "System Update", isSystemApp = true)),
        )
    }

    @Test
    fun `signer mismatch only when hashes are configured`() {
        val catalog = KnownAppsCatalog(
            1,
            listOf(KnownApp("Kodi", listOf("Kodi"), listOf("org.xbmc.kodi"), listOf("11".repeat(32)))),
        )
        val c = ImpersonationCheck(catalog)
        assertTrue(c.check(facts(packageName = "org.xbmc.kodi", label = "Kodi")) is ImpersonationResult.SignerMismatch)
        val good = facts(
            packageName = "org.xbmc.kodi",
            label = "Kodi",
            signers = listOf(Fixtures.releaseCert.copy(sha256 = "11".repeat(32))),
        )
        assertEquals(ImpersonationResult.None, c.check(good))
    }

    @Test
    fun `bundled catalog has no invented cert hashes`() {
        assertTrue(Fixtures.bundle.knownApps.apps.all { it.signingCertSha256.isEmpty() })
    }
}
