package com.bastionsecurity.sidecheck.engine.rules

import com.bastionsecurity.sidecheck.engine.Analyzer
import com.bastionsecurity.sidecheck.engine.Fixtures
import com.bastionsecurity.sidecheck.engine.Fixtures.P
import com.bastionsecurity.sidecheck.engine.Fixtures.facts
import com.bastionsecurity.sidecheck.engine.Fixtures.receiver
import com.bastionsecurity.sidecheck.engine.Fixtures.service
import com.bastionsecurity.sidecheck.engine.model.AppFacts
import com.bastionsecurity.sidecheck.engine.model.DexScanResult
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.engine.model.ReputationResult
import com.bastionsecurity.sidecheck.engine.model.Severity
import com.bastionsecurity.sidecheck.engine.providers.ReputationProvider
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleEngineTest {
    private val analyzer = Analyzer(Fixtures.bundle)

    private fun report(f: AppFacts) = kotlinx.coroutines.runBlocking { analyzer.analyze(f) }
    private fun ids(f: AppFacts) = report(f).findings.map { it.id }.toSet()

    @Test
    fun `bundle has 30+ rules and all are supported`() {
        assertTrue(Fixtures.bundle.rules.rules.size >= 30)
        assertEquals(emptyList<String>(), analyzer.unsupportedRules)
    }

    @Test
    fun `superseded ids exist`() {
        val all = Fixtures.bundle.rules.rules.map { it.id }.toSet()
        for (r in Fixtures.bundle.rules.rules) for (s in r.supersedes) assertTrue("${r.id} -> $s", s in all)
    }

    @Test
    fun `clean sideloaded app gets an A and no penalty for being sideloaded`() {
        val r = report(facts())
        assertEquals(Grade.A, r.grade)
        assertEquals(100, r.score)
    }

    @Test
    fun `accessibility overlay boot combo`() {
        val r = report(
            facts(
                permissions = listOf("${P}SYSTEM_ALERT_WINDOW", "${P}RECEIVE_BOOT_COMPLETED"),
                components = listOf(service("com.x.Acc", Signals.BIND_ACCESSIBILITY)),
            ),
        )
        val byId = r.findings.associateBy { it.id }
        assertEquals(Severity.HIGH, byId.getValue("accessibility_overlay_boot").severity)
        assertEquals("accessibility_overlay_boot", byId.getValue("accessibility_service").countedIn)
        assertEquals("accessibility_overlay_boot", byId.getValue("overlay_permission").countedIn)
        assertEquals(0, byId.getValue("accessibility_service").pointsDeducted)
        assertEquals(80, r.score)
        assertEquals(Grade.C, r.grade)
        assertEquals("accessibility_overlay_boot", r.findings.first().id)
    }

    @Test
    fun `accessibility alone is medium, not combo`() {
        val got = ids(facts(components = listOf(service("com.x.Acc", Signals.BIND_ACCESSIBILITY))))
        assertTrue("accessibility_service" in got)
        assertFalse("accessibility_overlay_boot" in got)
    }

    @Test
    fun `device admin on a media app`() {
        val got = ids(
            facts(label = "Super IPTV Player", components = listOf(receiver("com.x.Admin", Signals.BIND_DEVICE_ADMIN))),
        )
        assertTrue("device_admin_media_app" in got)
    }

    @Test
    fun `sms and call log on tv`() {
        val r = report(facts(permissions = listOf("${P}READ_SMS", "${P}READ_CALL_LOG", "${P}READ_CONTACTS")))
        val ids = r.findings.map { it.id }
        assertTrue("sms_on_tv" in ids && "call_log_on_tv" in ids && "contacts_on_tv" in ids)
        assertTrue(r.findings.first { it.id == "sms_on_tv" }.plainExplanation.contains("your text messages"))
        assertEquals(Grade.D, r.grade) // 100 - 20 - 20 - 8 = 52
    }

    @Test
    fun `dynamic code plus cleartext`() {
        val dex = DexScanResult.EMPTY.copy(dynamicCodeLoaders = setOf("Ldalvik/system/DexClassLoader;"))
        val r = report(facts(cleartext = true, dexScan = dex))
        val byId = r.findings.associateBy { it.id }
        assertTrue(byId.getValue("dynamic_code_cleartext").isHeuristic)
        assertEquals("dynamic_code_cleartext", byId.getValue("dynamic_code").countedIn)
        assertEquals("dynamic_code_cleartext", byId.getValue("cleartext_allowed").countedIn)
    }

    @Test
    fun `debug signed impersonator is critical, plain impersonator is high`() {
        val crit = report(facts(label = "Netflix", packageName = "com.free.flix", signers = listOf(Fixtures.debugCert)))
        assertTrue("impersonation_debug_signed" in crit.findings.map { it.id })
        assertFalse("impersonates_brand" in crit.findings.map { it.id })
        assertEquals(Grade.D, crit.grade)
        assertTrue(crit.findings.first().plainTitle.contains("Netflix"))

        val high = ids(facts(label = "Netflix", packageName = "com.free.flix"))
        assertTrue("impersonates_brand" in high)
    }

    @Test
    fun `debug signed alone is only low`() {
        val r = report(facts(signers = listOf(Fixtures.debugCert)))
        assertEquals(listOf("debug_signed"), r.findings.map { it.id })
        assertEquals(Grade.A, r.grade)
    }

    @Test
    fun `very old target sdk with dangerous permissions`() {
        val got = ids(facts(targetSdk = 22, permissions = listOf("${P}RECORD_AUDIO")))
        assertTrue("old_target_auto_grant" in got)
        assertTrue("very_old_target" in got)
        assertFalse("old_target" in got)
        val mid = ids(facts(targetSdk = 24))
        assertTrue("old_target" in mid && "very_old_target" !in mid)
    }

    @Test
    fun `packed and hidden`() {
        val f = facts(
            packerLibs = listOf("libjiagu.so"),
            hasLauncherEntry = false,
            permissions = listOf("${P}RECEIVE_BOOT_COMPLETED"),
            components = listOf(service("com.x.Bg", null)),
        )
        val got = ids(f)
        assertTrue("packed_hidden" in got)
    }

    @Test
    fun `keyboard without launcher is not hidden app`() {
        val f = facts(
            hasLauncherEntry = false,
            components = listOf(service("com.x.Ime", "${P}BIND_INPUT_METHOD"), service("com.x.Other", null)),
        )
        assertFalse("hidden_app" in ids(f))
    }

    @Test
    fun `disabled app is not a hidden app`() {
        val f = facts(hasLauncherEntry = false, permissions = listOf("${P}RECEIVE_BOOT_COMPLETED")).copy(enabled = false)
        assertFalse("hidden_app" in ids(f))
    }

    @Test
    fun `unknown launcher state never triggers hidden app`() {
        val f = facts(hasLauncherEntry = null, permissions = listOf("${P}RECEIVE_BOOT_COMPLETED"))
        assertFalse("hidden_app" in ids(f))
    }

    @Test
    fun `vpn app vs unexpected vpn`() {
        val vpnSvc = listOf(service("com.x.Vpn", Signals.BIND_VPN))
        assertTrue("vpn_expected" in ids(facts(label = "Fast VPN", components = vpnSvc)))
        assertTrue("vpn_unexpected" in ids(facts(label = "Movie Box", components = vpnSvc)))
    }

    @Test
    fun `trackers many vs some`() {
        val five = DexScanResult.EMPTY.copy(trackerHits = listOf("appsflyer", "adjust", "applovin", "vungle", "inmobi").associateWith { "x" })
        val r = report(facts(dexScan = five))
        val t = r.findings.single { it.id == "trackers_many" }
        assertTrue(t.plainTitle.contains("5"))
        assertTrue(t.plainExplanation.contains("AppsFlyer"))
        val one = ids(facts(dexScan = DexScanResult.EMPTY.copy(trackerHits = mapOf("google_admob" to "x"))))
        assertTrue("trackers_some" in one && "trackers_many" !in one)
    }

    @Test
    fun `every template gets filled`() {
        // Trigger as many rules as possible at once and check no {placeholder} survives.
        val dex = DexScanResult.EMPTY.copy(
            trackerHits = listOf("appsflyer", "adjust", "applovin", "vungle", "inmobi").associateWith { "x" },
            dynamicCodeLoaders = setOf("Ldalvik/system/DexClassLoader;"),
            runtimeExec = true,
            ipAddresses = setOf("45.33.32.156"),
            reflectionApis = setOf("a", "b", "c"),
            hiddenApiReflectionTargets = setOf("x", "y", "z"),
            truncated = true,
            truncationReasons = listOf("ran out of time"),
        )
        val all = Signals.DANGEROUS_PERMISSIONS.toList() + listOf(
            "${P}SYSTEM_ALERT_WINDOW", "${P}RECEIVE_BOOT_COMPLETED", "${P}REQUEST_INSTALL_PACKAGES",
            "${P}ACCESS_BACKGROUND_LOCATION", "${P}WRITE_SETTINGS", "${P}PACKAGE_USAGE_STATS", "${P}QUERY_ALL_PACKAGES",
        )
        val f = facts(
            label = "Netflix",
            packageName = "com.fake.flix",
            targetSdk = 22,
            permissions = all,
            debuggable = true,
            cleartext = true,
            packerLibs = listOf("libjiagu.so"),
            hasLauncherEntry = false,
            dexScan = dex,
            components = listOf(
                service("a.Acc", Signals.BIND_ACCESSIBILITY), receiver("a.Adm", Signals.BIND_DEVICE_ADMIN),
                service("a.Nl", Signals.BIND_NOTIFICATION_LISTENER), service("a.Vpn", Signals.BIND_VPN),
                service("a.S1", null), service("a.S2", null), receiver("a.R1", null),
            ),
        )
        val r = report(f)
        assertTrue(r.findings.size >= 30)
        for (finding in r.findings) {
            for (text in listOf(finding.plainTitle, finding.plainExplanation, finding.whyItMatters)) {
                assertFalse("${finding.id}: $text", Regex("\\{\\w+}").containsMatchIn(text))
            }
            assertTrue(finding.id, finding.technicalEvidence.isNotEmpty())
        }
        assertEquals(Grade.F, r.grade)
    }

    @Test
    fun `reputation hit is critical and lookup failure is ignored`() = runTest {
        val bad = object : ReputationProvider {
            override val name = "test"
            override suspend fun lookup(apkSha256: String?, packageName: String, signerSha256: String?) =
                ReputationResult("TestDB", true, "Trojan.Test", null)
        }
        val r = Analyzer(Fixtures.bundle, bad).analyze(facts())
        assertEquals("known_malware", r.findings.first().id)

        val broken = object : ReputationProvider {
            override val name = "broken"
            override suspend fun lookup(apkSha256: String?, packageName: String, signerSha256: String?): ReputationResult? =
                error("offline")
        }
        val ok = Analyzer(Fixtures.bundle, broken).analyze(facts())
        assertNull(ok.reputation)
        assertEquals(Grade.A, ok.grade)
    }

    @Test
    fun `verdict mentions main concern for low grades`() {
        val r = report(facts(label = "Netflix", packageName = "com.free.flix", signers = listOf(Fixtures.debugCert)))
        assertTrue(r.verdict, r.verdict.contains("Main concern"))
    }
}
