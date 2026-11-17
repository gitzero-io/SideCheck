package com.bastionsecurity.sidecheck.engine.dex

import com.bastionsecurity.sidecheck.engine.Fixtures
import com.bastionsecurity.sidecheck.engine.trackers.TrackerMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DexSignalCollectorTest {

    private val matcher = TrackerMatcher(Fixtures.bundle.trackers)

    private fun collect(vararg strings: String) =
        DexSignalCollector(matcher).apply { strings.forEach { visit(it) } }.result()

    @Test
    fun `matches trackers by descriptor and dotted name`() {
        val r = collect("Lcom/facebook/ads/AdView;", "com.appsflyer.AppsFlyerLib", "Lio/branch/referral/Branch;")
        assertEquals(setOf("facebook_ads", "appsflyer", "branch"), r.trackerHits.keys)
    }

    @Test
    fun `tracker match respects package boundaries`() {
        assertNull(matcher.match("Lcom/applovinx/Thing;"))
        assertNull(matcher.match("Lcom/google/android/gms/adsx/Foo;"))
        assertEquals("google_admob", matcher.match("Lcom/google/android/gms/ads/MobileAds;"))
        assertEquals("pangle", matcher.match("Lcom/bytedance/sdk/openadsdk/TTAdSdk;"))
        assertNull(matcher.match("Lcom/bytedance/sdk/other/Foo;"))
    }

    @Test
    fun `detects dynamic code loading and runtime exec`() {
        val r = collect("Ldalvik/system/DexClassLoader;", "Ljava/lang/Runtime;", "exec")
        assertEquals(setOf("Ldalvik/system/DexClassLoader;"), r.dynamicCodeLoaders)
        assertTrue(r.runtimeExec)
    }

    @Test
    fun `runtime alone is not exec`() {
        assertFalse(collect("Ljava/lang/Runtime;", "availableProcessors").runtimeExec)
    }

    @Test
    fun `path class loader with download hints`() {
        val r = collect("Ldalvik/system/PathClassLoader;", "Ljava/net/HttpURLConnection;", "payload.dex")
        assertTrue(r.pathClassLoaderWithDownload)
        assertFalse(collect("Ldalvik/system/PathClassLoader;").pathClassLoaderWithDownload)
    }

    @Test
    fun `finds public ips and ignores versions and private ranges`() {
        val r = collect("45.33.32.156", "1.2.3.4", "192.168.1.10", "10.0.0.1", "127.0.0.1", "http://8.8.4.4:8080/x", "999.1.1.1")
        assertEquals(setOf("45.33.32.156", "8.8.4.4"), r.ipAddresses)
    }

    @Test
    fun `extracts urls and ignores xml namespaces`() {
        val r = collect("http://schemas.android.com/apk/res/android", "see http://cdn.example.org/a.json now", "https://api.example.net/v1")
        assertEquals(setOf("http://cdn.example.org/a.json", "https://api.example.net/v1"), r.urls)
        assertEquals(setOf("http://cdn.example.org/a.json"), r.cleartextUrls)
    }

    @Test
    fun `reflection heavy needs internal targets`() {
        assertFalse(collect("getDeclaredMethod", "setAccessible", "forName").reflectionHeavy)
        assertTrue(
            collect(
                "getDeclaredMethod", "setAccessible", "forName",
                "android.app.ActivityThread", "currentActivityThread", "mClassLoader",
            ).reflectionHeavy,
        )
    }
}
