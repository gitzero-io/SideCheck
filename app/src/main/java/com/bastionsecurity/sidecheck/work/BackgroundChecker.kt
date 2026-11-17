package com.bastionsecurity.sidecheck.work

import android.content.Context
import android.provider.Settings
import android.util.Log
import com.bastionsecurity.sidecheck.collect.PackageCollector
import com.bastionsecurity.sidecheck.data.KnownGrade
import com.bastionsecurity.sidecheck.data.RecentChange
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.data.TrustStore
import com.bastionsecurity.sidecheck.data.WatchState
import com.bastionsecurity.sidecheck.engine.model.AppReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Finds apps installed or updated since the last check, checks them, and decides who deserves a
 * notification. Used by the periodic worker and when SideCheck is opened.
 *
 * Why not a PACKAGE_ADDED broadcast receiver: since Android 8, apps can't receive that broadcast
 * from the manifest. Instead we read PackageManager.getChangedPackages(), Android's own log of
 * changed packages, and keep our place in it.
 */
class BackgroundChecker(
    private val context: Context,
    private val collector: () -> PackageCollector,
    private val repo: ScanRepository,
    private val trust: TrustStore,
    private val watch: WatchState,
    private val notifier: Notifier,
) {
    private val mutex = Mutex()

    data class Outcome(val checked: List<AppReport>, val notified: Int, val baselineOnly: Boolean)

    /**
     * @param notify post notifications (background). When the user just opened SideCheck we skip
     *   notifications and rely on the Home screen list instead.
     */
    suspend fun check(notify: Boolean): Outcome = mutex.withLock {
        withContext(Dispatchers.IO) {
            val now = System.currentTimeMillis()
            val cursor = watch.cursor()
            val c = collector()
            val times = c.userPackageTimes().associateBy { it.packageName }

            // Very first run: remember where we are, don't flag every app already on the TV.
            if (cursor.lastCheckTime == 0L) {
                watch.saveCursor(WatchState.Cursor(currentSequence(0), bootCount(), now))
                return@withContext Outcome(emptyList(), 0, baselineOnly = true)
            }

            // 1) Android's change log. Sequence numbers restart at 0 after a reboot.
            val boot = bootCount()
            val startSeq = if (boot != cursor.bootCount) 0 else cursor.sequence
            val changed = runCatching { context.packageManager.getChangedPackages(startSeq) }.getOrNull()
            val fromLog = changed?.packageNames.orEmpty()
            val newSeq = changed?.sequenceNumber ?: startSeq

            // 2) Safety net: anything updated since our last check (covers time the TV was off,
            //    or OEM builds where the change log is unreliable).
            val fromTimes = times.values.filter { it.lastUpdateTime > cursor.lastCheckTime }.map { it.packageName }

            val candidates = (fromLog + fromTimes).distinct().filter { it in times }
            Log.i(TAG, "Background check: ${candidates.size} changed (log=${fromLog.size}, times=${fromTimes.size})")

            val known = watch.knownGrades()
            val trustNow = trust.snapshot.first()
            val reports = mutableListOf<AppReport>()
            val recents = mutableListOf<RecentChange>()
            val newKnown = mutableMapOf<String, KnownGrade>()
            var posted = 0

            for (pkg in candidates) {
                val report = runCatching { repo.rescan(pkg) }.onFailure { Log.w(TAG, "Check failed for $pkg", it) }.getOrNull() ?: continue
                reports += report
                val cert = report.facts.primarySigner?.sha256 ?: "unsigned"
                val t = times.getValue(pkg)
                val isNew = t.firstInstallTime > cursor.lastCheckTime
                val prev = known[pkg]
                newKnown[pkg] = KnownGrade(report.grade, cert)

                val trusted = trustNow.isTrusted(pkg, report.facts.primarySigner?.sha256)
                val signerChanged = prev != null && prev.cert != cert
                val worse = prev != null && report.grade > prev.grade
                val reason = when {
                    trusted -> null // the user chose Keep: no nagging
                    isNew -> Notifier.Reason.NEW_INSTALL
                    signerChanged -> Notifier.Reason.NEW_SIGNER
                    worse -> Notifier.Reason.WORSE_GRADE
                    // An app we'd never graded before, updated: only speak up if it needs attention.
                    prev == null && report.needsAttention -> Notifier.Reason.UPDATED_NEEDS_ATTENTION
                    else -> null
                }
                if (reason != null) {
                    recents += RecentChange(pkg, t.lastUpdateTime, isNew, report.grade)
                    if (notify && notifier.post(report, reason)) posted++
                }
            }

            watch.rememberGrades(newKnown)
            watch.addRecent(recents)
            watch.saveCursor(WatchState.Cursor(newSeq, boot, now))
            Outcome(reports, posted, baselineOnly = false)
        }
    }

    private fun currentSequence(fallback: Int): Int =
        runCatching { context.packageManager.getChangedPackages(0)?.sequenceNumber }.getOrNull() ?: fallback

    private fun bootCount(): Int =
        runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT) }.getOrDefault(-1)

    companion object { private const val TAG = "SideCheck" }
}
