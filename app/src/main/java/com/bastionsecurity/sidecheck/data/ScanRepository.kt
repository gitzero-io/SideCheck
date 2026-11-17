package com.bastionsecurity.sidecheck.data

import android.content.Context
import android.util.Log
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.bastionsecurity.sidecheck.collect.FirmwareCheck
import com.bastionsecurity.sidecheck.collect.FirmwareMatch
import com.bastionsecurity.sidecheck.collect.PackageCollector
import com.bastionsecurity.sidecheck.engine.Analyzer
import com.bastionsecurity.sidecheck.engine.model.AppReport
import com.bastionsecurity.sidecheck.engine.model.Grade
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

private val Context.scanDataStore by preferencesDataStore(name = "scan")

sealed interface ScanState {
    data object Idle : ScanState
    data class Scanning(val done: Int, val total: Int, val currentLabel: String?) : ScanState
    data class Failed(val message: String) : ScanState
}

data class LastScan(
    val timeMillis: Long,
    val appCount: Int,
    val attentionCount: Int,
    /** Apps that needed attention at scan time, as "package|cert", so the count can be updated live. */
    val attentionApps: Set<String> = emptySet(),
)

/** A report plus the user's choices about it. */
data class AppEntry(
    val report: AppReport,
    val trusted: Boolean,
    val keptFindings: Set<String>,
) {
    val packageName get() = report.facts.packageName
    val cert get() = report.facts.primarySigner?.sha256

    /**
     * Shown under "Needs attention" when the grade is C or worse, the user hasn't trusted the app,
     * and at least one point-costing finding hasn't been marked "Keep".
     */
    val needsAttention: Boolean
        get() = !trusted && report.grade >= Grade.C &&
            report.findings.any { it.pointsDeducted > 0 && it.id !in keptFindings }
}

class ScanRepository(
    private val context: Context,
    private val collector: () -> PackageCollector,
    private val analyzer: () -> Analyzer,
    private val firmware: () -> FirmwareCheck,
    private val trust: TrustStore,
    private val watch: WatchState,
    private val scope: CoroutineScope,
) {
    private val mutex = Mutex()
    private val _state = MutableStateFlow<ScanState>(ScanState.Idle)
    val state: StateFlow<ScanState> = _state.asStateFlow()

    private val _reports = MutableStateFlow<Map<String, AppReport>>(emptyMap())
    val reports: StateFlow<Map<String, AppReport>> = _reports.asStateFlow()

    /** Have we scanned in this session? (Reports live in memory only.) */
    private val _hasResults = MutableStateFlow(false)
    val hasResults: StateFlow<Boolean> = _hasResults.asStateFlow()

    val entries: Flow<List<AppEntry>> = combine(reports, trust.snapshot) { reps, t ->
        reps.values.map { r ->
            val pkg = r.facts.packageName
            val cert = r.facts.primarySigner?.sha256
            AppEntry(
                report = r,
                trusted = t.isTrusted(pkg, cert),
                keptFindings = r.findings.filter { t.isKept(pkg, cert, it.id) }.map { it.id }.toSet(),
            )
        }.sortedWith(compareByDescending<AppEntry> { it.report.grade }.thenBy { it.report.score }.thenBy { it.report.facts.label.lowercase() })
    }

    private val timeKey = longPreferencesKey("last_scan_time")
    private val countKey = intPreferencesKey("last_scan_apps")
    private val attentionKey = intPreferencesKey("last_scan_attention")
    private val attentionSetKey = stringSetPreferencesKey("last_scan_attention_apps") // pkg|cert
    private val firmwareKey = stringSetPreferencesKey("firmware_matches") // pkg|family|source|signer|url|label

    /** Preinstalled apps that matched the known-malware list in the last full scan. */
    val firmwareMatches: Flow<List<FirmwareMatch>> = context.scanDataStore.data.map { p ->
        p[firmwareKey].orEmpty().mapNotNull { row ->
            val f = row.split('|', limit = 6)
            if (f.size < 6) null else FirmwareMatch(f[0], f[5], f[1], f[2], f[4], f[3] == "1", enabled = true)
        }.sortedBy { it.label.lowercase() }
    }

    private suspend fun saveFirmware(list: List<FirmwareMatch>) {
        context.scanDataStore.edit { p ->
            p[firmwareKey] = list.map { m ->
                listOf(m.packageName, m.family.replace("|", "/"), m.source.replace("|", "/"),
                    if (m.bySigner) "1" else "0", m.sourceUrl.replace("|", "%7C"), m.label).joinToString("|")
            }.toSet()
        }
    }

    val lastScan: Flow<LastScan?> = context.scanDataStore.data.map { p ->
        p[timeKey]?.let { LastScan(it, p[countKey] ?: 0, p[attentionKey] ?: 0, p[attentionSetKey].orEmpty()) }
    }

    fun startFullScan() {
        if (_state.value is ScanState.Scanning) return
        scope.launch { scanAll() }
    }

    private suspend fun scanAll() = mutex.withLock {
        withContext(Dispatchers.IO) {
            try {
                val c = collector()
                val a = analyzer()
                val pkgs = c.userPackages()
                _state.value = ScanState.Scanning(0, pkgs.size, null)
                val out = LinkedHashMap<String, AppReport>()
                // One app at a time: the dex scan is the heavy part and cheap boxes have little RAM.
                pkgs.forEachIndexed { i, pkg ->
                    val facts = runCatching { c.collectInstalled(pkg) }
                        .onFailure { Log.w(TAG, "Collect failed for $pkg", it) }
                        .getOrNull()
                    _state.value = ScanState.Scanning(i, pkgs.size, facts?.label ?: pkg)
                    // One bad app must never stop the whole scan.
                    if (facts != null) {
                        runCatching { a.analyze(facts) }
                            .onSuccess { out[pkg] = it }
                            .onFailure { Log.w(TAG, "Analysis failed for $pkg", it) }
                    }
                }
                _state.value = ScanState.Scanning(pkgs.size, pkgs.size, "built-in apps")
                val fw = runCatching { firmware().run() }.onFailure { Log.w(TAG, "Firmware check failed", it) }.getOrNull()
                if (fw != null) saveFirmware(fw)
                _reports.value = out
                _hasResults.value = true
                // Baseline for background checks: later updates are compared against these.
                watch.rememberGrades(out.mapValues { (_, r) -> KnownGrade(r.grade, r.facts.primarySigner?.sha256 ?: "unsigned") })
                saveSummary(updateTime = true)
                _state.value = ScanState.Idle
            } catch (e: Exception) {
                Log.e(TAG, "Scan failed", e)
                _state.value = ScanState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    sealed interface Rescan {
        data class Ok(val report: AppReport) : Rescan
        data object NotInstalled : Rescan
        data class Failed(val error: Throwable) : Rescan
    }

    /**
     * Re-check one app (e.g. after it was updated). Only a confirmed uninstall clears the user's
     * Keep/Trust choices; a failed read leaves them alone.
     */
    suspend fun rescanResult(pkg: String): Rescan = withContext(Dispatchers.IO) {
        if (!isInstalled(pkg)) {
            remove(pkg)
            return@withContext Rescan.NotInstalled
        }
        try {
            val facts = collector().collectInstalled(pkg) ?: return@withContext Rescan.Failed(IllegalStateException("Couldn't read $pkg"))
            val r = analyzer().analyze(facts)
            _reports.update { it + (pkg to r) }
            Rescan.Ok(r)
        } catch (e: Exception) {
            Log.w(TAG, "Re-check failed for $pkg", e)
            Rescan.Failed(e)
        }
    }

    /** Convenience: the report, or null if it's gone or couldn't be read. */
    suspend fun rescan(pkg: String): AppReport? = (rescanResult(pkg) as? Rescan.Ok)?.report

    private fun isInstalled(pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
        false
    }

    suspend fun remove(pkg: String) {
        _reports.update { it - pkg }
        trust.forget(pkg)
        watch.acknowledge(pkg)
        if (_hasResults.value) saveSummary(updateTime = false)
    }

    init {
        // Keep the saved summary in step with Keep/Trust choices made after the scan.
        scope.launch { trust.snapshot.collect { if (_hasResults.value) saveSummary(updateTime = false) } }
    }

    private suspend fun saveSummary(updateTime: Boolean) {
        val t = trustSnapshot()
        val reps = _reports.value.values
        val attention = reps.filter { r ->
            val cert = r.facts.primarySigner?.sha256
            AppEntry(r, t.isTrusted(r.facts.packageName, cert),
                r.findings.filter { t.isKept(r.facts.packageName, cert, it.id) }.map { it.id }.toSet()).needsAttention
        }.map { TrustStore.appKey(it.facts.packageName, it.facts.primarySigner?.sha256) }.toSet()
        context.scanDataStore.edit {
            if (updateTime || it[timeKey] == null) it[timeKey] = System.currentTimeMillis()
            it[countKey] = reps.size
            it[attentionKey] = attention.size
            it[attentionSetKey] = attention
        }
    }

    private suspend fun trustSnapshot() = trust.snapshot.first()

    companion object { private const val TAG = "SideCheck" }
}
