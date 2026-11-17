package com.bastionsecurity.sidecheck.engine

import com.bastionsecurity.sidecheck.engine.apk.ApkFileInspector
import com.bastionsecurity.sidecheck.engine.apk.PackerSignatures
import com.bastionsecurity.sidecheck.engine.dex.DexScanLimits
import com.bastionsecurity.sidecheck.engine.grading.Grader
import com.bastionsecurity.sidecheck.engine.grading.Verdicts
import com.bastionsecurity.sidecheck.engine.impersonation.ImpersonationCheck
import com.bastionsecurity.sidecheck.engine.model.AppFacts
import com.bastionsecurity.sidecheck.engine.model.AppReport
import com.bastionsecurity.sidecheck.engine.model.Finding
import com.bastionsecurity.sidecheck.engine.model.ReputationResult
import com.bastionsecurity.sidecheck.engine.providers.NoOpReputationProvider
import com.bastionsecurity.sidecheck.engine.providers.ReputationProvider
import com.bastionsecurity.sidecheck.engine.providers.RuleBundle
import com.bastionsecurity.sidecheck.engine.rules.RuleContext
import com.bastionsecurity.sidecheck.engine.rules.RuleEngine
import com.bastionsecurity.sidecheck.engine.trackers.TrackerMatcher
import kotlin.coroutines.cancellation.CancellationException

/**
 * Entry point: facts in, report out. Holds no Android types, keeps no state between apps.
 */
class Analyzer(
    private val bundle: RuleBundle,
    private val reputation: ReputationProvider = NoOpReputationProvider,
    limits: DexScanLimits = DexScanLimits(),
) {
    private val engine = RuleEngine(bundle.rules)
    private val impersonation = ImpersonationCheck(bundle.knownApps)

    /** Reads APK files (zip + dex). Shared so the Android layer doesn't rebuild matchers per app. */
    val apkInspector = ApkFileInspector(
        trackers = TrackerMatcher(bundle.trackers),
        packers = PackerSignatures(bundle.packers.libraries.map { it.glob }),
        limits = limits,
    )

    val unsupportedRules: List<String> get() = engine.unsupportedRules

    suspend fun analyze(facts: AppFacts): AppReport {
        val rep: ReputationResult? = try {
            reputation.lookup(facts.apkSha256, facts.packageName, facts.primarySigner?.sha256)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            null // A failed lookup must never block or change the local result.
        }
        val ctx = RuleContext(facts, impersonation.check(facts), bundle.trackers, rep)
        val graded = Grader.grade(engine.evaluate(ctx))
        // Worst first; within a severity, combined findings before the parts they include.
        val sorted = graded.findings.sortedWith(
            compareByDescending<Finding> { it.severity }.thenBy { it.countedIn != null },
        )
        return AppReport(
            facts = facts,
            findings = sorted,
            score = graded.score,
            grade = graded.grade,
            verdict = Verdicts.verdict(graded.grade, sorted),
            breakdown = graded.breakdown,
            reputation = rep,
        )
    }
}
