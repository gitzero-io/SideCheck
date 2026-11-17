package com.bastionsecurity.sidecheck.engine.model

import kotlinx.serialization.Serializable

@Serializable
enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

@Serializable
enum class Category {
    /** Reading personal data: messages, contacts, location, notifications. */
    PRIVACY,
    /** Control over the device: screen reading, admin, install other apps. */
    DEVICE_CONTROL,
    /** Ad and analytics SDKs. */
    TRACKING,
    /** Who made it / is it pretending to be something else. */
    IDENTITY,
    /** How the code is built: hidden, packed, downloads more code. */
    CODE,
    /** How it talks to the internet. */
    NETWORK,
    /** How it was built and maintained (old target, debug build). */
    BUILD,
}

@Serializable
enum class SuggestedAction {
    /** Informational. Nothing to do. */
    NONE,
    /** Worth a look; keeping it is reasonable if you trust the source. */
    REVIEW,
    /** We'd lean toward removing unless you know why it needs this. */
    CONSIDER_REMOVING,
    /** We recommend removing it. The choice is still yours. */
    REMOVE,
}

data class Finding(
    val id: String,
    val severity: Severity,
    val category: Category,
    val plainTitle: String,
    val plainExplanation: String,
    val whyItMatters: String,
    val technicalEvidence: List<String>,
    val suggestedAction: SuggestedAction,
    /** Points this finding took off the score. 0 if informational or counted inside another finding. */
    val pointsDeducted: Int = 0,
    /** If set, this finding's points are counted inside the combined finding with this id. */
    val countedIn: String? = null,
    /** True for findings based on string hints rather than proof (e.g. dex string matches). */
    val isHeuristic: Boolean = false,
    /** If set, the app's grade can be no better than this (e.g. known malware → F). */
    val gradeCap: Grade? = null,
)

@Serializable
enum class Grade(val label: String) { A("A"), B("B"), C("C"), D("D"), F("F") }

data class GradeBreakdown(
    val startingScore: Int,
    val deductions: List<Pair<String, Int>>,
    val rawScore: Int,
    /** Why the grade is lower than the raw score alone would give, if a cap applied. */
    val capReason: String?,
)

data class AppReport(
    val facts: AppFacts,
    val findings: List<Finding>,
    val score: Int,
    val grade: Grade,
    val verdict: String,
    val breakdown: GradeBreakdown,
    val reputation: ReputationResult?,
) {
    val needsAttention: Boolean get() = grade >= Grade.C
}

data class ReputationResult(
    val source: String,
    val knownMalicious: Boolean,
    val label: String?,
    val detail: String?,
    val matchedBy: MatchedBy = MatchedBy.FILE,
    /** The hash that matched (file or certificate SHA-256). */
    val matchedValue: String? = null,
    val sourceUrl: String? = null,
) {
    enum class MatchedBy { FILE, SIGNER }
}
