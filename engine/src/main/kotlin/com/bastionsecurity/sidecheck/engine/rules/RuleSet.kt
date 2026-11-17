package com.bastionsecurity.sidecheck.engine.rules

import com.bastionsecurity.sidecheck.engine.model.Category
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.engine.model.Severity
import com.bastionsecurity.sidecheck.engine.model.SuggestedAction
import kotlinx.serialization.Serializable

/**
 * Rules are data. Each rule says *when* it fires (a combination of named signals and simple
 * permission / targetSdk conditions) and *what to tell the user* (plain-language templates).
 * The signals themselves are small pieces of Kotlin in [Signals] — that's the "code only where
 * needed" part. A rule set can be downloaded later and swapped in without an app update, as long
 * as it only uses signals this build knows about. Rules that reference an unknown signal are skipped.
 *
 * Templates may use {app} plus any parameter produced by the signals that matched
 * (see [Signals] for which parameters each provides).
 */
@Serializable
data class RuleSet(
    val version: Int,
    val rules: List<RuleDef>,
)

@Serializable
data class RuleDef(
    val id: String,
    val severity: Severity,
    val category: Category,
    val action: SuggestedAction,
    val title: String,
    val explanation: String,
    val why: String,
    val `when`: Condition,
    /** Findings whose points are already counted by this (combined) finding. */
    val supersedes: List<String> = emptyList(),
    /** True if the evidence is a hint from code strings rather than a declared fact. */
    val heuristic: Boolean = false,
    val enabled: Boolean = true,
    /** Grade can be no better than this when the rule fires (e.g. "F" for known malware). */
    val gradeCap: Grade? = null,
)

@Serializable
data class Condition(
    /** Every one of these signals must match. */
    val all: List<String> = emptyList(),
    /** At least one of these signals must match (ignored if empty). */
    val any: List<String> = emptyList(),
    /** None of these signals may match. */
    val none: List<String> = emptyList(),
    /** App requests at least one of these permissions. */
    val anyPermission: List<String> = emptyList(),
    val targetSdkBelow: Int? = null,
    val targetSdkAtLeast: Int? = null,
)
