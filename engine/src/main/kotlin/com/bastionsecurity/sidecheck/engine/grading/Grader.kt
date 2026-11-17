package com.bastionsecurity.sidecheck.engine.grading

import com.bastionsecurity.sidecheck.engine.model.Finding
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.engine.model.GradeBreakdown
import com.bastionsecurity.sidecheck.engine.model.Severity

/**
 * Transparent scoring:
 *  - Start at 100.
 *  - Each finding takes off a fixed number of points by severity:
 *      INFO 0, LOW 3, MEDIUM 8, HIGH 20, CRITICAL 40.
 *    A finding that is already counted inside a combined finding takes off nothing.
 *  - Score → grade: A ≥ 90, B ≥ 75, C ≥ 55, D ≥ 35, otherwise F.
 *  - Caps, so one serious problem can't hide behind a clean record:
 *      any MEDIUM → at best B, any HIGH → at best C, any CRITICAL → at best D.
 *
 * Nothing here looks at where the app came from. Sideloading alone never costs points.
 */
object Grader {

    const val START = 100

    fun points(severity: Severity): Int = when (severity) {
        Severity.INFO -> 0
        Severity.LOW -> 3
        Severity.MEDIUM -> 8
        Severity.HIGH -> 20
        Severity.CRITICAL -> 40
    }

    fun gradeForScore(score: Int): Grade = when {
        score >= 90 -> Grade.A
        score >= 75 -> Grade.B
        score >= 55 -> Grade.C
        score >= 35 -> Grade.D
        else -> Grade.F
    }

    data class Result(val score: Int, val grade: Grade, val findings: List<Finding>, val breakdown: GradeBreakdown)

    fun grade(findings: List<Finding>): Result {
        val scored = findings.map { f ->
            f.copy(pointsDeducted = if (f.countedIn != null) 0 else points(f.severity))
        }
        val deductions = scored.filter { it.pointsDeducted > 0 }.map { it.id to it.pointsDeducted }
        val score = (START - deductions.sumOf { it.second }).coerceAtLeast(0)
        val byScore = gradeForScore(score)

        val worst = scored.maxOfOrNull { it.severity }
        val (cap, reason) = when (worst) {
            Severity.CRITICAL -> Grade.D to "Capped at D because of a critical finding"
            Severity.HIGH -> Grade.C to "Capped at C because of a high-severity finding"
            Severity.MEDIUM -> Grade.B to "Capped at B because of a medium-severity finding"
            else -> null to null
        }
        val grade = if (cap != null && cap > byScore) cap else byScore
        return Result(
            score = score,
            grade = grade,
            findings = scored,
            breakdown = GradeBreakdown(
                startingScore = START,
                deductions = deductions,
                rawScore = score,
                capReason = if (grade != byScore) reason else null,
            ),
        )
    }
}
