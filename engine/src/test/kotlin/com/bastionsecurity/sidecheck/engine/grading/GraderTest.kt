package com.bastionsecurity.sidecheck.engine.grading

import com.bastionsecurity.sidecheck.engine.model.Category
import com.bastionsecurity.sidecheck.engine.model.Finding
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.engine.model.Severity
import com.bastionsecurity.sidecheck.engine.model.SuggestedAction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class GraderTest {
    private fun f(id: String, s: Severity, countedIn: String? = null) =
        Finding(id, s, Category.CODE, "t", "e", "w", emptyList(), SuggestedAction.NONE, countedIn = countedIn)

    @Test
    fun `no findings is an A with 100`() {
        val r = Grader.grade(emptyList())
        assertEquals(100, r.score)
        assertEquals(Grade.A, r.grade)
    }

    @Test
    fun `info costs nothing`() {
        assertEquals(100, Grader.grade(listOf(f("a", Severity.INFO), f("b", Severity.INFO))).score)
    }

    @Test
    fun `score thresholds`() {
        assertEquals(Grade.A, Grader.gradeForScore(90))
        assertEquals(Grade.B, Grader.gradeForScore(89))
        assertEquals(Grade.B, Grader.gradeForScore(75))
        assertEquals(Grade.C, Grader.gradeForScore(74))
        assertEquals(Grade.C, Grader.gradeForScore(55))
        assertEquals(Grade.D, Grader.gradeForScore(54))
        assertEquals(Grade.D, Grader.gradeForScore(35))
        assertEquals(Grade.F, Grader.gradeForScore(34))
    }

    @Test
    fun `lows add up`() {
        val r = Grader.grade(List(4) { f("l$it", Severity.LOW) })
        assertEquals(88, r.score)
        assertEquals(Grade.B, r.grade)
        assertNull(r.breakdown.capReason)
    }

    @Test
    fun `one medium caps at B`() {
        val r = Grader.grade(listOf(f("m", Severity.MEDIUM)))
        assertEquals(92, r.score)
        assertEquals(Grade.B, r.grade)
        assertNotNull(r.breakdown.capReason)
    }

    @Test
    fun `one high caps at C, one critical caps at D`() {
        assertEquals(Grade.C, Grader.grade(listOf(f("h", Severity.HIGH))).grade)
        assertEquals(Grade.D, Grader.grade(listOf(f("c", Severity.CRITICAL))).grade)
    }

    @Test
    fun `superseded findings cost nothing`() {
        val r = Grader.grade(listOf(f("combo", Severity.HIGH), f("part", Severity.MEDIUM, countedIn = "combo")))
        assertEquals(80, r.score)
        assertEquals(0, r.findings.first { it.id == "part" }.pointsDeducted)
        assertEquals(listOf("combo" to 20), r.breakdown.deductions)
    }

    @Test
    fun `score never goes below zero`() {
        val r = Grader.grade(List(5) { f("c$it", Severity.CRITICAL) })
        assertEquals(0, r.score)
        assertEquals(Grade.F, r.grade)
    }
}
