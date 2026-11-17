package com.bastionsecurity.sidecheck.engine.grading

import com.bastionsecurity.sidecheck.engine.model.Finding
import com.bastionsecurity.sidecheck.engine.model.Grade

/** The one-line "Our take". Advice, never a decision. */
object Verdicts {
    fun verdict(grade: Grade, findings: List<Finding>): String {
        val top = findings.filter { it.countedIn == null }.maxByOrNull { it.severity }?.plainTitle
        return when (grade) {
            Grade.A -> if (findings.isEmpty()) {
                "Looks fine. We didn't find anything worrying."
            } else {
                "Looks fine. Nothing here needs your attention."
            }
            Grade.B -> "Mostly fine. There are a few things worth knowing."
            Grade.C -> "Use with care. ${top?.let { "Main concern: ${it.lowercaseFirst()}." } ?: "Look over the items below."}"
            Grade.D -> "We'd be careful with this one. ${top?.let { "Main concern: ${it.lowercaseFirst()}." } ?: ""}".trim()
            Grade.F -> "We suggest removing this unless you trust where it came from. ${top?.let { "Main concern: ${it.lowercaseFirst()}." } ?: ""}".trim()
        }
    }

    private fun String.lowercaseFirst(): String =
        if (length > 1 && this[1].isLowerCase()) replaceFirstChar { it.lowercase() } else this
}
