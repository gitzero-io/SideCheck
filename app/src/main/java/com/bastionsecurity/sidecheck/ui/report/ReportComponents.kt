package com.bastionsecurity.sidecheck.ui.report

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.engine.grading.Grader
import com.bastionsecurity.sidecheck.engine.model.AppFacts
import com.bastionsecurity.sidecheck.engine.model.AppReport
import com.bastionsecurity.sidecheck.engine.model.Finding
import com.bastionsecurity.sidecheck.engine.model.Severity
import com.bastionsecurity.sidecheck.ui.components.ButtonRow
import com.bastionsecurity.sidecheck.ui.components.FocusCard
import com.bastionsecurity.sidecheck.ui.components.GradeBadge
import com.bastionsecurity.sidecheck.ui.components.Panel
import com.bastionsecurity.sidecheck.ui.components.Pill
import com.bastionsecurity.sidecheck.ui.components.SecondaryButton
import com.bastionsecurity.sidecheck.ui.theme.SC

/** Report pieces shared by the installed-app detail screen and the APK check screen. */

@Composable
fun GradeCard(r: AppReport) {
    var showHow by rememberSaveable { mutableStateOf(false) }
    FocusCard(onClick = { showHow = !showHow }, modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(24.dp)) {
            GradeBadge(r.grade, 88.dp)
            Column(Modifier.weight(1f)) {
                Text("Our take", style = MaterialTheme.typography.labelLarge, color = SC.TextFaint)
                Text(r.verdict, style = MaterialTheme.typography.headlineSmall)
                Text(
                    "Score ${r.score} of 100 · ${if (showHow) "Hide how we graded" else "Select to see how we graded"}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = SC.TextDim,
                )
            }
        }
        if (showHow) {
            Spacer(Modifier.height(14.dp))
            Text("Everything starts at ${r.breakdown.startingScore}.", style = MaterialTheme.typography.bodyMedium)
            r.breakdown.deductions.forEach { (id, pts) ->
                val title = r.findings.firstOrNull { it.id == id }?.plainTitle ?: id
                Text("−$pts  $title", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
            }
            Text(
                "Points: Minor −${Grader.points(Severity.LOW)}, Worth a look −${Grader.points(Severity.MEDIUM)}, " +
                    "Serious −${Grader.points(Severity.HIGH)}, Very serious −${Grader.points(Severity.CRITICAL)}. " +
                    "A 90+, B 75+, C 55+, D 35+, F below 35.",
                style = MaterialTheme.typography.bodySmall,
                color = SC.TextFaint,
            )
            r.breakdown.capReason?.let { Text("$it.", style = MaterialTheme.typography.bodySmall, color = SC.TextFaint) }
            Text("Where you got the app never changes the grade.", style = MaterialTheme.typography.bodySmall, color = SC.TextFaint)
        }
    }
}


@Composable
fun FindingRow(
    finding: Finding,
    kept: Boolean,
    allTitles: Map<String, String>,
    /** The choice buttons shown when a finding is expanded (e.g. Keep / Remove). */
    actions: @Composable RowScope.() -> Unit,
) {
    var expanded by rememberSaveable(finding.id) { mutableStateOf(false) }
    var details by rememberSaveable(finding.id + "d") { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        FocusCard(onClick = { expanded = !expanded }, modifier = Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Pill(SC.severityLabel(finding.severity), SC.severity(finding.severity))
                if (finding.isHeuristic) Pill("Hint", SC.TextDim)
                if (kept) Pill("You kept this", SC.Brand)
                Spacer(Modifier.weight(1f))
                if (finding.pointsDeducted > 0) Text("−${finding.pointsDeducted}", style = MaterialTheme.typography.labelLarge, color = SC.TextFaint)
            }
            Spacer(Modifier.height(6.dp))
            Text(finding.plainTitle, style = MaterialTheme.typography.titleLarge, color = if (kept) SC.TextDim else SC.Text)
            Text(finding.plainExplanation, style = MaterialTheme.typography.bodyLarge, color = SC.TextDim, maxLines = if (expanded) 10 else 2)
        }
        if (expanded) {
            Panel(Modifier.fillMaxWidth().padding(start = 24.dp), container = SC.SurfaceHigh) {
                Text("Why does this matter?", style = MaterialTheme.typography.titleMedium, color = SC.Brand)
                Text(finding.whyItMatters, style = MaterialTheme.typography.bodyLarge)
                finding.countedIn?.let {
                    Spacer(Modifier.height(6.dp))
                    Text("Counted as part of: ${allTitles[it] ?: it}", style = MaterialTheme.typography.bodyMedium, color = SC.TextFaint)
                }
                if (finding.isHeuristic) {
                    Text(
                        "This is a hint from the app's code, not proof. The code is there, but we can't tell if it's used.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = SC.TextFaint,
                    )
                }
                Spacer(Modifier.height(12.dp))
                ButtonRow {
                    SecondaryButton(if (details) "Hide details" else "Details", { details = !details })
                    actions()
                }
                if (details) {
                    Spacer(Modifier.height(12.dp))
                    finding.technicalEvidence.forEach {
                        Text(it, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace), color = SC.TextDim)
                    }
                    Text("Rule: ${finding.id} · ${finding.category.name.lowercase()}", style = MaterialTheme.typography.bodySmall, color = SC.TextFaint)
                }
            }
        }
    }
}


@Composable
fun TechDetails(f: AppFacts) {
    var open by rememberSaveable { mutableStateOf(false) }
    FocusCard(onClick = { open = !open }, modifier = Modifier.fillMaxWidth()) {
        Text(if (open) "Hide technical details" else "Show technical details", style = MaterialTheme.typography.titleMedium)
        if (open) {
            val mono = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)
            val lines = buildList {
                add("Package: ${f.packageName}")
                add("Version: ${f.versionName} (${f.versionCode})")
                add("Target SDK: ${f.targetSdk}  Min SDK: ${f.minSdk ?: "?"}")
                add("Installer: ${f.installSource.installerPackage ?: "none"}  Initiated by: ${f.installSource.initiatingPackage ?: "none"}")
                f.signers.forEach { add("Signer: ${it.subject}"); add("  SHA-256: ${it.sha256}") }
                add("APK SHA-256: ${f.apkSha256 ?: "unknown"}")
                f.apkContents?.let { add("Code files: ${it.dexCount}  Native libraries: ${it.nativeLibs.size}  ABIs: ${it.abis.joinToString()}") }
                f.dexScan?.let { add("Strings scanned: ${it.stringsScanned}${if (it.truncated) " (partial)" else ""}") }
                add("Debuggable: ${f.debuggable}  Cleartext allowed: ${f.cleartextTrafficAllowed}")
            }
            Spacer(Modifier.height(8.dp))
            lines.forEach { Text(it, style = mono, color = SC.TextDim) }
        }
    }
}

