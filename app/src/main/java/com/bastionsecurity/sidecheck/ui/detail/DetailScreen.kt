package com.bastionsecurity.sidecheck.ui.detail

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.data.AppEntry
import com.bastionsecurity.sidecheck.engine.grading.Grader
import com.bastionsecurity.sidecheck.engine.model.Finding
import com.bastionsecurity.sidecheck.engine.model.Severity
import com.bastionsecurity.sidecheck.grants.Grant
import com.bastionsecurity.sidecheck.grants.ShizukuBridge
import com.bastionsecurity.sidecheck.ui.components.AppIcon
import com.bastionsecurity.sidecheck.ui.components.ButtonRow
import com.bastionsecurity.sidecheck.ui.components.FocusCard
import com.bastionsecurity.sidecheck.ui.components.GradeBadge
import com.bastionsecurity.sidecheck.ui.components.Panel
import com.bastionsecurity.sidecheck.ui.components.Pill
import com.bastionsecurity.sidecheck.ui.components.PrimaryButton
import com.bastionsecurity.sidecheck.ui.components.SecondaryButton
import com.bastionsecurity.sidecheck.ui.report.FindingRow
import com.bastionsecurity.sidecheck.ui.report.GradeCard
import com.bastionsecurity.sidecheck.ui.report.TechDetails
import com.bastionsecurity.sidecheck.ui.theme.SC
import java.util.Date

@Composable
fun DetailScreen(vm: DetailViewModel, onGone: () -> Unit) {
    val entry by vm.entry.collectAsStateWithLifecycle()
    val removed by vm.removed.collectAsStateWithLifecycle()
    val grants by vm.grants.collectAsStateWithLifecycle()
    val shizuku by vm.shizuku.status.collectAsStateWithLifecycle()
    val message by vm.message.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val failed by vm.failed.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LifecycleResumeEffect(vm.packageName) {
        vm.onResume()
        onPauseOrDispose { }
    }
    LaunchedEffect(removed) { if (removed) onGone() }

    val e = entry
    if (e == null) {
        Box(Modifier.fillMaxSize().background(SC.Bg), contentAlignment = Alignment.Center) {
            if (failed) {
                val retryFocus = remember { FocusRequester() }
                LaunchedEffect(Unit) { runCatching { retryFocus.requestFocus() } }
                Column(Modifier.width(560.dp)) {
                    Text("We couldn't check this app", style = MaterialTheme.typography.headlineMedium)
                    Text(
                        "Something went wrong while reading it. Your choices about this app are unchanged.",
                        style = MaterialTheme.typography.bodyLarge,
                        color = SC.TextDim,
                    )
                    Spacer(Modifier.height(18.dp))
                    PrimaryButton("Try again", { vm.retry() }, Modifier.focusRequester(retryFocus))
                }
            } else {
                Text("Checking this app…", style = MaterialTheme.typography.headlineSmall, color = SC.TextDim)
            }
        }
        return
    }
    val f = e.report.facts
    val firstFocus = remember { FocusRequester() }
    val listState = rememberLazyListState()
    LaunchedEffect(Unit) {
        runCatching { firstFocus.requestFocus() }
        // Focusing the buttons scrolls them into view on the next frame; scroll back so the app
        // name and grade stay visible.
        kotlinx.coroutines.delay(150)
        listState.scrollToItem(0)
    }

    val uninstall = { startSafely(context, Intent(Intent.ACTION_DELETE, Uri.fromParts("package", f.packageName, null))) }

    LazyColumn(
        Modifier.fillMaxSize().background(SC.Bg),
        state = listState,
        contentPadding = PaddingValues(horizontal = 56.dp, vertical = 32.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item { Header(e, vm.installSourceText(f)) }
        item { GradeCard(e.report) }
        if (e.trusted) {
            item {
                Panel(container = SC.BrandDark) {
                    Text("You chose to keep this app", style = MaterialTheme.typography.titleMedium, color = SC.Brand)
                    Text(
                        "We won't flag it again. If it's ever replaced by a version from someone else, we'll ask again.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
        item {
            ButtonRow(Modifier.padding(vertical = 4.dp)) {
                if (e.trusted) {
                    SecondaryButton("Stop trusting", { vm.setTrusted(false) }, Modifier.focusRequester(firstFocus))
                } else {
                    PrimaryButton("Keep / Trust", { vm.setTrusted(true) }, Modifier.focusRequester(firstFocus))
                }
                SecondaryButton("Remove", uninstall, danger = true)
                SecondaryButton("Open app settings", {
                    startSafely(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", f.packageName, null)))
                })
            }
        }

        item { SectionTitle(if (e.report.findings.isEmpty()) "What we found" else "What we found (${e.report.findings.size})") }
        if (e.report.findings.isEmpty()) {
            item { Panel { Text("Nothing worth mentioning. This app only does ordinary things.", style = MaterialTheme.typography.bodyLarge) } }
        }
        items(e.report.findings, key = { it.id }) { finding ->
            FindingRow(
                finding = finding,
                kept = finding.id in e.keptFindings,
                allTitles = e.report.findings.associate { it.id to it.plainTitle },
            ) {
                if (finding.id in e.keptFindings) {
                    SecondaryButton("Undo keep", { vm.setKept(finding.id, false) })
                } else {
                    SecondaryButton("Keep", { vm.setKept(finding.id, true) })
                }
                SecondaryButton("Remove app", uninstall, danger = true)
            }
        }

        item { SectionTitle("What it's allowed to do") }
        item { ShizukuPanel(shizuku, vm::requestShizuku) }
        message?.let { msg -> item { Text(msg, style = MaterialTheme.typography.bodyLarge, color = SC.Brand) } }
        val g = grants
        when {
            g == null -> item { Text("Reading permissions…", color = SC.TextDim) }
            g.isEmpty() -> item {
                Panel { Text("This app doesn't use any permissions that need your OK.", style = MaterialTheme.typography.bodyLarge) }
            }
            else -> items(g, key = { it.key }) { grant ->
                GrantRow(grant, shizuku == ShizukuBridge.Status.READY, busy, onToggle = { vm.toggle(grant) }, onSettings = {
                    grant.settingsIntent?.let { startSafely(context, it) }
                })
            }
        }

        item { SectionTitle("Technical details") }
        item { TechDetails(e.report.facts) }
    }
}

@Composable
private fun Header(e: AppEntry, source: String) {
    val f = e.report.facts
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(20.dp)) {
        AppIcon(f.packageName, 72.dp)
        Column {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(f.label, style = MaterialTheme.typography.displaySmall)
                if (!f.enabled) Pill("Turned off", SC.TextDim)
            }
            val added = f.firstInstallTime?.let { " · Added " + java.text.DateFormat.getDateInstance().format(Date(it)) }.orEmpty()
            Text("Version ${f.versionName ?: f.versionCode} · $source$added", style = MaterialTheme.typography.bodyLarge, color = SC.TextDim)
        }
    }
}

@Composable
private fun ShizukuPanel(status: ShizukuBridge.Status, onRequest: () -> Unit) {
    Panel(Modifier.fillMaxWidth(), container = SC.Surface) {
        when (status) {
            ShizukuBridge.Status.READY -> {
                Text("Shizuku is connected", style = MaterialTheme.typography.titleMedium, color = SC.Brand)
                Text("Changes below happen right away.", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
            }
            ShizukuBridge.Status.NEEDS_PERMISSION -> {
                Text("Shizuku is running", style = MaterialTheme.typography.titleMedium)
                Text("Allow SideCheck to use it, and you can turn permissions on and off right here.", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
                Spacer(Modifier.height(10.dp))
                SecondaryButton("Allow SideCheck to use Shizuku", onRequest)
            }
            ShizukuBridge.Status.NOT_RUNNING -> {
                Text("Shizuku is installed but not running", style = MaterialTheme.typography.titleMedium)
                Text("Start it in the Shizuku app (it needs restarting after the TV reboots). Until then, buttons open Android Settings.", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
            }
            ShizukuBridge.Status.NOT_INSTALLED -> {
                Text("Buttons below open Android Settings, where you can make changes.", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
                Text("Advanced: install the free Shizuku app to change permissions right here.", style = MaterialTheme.typography.bodySmall, color = SC.TextFaint)
            }
        }
    }
}

@Composable
private fun GrantRow(grant: Grant, shizukuReady: Boolean, busy: Boolean, onToggle: () -> Unit, onSettings: () -> Unit) {
    Panel(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Column(Modifier.weight(1f)) {
                Text(grant.title, style = MaterialTheme.typography.titleMedium)
                grant.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = SC.TextFaint) }
            }
            when (grant.allowed) {
                true -> Pill("Allowed", SC.grade(com.bastionsecurity.sidecheck.engine.model.Grade.C))
                false -> Pill("Not allowed", SC.TextDim)
                null -> Pill("Can't check", SC.TextFaint)
            }
            when {
                shizukuReady && grant.shizukuToggle != null ->
                    SecondaryButton(if (grant.allowed == true) "Turn off" else "Turn on", onToggle, enabled = !busy, modifier = Modifier.width(150.dp))
                grant.settingsIntent != null -> SecondaryButton("Change in Settings", onSettings)
                else -> Text("Change it in Android Settings", style = MaterialTheme.typography.bodySmall, color = SC.TextFaint)
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(top = 14.dp))
}

private fun startSafely(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        // Some TV builds lack certain Settings screens; fall back to the main Settings screen.
        runCatching {
            context.startActivity(Intent(Settings.ACTION_SETTINGS))
        }
    }
}
