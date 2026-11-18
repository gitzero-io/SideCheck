package com.bastionsecurity.sidecheck.ui.apk

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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.unit.dp
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.engine.model.Severity
import com.bastionsecurity.sidecheck.ui.components.AppIcon
import com.bastionsecurity.sidecheck.ui.components.ButtonRow
import com.bastionsecurity.sidecheck.ui.components.Panel
import com.bastionsecurity.sidecheck.ui.components.PrimaryButton
import com.bastionsecurity.sidecheck.ui.components.SecondaryButton
import com.bastionsecurity.sidecheck.ui.report.FindingRow
import com.bastionsecurity.sidecheck.ui.report.GradeCard
import com.bastionsecurity.sidecheck.ui.report.TechDetails
import com.bastionsecurity.sidecheck.ui.theme.SC
import com.bastionsecurity.sidecheck.ui.theme.deviceNoun
import com.bastionsecurity.sidecheck.ui.theme.tvWidth
import com.bastionsecurity.sidecheck.ui.theme.screenPadding
import com.bastionsecurity.sidecheck.ui.theme.focusFirst
import com.bastionsecurity.sidecheck.ui.theme.isPhone

@Composable
fun ApkCheckScreen(
    state: ApkCheckState,
    onInstall: () -> Unit,
    onDontInstall: () -> Unit,
    onAllowInstalls: () -> Unit,
    onOpenApp: (String) -> Unit,
    onDone: () -> Unit,
) {
    Box(Modifier.fillMaxSize().background(SC.Bg)) {
        when (state) {
            ApkCheckState.NoFile -> Message(
                "Check an app before you install it",
                "Open the APK in Downloader or your file manager, choose \"Open with\", and pick SideCheck.",
                null,
                onDone,
            )
            is ApkCheckState.Working -> Centered { Text(state.message, style = MaterialTheme.typography.headlineSmall, color = SC.TextDim) }
            is ApkCheckState.Failed -> Message(state.title, state.body, null, onDone)
            is ApkCheckState.Installed -> InstalledView(state, onOpenApp, onDone)
            is ApkCheckState.Ready -> Report(state, onInstall, onDontInstall, onAllowInstalls)
        }
    }
}

@Composable
private fun Report(s: ApkCheckState.Ready, onInstall: () -> Unit, onDontInstall: () -> Unit, onAllowInstalls: () -> Unit) {
    val r = s.report
    val f = r.facts
    val focus = remember { FocusRequester() }
    val listState = rememberLazyListState()
    val phone = isPhone()
    LaunchedEffect(s.needsInstallPermission) {
        if (phone) return@LaunchedEffect // no starting focus on touch screens
        runCatching { focus.requestFocus() }
        kotlinx.coroutines.delay(150)
        listState.scrollToItem(0)
    }
    val serious = r.findings.any { it.countedIn == null && it.severity >= Severity.HIGH }

    LazyColumn(
        Modifier.fillMaxSize(),
        state = listState,
        contentPadding = screenPadding(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(if (phone) 14.dp else 20.dp)) {
                AppIcon(f.packageName + "@archive", if (phone) 56.dp else 72.dp, archivePath = s.file.absolutePath)
                Column {
                    Text("Before you install", style = MaterialTheme.typography.labelLarge, color = SC.Brand)
                    Text(f.label, style = MaterialTheme.typography.displaySmall)
                    Text("Version ${f.versionName ?: f.versionCode} · ${s.fileName}", style = MaterialTheme.typography.bodyLarge, color = SC.TextDim)
                }
            }
        }
        s.existing?.let { ex -> item { ExistingPanel(ex, f.versionCode) } }
        item { GradeCard(r) }
        if (s.needsInstallPermission) {
            item {
                Panel(Modifier.fillMaxWidth(), container = SC.SurfaceHigh) {
                    Text("One more step", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "To hand this app to Android's installer, SideCheck needs permission to install apps. " +
                            "Turn on \"SideCheck\" on the next screen, then press Back.",
                        style = MaterialTheme.typography.bodyLarge,
                        color = SC.TextDim,
                    )
                    Spacer(Modifier.height(12.dp))
                    PrimaryButton("Open Settings", onAllowInstalls, Modifier.focusRequester(focus))
                }
            }
        }
        item {
            ButtonRow(Modifier.padding(vertical = 4.dp)) {
                // Lead with the safer choice when there's something serious; otherwise lead with install.
                if (serious) {
                    PrimaryButton("Don't install", onDontInstall, if (s.needsInstallPermission) Modifier else Modifier.focusRequester(focus))
                    SecondaryButton("Install anyway", onInstall)
                } else {
                    PrimaryButton("Install", onInstall, if (s.needsInstallPermission) Modifier else Modifier.focusRequester(focus))
                    SecondaryButton("Don't install", onDontInstall)
                }
            }
        }
        item {
            Text(
                if (r.findings.isEmpty()) "What we found" else "What we found (${r.findings.size})",
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.padding(top = 14.dp),
            )
        }
        if (r.findings.isEmpty()) {
            item { Panel { Text("Nothing worth mentioning. This app only does ordinary things.", style = MaterialTheme.typography.bodyLarge) } }
        }
        items(r.findings, key = { it.id }) { finding ->
            FindingRow(finding, kept = false, allTitles = r.findings.associate { it.id to it.plainTitle }) {
                SecondaryButton("Install anyway", onInstall)
                SecondaryButton("Don't install", onDontInstall, danger = true)
            }
        }
        item {
            Text("Technical details", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(top = 14.dp))
        }
        item { TechDetails(f) }
        item {
            Text(
                "Some checks need the app to be installed (like whether it has a home screen icon), so they're skipped here.",
                style = MaterialTheme.typography.bodySmall,
                color = SC.TextFaint,
            )
        }
    }
}

@Composable
private fun ExistingPanel(ex: ExistingInstall, newVersionCode: Long) {
    val noun = deviceNoun()
    val (title, body, warn) = when {
        ex.sameSigner == false -> Triple(
            "You already have ${ex.label}, from a different maker",
            "The app on your $noun and this file were signed by different people. Android won't install this over it. " +
                "If you install it anyway, you'd have to remove the current one first, and you'll lose its data.",
            true,
        )
        newVersionCode < ex.versionCode -> Triple(
            "This is an older version of ${ex.label}",
            "You have version ${ex.versionName ?: ex.versionCode}. Android usually won't install an older version over a newer one.",
            true,
        )
        newVersionCode == ex.versionCode -> Triple("You already have this version", "It's the same version that's on your $noun now.", false)
        else -> Triple("This updates ${ex.label}", "You have version ${ex.versionName ?: ex.versionCode} now. It comes from the same maker.", false)
    }
    Panel(Modifier.fillMaxWidth(), container = if (warn) SC.SurfaceHigh else SC.Surface) {
        Text(title, style = MaterialTheme.typography.titleLarge, color = if (warn) SC.severity(Severity.HIGH) else SC.Text)
        Text(body, style = MaterialTheme.typography.bodyLarge, color = SC.TextDim)
    }
}

@Composable
private fun InstalledView(s: ApkCheckState.Installed, onOpenApp: (String) -> Unit, onDone: () -> Unit) {
    val focus = remember { FocusRequester() }
    val phone = isPhone()
    LaunchedEffect(Unit) { focus.focusFirst(phone) }
    Centered {
        Text("${s.label} is installed", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text("You can find its report in SideCheck any time.", style = MaterialTheme.typography.bodyLarge, color = SC.TextDim)
        Spacer(Modifier.height(20.dp))
        ButtonRow {
            PrimaryButton("Done", onDone, Modifier.focusRequester(focus))
            SecondaryButton("See its report in SideCheck", { onOpenApp(s.packageName) })
        }
    }
}

@Composable
private fun Message(title: String, body: String, action: Pair<String, () -> Unit>?, onDone: () -> Unit) {
    val focus = remember { FocusRequester() }
    val phone = isPhone()
    LaunchedEffect(title) { focus.focusFirst(phone) }
    Centered {
        Text(title, style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text(body, style = MaterialTheme.typography.bodyLarge, color = SC.TextDim)
        Spacer(Modifier.height(20.dp))
        ButtonRow {
            if (action != null) {
                PrimaryButton(action.first, action.second, Modifier.focusRequester(focus))
                SecondaryButton("Close", onDone)
            } else {
                PrimaryButton("Close", onDone, Modifier.focusRequester(focus))
            }
        }
    }
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(Modifier.tvWidth(640.dp).padding(screenPadding()), horizontalAlignment = Alignment.Start) { content() }
    }
}
