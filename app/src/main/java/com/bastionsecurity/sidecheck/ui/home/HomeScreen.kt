package com.bastionsecurity.sidecheck.ui.home

import android.app.Application
import android.text.format.DateUtils
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.data.AppEntry
import com.bastionsecurity.sidecheck.data.LastScan
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.data.ScanState
import com.bastionsecurity.sidecheck.data.TrustStore
import com.bastionsecurity.sidecheck.data.WatchState
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.ui.components.AppIcon
import com.bastionsecurity.sidecheck.ui.components.GradeBadge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import com.bastionsecurity.sidecheck.ui.components.FocusCard
import com.bastionsecurity.sidecheck.ui.components.Panel
import com.bastionsecurity.sidecheck.ui.components.PrimaryButton
import com.bastionsecurity.sidecheck.ui.theme.SC
import com.bastionsecurity.sidecheck.ui.theme.focusFirst
import com.bastionsecurity.sidecheck.ui.theme.deviceNoun
import com.bastionsecurity.sidecheck.ui.theme.isPhone
import com.bastionsecurity.sidecheck.ui.theme.screenPadding
import com.bastionsecurity.sidecheck.ui.theme.tvWidth
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn

/** An app installed or updated since the user last looked, for the Home screen. */
data class RecentItem(val packageName: String, val label: String, val isNew: Boolean, val grade: Grade?)

class HomeViewModel(context: Application, private val repo: ScanRepository, watch: WatchState, trust: TrustStore) : ViewModel() {
    /** Built-in apps matching the known-malware list (from the last full scan). */
    val firmwareCount: StateFlow<Int> = repo.firmwareMatches.map { it.size }
        .stateIn(viewModelScope, SharingStarted.Eagerly, 0)

    /** Saved "needs attention" apps minus any the user has since trusted. */
    val savedAttention: StateFlow<Int?> = combine(repo.lastScan, trust.snapshot) { last, t ->
        last?.let { l -> if (l.attentionApps.isEmpty()) l.attentionCount else l.attentionApps.count { it !in t.trustedApps } }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val recent: StateFlow<List<RecentItem>> = combine(watch.recent, repo.reports) { list, reps ->
        val pm = context.packageManager
        list.mapNotNull { rc ->
            val label = runCatching { pm.getApplicationLabel(pm.getApplicationInfo(rc.packageName, 0)).toString() }
                .getOrNull() ?: return@mapNotNull null // removed since
            RecentItem(rc.packageName, label, rc.isNewInstall, reps[rc.packageName]?.grade ?: rc.grade)
        }
    }.flowOn(Dispatchers.IO).stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val scanState: StateFlow<ScanState> = repo.state
    val hasResults: StateFlow<Boolean> = repo.hasResults
    val lastScan: StateFlow<LastScan?> = repo.lastScan.stateIn(viewModelScope, SharingStarted.Eagerly, null)
    val entries: StateFlow<List<AppEntry>> = repo.entries.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    fun scan() = repo.startFullScan()
}

@Composable
fun HomeScreen(
    vm: HomeViewModel,
    onOpenResults: () -> Unit,
    onOpenTrusted: () -> Unit,
    onOpenApp: (String) -> Unit,
    onOpenFirmware: () -> Unit,
    onCheckApp: () -> Unit,
    onSwitchDevice: () -> Unit,
) {
    val state by vm.scanState.collectAsStateWithLifecycle()
    val hasResults by vm.hasResults.collectAsStateWithLifecycle()
    val last by vm.lastScan.collectAsStateWithLifecycle()
    val entries by vm.entries.collectAsStateWithLifecycle()
    val recent by vm.recent.collectAsStateWithLifecycle()
    val savedAttention by vm.savedAttention.collectAsStateWithLifecycle()
    val firmwareCount by vm.firmwareCount.collectAsStateWithLifecycle()
    val scanFocus = remember { FocusRequester() }

    // Jump to results when a scan the user started finishes.
    var wasScanning by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(state) {
        if (state is ScanState.Scanning) wasScanning = true
        else if (wasScanning && state is ScanState.Idle) { wasScanning = false; onOpenResults() }
    }
    val phone = isPhone()
    LaunchedEffect(Unit) { scanFocus.focusFirst(phone) }

    val noun = deviceNoun()

    // Low-key way to change the first-launch answer. On TV it sits under the summary (reached with
    // Down), so pressing Right from the scan button can't land on it by accident.
    val switchCard: @Composable () -> Unit = {
        FocusCard(onClick = onSwitchDevice, modifier = Modifier.tvWidth(460.dp), container = SC.Bg) {
            Text(if (phone) "Using a TV?" else "Using a phone or tablet?", style = MaterialTheme.typography.titleMedium)
            Text(
                if (phone) "Switch to the TV layout" else "Switch to the phone and tablet layout",
                style = MaterialTheme.typography.bodySmall,
                color = SC.TextDim,
            )
        }
    }

    // Title, scan button and summary.
    val main: @Composable ColumnScope.() -> Unit = {
        Text("SideCheck", style = MaterialTheme.typography.displaySmall, color = SC.Text)
        Text("by Bastion Security", style = MaterialTheme.typography.bodyMedium, color = SC.Brand)
        // The tagline makes room for the firmware warning when there is one.
        if (firmwareCount == 0) {
            Spacer(Modifier.height(20.dp))
            Text(
                "See what the apps on this $noun can really do. You decide what stays.",
                style = MaterialTheme.typography.headlineSmall,
                color = SC.TextDim,
            )
        }
        Spacer(Modifier.height(28.dp))

        when (val s = state) {
            is ScanState.Scanning -> ScanProgress(s)
            else -> PrimaryButton(
                if (hasResults) "Scan again" else "Scan my apps",
                onClick = vm::scan,
                modifier = Modifier.focusRequester(scanFocus),
            )
        }
        if (state is ScanState.Failed) {
            Spacer(Modifier.height(12.dp))
            Text(
                "The scan stopped early: ${(state as ScanState.Failed).message}. Try again.",
                color = SC.Danger,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Spacer(Modifier.height(28.dp))
        if (firmwareCount > 0) {
            FocusCard(onClick = onOpenFirmware, modifier = Modifier.tvWidth(560.dp), container = SC.Danger.copy(alpha = 0.22f)) {
                Text(if (phone) "This device's built-in software matches known malware" else "Your TV box's built-in software matches known malware", style = MaterialTheme.typography.titleLarge, color = SC.Text)
                Text(
                    "$firmwareCount built-in app${if (firmwareCount == 1) "" else "s"} matched. ${if (phone) "Tap" else "Select"} to see what you can do.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = SC.TextDim,
                )
            }
            Spacer(Modifier.height(16.dp))
        }
        Summary(hasResults, entries, last, savedAttention)
        if (!phone) {
            Spacer(Modifier.height(12.dp))
            switchCard()
        }
    }

    // "New since you last looked" and the navigation cards.
    val side: @Composable ColumnScope.() -> Unit = {
        if (recent.isNotEmpty()) {
            Text("New since you last looked", style = MaterialTheme.typography.titleMedium, color = SC.Brand)
            recent.take(2).forEach { item ->
                FocusCard(
                    onClick = { onOpenApp(item.packageName) },
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                        AppIcon(item.packageName, 40.dp)
                        Column(Modifier.weight(1f)) {
                            Text(item.label, style = MaterialTheme.typography.titleMedium, maxLines = 1)
                            Text(if (item.isNew) "Just installed" else "Just updated", style = MaterialTheme.typography.bodySmall, color = SC.TextDim)
                        }
                        item.grade?.let { GradeBadge(it, 34.dp) }
                    }
                }
            }
            if (recent.size > 2) {
                Text("and ${recent.size - 2} more in your results", style = MaterialTheme.typography.bodySmall, color = SC.TextFaint)
            }
        }
        if (hasResults) {
            val attention = entries.count { it.needsAttention }
            FocusCard(onClick = onOpenResults, modifier = Modifier.fillMaxWidth()) {
                Text("See results", style = MaterialTheme.typography.titleLarge)
                Text(
                    if (attention == 0) "${entries.size} apps checked" else "$attention need your attention",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (attention == 0) SC.TextDim else SC.grade(com.bastionsecurity.sidecheck.engine.model.Grade.C),
                )
            }
        }
        FocusCard(onClick = onCheckApp, modifier = Modifier.fillMaxWidth()) {
            Text("Check an app", style = MaterialTheme.typography.titleLarge)
            Text("Pick one app from your list", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
        }
        FocusCard(onClick = onOpenTrusted, modifier = Modifier.fillMaxWidth()) {
            Text("Trusted apps", style = MaterialTheme.typography.titleLarge)
            Text("Apps you chose to keep", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
        }
        if (phone) switchCard()
    }

    if (phone) {
        BoxWithConstraints(Modifier.fillMaxSize().background(SC.Bg)) {
            if (maxWidth >= 720.dp) {
                // Landscape phone or tablet: two columns, each scrolling on its own.
                Row(Modifier.fillMaxSize().padding(screenPadding()), horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                    Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), content = main)
                    Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp), content = side)
                }
            } else {
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(screenPadding())) {
                    main()
                    Spacer(Modifier.height(24.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp), content = side)
                }
            }
        }
    } else {
        Row(
            Modifier.fillMaxSize().background(SC.Bg).padding(horizontal = 56.dp, vertical = 40.dp),
            horizontalArrangement = Arrangement.spacedBy(40.dp),
        ) {
            Box(Modifier.weight(1.25f).fillMaxHeight(), contentAlignment = Alignment.CenterStart) {
                Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()), content = main)
            }
            // Centered when it fits; scrolls (following D-pad focus) when it doesn't.
            Box(Modifier.weight(1f).fillMaxHeight(), contentAlignment = Alignment.Center) {
                Column(
                    Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                    content = side,
                )
            }
        }
    }
}

@Composable
private fun ScanProgress(s: ScanState.Scanning) {
    val frac = if (s.total == 0) 0f else s.done.toFloat() / s.total
    Column(Modifier.tvWidth(420.dp)) {
        Text(
            if (s.total == 0) "Getting ready…" else "Checking ${s.currentLabel ?: "apps"}…",
            style = MaterialTheme.typography.titleLarge,
            maxLines = 1,
        )
        Spacer(Modifier.height(12.dp))
        Box(Modifier.fillMaxWidth().height(10.dp).clip(RoundedCornerShape(5.dp)).background(SC.SurfaceHigh)) {
            Box(Modifier.fillMaxWidth(frac).fillMaxHeight().clip(RoundedCornerShape(5.dp)).background(SC.Brand))
        }
        Spacer(Modifier.height(8.dp))
        Text("${s.done} of ${s.total} apps", style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
    }
}

@Composable
private fun Summary(hasResults: Boolean, entries: List<AppEntry>, last: LastScan?, savedAttention: Int?) {
    val count: Int
    val attention: Int
    val time: Long
    if (hasResults) {
        count = entries.size; attention = entries.count { it.needsAttention }; time = last?.timeMillis ?: System.currentTimeMillis()
    } else if (last != null) {
        count = last.appCount; attention = savedAttention ?: last.attentionCount; time = last.timeMillis
    } else {
        Text("You haven't scanned yet.", style = MaterialTheme.typography.bodyLarge, color = SC.TextFaint)
        return
    }
    Panel(Modifier.tvWidth(460.dp)) {
        Text(
            "Last scan " + DateUtils.getRelativeTimeSpanString(time, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS),
            style = MaterialTheme.typography.bodyMedium,
            color = SC.TextFaint,
        )
        Spacer(Modifier.height(6.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(36.dp)) {
            Stat("$count", "apps checked", SC.Text)
            Stat("$attention", "need attention", if (attention > 0) SC.grade(com.bastionsecurity.sidecheck.engine.model.Grade.C) else SC.Brand)
        }
    }
}

@Composable
private fun Stat(value: String, label: String, color: androidx.compose.ui.graphics.Color) {
    Column {
        Text(value, style = MaterialTheme.typography.displaySmall, color = color)
        Text(label, style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
    }
}
