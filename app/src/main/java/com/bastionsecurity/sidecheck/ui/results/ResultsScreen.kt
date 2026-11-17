package com.bastionsecurity.sidecheck.ui.results

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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.tv.material3.ExperimentalTvMaterial3Api
import androidx.tv.material3.FilterChip
import androidx.tv.material3.FilterChipDefaults
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.data.AppEntry
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.ui.components.AppIcon
import com.bastionsecurity.sidecheck.ui.components.FocusCard
import com.bastionsecurity.sidecheck.ui.components.GradeBadge
import com.bastionsecurity.sidecheck.ui.components.Pill
import com.bastionsecurity.sidecheck.ui.components.PrimaryButton
import com.bastionsecurity.sidecheck.ui.theme.SC
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn

enum class ResultsFilter(val label: String) { ALL("All"), ATTENTION("Needs attention"), TRUSTED("Trusted") }

class ResultsViewModel(private val repo: ScanRepository) : ViewModel() {
    val entries: StateFlow<List<AppEntry>> = repo.entries.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val hasResults = repo.hasResults
    fun scan() = repo.startFullScan()
}

@OptIn(ExperimentalTvMaterial3Api::class)
@Composable
fun ResultsScreen(vm: ResultsViewModel, initialFilter: ResultsFilter, onOpenApp: (String) -> Unit, onBackHome: () -> Unit) {
    val entries by vm.entries.collectAsStateWithLifecycle()
    val hasResults by vm.hasResults.collectAsStateWithLifecycle()
    var filter by rememberSaveable { mutableStateOf(initialFilter) }
    val firstFocus = remember { FocusRequester() }

    val shown = when (filter) {
        ResultsFilter.ALL -> entries
        ResultsFilter.ATTENTION -> entries.filter { it.needsAttention }
        ResultsFilter.TRUSTED -> entries.filter { it.trusted }
    }

    LaunchedEffect(Unit) { runCatching { firstFocus.requestFocus() } }

    Column(Modifier.fillMaxSize().background(SC.Bg).padding(start = 56.dp, end = 56.dp, top = 32.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Your apps", style = MaterialTheme.typography.displaySmall, modifier = Modifier.weight(1f))
            Text(
                "${entries.count { it.needsAttention }} need attention · ${entries.size} checked",
                style = MaterialTheme.typography.bodyLarge,
                color = SC.TextDim,
            )
        }
        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ResultsFilter.entries.forEach { f ->
                val count = when (f) {
                    ResultsFilter.ALL -> entries.size
                    ResultsFilter.ATTENTION -> entries.count { it.needsAttention }
                    ResultsFilter.TRUSTED -> entries.count { it.trusted }
                }
                FilterChip(
                    selected = filter == f,
                    onClick = { filter = f },
                    modifier = if (f == initialFilter) Modifier.focusRequester(firstFocus) else Modifier,
                    colors = FilterChipDefaults.colors(
                        containerColor = SC.Surface,
                        contentColor = SC.TextDim,
                        selectedContainerColor = SC.BrandDark,
                        selectedContentColor = SC.Brand,
                        focusedContainerColor = SC.Text,
                        focusedContentColor = SC.Bg,
                        focusedSelectedContainerColor = SC.Brand,
                        focusedSelectedContentColor = SC.Bg,
                    ),
                ) { Text("${f.label}  $count", style = MaterialTheme.typography.labelLarge) }
            }
        }
        Spacer(Modifier.height(16.dp))

        when {
            !hasResults -> Empty("No scan yet", "Scan your apps to see how they rate.", "Scan my apps") { vm.scan(); onBackHome() }
            shown.isEmpty() -> when (filter) {
                ResultsFilter.ATTENTION -> Empty("Nothing needs your attention", "Every app either looks fine or is one you chose to keep.", null) {}
                ResultsFilter.TRUSTED -> Empty("No trusted apps yet", "Open an app and choose Keep to trust it. We'll stop flagging it.", null) {}
                ResultsFilter.ALL -> Empty("No apps to check", "There are no apps added to this TV besides the built-in ones.", null) {}
            }
            else -> LazyColumn(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 40.dp, top = 4.dp, start = 4.dp, end = 4.dp),
            ) {
                items(shown, key = { it.packageName }) { e -> AppRow(e) { onOpenApp(e.packageName) } }
            }
        }
    }
}

@Composable
private fun AppRow(e: AppEntry, onClick: () -> Unit) {
    FocusCard(onClick = onClick, modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(horizontal = 18.dp, vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(18.dp)) {
            AppIcon(e.packageName, 48.dp)
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(e.report.facts.label, style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (e.trusted) Pill("Trusted", SC.Brand)
                }
                Text(
                    e.report.verdict,
                    style = MaterialTheme.typography.bodyMedium,
                    color = SC.TextDim,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            GradeBadge(e.report.grade, 48.dp)
        }
    }
}

@Composable
private fun Empty(title: String, body: String, action: String?, onAction: () -> Unit) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.width(520.dp)) {
            Text(title, style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            Text(body, style = MaterialTheme.typography.bodyLarge, color = SC.TextDim)
            if (action != null) {
                Spacer(Modifier.height(20.dp))
                PrimaryButton(action, onAction)
            }
        }
    }
}
