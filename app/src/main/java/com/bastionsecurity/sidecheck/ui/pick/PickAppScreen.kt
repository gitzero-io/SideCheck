package com.bastionsecurity.sidecheck.ui.pick

import android.app.Application
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
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.itemsIndexed
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.collect.PackageCollector
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.ui.components.AppIcon
import com.bastionsecurity.sidecheck.ui.components.FocusCard
import com.bastionsecurity.sidecheck.ui.components.GradeBadge
import com.bastionsecurity.sidecheck.ui.theme.SC
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class PickableApp(val packageName: String, val label: String)

class PickAppViewModel(
    private val context: Application,
    private val collector: () -> PackageCollector,
    repo: ScanRepository,
) : ViewModel() {
    private val _apps = MutableStateFlow<List<PickableApp>?>(null)
    val apps: StateFlow<List<PickableApp>?> = _apps.asStateFlow()

    /** Grades from a scan this session, if any, shown next to each app. */
    val grades: StateFlow<Map<String, Grade>> = repo.reports
        .map { m -> m.mapValues { it.value.grade } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyMap())

    init {
        viewModelScope.launch {
            _apps.value = withContext(Dispatchers.IO) {
                val pm = context.packageManager
                // Only labels here (cheap). The full check runs when an app is picked.
                collector().userPackages().map { pkg ->
                    val label = runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
                    PickableApp(pkg, label)
                }.sortedBy { it.label.lowercase() }
            }
        }
    }
}

@Composable
fun PickAppScreen(vm: PickAppViewModel, onPick: (String) -> Unit) {
    val apps by vm.apps.collectAsStateWithLifecycle()
    val grades by vm.grades.collectAsStateWithLifecycle()
    val first = remember { FocusRequester() }

    Column(Modifier.fillMaxSize().background(SC.Bg).padding(start = 56.dp, end = 56.dp, top = 32.dp)) {
        Text("Check an app", style = MaterialTheme.typography.displaySmall)
        Text(
            "Pick an app on this TV to see what it can do.",
            style = MaterialTheme.typography.bodyLarge,
            color = SC.TextDim,
        )
        Text(
            "To check an APK before you install it, open the file in Downloader or your file manager and choose SideCheck.",
            style = MaterialTheme.typography.bodyMedium,
            color = SC.TextFaint,
        )
        Spacer(Modifier.height(18.dp))

        val list = apps
        when {
            list == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("Loading your apps…", style = MaterialTheme.typography.headlineSmall, color = SC.TextDim)
            }
            list.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No apps have been added to this TV besides the built-in ones.", style = MaterialTheme.typography.headlineSmall, color = SC.TextDim)
            }
            else -> {
                val repeated = remember(list) { list.groupBy { it.label }.filterValues { it.size > 1 }.keys }
                LaunchedEffect(Unit) { runCatching { first.requestFocus() } }
                LazyVerticalGrid(
                    columns = GridCells.Fixed(3),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                    contentPadding = PaddingValues(top = 4.dp, bottom = 40.dp, start = 4.dp, end = 4.dp),
                ) {
                    itemsIndexed(list, key = { _, a -> a.packageName }) { i, app ->
                        FocusCard(
                            onClick = { onPick(app.packageName) },
                            modifier = Modifier.fillMaxWidth().then(if (i == 0) Modifier.focusRequester(first) else Modifier),
                            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                                AppIcon(app.packageName, 44.dp)
                                Column(Modifier.weight(1f)) {
                                    Text(app.label, style = MaterialTheme.typography.titleMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                    // Same name twice? Show the app ID so they can be told apart.
                                    if (app.label in repeated) {
                                        Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = SC.TextFaint, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    }
                                }
                                grades[app.packageName]?.let { GradeBadge(it, 34.dp) }
                            }
                        }
                    }
                }
            }
        }
    }
}
