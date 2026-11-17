package com.bastionsecurity.sidecheck.ui.firmware

import android.app.Application
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.collect.FirmwareMatch
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.engine.model.Severity
import com.bastionsecurity.sidecheck.grants.ShizukuBridge
import com.bastionsecurity.sidecheck.ui.components.AppIcon
import com.bastionsecurity.sidecheck.ui.components.ButtonRow
import com.bastionsecurity.sidecheck.ui.components.Panel
import com.bastionsecurity.sidecheck.ui.components.Pill
import com.bastionsecurity.sidecheck.ui.components.PrimaryButton
import com.bastionsecurity.sidecheck.ui.components.SecondaryButton
import com.bastionsecurity.sidecheck.ui.theme.SC
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class FirmwareViewModel(private val app: Application, repo: ScanRepository, val shizuku: ShizukuBridge) : ViewModel() {
    private val refresh = MutableStateFlow(0)

    /** Saved matches, with the "turned off" state read live (the user may change it in Settings). */
    val matches: StateFlow<List<FirmwareMatch>> = combine(repo.firmwareMatches, refresh) { list, _ ->
        list.mapNotNull { m ->
            val ai: ApplicationInfo = runCatching { app.packageManager.getApplicationInfo(m.packageName, 0) }.getOrNull()
                ?: return@mapNotNull null // gone (e.g. after a firmware update)
            m.copy(enabled = ai.enabled)
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    fun onResume() {
        shizuku.refresh()
        refresh.value++
    }

    fun turnOff(m: FirmwareMatch) = viewModelScope.launch {
        val r = shizuku.setPackageEnabled(m.packageName, enabled = false)
        _message.value = if (r.ok) "Turned off: ${m.label}" else "Couldn't turn off ${m.label}. ${r.output.lineSequence().firstOrNull().orEmpty()}"
        refresh.value++
    }
}

@Composable
fun FirmwareScreen(vm: FirmwareViewModel) {
    val matches by vm.matches.collectAsStateWithLifecycle()
    val message by vm.message.collectAsStateWithLifecycle()
    val shizuku by vm.shizuku.status.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val first = remember { FocusRequester() }
    LifecycleResumeEffect(Unit) {
        vm.onResume()
        onPauseOrDispose { }
    }
    LaunchedEffect(matches.isNotEmpty()) { if (matches.isNotEmpty()) runCatching { first.requestFocus() } }

    LazyColumn(
        Modifier.fillMaxSize().background(SC.Bg),
        contentPadding = PaddingValues(horizontal = 56.dp, vertical = 32.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Text("Built-in apps that match known malware", style = MaterialTheme.typography.displaySmall)
            Spacer(Modifier.height(6.dp))
            Text(
                "These apps came with your TV box. Their files or digital signatures match malware that " +
                    "security researchers have reported, often used to turn TV boxes into botnets. " +
                    "That can mean strangers use your internet connection, or your box takes part in attacks on websites.",
                style = MaterialTheme.typography.bodyLarge,
                color = SC.TextDim,
            )
        }
        item {
            Panel(Modifier.fillMaxWidth(), container = SC.SurfaceHigh) {
                Text("What you can do", style = MaterialTheme.typography.titleLarge)
                Text(
                    "• Turn the app off below. That usually stops it, but a firmware update can turn it back on.\n" +
                        "• A factory reset won't remove it, because it's part of the box's software.\n" +
                        "• Contact the seller, or consider a box that has Google's Play Protect certification.",
                    style = MaterialTheme.typography.bodyLarge,
                    color = SC.TextDim,
                )
            }
        }
        message?.let { item { Text(it, style = MaterialTheme.typography.bodyLarge, color = SC.Brand) } }
        if (matches.isEmpty()) {
            item { Text("No built-in apps match the list right now.", style = MaterialTheme.typography.headlineSmall, color = SC.TextDim) }
        }
        items(matches, key = { it.packageName }) { m ->
            Panel(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    AppIcon(m.packageName, 56.dp)
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text(m.label, style = MaterialTheme.typography.headlineSmall)
                            Pill(if (m.enabled) "Turned on" else "Turned off", if (m.enabled) SC.severity(Severity.CRITICAL) else SC.TextDim)
                        }
                        Text(
                            if (m.bySigner) "Signed with the same key as ${m.family}, reported by ${m.source}."
                            else "This exact file is ${m.family}, reported by ${m.source}.",
                            style = MaterialTheme.typography.bodyLarge,
                            color = SC.TextDim,
                        )
                        Text("${m.packageName} · ${m.sourceUrl}", style = MaterialTheme.typography.bodySmall, color = SC.TextFaint)
                    }
                }
                Spacer(Modifier.height(12.dp))
                val focusMod = if (m == matches.first()) Modifier.focusRequester(first) else Modifier
                ButtonRow {
                    if (m.enabled && shizuku == ShizukuBridge.Status.READY) {
                        PrimaryButton("Turn off", { vm.turnOff(m) }, focusMod)
                        SecondaryButton("Open app settings", { openAppSettings(context, m.packageName) })
                    } else {
                        PrimaryButton(
                            if (m.enabled) "Turn off in Settings" else "Open app settings",
                            { openAppSettings(context, m.packageName) },
                            focusMod,
                        )
                    }
                }
            }
        }
    }
}

private fun openAppSettings(context: android.content.Context, pkg: String) {
    runCatching {
        context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", pkg, null)))
    }
}
