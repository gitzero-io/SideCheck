package com.bastionsecurity.sidecheck.ui.setup

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import com.bastionsecurity.sidecheck.data.DeviceMode
import com.bastionsecurity.sidecheck.ui.components.FocusCard
import com.bastionsecurity.sidecheck.ui.components.Pill
import com.bastionsecurity.sidecheck.ui.theme.SC

/** First-launch question: TV or phone/tablet. [suggested] gets initial focus and a "Detected" tag. */
@Composable
fun DeviceChoiceScreen(suggested: DeviceMode, onChoose: (DeviceMode) -> Unit) {
    val tvFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) {
        // Only TVs need a starting focus; on a touch screen it would look pre-pressed.
        if (suggested == DeviceMode.TV) runCatching { tvFocus.requestFocus() }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Welcome to SideCheck", style = MaterialTheme.typography.displaySmall)
        Spacer(Modifier.height(8.dp))
        Text(
            "What are you using SideCheck on?",
            style = MaterialTheme.typography.bodyLarge,
            color = SC.TextDim,
        )
        Spacer(Modifier.height(28.dp))
        Column(Modifier.widthIn(max = 520.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Option(
                title = "TV",
                body = "Android TV, Google TV, Fire TV or a TV box. Built for the remote.",
                detected = suggested == DeviceMode.TV,
                modifier = Modifier.focusRequester(tvFocus),
                onClick = { onChoose(DeviceMode.TV) },
            )
            Option(
                title = "Phone or tablet",
                body = "Touch screen. Lets the screen rotate.",
                detected = suggested == DeviceMode.MOBILE,
                modifier = Modifier,
                onClick = { onChoose(DeviceMode.MOBILE) },
            )
        }
    }
}

@Composable
private fun Option(title: String, body: String, detected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    FocusCard(onClick = onClick, modifier = modifier.fillMaxWidth()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            if (detected) Pill("Detected", SC.Brand)
        }
        Spacer(Modifier.height(4.dp))
        Text(body, style = MaterialTheme.typography.bodyMedium, color = SC.TextDim)
    }
}
