package com.bastionsecurity.sidecheck.ui.theme

import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.bastionsecurity.sidecheck.data.DeviceMode

/** TV or phone/tablet, as the user chose on first launch. Provided by [SideCheckTheme]. */
val LocalDeviceMode = staticCompositionLocalOf { DeviceMode.TV }

/** True on phones and tablets: touch first, smaller type, single-column layouts. */
@Composable
@ReadOnlyComposable
fun isPhone(): Boolean = LocalDeviceMode.current == DeviceMode.MOBILE

/** "TV" or "device", for copy like "the apps on this TV". */
@Composable
@ReadOnlyComposable
fun deviceNoun(): String = if (isPhone()) "device" else "TV"

/** Outer padding for a full screen. TV keeps room for overscan; phones use a normal gutter. */
@Composable
@ReadOnlyComposable
fun screenPadding(): PaddingValues =
    if (isPhone()) PaddingValues(horizontal = 16.dp, vertical = 16.dp) else PaddingValues(horizontal = 56.dp, vertical = 32.dp)

/** A fixed width on TV; the full available width on a phone. */
@Composable
@ReadOnlyComposable
fun Modifier.tvWidth(width: Dp): Modifier = if (isPhone()) fillMaxWidth() else width(width)

/**
 * Moves D-pad focus to [this] when a screen opens. Skipped on phones, where a focus highlight on a
 * button nobody touched looks like a stuck press.
 */
fun androidx.compose.ui.focus.FocusRequester.focusFirst(phone: Boolean) {
    if (!phone) runCatching { requestFocus() }
}

/** Like [screenPadding] but with no bottom padding, for screens whose list scrolls to the bottom edge. */
@Composable
@ReadOnlyComposable
fun listScreenPadding(): PaddingValues =
    if (isPhone()) PaddingValues(start = 16.dp, end = 16.dp, top = 16.dp) else PaddingValues(start = 56.dp, end = 56.dp, top = 32.dp)

/**
 * TV Material's buttons and cards only react to the remote's OK button, not to touch. This adds tap
 * handling and reports the press to [interactionSource], so the component's own pressed colour
 * shows. It adds no extra focus stop, so D-pad navigation is unchanged. It's on in both modes so a
 * phone switched to the TV layout can still be tapped back.
 */
@Composable
fun Modifier.tapToClick(enabled: Boolean, interactionSource: MutableInteractionSource, onClick: () -> Unit): Modifier {
    if (!enabled) return this
    val latest by rememberUpdatedState(onClick)
    return pointerInput(interactionSource) {
        detectTapGestures(
            onPress = { offset ->
                val press = PressInteraction.Press(offset)
                interactionSource.emit(press)
                interactionSource.emit(if (tryAwaitRelease()) PressInteraction.Release(press) else PressInteraction.Cancel(press))
            },
            onTap = { latest() },
        )
    }
}
