package com.bastionsecurity.sidecheck.ui.components

import android.content.Context
import android.util.LruCache
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.tv.material3.Border
import androidx.tv.material3.Button
import androidx.tv.material3.ButtonDefaults
import androidx.tv.material3.ClickableSurfaceDefaults
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.OutlinedButton
import androidx.tv.material3.OutlinedButtonDefaults
import androidx.tv.material3.Surface
import androidx.tv.material3.SurfaceDefaults
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.ui.theme.SC
import com.bastionsecurity.sidecheck.ui.theme.isPhone
import com.bastionsecurity.sidecheck.ui.theme.tapToClick
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

val CardShape = RoundedCornerShape(14.dp)

/** A focusable card. Focus = lighter fill + brand outline + slight zoom, readable across a room. */
@Composable
fun FocusCard(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    container: Color = SC.Surface,
    contentPadding: PaddingValues = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    Surface(
        onClick = onClick,
        modifier = modifier.tapToClick(true, interaction, onClick),
        interactionSource = interaction,
        shape = ClickableSurfaceDefaults.shape(CardShape),
        colors = ClickableSurfaceDefaults.colors(
            containerColor = container,
            contentColor = SC.Text,
            focusedContainerColor = SC.Focus,
            focusedContentColor = SC.Text,
            pressedContainerColor = SC.Focus,
        ),
        border = ClickableSurfaceDefaults.border(
            focusedBorder = Border(BorderStroke(3.dp, SC.Brand), shape = CardShape),
        ),
        // Zooming is a TV focus cue; on touch screens it just makes cards jump.
        scale = ClickableSurfaceDefaults.scale(focusedScale = if (isPhone()) 1f else 1.02f),
    ) {
        Column(Modifier.padding(contentPadding), content = content)
    }
}

/** A plain, non-focusable panel. */
@Composable
fun Panel(modifier: Modifier = Modifier, container: Color = SC.Surface, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier = modifier,
        shape = CardShape,
        colors = SurfaceDefaults.colors(containerColor = container, contentColor = SC.Text),
    ) {
        Column(
            Modifier.padding(if (isPhone()) PaddingValues(16.dp) else PaddingValues(horizontal = 24.dp, vertical = 20.dp)),
            content = content,
        )
    }
}

@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val interaction = remember { MutableInteractionSource() }
    Button(
        onClick = onClick,
        modifier = modifier.tapToClick(enabled, interaction, onClick),
        interactionSource = interaction,
        enabled = enabled,
        colors = ButtonDefaults.colors(
            containerColor = SC.Brand,
            contentColor = Color(0xFF04150F),
            focusedContainerColor = Color(0xFF6FE0B4),
            focusedContentColor = Color(0xFF04150F),
        ),
        contentPadding = if (isPhone()) PaddingValues(horizontal = 20.dp, vertical = 10.dp) else PaddingValues(horizontal = 26.dp, vertical = 12.dp),
    ) { Text(text, style = MaterialTheme.typography.titleMedium) }
}

@Composable
fun SecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    danger: Boolean = false,
    enabled: Boolean = true,
) {
    val accent = if (danger) SC.Danger else SC.Text
    val interaction = remember { MutableInteractionSource() }
    OutlinedButton(
        onClick = onClick,
        modifier = modifier.tapToClick(enabled, interaction, onClick),
        interactionSource = interaction,
        enabled = enabled,
        colors = OutlinedButtonDefaults.colors(
            containerColor = Color.Transparent,
            contentColor = accent,
            focusedContainerColor = if (danger) SC.Danger else SC.Text,
            focusedContentColor = SC.Bg,
        ),
        border = OutlinedButtonDefaults.border(
            border = Border(BorderStroke(2.dp, if (danger) SC.Danger.copy(alpha = 0.7f) else SC.Outline)),
        ),
        contentPadding = if (isPhone()) PaddingValues(horizontal = 16.dp, vertical = 8.dp) else PaddingValues(horizontal = 22.dp, vertical = 10.dp),
    ) { Text(text, style = MaterialTheme.typography.labelLarge) }
}

@Composable
fun GradeBadge(grade: Grade, size: Dp = 48.dp, modifier: Modifier = Modifier) {
    Box(
        modifier
            .size(size)
            .clip(RoundedCornerShape(size / 4))
            .background(SC.grade(grade)),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            grade.label,
            color = Color(0xFF0B1220),
            fontSize = (size.value * 0.55f).sp,
            fontWeight = FontWeight.Black,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
fun Pill(text: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.18f))
            .padding(horizontal = 10.dp, vertical = 3.dp),
    ) { Text(text, color = color, style = MaterialTheme.typography.labelMedium) }
}

/** A row of buttons. On a phone they wrap onto the next line instead of running off the screen. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ButtonRow(modifier: Modifier = Modifier, content: @Composable RowScope.() -> Unit) {
    if (isPhone()) {
        FlowRow(
            modifier,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            itemVerticalAlignment = Alignment.CenterVertically,
            content = content,
        )
    } else {
        Row(modifier, horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically, content = content)
    }
}

private object IconCache {
    val cache = LruCache<String, ImageBitmap>(80)
}

/** An installed app's icon, loaded off the main thread and cached. */
@Composable
fun AppIcon(packageName: String, size: Dp = 48.dp, archivePath: String? = null) {
    val context = LocalContext.current
    var bmp by remember(packageName) { mutableStateOf(IconCache.cache.get(packageName)) }
    LaunchedEffect(packageName, archivePath) {
        if (bmp == null) {
            bmp = withContext(Dispatchers.IO) { loadIcon(context, packageName, archivePath) }
                ?.also { IconCache.cache.put(packageName, it) }
        }
    }
    val b = bmp
    if (b != null) {
        Image(b, contentDescription = null, modifier = Modifier.size(size).clip(RoundedCornerShape(size / 5)))
    } else {
        Box(Modifier.size(size).clip(RoundedCornerShape(size / 5)).background(SC.SurfaceHigh))
    }
}

private fun loadIcon(context: Context, pkg: String, archivePath: String?): ImageBitmap? = runCatching {
    val pm = context.packageManager
    val d = if (archivePath != null) {
        @Suppress("DEPRECATION")
        val ai = pm.getPackageArchiveInfo(archivePath, 0)?.applicationInfo ?: return null
        ai.sourceDir = archivePath
        ai.publicSourceDir = archivePath
        ai.loadIcon(pm)
    } else {
        pm.getApplicationIcon(pkg)
    }
    d.toBitmap(128, 128).asImageBitmap()
}.getOrNull()
