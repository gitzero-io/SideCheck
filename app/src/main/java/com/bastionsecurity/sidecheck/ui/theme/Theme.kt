package com.bastionsecurity.sidecheck.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.tv.material3.ExperimentalTvMaterial3Api
import androidx.tv.material3.MaterialTheme
import androidx.tv.material3.Typography
import androidx.tv.material3.darkColorScheme
import com.bastionsecurity.sidecheck.data.DeviceMode
import com.bastionsecurity.sidecheck.engine.model.Grade
import com.bastionsecurity.sidecheck.engine.model.Severity

/** Deep navy base with a calm green brand accent. Grades use a green→red scale. */
object SC {
    val Bg = Color(0xFF0B1220)
    val Surface = Color(0xFF131C2E)
    val SurfaceHigh = Color(0xFF1B2740)
    val Focus = Color(0xFF24345A)
    val Outline = Color(0xFF2C3B5C)
    val Text = Color(0xFFE6EDF7)
    val TextDim = Color(0xFF9AABC6)
    val TextFaint = Color(0xFF6D7F9E)
    val Brand = Color(0xFF3FB68B)
    val BrandDark = Color(0xFF0E3B2C)
    val Danger = Color(0xFFE5534B)

    fun grade(g: Grade): Color = when (g) {
        Grade.A -> Color(0xFF3FB68B)
        Grade.B -> Color(0xFF8CC152)
        Grade.C -> Color(0xFFF2B84B)
        Grade.D -> Color(0xFFF08A4B)
        Grade.F -> Color(0xFFE5534B)
    }

    fun severity(s: Severity): Color = when (s) {
        Severity.INFO -> Color(0xFF6D9EEB)
        Severity.LOW -> Color(0xFF8CC152)
        Severity.MEDIUM -> Color(0xFFF2B84B)
        Severity.HIGH -> Color(0xFFF08A4B)
        Severity.CRITICAL -> Color(0xFFE5534B)
    }

    fun severityLabel(s: Severity): String = when (s) {
        Severity.INFO -> "Good to know"
        Severity.LOW -> "Minor"
        Severity.MEDIUM -> "Worth a look"
        Severity.HIGH -> "Serious"
        Severity.CRITICAL -> "Very serious"
    }
}

// Sizes chosen for reading from ~3 m away on a 1080p TV (Compose TV renders at 960x540 dp).
private val tvTypography = Typography(
    displaySmall = TextStyle(fontSize = 34.sp, fontWeight = FontWeight.Bold, lineHeight = 40.sp),
    headlineMedium = TextStyle(fontSize = 26.sp, fontWeight = FontWeight.SemiBold, lineHeight = 32.sp),
    headlineSmall = TextStyle(fontSize = 22.sp, fontWeight = FontWeight.SemiBold, lineHeight = 28.sp),
    titleLarge = TextStyle(fontSize = 20.sp, fontWeight = FontWeight.SemiBold, lineHeight = 26.sp),
    titleMedium = TextStyle(fontSize = 17.sp, fontWeight = FontWeight.SemiBold, lineHeight = 22.sp),
    bodyLarge = TextStyle(fontSize = 17.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontSize = 15.sp, lineHeight = 21.sp),
    bodySmall = TextStyle(fontSize = 13.sp, lineHeight = 18.sp),
    labelLarge = TextStyle(fontSize = 15.sp, fontWeight = FontWeight.SemiBold),
    labelMedium = TextStyle(fontSize = 13.sp, fontWeight = FontWeight.SemiBold),
)

// Phones are held at arm's length: closer to standard Material sizes.
private val phoneTypography = Typography(
    displaySmall = TextStyle(fontSize = 26.sp, fontWeight = FontWeight.Bold, lineHeight = 32.sp),
    headlineMedium = TextStyle(fontSize = 21.sp, fontWeight = FontWeight.SemiBold, lineHeight = 27.sp),
    headlineSmall = TextStyle(fontSize = 18.sp, fontWeight = FontWeight.SemiBold, lineHeight = 24.sp),
    titleLarge = TextStyle(fontSize = 17.sp, fontWeight = FontWeight.SemiBold, lineHeight = 23.sp),
    titleMedium = TextStyle(fontSize = 15.sp, fontWeight = FontWeight.SemiBold, lineHeight = 20.sp),
    bodyLarge = TextStyle(fontSize = 15.sp, lineHeight = 22.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 17.sp),
    labelLarge = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.SemiBold),
    labelMedium = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.SemiBold),
)

@OptIn(ExperimentalTvMaterial3Api::class)
@Composable
fun SideCheckTheme(mode: DeviceMode = DeviceMode.TV, content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalDeviceMode provides mode) {
        MaterialTheme(
            colorScheme = darkColorScheme(
                primary = SC.Brand,
                onPrimary = Color(0xFF04150F),
                background = SC.Bg,
                onBackground = SC.Text,
                surface = SC.Surface,
                onSurface = SC.Text,
                surfaceVariant = SC.SurfaceHigh,
                onSurfaceVariant = SC.TextDim,
                border = SC.Outline,
                error = SC.Danger,
            ),
            typography = if (mode == DeviceMode.MOBILE) phoneTypography else tvTypography,
            content = content,
        )
    }
}
