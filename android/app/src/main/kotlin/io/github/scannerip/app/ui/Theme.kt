package io.github.scannerip.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import io.github.scannerip.core.Level
import io.github.scannerip.core.Severity

// A green "security" palette. Every slot Material uses is set, so none of the
// default purple leaks through (sliders, nav bar and so on).
private val Light = lightColorScheme(
    primary = Color(0xFF0B6B4F),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB8F0D6),
    onPrimaryContainer = Color(0xFF002116),
    secondary = Color(0xFF4C6358),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCEE9DA),
    onSecondaryContainer = Color(0xFF092016),
    tertiary = Color(0xFF3D6373),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFC1E8FB),
    onTertiaryContainer = Color(0xFF001F29),
    background = Color(0xFFF5F7F6),
    onBackground = Color(0xFF171D1A),
    surface = Color(0xFFF5F7F6),
    onSurface = Color(0xFF171D1A),
    surfaceVariant = Color(0xFFDCE5DF),
    onSurfaceVariant = Color(0xFF404944),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFEFF3F0),
    surfaceContainer = Color(0xFFE9EEEB),
    surfaceContainerHigh = Color(0xFFE3E9E5),
    surfaceContainerHighest = Color(0xFFDDE4E0),
    outline = Color(0xFF707973),
    outlineVariant = Color(0xFFBFC9C2),
    error = Color(0xFFB3261E),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF6FDDB0),
    onPrimary = Color(0xFF003828),
    primaryContainer = Color(0xFF00513A),
    onPrimaryContainer = Color(0xFFB8F0D6),
    secondary = Color(0xFFB3CCBF),
    onSecondary = Color(0xFF1F352A),
    secondaryContainer = Color(0xFF354B40),
    onSecondaryContainer = Color(0xFFCEE9DA),
    tertiary = Color(0xFFA5CCDF),
    onTertiary = Color(0xFF073543),
    tertiaryContainer = Color(0xFF244C5B),
    onTertiaryContainer = Color(0xFFC1E8FB),
    background = Color(0xFF0F1412),
    onBackground = Color(0xFFDEE4E0),
    surface = Color(0xFF0F1412),
    onSurface = Color(0xFFDEE4E0),
    surfaceVariant = Color(0xFF3F4944),
    onSurfaceVariant = Color(0xFFBFC9C2),
    surfaceContainerLowest = Color(0xFF0A0F0D),
    surfaceContainerLow = Color(0xFF171D1A),
    surfaceContainer = Color(0xFF1B211E),
    surfaceContainerHigh = Color(0xFF252B28),
    surfaceContainerHighest = Color(0xFF303633),
    outline = Color(0xFF89938D),
    outlineVariant = Color(0xFF3F4944),
    error = Color(0xFFF2B8B5),
)

@Composable
fun ScannerIpTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (dark) Dark else Light, content = content)
}

/** Same traffic-light colours as the desktop app. (background, text) */
fun levelColours(level: Level): Pair<Color, Color> = when (level) {
    Level.CLEAN -> Color(0xFF2E7D32) to Color.White
    Level.LOW -> Color(0xFF00838F) to Color.White
    Level.MEDIUM -> Color(0xFFF9A825) to Color.Black
    Level.HIGH -> Color(0xFFE65100) to Color.White
    Level.DANGEROUS -> Color(0xFFB71C1C) to Color.White
}

fun levelColours(name: String): Pair<Color, Color> =
    levelColours(Level.entries.find { it.name == name } ?: Level.CLEAN)

fun severityColour(severity: Severity, dark: Boolean): Color = when (severity) {
    Severity.INFO -> if (dark) Color(0xFFB0B8B4) else Color(0xFF555555)
    Severity.LOW -> if (dark) Color(0xFF4DD0E1) else Color(0xFF00838F)
    Severity.MEDIUM -> if (dark) Color(0xFFFFCA28) else Color(0xFF9A6200)
    Severity.HIGH -> if (dark) Color(0xFFFF8A50) else Color(0xFFE65100)
    Severity.CRITICAL -> if (dark) Color(0xFFFF6E6E) else Color(0xFFB71C1C)
}

val ShieldGreen = Color(0xFF2E7D32)
val ShieldAmber = Color(0xFFF9A825)
val ShieldRed = Color(0xFFB71C1C)
val ShieldGrey = Color(0xFF78858A)
