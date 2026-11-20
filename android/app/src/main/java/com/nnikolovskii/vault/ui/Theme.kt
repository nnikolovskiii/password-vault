package com.nnikolovskii.vault.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val Ink = Color(0xFF0E1118)
val SurfaceInk = Color(0xFF161B26)
val SurfaceRaised = Color(0xFF1E2533)
val Paper = Color(0xFFF2F4F8)
val Muted = Color(0xFF8B93A7)
val Brass = Color(0xFFE2B866)
val OnBrass = Color(0xFF1A1206)
val SoftSky = Color(0xFF5B8DEF)
val Hot = Color(0xFFFF5C5C)
val Line = Color(0xFF2A3344)
val Sage = Color(0xFF7DCFB6)

private val Scheme = darkColorScheme(
    primary = Brass,
    onPrimary = OnBrass,
    secondary = SoftSky,
    background = Ink,
    surface = Ink,
    surfaceContainer = SurfaceInk,
    surfaceContainerHigh = SurfaceRaised,
    surfaceContainerHighest = SurfaceRaised,
    onBackground = Paper,
    onSurface = Paper,
    onSurfaceVariant = Muted,
    error = Hot,
    outline = Line,
)

@Composable
fun VaultTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Scheme, content = content)
}
