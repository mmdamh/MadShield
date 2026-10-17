package com.aethershield.app.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import androidx.core.graphics.ColorUtils

enum class DarkMode { SYSTEM, LIGHT, DARK }

/** Appearance only; never touches the tunnel. */
data class UiPrefs(
    val themeId: String = Palettes.DEFAULT_ID,
    val darkMode: DarkMode = DarkMode.SYSTEM,
    val amoled: Boolean = false
)

/**
 * A colour theme is three seed colours, like the connect / download / upload
 * accents of the ZedSecure themes this look is modelled on. Everything else
 * (surfaces, containers, text) is derived from them in [PaletteScheme], so each
 * theme stays coherent in both light and dark.
 */
data class Palette(
    val id: String,
    val name: String,
    val primary: Color,
    val secondary: Color,
    val tertiary: Color
)

object Palettes {
    const val DEFAULT_ID = "aurora"

    val ALL: List<Palette> = listOf(
        Palette("aurora", "Aurora", Color(0xFF12A594), Color(0xFF4FE3D8), Color(0xFFB49BFF)),
        Palette("ember", "Ember", Color(0xFFE07A1F), Color(0xFFFFB870), Color(0xFFFF8A65)),
        Palette("midnight", "Midnight", Color(0xFF2563EB), Color(0xFF7FB2FF), Color(0xFF9BC4FF)),
        Palette("sakura", "Sakura", Color(0xFFD9407A), Color(0xFFFFA8C5), Color(0xFFFFC2D6)),
        Palette("citrus", "Citrus", Color(0xFF9BC91F), Color(0xFFC7F24E), Color(0xFF8FD14F)),
        Palette("moss", "Moss", Color(0xFF10B981), Color(0xFF6EE7A8), Color(0xFF34D399)),
        Palette("tokyo", "Tokyo", Color(0xFF7AA2F7), Color(0xFFBB9AF7), Color(0xFF9AA5CE)),
        Palette("solar", "Solar", Color(0xFFFFC107), Color(0xFFFFD54F), Color(0xFFFFB300)),
        Palette("mono", "Mono", Color(0xFF8E8E96), Color(0xFFE4E4E7), Color(0xFFB4B4BB)),
    )

    fun byId(id: String?): Palette = ALL.firstOrNull { it.id == id } ?: ALL.first()
}

object PaletteScheme {

    private val INK_DARK = Color(0xFF10131A)

    private fun hsl(c: Color): FloatArray =
        FloatArray(3).also { ColorUtils.colorToHSL(c.toArgb(), it) }

    private fun hslColor(h: Float, s: Float, l: Float): Color =
        Color(ColorUtils.HSLToColor(floatArrayOf(h.mod(360f), s.coerceIn(0f, 1f), l.coerceIn(0f, 1f))))

    private fun on(c: Color): Color = if (c.luminance() > 0.5f) INK_DARK else Color.White

    fun build(p: Palette, dark: Boolean, amoled: Boolean): ColorScheme {
        val (h, s, _) = hsl(p.primary).let { Triple(it[0], it[1], it[2]) }
        val sh = hsl(p.secondary)[0]
        val th = hsl(p.tertiary)[0]
        // Neutrals carry a whisper of the theme hue, which is what makes the surfaces feel designed.
        fun neutral(l: Float, sat: Float = 0.10f) = hslColor(h, sat, l)

        return if (dark) {
            val primary = hslColor(h, s.coerceAtLeast(0.45f), 0.66f)
            val secondary = hslColor(sh, hsl(p.secondary)[1].coerceAtLeast(0.4f), 0.72f)
            val tertiary = hslColor(th, hsl(p.tertiary)[1].coerceAtLeast(0.4f), 0.76f)
            val base = if (amoled) Color.Black else neutral(0.075f)
            darkColorScheme(
                primary = primary,
                onPrimary = on(primary),
                primaryContainer = hslColor(h, s * 0.65f, 0.24f),
                onPrimaryContainer = hslColor(h, s.coerceAtLeast(0.4f), 0.90f),
                secondary = secondary,
                onSecondary = on(secondary),
                secondaryContainer = hslColor(sh, 0.35f, 0.22f),
                onSecondaryContainer = hslColor(sh, 0.6f, 0.90f),
                tertiary = tertiary,
                onTertiary = on(tertiary),
                tertiaryContainer = hslColor(th, 0.35f, 0.24f),
                onTertiaryContainer = hslColor(th, 0.6f, 0.90f),
                background = base,
                onBackground = neutral(0.92f),
                surface = base,
                onSurface = neutral(0.92f),
                surfaceVariant = neutral(0.20f, 0.08f),
                onSurfaceVariant = neutral(0.74f, 0.08f),
                surfaceTint = primary,
                surfaceDim = if (amoled) Color.Black else neutral(0.06f),
                surfaceBright = neutral(0.22f),
                surfaceContainerLowest = if (amoled) Color.Black else neutral(0.05f),
                surfaceContainerLow = if (amoled) neutral(0.06f) else neutral(0.095f),
                surfaceContainer = if (amoled) neutral(0.085f) else neutral(0.115f),
                surfaceContainerHigh = if (amoled) neutral(0.11f) else neutral(0.145f),
                surfaceContainerHighest = if (amoled) neutral(0.14f) else neutral(0.175f),
                outline = neutral(0.48f, 0.06f),
                outlineVariant = neutral(0.28f, 0.06f),
                error = Color(0xFFFFB4AB),
                onError = Color(0xFF690005),
                errorContainer = Color(0xFF93000A),
                onErrorContainer = Color(0xFFFFDAD6),
            )
        } else {
            val primary = hslColor(h, s.coerceAtLeast(0.5f), 0.38f)
            val secondary = hslColor(sh, hsl(p.secondary)[1].coerceAtLeast(0.45f), 0.36f)
            val tertiary = hslColor(th, hsl(p.tertiary)[1].coerceAtLeast(0.45f), 0.40f)
            val base = hslColor(h, 0.25f, 0.975f)
            lightColorScheme(
                primary = primary,
                onPrimary = on(primary),
                primaryContainer = hslColor(h, s.coerceAtLeast(0.5f) * 0.9f, 0.88f),
                onPrimaryContainer = hslColor(h, s.coerceAtLeast(0.5f), 0.14f),
                secondary = secondary,
                onSecondary = on(secondary),
                secondaryContainer = hslColor(sh, 0.55f, 0.89f),
                onSecondaryContainer = hslColor(sh, 0.6f, 0.14f),
                tertiary = tertiary,
                onTertiary = on(tertiary),
                tertiaryContainer = hslColor(th, 0.55f, 0.90f),
                onTertiaryContainer = hslColor(th, 0.6f, 0.15f),
                background = base,
                onBackground = neutral(0.10f),
                surface = base,
                onSurface = neutral(0.10f),
                surfaceVariant = hslColor(h, 0.18f, 0.90f),
                onSurfaceVariant = neutral(0.30f, 0.10f),
                surfaceTint = primary,
                surfaceDim = hslColor(h, 0.14f, 0.88f),
                surfaceBright = base,
                surfaceContainerLowest = Color.White,
                surfaceContainerLow = hslColor(h, 0.22f, 0.955f),
                surfaceContainer = hslColor(h, 0.20f, 0.935f),
                surfaceContainerHigh = hslColor(h, 0.18f, 0.915f),
                surfaceContainerHighest = hslColor(h, 0.16f, 0.895f),
                outline = neutral(0.50f, 0.08f),
                outlineVariant = hslColor(h, 0.12f, 0.78f),
                error = Color(0xFFBA1A1A),
                onError = Color.White,
                errorContainer = Color(0xFFFFDAD6),
                onErrorContainer = Color(0xFF410002),
            )
        }
    }
}
