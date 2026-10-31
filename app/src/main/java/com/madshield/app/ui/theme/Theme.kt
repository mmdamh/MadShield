package com.madshield.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp

/** Generous corner radii: the soft, rounded look is most of what makes the ZedSecure UI recognisable. */
val AetherShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(26.dp),
    extraLarge = RoundedCornerShape(36.dp),
)

@Composable
fun MadShieldTheme(prefs: UiPrefs = UiPrefs(), content: @Composable () -> Unit) {
    val dark = when (prefs.darkMode) {
        DarkMode.SYSTEM -> isSystemInDarkTheme()
        DarkMode.LIGHT -> false
        DarkMode.DARK -> true
    }
    val scheme = remember(prefs.themeId, prefs.customColor, dark, prefs.amoled) {
        val palette =
            if (prefs.themeId == Palettes.CUSTOM_ID && prefs.customColor != 0) Palettes.custom(prefs.customColor)
            else Palettes.byId(prefs.themeId)
        PaletteScheme.build(palette, dark, prefs.amoled && dark)
    }
    val tag = LocalConfiguration.current.locales.get(0)?.toLanguageTag() ?: "en"
    MaterialTheme(
        colorScheme = scheme,
        shapes = AetherShapes,
        typography = remember(tag) { typographyFor(tag) },
        content = content
    )
}
