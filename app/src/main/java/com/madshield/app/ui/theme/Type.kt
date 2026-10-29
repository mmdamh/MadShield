package com.madshield.app.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp
import com.madshield.app.R

/**
 * Inter for Latin text and Estedad for Persian/Arabic script, both bundled
 * (SIL OFL, see THIRD_PARTY_FONTS.md). The two are combined per language: Persian
 * gets Estedad with the taller line heights its script needs; every other
 * language gets Inter.
 */
val InterFamily = FontFamily(
    Font(R.font.inter_regular, FontWeight.Normal),
    Font(R.font.inter_medium, FontWeight.Medium),
    Font(R.font.inter_semibold, FontWeight.SemiBold),
    Font(R.font.inter_bold, FontWeight.Bold),
)

val EstedadFamily = FontFamily(
    Font(R.font.estedad_regular, FontWeight.Normal),
    Font(R.font.estedad_medium, FontWeight.Medium),
    Font(R.font.estedad_semibold, FontWeight.SemiBold),
    Font(R.font.estedad_bold, FontWeight.Bold),
)

private val centered = LineHeightStyle(
    alignment = LineHeightStyle.Alignment.Center,
    trim = LineHeightStyle.Trim.None,
)

private fun s(f: FontFamily, w: FontWeight, size: TextUnit, line: TextUnit, track: TextUnit = 0.sp) =
    TextStyle(
        fontFamily = f, fontWeight = w, fontSize = size, lineHeight = line,
        letterSpacing = track, lineHeightStyle = centered
    )

private fun latin(): Typography = Typography(
    displayLarge = s(InterFamily, FontWeight.Bold, 57.sp, 64.sp, (-0.5).sp),
    displayMedium = s(InterFamily, FontWeight.Bold, 45.sp, 52.sp, (-0.25).sp),
    displaySmall = s(InterFamily, FontWeight.SemiBold, 36.sp, 44.sp),
    headlineLarge = s(InterFamily, FontWeight.SemiBold, 32.sp, 40.sp),
    headlineMedium = s(InterFamily, FontWeight.SemiBold, 28.sp, 36.sp),
    headlineSmall = s(InterFamily, FontWeight.SemiBold, 24.sp, 32.sp),
    titleLarge = s(InterFamily, FontWeight.SemiBold, 22.sp, 28.sp),
    titleMedium = s(InterFamily, FontWeight.SemiBold, 16.sp, 24.sp, 0.1.sp),
    titleSmall = s(InterFamily, FontWeight.Medium, 14.sp, 20.sp, 0.1.sp),
    bodyLarge = s(InterFamily, FontWeight.Normal, 16.sp, 24.sp, 0.3.sp),
    bodyMedium = s(InterFamily, FontWeight.Normal, 14.sp, 20.sp, 0.2.sp),
    bodySmall = s(InterFamily, FontWeight.Normal, 12.sp, 16.sp, 0.3.sp),
    labelLarge = s(InterFamily, FontWeight.SemiBold, 14.sp, 20.sp, 0.1.sp),
    labelMedium = s(InterFamily, FontWeight.Medium, 12.sp, 16.sp, 0.4.sp),
    labelSmall = s(InterFamily, FontWeight.Medium, 11.sp, 16.sp, 0.4.sp),
)

private fun persian(): Typography = Typography(
    displayLarge = s(EstedadFamily, FontWeight.Bold, 54.sp, 68.sp),
    displayMedium = s(EstedadFamily, FontWeight.Bold, 43.sp, 56.sp),
    displaySmall = s(EstedadFamily, FontWeight.SemiBold, 35.sp, 46.sp),
    headlineLarge = s(EstedadFamily, FontWeight.SemiBold, 31.sp, 42.sp),
    headlineMedium = s(EstedadFamily, FontWeight.SemiBold, 27.sp, 38.sp),
    headlineSmall = s(EstedadFamily, FontWeight.SemiBold, 23.sp, 34.sp),
    titleLarge = s(EstedadFamily, FontWeight.SemiBold, 21.sp, 30.sp),
    titleMedium = s(EstedadFamily, FontWeight.SemiBold, 16.sp, 26.sp),
    titleSmall = s(EstedadFamily, FontWeight.Medium, 14.sp, 22.sp),
    bodyLarge = s(EstedadFamily, FontWeight.Normal, 16.sp, 28.sp),
    bodyMedium = s(EstedadFamily, FontWeight.Normal, 14.sp, 24.sp),
    bodySmall = s(EstedadFamily, FontWeight.Normal, 12.sp, 20.sp),
    labelLarge = s(EstedadFamily, FontWeight.SemiBold, 14.sp, 22.sp),
    labelMedium = s(EstedadFamily, FontWeight.Medium, 12.sp, 18.sp),
    labelSmall = s(EstedadFamily, FontWeight.Medium, 11.sp, 18.sp),
)

fun typographyFor(languageTag: String): Typography =
    if (languageTag.startsWith("fa") || languageTag.startsWith("ar")) persian() else latin()
