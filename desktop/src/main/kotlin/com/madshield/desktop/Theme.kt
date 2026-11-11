package com.madshield.desktop

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.platform.Font
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/*
 * Look of the desktop app: "spec sheet". The tunnel is shown the way a data sheet shows an instrument: hairline rules,
 * small monospaced figures, one signal colour. Colour is spent on STATE only (connected, working, failed); everything
 * else is ink on a grey ground. Corners are small, nothing casts a shadow, and the numbers are real (a live readout, not
 * a picture of one).
 */

@Immutable
class Spec(
    val dark: Boolean,
    val ground: Color, val surface: Color, val ink: Color, val muted: Color, val hair: Color,
    val accent: Color, val accentInk: Color, val onAccent: Color, val tint: Color,
    val warn: Color, val amber: Color
)

val LightSpec = Spec(
    false, ground = Color(0xFFEDEFEC), surface = Color(0xFFF8F9F7), ink = Color(0xFF121512), muted = Color(0xFF586058),
    hair = Color(0xFFC8CDC8), accent = Color(0xFF00C25E), accentInk = Color(0xFF006B35), onAccent = Color(0xFF04130A),
    tint = Color(0xFFDDF3E5), warn = Color(0xFFB93A0B), amber = Color(0xFF9A5B00)
)
val DarkSpec = Spec(
    true, ground = Color(0xFF0E110E), surface = Color(0xFF151915), ink = Color(0xFFE9EDE9), muted = Color(0xFF9AA39B),
    hair = Color(0xFF2A302A), accent = Color(0xFF2EE58A), accentInk = Color(0xFF4CE89A), onAccent = Color(0xFF04130A),
    tint = Color(0xFF16301F), warn = Color(0xFFFF7A4D), amber = Color(0xFFE8A33A)
)
val LocalSpec = staticCompositionLocalOf { LightSpec }

/** Two faces: Vazirmatn for reading (Persian and Latin), JetBrains Mono for figures. Both are SIL OFL, licences in resources/fonts. */
object Fonts {
    val ui = FontFamily(
        Font(resource = "fonts/Vazirmatn-Regular.ttf", weight = FontWeight.Normal),
        Font(resource = "fonts/Vazirmatn-Medium.ttf", weight = FontWeight.Medium),
        Font(resource = "fonts/Vazirmatn-SemiBold.ttf", weight = FontWeight.SemiBold),
        Font(resource = "fonts/Vazirmatn-Bold.ttf", weight = FontWeight.Bold)
    )
    val mono = FontFamily(
        Font(resource = "fonts/JetBrainsMono-Regular.ttf", weight = FontWeight.Normal),
        Font(resource = "fonts/JetBrainsMono-Medium.ttf", weight = FontWeight.Medium),
        Font(resource = "fonts/JetBrainsMono-Bold.ttf", weight = FontWeight.Bold)
    )
}

private fun typography(fa: Boolean): Typography {
    // Persian needs more line height than Latin, and is never letter-spaced.
    val lh = if (fa) 1.75f else 1.45f
    fun s(size: Int, w: FontWeight = FontWeight.Normal) =
        TextStyle(fontFamily = Fonts.ui, fontSize = size.sp, fontWeight = w, lineHeight = (size * lh).sp)
    return Typography(
        displayLarge = s(56, FontWeight.SemiBold), displayMedium = s(44, FontWeight.SemiBold), displaySmall = s(34, FontWeight.SemiBold),
        headlineLarge = s(30, FontWeight.SemiBold), headlineMedium = s(26, FontWeight.SemiBold), headlineSmall = s(22, FontWeight.SemiBold),
        titleLarge = s(20, FontWeight.SemiBold), titleMedium = s(16, FontWeight.SemiBold), titleSmall = s(14, FontWeight.SemiBold),
        bodyLarge = s(15), bodyMedium = s(14), bodySmall = s(12),
        labelLarge = s(14, FontWeight.Medium), labelMedium = s(12, FontWeight.Medium), labelSmall = s(11, FontWeight.Medium)
    )
}

@Composable
fun SpecTheme(dark: Boolean, fa: Boolean, content: @Composable () -> Unit) {
    val sp = if (dark) DarkSpec else LightSpec
    val scheme = if (dark) {
        darkColorScheme(
            primary = sp.accent, onPrimary = sp.onAccent, secondary = sp.accentInk, onSecondary = sp.onAccent,
            secondaryContainer = sp.tint, onSecondaryContainer = sp.ink, background = sp.ground, onBackground = sp.ink,
            surface = sp.surface, onSurface = sp.ink, surfaceVariant = sp.surface, onSurfaceVariant = sp.muted,
            outline = sp.hair, outlineVariant = sp.hair, error = sp.warn, onError = Color.Black
        )
    } else {
        lightColorScheme(
            primary = sp.accent, onPrimary = sp.onAccent, secondary = sp.accentInk, onSecondary = Color.White,
            secondaryContainer = sp.tint, onSecondaryContainer = sp.ink, background = sp.ground, onBackground = sp.ink,
            surface = sp.surface, onSurface = sp.ink, surfaceVariant = sp.surface, onSurfaceVariant = sp.muted,
            outline = sp.hair, outlineVariant = sp.hair, error = sp.warn, onError = Color.White
        )
    }
    val small = RoundedCornerShape(4.dp)
    CompositionLocalProvider(LocalSpec provides sp) {
        MaterialTheme(
            colorScheme = scheme, typography = typography(fa),
            shapes = Shapes(extraSmall = RoundedCornerShape(2.dp), small = small, medium = small, large = RoundedCornerShape(6.dp), extraLarge = RoundedCornerShape(6.dp)),
            content = content
        )
    }
}

val PanelShape = RoundedCornerShape(4.dp)

// ------------------------------------------------------------------------------------------------------ primitives

/** One surface, one hairline, small corners. */
@Composable
fun Panel(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val sp = LocalSpec.current
    Box(modifier.background(sp.surface, PanelShape).border(1.dp, sp.hair, PanelShape)) { content() }
}

@Composable
fun Hairline(modifier: Modifier = Modifier) {
    Box(modifier.fillMaxWidth().height(1.dp).background(LocalSpec.current.hair))
}

/** Small label above a block. Upper case only in English (Persian has no case, and must not be letter-spaced). */
@Composable
fun Eyebrow(text: String, modifier: Modifier = Modifier) {
    val en = LocalLang.current != "fa"
    Text(
        if (en) text.uppercase() else text,
        modifier = modifier,
        style = MaterialTheme.typography.labelSmall.copy(letterSpacing = if (en) 1.2.sp else 0.sp),
        color = LocalSpec.current.muted
    )
}

@Composable
fun PageHeader(title: String, hint: String? = null) {
    Column(Modifier.padding(bottom = 20.dp)) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        if (hint != null) Text(hint, style = MaterialTheme.typography.bodyMedium, color = LocalSpec.current.muted, modifier = Modifier.padding(top = 4.dp))
    }
}

/** A line of the data sheet: label on the start side, figure on the end side, hairline below. */
@Composable
fun SpecRow(label: String, value: String, mono: Boolean = true, valueColor: Color = Color.Unspecified, last: Boolean = false) {
    val sp = LocalSpec.current
    Column {
        Row(Modifier.fillMaxWidth().padding(vertical = 11.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(label, color = sp.muted, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            Text(
                value, color = if (valueColor == Color.Unspecified) sp.ink else valueColor,
                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = if (mono) Fonts.mono else Fonts.ui, fontWeight = FontWeight.Medium),
                maxLines = 1
            )
        }
        if (!last) Hairline()
    }
}

/** Label on the start side, a control on the end side. */
@Composable
fun FormRow(label: String, last: Boolean = false, control: @Composable RowScope.() -> Unit) {
    Column {
        Row(Modifier.fillMaxWidth().padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            control()
        }
        if (!last) Hairline()
    }
}

/** Flat button that answers the pointer: it steps on hover, presses on click, and shows a ring on keyboard focus. */
@Composable
fun ActionButton(
    text: String, onClick: () -> Unit, modifier: Modifier = Modifier,
    primary: Boolean = true, enabled: Boolean = true, height: Dp = 44.dp
) {
    val sp = LocalSpec.current
    val src = remember { MutableInteractionSource() }
    val hovered by src.collectIsHoveredAsState()
    val pressed by src.collectIsPressedAsState()
    val focused by src.collectIsFocusedAsState()
    val base = if (primary) sp.accent else sp.surface
    val toward = if (sp.dark) Color.White else Color.Black
    val bg = when {
        !enabled -> sp.hair
        pressed -> lerp(base, toward, 0.16f)
        hovered -> lerp(base, toward, 0.07f)
        else -> base
    }
    val shape = PanelShape
    Box(
        modifier.height(height)
            .background(bg, shape)
            .border(if (focused) 2.dp else 1.dp, if (focused) sp.ink else if (primary) Color.Transparent else sp.hair, shape)
            .hoverable(src)
            .clickable(interactionSource = src, indication = null, enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text, maxLines = 1,
            color = if (!enabled) sp.muted else if (primary) sp.onAccent else sp.ink,
            style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold)
        )
    }
}

/** A choice from a list, as a button that opens a menu. */
@Composable
fun <T> Dropdown(current: T, options: List<T>, text: @Composable (T) -> String, onPick: (T) -> Unit) {
    var open by remember { androidx.compose.runtime.mutableStateOf(false) }
    Box {
        ActionButton(text(current) + "  ▾", { open = true }, Modifier.widthIn(min = 190.dp), primary = false, height = 36.dp)
        androidx.compose.material3.DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for (o in options) androidx.compose.material3.DropdownMenuItem(text = { Text(text(o)) }, onClick = { open = false; onPick(o) })
        }
    }
}

/** A round indicator for the state; it pulses only while something is in progress. */
@Composable
fun StatusLed(color: Color, pulse: Boolean, size: Dp = 12.dp) {
    val a = if (pulse) {
        val t = rememberInfiniteTransition(label = "led")
        t.animateFloat(0.3f, 1f, infiniteRepeatable(tween(750), RepeatMode.Reverse), label = "led-alpha").value
    } else 1f
    Box(Modifier.size(size).alpha(a).background(color, CircleShape))
}

/** The last [window] samples as a line, newest at the end. Real values, no smoothing, no fake wave when idle. */
@Composable
fun Sparkline(values: List<Long>, modifier: Modifier, color: Color, base: Color, window: Int = 60) {
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        drawLine(base, Offset(0f, h - 1f), Offset(w, h - 1f), strokeWidth = 1f)
        if (values.size < 2) return@Canvas
        val max = (values.maxOrNull() ?: 1L).coerceAtLeast(64L * 1024L).toFloat()
        val step = w / (window - 1)
        val path = Path()
        values.forEachIndexed { i, v ->
            val x = w - (values.size - 1 - i) * step
            val y = h - 4f - (v / max) * (h - 10f)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path, color, style = Stroke(width = 2.2f, join = StrokeJoin.Round))
    }
}

/** The mark: a hexagonal shield outline with a solid core. Drawn here, no picture file. */
@Composable
fun BrandMark(size: Dp = 26.dp) {
    val sp = LocalSpec.current
    Canvas(Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        fun p(x: Float, y: Float) = Offset(x * w, y * h)
        val outline = Path().apply {
            moveTo(p(0.5f, 0.03f).x, p(0.5f, 0.03f).y)
            lineTo(p(0.93f, 0.2f).x, p(0.93f, 0.2f).y)
            lineTo(p(0.93f, 0.56f).x, p(0.93f, 0.56f).y)
            lineTo(p(0.5f, 0.97f).x, p(0.5f, 0.97f).y)
            lineTo(p(0.07f, 0.56f).x, p(0.07f, 0.56f).y)
            lineTo(p(0.07f, 0.2f).x, p(0.07f, 0.2f).y)
            close()
        }
        drawPath(outline, sp.ink, style = Stroke(width = 2.4f, join = StrokeJoin.Miter))
        val core = Path().apply {
            moveTo(p(0.5f, 0.3f).x, p(0.5f, 0.3f).y)
            lineTo(p(0.7f, 0.4f).x, p(0.7f, 0.4f).y)
            lineTo(p(0.7f, 0.58f).x, p(0.7f, 0.58f).y)
            lineTo(p(0.5f, 0.78f).x, p(0.5f, 0.78f).y)
            lineTo(p(0.3f, 0.58f).x, p(0.3f, 0.58f).y)
            lineTo(p(0.3f, 0.4f).x, p(0.3f, 0.4f).y)
            close()
        }
        drawPath(core, sp.accent)
    }
}

@Composable
fun VSpace(h: Dp) = Spacer(Modifier.height(h))
