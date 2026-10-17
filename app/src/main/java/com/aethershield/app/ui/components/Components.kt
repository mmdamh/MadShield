package com.aethershield.app.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/**
 * The scalloped "cookie" button shape of the ZedSecure home screen, drawn with
 * plain Canvas maths (no extra dependency): radius = R * (1 + amplitude * cos(lobes * angle)).
 * Animating [amplitude] and [rotationDeg] gives the calm/searching/live looks.
 */
@Composable
fun CookieBlob(
    modifier: Modifier,
    brush: Brush,
    amplitude: Float,
    rotationDeg: Float,
    lobes: Int = 10
) {
    Canvas(modifier) {
        val steps = 220
        val outer = min(size.width, size.height) / 2f
        val base = outer / (1f + amplitude)
        val cx = size.width / 2f
        val cy = size.height / 2f
        val path = Path()
        for (i in 0..steps) {
            val a = 2.0 * PI * i / steps
            val r = base * (1f + amplitude * cos(lobes * a).toFloat())
            val x = cx + r * cos(a).toFloat()
            val y = cy + r * sin(a).toFloat()
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        path.close()
        rotate(rotationDeg, pivot = androidx.compose.ui.geometry.Offset(cx, cy)) { drawPath(path, brush) }
    }
}

/** Big page title used at the top of each tab, ZedSecure-style. */
@Composable
fun PageHeader(title: String, subtitle: String? = null, modifier: Modifier = Modifier) {
    Column(modifier.padding(horizontal = 4.dp, vertical = 8.dp)) {
        Text(title, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.onSurface)
        if (subtitle != null) {
            Spacer(Modifier.height(2.dp))
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** A rounded surface with a small coloured heading; the building block of every settings page. */
@Composable
fun SectionCard(
    title: String,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    Surface(
        shape = RoundedCornerShape(28.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(horizontal = 18.dp, vertical = 16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (icon != null) {
                    Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(10.dp))
                }
                Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
fun HelperText(text: String, modifier: Modifier = Modifier, error: Boolean = false) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(top = 4.dp)
    )
}

@Composable
fun SwitchRow(label: String, sub: String? = null, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface)
            if (sub != null) {
                Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

/** Tappable row with a round icon badge and a chevron: used for navigation entries. */
@Composable
fun NavRow(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val cs = MaterialTheme.colorScheme
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(24.dp),
        color = cs.surfaceContainerHigh,
        modifier = modifier.fillMaxWidth()
    ) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(44.dp).clip(CircleShape).background(cs.primaryContainer),
                contentAlignment = Alignment.Center
            ) { Icon(icon, null, tint = cs.onPrimaryContainer, modifier = Modifier.size(22.dp)) }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium, color = cs.onSurface)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
            }
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, null, tint = cs.onSurfaceVariant)
        }
    }
}

/** Wrap-around row of selectable chips; one value is selected. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun <T> ChoiceChips(options: List<Pair<String, T>>, selected: T, onSelect: (T) -> Unit) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        options.forEach { (label, value) ->
            FilterChip(
                selected = value == selected,
                onClick = { onSelect(value) },
                label = { Text(label) },
                shape = RoundedCornerShape(14.dp)
            )
        }
    }
}

/** Vertical list of radio options with a description each. */
@Composable
fun <T> SegmentedChoice(options: List<Pair<String, T>>, selected: T, onSelect: (T) -> Unit) {
    Column {
        options.forEach { (label, value) ->
            Row(
                Modifier.fillMaxWidth().padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RadioButton(selected = value == selected, onClick = { onSelect(value) })
                Text(
                    label, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}

/** Two-way pill toggle (used for Proxy / VPN). */
@Composable
fun <T> PillToggle(options: List<Pair<String, T>>, selected: T, enabled: Boolean = true, onSelect: (T) -> Unit) {
    val cs = MaterialTheme.colorScheme
    Row(
        Modifier.clip(CircleShape).background(cs.surfaceContainerHigh).padding(4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        options.forEach { (label, value) ->
            val on = value == selected
            val bg by animateColorAsState(if (on) cs.primary else cs.surfaceContainerHigh, label = "pill-bg")
            val fg by animateColorAsState(if (on) cs.onPrimary else cs.onSurfaceVariant, label = "pill-fg")
            Surface(
                onClick = { onSelect(value) },
                enabled = enabled,
                shape = CircleShape,
                color = bg,
                contentColor = fg
            ) {
                Text(
                    label,
                    Modifier.padding(horizontal = 18.dp, vertical = 9.dp),
                    style = MaterialTheme.typography.labelLarge
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackTopBar(title: String, onBack: () -> Unit, actions: @Composable RowScope.() -> Unit = {}) {
    TopAppBar(
        title = { Text(title, style = MaterialTheme.typography.titleLarge) },
        navigationIcon = {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = null) }
        },
        actions = actions,
        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface)
    )
}

val MonoFamily: FontFamily = FontFamily.Monospace

/** Space left at the bottom of every tab so the floating navigation bar never covers content. */
val NavClearance = 96.dp
