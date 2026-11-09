package com.madshield.app.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/** Outline samples per lobe. Joined with smooth curves (see [BlobTable.fill]), so this can stay small. */
private const val BLOB_SAMPLES_PER_LOBE = 12

/**
 * The fixed part of the cookie outline: sin/cos of every sample angle and cos(lobes * angle), computed ONCE per lobe
 * count. Per frame the outline then costs a multiply-add per point instead of three trigonometric calls per point.
 * [xs]/[ys] are scratch space reused by every rebuild (only touched on the main thread, from the draw cache).
 */
private class BlobTable(lobes: Int) {
    val n = lobes * BLOB_SAMPLES_PER_LOBE
    private val cosA = FloatArray(n)
    private val sinA = FloatArray(n)
    private val lobe = FloatArray(n)
    private val xs = FloatArray(n)
    private val ys = FloatArray(n)

    init {
        for (i in 0 until n) {
            val a = 2.0 * PI * i / n
            cosA[i] = cos(a).toFloat()
            sinA[i] = sin(a).toFloat()
            lobe[i] = cos(lobes * a).toFloat()
        }
    }

    /**
     * Rewrites [path] in place (no new Path, no new buffers): radius = base * (1 + amp * cos(lobes * angle)). The
     * samples are control points of quadratic curves between the midpoints of neighbouring samples, a closed smooth
     * outline with no visible facets even though there are only a dozen samples per lobe.
     */
    fun fill(path: Path, cx: Float, cy: Float, base: Float, amp: Float) {
        for (i in 0 until n) {
            val r = base * (1f + amp * lobe[i])
            xs[i] = cx + r * cosA[i]
            ys[i] = cy + r * sinA[i]
        }
        path.rewind()
        val last = n - 1
        path.moveTo((xs[last] + xs[0]) / 2f, (ys[last] + ys[0]) / 2f)
        for (i in 0 until n) {
            val j = if (i == last) 0 else i + 1
            path.quadraticBezierTo(xs[i], ys[i], (xs[i] + xs[j]) / 2f, (ys[i] + ys[j]) / 2f)
        }
        path.close()
    }
}

/**
 * The scalloped "cookie" button shape of the ZedSecure home screen, drawn with plain Canvas maths (no extra
 * dependency): radius = R * (1 + amplitude * cos(lobes * angle)).
 *
 * Nothing here is read while composing. [amplitude], [endColor] and [rotationDeg] are lambdas over animated State:
 *  - [amplitude] and [endColor] are read inside the draw cache, so while they animate only the outline/gradient is
 *    rebuilt (into the same Path, from the precomputed table), never the composition;
 *  - [rotationDeg] drives a graphicsLayer, so spinning only moves the layer on the render thread: the outline is not
 *    redrawn per frame at all. (The gradient turns with the shape, as it did when the canvas was rotated.)
 * The Brush is created with the cache, not on every draw.
 */
@Composable
fun CookieBlob(
    modifier: Modifier,
    startColor: Color,
    endColor: () -> Color,
    amplitude: () -> Float,
    rotationDeg: (() -> Float)? = null,
    lobes: Int = 10
) {
    val table = remember(lobes) { BlobTable(lobes) }
    val path = remember { Path() }
    val turned = if (rotationDeg == null) modifier else modifier.graphicsLayer { rotationZ = rotationDeg() }
    Box(
        turned.drawWithCache {
            val amp = amplitude()
            val brush = Brush.linearGradient(listOf(startColor, endColor()))
            val outer = min(size.width, size.height) / 2f
            table.fill(path, size.width / 2f, size.height / 2f, outer / (1f + amp), amp)
            onDrawBehind { drawPath(path, brush) }
        }
    )
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

/**
 * A switch with its long explanation behind a small "i" beside the label: the page stays one line per option, and
 * whoever wants the details taps the "i". Open/closed survives a rotation.
 */
@Composable
fun InfoSwitchRow(label: String, info: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    val cs = MaterialTheme.colorScheme
    var open by rememberSaveable(label) { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(label, style = MaterialTheme.typography.bodyLarge, color = cs.onSurface, modifier = Modifier.weight(1f, fill = false))
            IconButton(onClick = { open = !open }, modifier = Modifier.size(36.dp)) {
                Icon(Icons.Outlined.Info, contentDescription = null, tint = if (open) cs.primary else cs.onSurfaceVariant, modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.weight(1f))
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
        AnimatedVisibility(visible = open, enter = Motion.reveal, exit = Motion.conceal) { HelperText(info) }
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

// ---------------------------------------------------------------------------------------------------------
// update17: the pieces that keep a page short. Long explanations hide behind an "i", rarely-touched groups fold
// into one line with a summary. Nothing is removed: it is one tap away, and open/closed survives a rotation.
// ---------------------------------------------------------------------------------------------------------

/**
 * A small "More info" line that opens the long explanation under it. It replaces the walls of grey text that used to
 * sit under every control. [error] colours the text when the explanation is really a warning.
 */
@Composable
fun InfoHint(text: String, modifier: Modifier = Modifier, error: Boolean = false) {
    val cs = MaterialTheme.colorScheme
    var open by rememberSaveable { mutableStateOf(false) }
    Column(modifier) {
        Row(
            Modifier.clip(RoundedCornerShape(12.dp)).clickable { open = !open }.padding(horizontal = 2.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Outlined.Info, null, tint = if (error) cs.error else cs.primary, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(
                stringResource(if (open) R.string.hint_less else R.string.hint_more),
                style = MaterialTheme.typography.labelMedium,
                color = if (error) cs.error else cs.primary
            )
        }
        AnimatedVisibility(visible = open, enter = Motion.reveal, exit = Motion.conceal) { HelperText(text, error = error) }
    }
}

/**
 * A card that is one line (icon, title, a summary of its current state) until tapped. For groups people rarely
 * touch after the first setup, so the page shows state at a glance instead of every control at once.
 */
@Composable
fun FoldCard(
    title: String,
    summary: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    startOpen: Boolean = false,
    content: @Composable ColumnScope.() -> Unit
) {
    val cs = MaterialTheme.colorScheme
    var open by rememberSaveable { mutableStateOf(startOpen) }
    val turn = animateFloatAsState(
        if (open) 180f else 0f,
        spring(dampingRatio = 0.8f, stiffness = Spring.StiffnessMediumLow), label = "fold-arrow"
    )
    Surface(shape = RoundedCornerShape(28.dp), color = cs.surfaceContainer, modifier = modifier.fillMaxWidth()) {
        Column {
            Row(
                Modifier.fillMaxWidth().clickable { open = !open }.padding(horizontal = 18.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    Modifier.size(40.dp).clip(CircleShape).background(cs.primaryContainer),
                    contentAlignment = Alignment.Center
                ) { Icon(icon, null, tint = cs.onPrimaryContainer, modifier = Modifier.size(20.dp)) }
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleMedium, color = cs.onSurface)
                    Text(
                        summary, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                }
                Icon(
                    Icons.Rounded.KeyboardArrowDown, null, tint = cs.onSurfaceVariant,
                    modifier = Modifier.graphicsLayer { rotationZ = turn.value }
                )
            }
            AnimatedVisibility(visible = open, enter = Motion.reveal, exit = Motion.conceal) {
                Column(Modifier.padding(start = 18.dp, end = 18.dp, bottom = 16.dp), content = content)
            }
        }
    }
}

/**
 * The app's signature mark: the scalloped "cookie" of the Connect button, small and still, with an icon or a flag
 * inside. It marks "what you are using right now" (the exit profile, the active link), so the same shape means the
 * same thing wherever it appears.
 */
@Composable
fun CookieBadge(size: Dp, modifier: Modifier = Modifier, content: @Composable BoxScope.() -> Unit) {
    val cs = MaterialTheme.colorScheme
    Box(modifier.size(size), contentAlignment = Alignment.Center) {
        CookieBlob(
            Modifier.matchParentSize(),
            startColor = cs.primaryContainer,
            endColor = { cs.tertiaryContainer },
            amplitude = { 0.06f },
            lobes = 8
        )
        content()
    }
}

val MonoFamily: FontFamily = FontFamily.Monospace

/** Space left at the bottom of every tab so the floating navigation bar never covers content. */
val NavClearance = 96.dp


/**
 * True while the app's screen is visible (lifecycle STARTED or later). Polling loops that only feed the UI
 * (uptime, throughput) must stop when this is false: a LaunchedEffect keeps running after the screen goes
 * off, and one JNI call a second all night is exactly the kind of idle drain that heats a phone.
 */
@Composable
fun rememberIsForeground(): State<Boolean> {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val lifecycle = remember(ctx) {
        generateSequence(ctx) { (it as? android.content.ContextWrapper)?.baseContext }
            .filterIsInstance<androidx.lifecycle.LifecycleOwner>()
            .firstOrNull()?.lifecycle
    }
    val state = remember(lifecycle) {
        mutableStateOf(lifecycle?.currentState?.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED) ?: true)
    }
    DisposableEffect(lifecycle) {
        val observer = androidx.lifecycle.LifecycleEventObserver { _, _ ->
            state.value = lifecycle?.currentState?.isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED) ?: true
        }
        lifecycle?.addObserver(observer)
        onDispose { lifecycle?.removeObserver(observer) }
    }
    return state
}
