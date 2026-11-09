package com.madshield.app.ui.components

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Route
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.madshield.app.R

enum class Tab(val icon: ImageVector, val labelRes: Int) {
    Home(Icons.Rounded.Home, R.string.nav_home),
    Routing(Icons.Rounded.Route, R.string.nav_routing),
    Dns(Icons.Rounded.Dns, R.string.nav_dns),
    Settings(Icons.Rounded.Settings, R.string.nav_settings),
}

private val TileSize = 52.dp
private val TileShape = RoundedCornerShape(18.dp)

/**
 * Floating pill navigation. Each destination is a square tile with an icon on its face; the selected one flips over
 * in 3D (a spring, so it settles with a small overshoot) to its other side, which carries the same icon on the
 * theme's primary-to-tertiary gradient. The label is not drawn but is the tile's accessibility description, and the
 * tile reports "selected" and the tab role to TalkBack.
 */
@Composable
fun FloatingNavBar(current: Tab, onSelect: (Tab) -> Unit) {
    val cs = MaterialTheme.colorScheme
    val tick = rememberTick()
    Box(
        Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .padding(start = 16.dp, end = 16.dp, bottom = 10.dp),
        contentAlignment = Alignment.Center
    ) {
        Surface(
            shape = RoundedCornerShape(30.dp),
            color = cs.surfaceContainerHigh,
            tonalElevation = 3.dp,
            shadowElevation = 6.dp
        ) {
            Row(
                Modifier.padding(8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Tab.entries.forEach { tab ->
                    FlipTab(
                        tab = tab,
                        selected = tab == current,
                        label = stringResource(tab.labelRes),
                        onClick = { if (tab != current) { tick(); onSelect(tab) } }
                    )
                }
            }
        }
    }
}

/**
 * One tile. Both animated numbers (the flip angle and the press scale) are State read only inside graphicsLayer
 * blocks, so while a tile moves nothing recomposes: it is render-thread work.
 *
 * Two faces share the tile. The back face is pre-turned by 180 degrees so it reads the right way round once the
 * tile has flipped, and each face is shown only on its own side of the 90 degree mark (alpha 0 on the hidden one).
 */
@Composable
private fun FlipTab(tab: Tab, selected: Boolean, label: String, onClick: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val density = LocalDensity.current.density
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()

    val flip = animateFloatAsState(
        if (selected) 180f else 0f,
        spring(dampingRatio = 0.72f, stiffness = Spring.StiffnessMediumLow), label = "nav-flip"
    )
    val press = animateFloatAsState(if (pressed) 0.92f else 1f, spring(stiffness = 500f), label = "nav-press")

    Box(
        Modifier
            .size(TileSize)
            .graphicsLayer {
                // A camera that is too close clips the corners of the tile as it turns edge-on.
                cameraDistance = 12f * density
                rotationY = flip.value
                scaleX = press.value
                scaleY = press.value
            }
            .selectable(
                selected = selected,
                interactionSource = source,
                indication = null,
                role = Role.Tab,
                onClick = onClick
            )
            .semantics { contentDescription = label },
        contentAlignment = Alignment.Center
    ) {
        Box(
            Modifier
                .matchParentSize()
                .graphicsLayer { alpha = if (flip.value < 90f) 1f else 0f }
                .clip(TileShape)
                .background(cs.surfaceContainerHighest),
            contentAlignment = Alignment.Center
        ) { Icon(tab.icon, contentDescription = null, tint = cs.onSurfaceVariant, modifier = Modifier.size(22.dp)) }
        Box(
            Modifier
                .matchParentSize()
                .graphicsLayer { rotationY = 180f; alpha = if (flip.value >= 90f) 1f else 0f }
                .clip(TileShape)
                .background(Brush.linearGradient(listOf(cs.primary, cs.tertiary))),
            contentAlignment = Alignment.Center
        ) { Icon(tab.icon, contentDescription = null, tint = cs.onPrimary, modifier = Modifier.size(22.dp)) }
    }
}
