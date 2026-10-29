package com.madshield.app.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.expandHorizontally
import androidx.compose.animation.shrinkHorizontally
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Route
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.vector.ImageVector
import com.madshield.app.R

enum class Tab(val icon: ImageVector, val labelRes: Int) {
    Home(Icons.Rounded.Home, R.string.nav_home),
    Dns(Icons.Rounded.Dns, R.string.nav_dns),
    Routing(Icons.Rounded.Route, R.string.nav_routing),
    Settings(Icons.Rounded.Settings, R.string.nav_settings),
}

/**
 * Floating pill navigation in the style of ZedSecure's "expressive" bar: the
 * selected destination expands to show its label, the others are just icons.
 */
@Composable
fun FloatingNavBar(current: Tab, onSelect: (Tab) -> Unit) {
    val cs = MaterialTheme.colorScheme
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
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Tab.entries.forEach { tab ->
                    val selected = tab == current
                    val bg by animateColorAsState(if (selected) cs.primary else cs.surfaceContainerHigh, label = "nav-bg")
                    val fg by animateColorAsState(if (selected) cs.onPrimary else cs.onSurfaceVariant, label = "nav-fg")
                    val label = stringResource(tab.labelRes)
                    Surface(
                        onClick = { onSelect(tab) },
                        shape = CircleShape,
                        color = bg,
                        contentColor = fg
                    ) {
                        Row(
                            Modifier.padding(horizontal = if (selected) 16.dp else 14.dp, vertical = 11.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(tab.icon, contentDescription = label, modifier = Modifier.size(22.dp))
                            AnimatedVisibility(
                                visible = selected,
                                enter = fadeIn() + expandHorizontally(),
                                exit = fadeOut() + shrinkHorizontally()
                            ) {
                                Text(
                                    label,
                                    Modifier.padding(start = 8.dp),
                                    style = MaterialTheme.typography.labelLarge,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
