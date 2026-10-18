package com.aethershield.app.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import android.widget.Toast
import com.aethershield.app.R
import com.aethershield.app.core.*
import com.aethershield.app.ui.components.CookieBlob
import com.aethershield.app.ui.components.NavClearance
import com.aethershield.app.ui.components.rememberIsForeground
import com.aethershield.app.ui.components.PillToggle
import com.aethershield.app.vpn.TProxyService
import kotlinx.coroutines.delay
import java.util.Locale

/**
 * Home tab. Everything on screen is driven by [connectionState], i.e. the real
 * service state (health-checked), never a local tap toggle: tapping Connect
 * shows "Connecting" at once and only becomes "Connected" after the service has
 * seen a real SOCKS5 answer from the engine.
 *
 * Look and layout follow the ZedSecure home screen (big scalloped connect
 * button on a rounded hero card, pill chips, asymmetric download/upload tiles),
 * re-implemented from scratch with stable Material 3 APIs and plain Canvas.
 */
@Composable
fun HomeScreen(
    config: EngineConfig,
    connectionState: ConnectionState,
    onSetMode: (ConnectionMode) -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onOpenLog: () -> Unit,
    contentPadding: PaddingValues
) {
    Column(
        Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
    ) {
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.weight(1f).padding(start = 4.dp)
            )
            FilledTonalIconButton(onClick = onOpenLog) {
                Icon(Icons.Rounded.Terminal, contentDescription = stringResource(R.string.log_title))
            }
        }
        Spacer(Modifier.height(12.dp))
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            PillToggle(
                options = listOf(
                    stringResource(R.string.mode_proxy) to ConnectionMode.PROXY_ONLY,
                    stringResource(R.string.mode_vpn) to ConnectionMode.VPN
                ),
                selected = config.mode,
                // Switching mode while a session exists would orphan it; only allowed when idle/failed.
                enabled = connectionState is ConnectionState.Idle || connectionState is ConnectionState.Error,
                onSelect = onSetMode
            )
        }
        Spacer(Modifier.height(12.dp))

        if (connectionState is ConnectionState.Error) {
            ErrorCard(connectionState.message, onRetry = onConnect, onStop = onDisconnect, onLog = onOpenLog)
        } else {
            HeroCard(config, connectionState, onTap = {
                when (connectionState) {
                    is ConnectionState.Idle -> onConnect()
                    is ConnectionState.Connected, is ConnectionState.Connecting -> onDisconnect()
                    else -> {}
                }
            })
        }

        Spacer(Modifier.height(10.dp))
        val running by AetherController.active.collectAsState()
        FactChips(config, running)
        Spacer(Modifier.height(10.dp))
        if (config.mode == ConnectionMode.VPN) {
            TrafficTiles(active = connectionState is ConnectionState.Connected)
        } else {
            ProxyAddressPill(config.socksPort, visible = connectionState is ConnectionState.Connected)
        }
        // Bottom padding so the floating navigation bar never covers the last card.
        Spacer(Modifier.height(NavClearance))
    }
}

// ----------------------------------------------------------------------- hero

@Composable
private fun HeroCard(config: EngineConfig, state: ConnectionState, onTap: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val live = state is ConnectionState.Connected
    val busy = state is ConnectionState.Connecting || state is ConnectionState.Disconnecting
    val container by animateColorAsState(if (live) cs.primaryContainer else cs.surfaceContainer, label = "hero-bg")
    val ink by animateColorAsState(if (live) cs.onPrimaryContainer else cs.onSurface, label = "hero-ink")
    val sub by animateColorAsState(
        if (live) cs.onPrimaryContainer.copy(alpha = 0.78f) else cs.onSurfaceVariant, label = "hero-sub"
    )

    Surface(shape = RoundedCornerShape(44.dp), color = container, modifier = Modifier.fillMaxWidth()) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 26.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            ConnectBlob(state, onTap)
            Spacer(Modifier.height(18.dp))
            AnimatedContent(
                targetState = statusRes(state),
                transitionSpec = { fadeIn(tween(240)) togetherWith fadeOut(tween(140)) },
                label = "hero-status"
            ) { res ->
                Text(
                    stringResource(res),
                    style = MaterialTheme.typography.headlineMedium,
                    color = ink,
                    textAlign = TextAlign.Center,
                    maxLines = 1
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                stringResource(
                    when {
                        state is ConnectionState.Disconnecting -> R.string.hint_disconnecting
                        busy -> R.string.hint_busy
                        live && config.mode == ConnectionMode.VPN -> R.string.hint_live_vpn
                        live -> R.string.hint_live_proxy
                        else -> R.string.hint_idle
                    }
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = sub,
                textAlign = TextAlign.Center
            )
            if (busy) {
                Spacer(Modifier.height(14.dp))
                LinearProgressIndicator(
                    modifier = Modifier.width(156.dp).clip(CircleShape),
                    color = cs.primary,
                    trackColor = cs.primary.copy(alpha = 0.18f)
                )
            }
        }
    }
}

private fun statusRes(s: ConnectionState): Int = when (s) {
    is ConnectionState.Idle -> R.string.status_idle
    is ConnectionState.Connecting -> R.string.status_connecting
    is ConnectionState.Connected -> R.string.status_connected
    is ConnectionState.Disconnecting -> R.string.status_disconnecting
    is ConnectionState.Error -> R.string.status_error
}

@Composable
private fun ConnectBlob(state: ConnectionState, onTap: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val live = state is ConnectionState.Connected
    val busy = state is ConnectionState.Connecting || state is ConnectionState.Disconnecting

    // Rotation only runs while it means something (connecting / connected); an idle
    // button costs nothing, which keeps battery use flat.
    val spin = if (busy || live) {
        val transition = rememberInfiniteTransition(label = "blob")
        val angle by transition.animateFloat(
            initialValue = 0f, targetValue = 360f,
            animationSpec = infiniteRepeatable(
                tween(if (busy) 3200 else 24000, easing = LinearEasing), RepeatMode.Restart
            ),
            label = "blob-spin"
        )
        angle
    } else 0f
    val amplitude by animateFloatAsState(
        when { busy -> 0.10f; live -> 0.075f; else -> 0.04f },
        spring(dampingRatio = 0.6f, stiffness = 260f), label = "blob-amp"
    )
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()
    val squash by animateFloatAsState(if (pressed) 0.92f else 1f, spring(stiffness = 500f), label = "blob-squash")
    val end by animateColorAsState(if (live || busy) cs.tertiary else cs.primary, label = "blob-end")

    val action = stringResource(
        when (state) {
            is ConnectionState.Disconnecting -> R.string.status_disconnecting
            is ConnectionState.Connecting -> R.string.action_cancel
            is ConnectionState.Connected -> R.string.action_disconnect
            else -> R.string.action_connect
        }
    )
    Box(
        Modifier
            .size(196.dp)
            .scale(squash)
            .clip(CircleShape)
            .clickable(
                interactionSource = source, indication = null,
                enabled = state !is ConnectionState.Disconnecting, onClick = onTap
            ),
        contentAlignment = Alignment.Center
    ) {
        CookieBlob(
            Modifier.matchParentSize(),
            brush = Brush.linearGradient(listOf(cs.primary, end)),
            amplitude = amplitude,
            rotationDeg = if (busy || live) spin else 0f
        )
        if (live) {
            UptimeText((state as ConnectionState.Connected).sinceMs, cs.onPrimary)
        } else {
            Icon(
                Icons.Rounded.PowerSettingsNew, contentDescription = action,
                tint = cs.onPrimary, modifier = Modifier.size(64.dp)
            )
        }
    }
}

@Composable
private fun UptimeText(sinceMs: Long, color: Color) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val foreground by rememberIsForeground()
    LaunchedEffect(sinceMs, foreground) {
        if (!foreground) return@LaunchedEffect
        while (true) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }
    val t = ((now - sinceMs) / 1000).coerceAtLeast(0)
    Text(
        ltr(String.format(Locale.US, "%02d:%02d:%02d", t / 3600, (t % 3600) / 60, t % 60)),
        style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
        color = color
    )
}

// ---------------------------------------------------------------------- error

@Composable
private fun ErrorCard(message: String, onRetry: () -> Unit, onStop: () -> Unit, onLog: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    Surface(
        shape = RoundedCornerShape(44.dp),
        color = cs.errorContainer,
        contentColor = cs.onErrorContainer,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 22.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Box(Modifier.size(84.dp).clip(CircleShape).background(cs.error), contentAlignment = Alignment.Center) {
                Text("!", style = MaterialTheme.typography.displaySmall, color = cs.onError)
            }
            Spacer(Modifier.height(14.dp))
            Text(stringResource(R.string.status_error), style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
            Spacer(Modifier.height(8.dp))
            // The real reason (engine exit reason, timeout, missing library ...), selectable so it can be copied.
            SelectionContainer {
                Text(
                    ltr(message),
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    color = cs.onErrorContainer.copy(alpha = 0.9f),
                    maxLines = 6,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.height(18.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
                FilledTonalButton(onClick = onStop) { Text(stringResource(R.string.action_stop)) }
            }
            TextButton(onClick = onLog) { Text(stringResource(R.string.action_open_log)) }
        }
    }
}

// ---------------------------------------------------------------------- chips

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FactChips(config: EngineConfig, running: EngineConfig?) {
    val dnsName = DnsPresets.matching(config.dnsResolvers)?.name
        ?: if (config.dnsResolvers.isEmpty()) stringResource(R.string.dns_default)
        else stringResource(R.string.dns_custom_count, config.dnsResolvers.size)
    FlowRow(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // The protocol that is REALLY running: after a fallback (Gool -> HTTP/2 carrier -> classic Gool)
        // it differs from the setting, and a classic Gool exit is a plain WARP (Iranian) address.
        val shown = running ?: config
        Chip(protocolShort(shown.protocol))
        if (running != null && shown.protocol == Protocol.GOOL && shown.masqueHttp2) Chip("HTTP/2")
        if (running != null && running.protocol != config.protocol) Chip(stringResource(R.string.chip_fallback))
        Chip("DNS · $dnsName")
        if (config.mode == ConnectionMode.VPN) Chip("MTU ${config.effectiveMtu}")
        if (config.exitLoc != null) Chip(stringResource(R.string.chip_exit_guard))
        when (config.effectiveChain) {
            PrivacyChain.PSIPHON -> Chip(
                "Psiphon" + (Chain.normalizeRegion(config.psiphonRegion)?.let { " · $it" } ?: "")
            )
            PrivacyChain.TOR -> Chip("Tor")
            PrivacyChain.NONE -> Unit
        }
    }
}

@Composable
private fun Chip(text: String) {
    Surface(shape = CircleShape, color = MaterialTheme.colorScheme.surfaceContainerHigh) {
        Text(
            text,
            Modifier.padding(horizontal = 14.dp, vertical = 7.dp),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1
        )
    }
}

@Composable
private fun ProxyAddressPill(port: Int, visible: Boolean) {
    if (!visible) return
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val address = "${TunnelConfig.SOCKS_HOST}:$port"
    val copied = stringResource(R.string.copied)
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Surface(
            onClick = {
                clipboard.setText(AnnotatedString(address))
                Toast.makeText(context, copied, Toast.LENGTH_SHORT).show()
            },
            shape = CircleShape,
            color = MaterialTheme.colorScheme.surfaceContainerHigh
        ) {
            Row(Modifier.padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(R.string.proxy_address_label, ltr(address)),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.width(8.dp))
                Icon(Icons.Rounded.ContentCopy, null, modifier = Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

// ---------------------------------------------------------------------- stats

private data class Traffic(val downBps: Long = 0, val upBps: Long = 0, val totalDown: Long = 0, val totalUp: Long = 0)

/**
 * Live throughput from hev-socks5-tunnel's own counters. Direction mapping
 * (stats[1] = bytes uploaded by apps, stats[3] = bytes downloaded) follows the
 * reference app's field-tested fix. Polled once a second ONLY while connected
 * and on screen, so it costs nothing in the background.
 */
@Composable
private fun rememberTraffic(active: Boolean): State<Traffic> {
    val state = remember { mutableStateOf(Traffic()) }
    val foreground by rememberIsForeground()
    LaunchedEffect(active, foreground) {
        if (!active) { state.value = Traffic(); return@LaunchedEffect }
        if (!foreground) return@LaunchedEffect
        var last: LongArray? = null
        while (true) {
            val s = if (TProxyService.available) runCatching { TProxyService.TProxyGetStats() }.getOrNull() else null
            if (s != null && s.size >= 4) {
                val prev = last
                state.value = Traffic(
                    downBps = if (prev != null) (s[3] - prev[3]).coerceAtLeast(0) else 0,
                    upBps = if (prev != null) (s[1] - prev[1]).coerceAtLeast(0) else 0,
                    totalDown = s[3], totalUp = s[1]
                )
                last = s
            }
            delay(1000)
        }
    }
    return state
}

@Composable
private fun TrafficTiles(active: Boolean) {
    val traffic by rememberTraffic(active)
    val cs = MaterialTheme.colorScheme
    Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        StatTile(
            Icons.Rounded.ArrowDownward, stringResource(R.string.stat_download),
            traffic.downBps, traffic.totalDown, active, cs.tertiaryContainer, cs.onTertiaryContainer,
            RoundedCornerShape(topStart = 8.dp, topEnd = 8.dp, bottomEnd = 8.dp, bottomStart = 30.dp),
            Modifier.weight(1f).fillMaxHeight()
        )
        StatTile(
            Icons.Rounded.ArrowUpward, stringResource(R.string.stat_upload),
            traffic.upBps, traffic.totalUp, active, cs.primaryContainer, cs.onPrimaryContainer,
            RoundedCornerShape(topStart = 8.dp, topEnd = 8.dp, bottomStart = 8.dp, bottomEnd = 30.dp),
            Modifier.weight(1f).fillMaxHeight()
        )
    }
}

@Composable
private fun StatTile(
    icon: ImageVector, label: String, bps: Long, total: Long, active: Boolean,
    badge: Color, onBadge: Color, shape: RoundedCornerShape, modifier: Modifier
) {
    val cs = MaterialTheme.colorScheme
    val (value, unit) = formatRate(if (active) bps else 0L)
    Surface(shape = shape, color = cs.surfaceContainerHigh, modifier = modifier) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(38.dp).clip(CircleShape).background(badge), contentAlignment = Alignment.Center) {
                Icon(icon, null, tint = onBadge, modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.width(10.dp))
            Column {
                Text(label, style = MaterialTheme.typography.labelMedium, color = cs.onSurfaceVariant, maxLines = 1)
                Row(verticalAlignment = Alignment.Bottom) {
                    Text(
                        ltr(value), style = MaterialTheme.typography.titleLarge,
                        color = if (active && bps > 0) cs.onSurface else cs.onSurfaceVariant
                    )
                    Spacer(Modifier.width(3.dp))
                    Text(ltr(unit), style = MaterialTheme.typography.labelMedium, color = cs.onSurfaceVariant,
                        modifier = Modifier.padding(bottom = 3.dp))
                }
                Text(ltr(formatBytes(if (active) total else 0L)), style = MaterialTheme.typography.labelSmall, color = cs.onSurfaceVariant)
            }
        }
    }
}

internal fun formatRate(bytesPerSec: Long): Pair<String, String> = when {
    bytesPerSec >= 1_048_576 -> String.format(Locale.US, "%.1f", bytesPerSec / 1_048_576.0) to "MB/s"
    bytesPerSec >= 1024 -> String.format(Locale.US, "%.0f", bytesPerSec / 1024.0) to "KB/s"
    else -> bytesPerSec.toString() to "B/s"
}

internal fun formatBytes(bytes: Long): String = when {
    bytes >= 1_073_741_824 -> String.format(Locale.US, "%.2f GB", bytes / 1_073_741_824.0)
    bytes >= 1_048_576 -> String.format(Locale.US, "%.1f MB", bytes / 1_048_576.0)
    bytes >= 1024 -> String.format(Locale.US, "%.0f KB", bytes / 1024.0)
    else -> "$bytes B"
}
