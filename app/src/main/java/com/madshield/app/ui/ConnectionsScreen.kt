package com.madshield.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.ConnSnapshot
import com.madshield.app.core.ConnView
import com.madshield.app.core.EngineConfig
import com.madshield.app.core.InsightHub
import com.madshield.app.core.PrivacyChain
import com.madshield.app.core.RouteAction
import com.madshield.app.ui.components.BackTopBar
import com.madshield.app.ui.components.HelperText
import com.madshield.app.ui.components.MonoFamily
import com.madshield.app.ui.components.rememberIsForeground
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Route colours. VPN follows the theme; direct and blocked keep a fixed meaning in every theme. */
@Composable
internal fun routeColor(route: RouteAction): Color = when (route) {
    RouteAction.PROXY -> MaterialTheme.colorScheme.primary
    RouteAction.DIRECT -> Color(0xFFE8A33D)
    RouteAction.BLOCK -> MaterialTheme.colorScheme.error
}

@Composable
internal fun routeLabel(route: RouteAction): String = stringResource(
    when (route) {
        RouteAction.PROXY -> R.string.route_vpn
        RouteAction.DIRECT -> R.string.route_direct
        RouteAction.BLOCK -> R.string.route_blocked
    }
)

private enum class ConnFilter { ALL, VPN, DIRECT, BLOCKED }

internal fun formatAge(ms: Long): String {
    val s = ms / 1000
    return when {
        s < 60 -> "${s}s"
        s < 3600 -> "${s / 60}m ${s % 60}s"
        else -> "${s / 3600}h ${(s % 3600) / 60}m"
    }
}

/**
 * The open connections, like sing-box's list. Nothing runs while the page is closed: it asks the service for a
 * snapshot every two seconds, and only while it is composed AND the app is in the foreground. Names exist only
 * in memory (see ConnTracker); nothing here is written anywhere.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionsScreen(config: EngineConfig, onBack: () -> Unit) {
    val foreground by rememberIsForeground()
    var snap by remember { mutableStateOf<ConnSnapshot?>(null) }
    var running by remember { mutableStateOf(InsightHub.connections != null) }
    var filter by remember { mutableStateOf(ConnFilter.ALL) }
    var query by remember { mutableStateOf("") }
    var detail by remember { mutableStateOf<ConnView?>(null) }
    val scope = rememberCoroutineScope()
    // Closing a socket is done off the main thread; the list is refreshed right after.
    fun act(block: () -> Unit) {
        scope.launch {
            withContext(Dispatchers.IO) { runCatching(block) }
            snap = InsightHub.connections?.invoke()
        }
    }

    LaunchedEffect(foreground) {
        if (!foreground) return@LaunchedEffect
        while (true) {
            val hook = InsightHub.connections
            running = hook != null
            snap = hook?.invoke()
            delay(2000)
        }
    }

    Scaffold(topBar = {
        BackTopBar(stringResource(R.string.conn_title), onBack, actions = {
            val s = snap
            TextButton(
                onClick = { act { InsightHub.closeAllConnections?.invoke() } },
                enabled = s != null && s.active.isNotEmpty()
            ) { Text(stringResource(R.string.conn_close_all)) }
        })
    }) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            val s = snap
            if (!running || s == null) {
                Spacer(Modifier.height(24.dp))
                Text(
                    stringResource(if (running) R.string.conn_loading else R.string.conn_empty_title),
                    style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface
                )
                if (!running) HelperText(stringResource(R.string.conn_empty_body))
                return@Column
            }
            SummaryCard(s)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ConnFilter.entries.forEach { f ->
                    FilterChip(
                        selected = filter == f, onClick = { filter = f },
                        label = {
                            Text(
                                when (f) {
                                    ConnFilter.ALL -> stringResource(R.string.conn_filter_all)
                                    ConnFilter.VPN -> stringResource(R.string.route_vpn)
                                    ConnFilter.DIRECT -> stringResource(R.string.route_direct)
                                    ConnFilter.BLOCKED -> stringResource(R.string.route_blocked)
                                }
                            )
                        },
                        shape = RoundedCornerShape(14.dp)
                    )
                }
            }
            OutlinedTextField(
                value = query, onValueChange = { query = it }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text(stringResource(R.string.conn_search)) },
                leadingIcon = { Icon(Icons.Rounded.Search, null) },
                shape = RoundedCornerShape(18.dp)
            )
            val q = query.trim()
            val rows = when (filter) {
                ConnFilter.ALL -> s.active + s.blocked
                ConnFilter.VPN -> s.active.filter { it.route == RouteAction.PROXY }
                ConnFilter.DIRECT -> s.active.filter { it.route == RouteAction.DIRECT }
                ConnFilter.BLOCKED -> s.blocked
            }.filter { q.isEmpty() || it.name.contains(q, ignoreCase = true) || it.port.toString() == q }
            if (rows.isEmpty()) {
                HelperText(stringResource(R.string.conn_none))
            }
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), contentPadding = PaddingValues(bottom = 24.dp)) {
                items(rows, key = { (if (it.route == RouteAction.BLOCK) "b" else "a") + it.id }) { c ->
                    ConnRow(c, onOpen = { detail = c }, onClose = { act { InsightHub.closeConnection?.invoke(c.id) } })
                }
            }
        }
    }

    detail?.let { c ->
        ModalBottomSheet(onDismissRequest = { detail = null }) {
            DetailSheet(c, config) {
                act { InsightHub.closeConnection?.invoke(c.id) }
                detail = null
            }
        }
    }
}

@Composable
private fun SummaryCard(s: ConnSnapshot) {
    Surface(shape = RoundedCornerShape(24.dp), color = MaterialTheme.colorScheme.surfaceContainer, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.SpaceBetween) {
            Stat(s.active.size.toString(), stringResource(R.string.conn_active), MaterialTheme.colorScheme.onSurface)
            Stat(s.vpnCount.toString(), stringResource(R.string.route_vpn), routeColor(RouteAction.PROXY))
            Stat(s.directCount.toString(), stringResource(R.string.route_direct), routeColor(RouteAction.DIRECT))
            Stat(s.blockedTotal.toString(), stringResource(R.string.route_blocked), routeColor(RouteAction.BLOCK))
        }
    }
}

@Composable
private fun Stat(value: String, label: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.headlineSmall, color = color)
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ConnRow(c: ConnView, onOpen: () -> Unit, onClose: () -> Unit) {
    val color = routeColor(c.route)
    val blocked = c.route == RouteAction.BLOCK
    Surface(
        onClick = onOpen, shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.fillMaxWidth()
    ) {
        Row(Modifier.padding(start = 14.dp, top = 10.dp, bottom = 10.dp, end = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(10.dp).clip(CircleShape).background(color))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    c.name, style = MaterialTheme.typography.bodyLarge.copy(textDirection = TextDirection.Ltr),
                    maxLines = 1, overflow = TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurface
                )
                val tail = if (blocked) {
                    if (c.repeat > 1) "× ${c.repeat}" else ""
                } else "↑ ${formatBytes(c.upBytes)}  ↓ ${formatBytes(c.downBytes)}  ·  ${formatAge(c.ageMs)}"
                Text(
                    ":${c.port}  ·  ${routeLabel(c.route)}" + if (tail.isEmpty()) "" else "  ·  $tail",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr),
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            if (!blocked) {
                IconButton(onClick = onClose) {
                    Icon(Icons.Rounded.Close, contentDescription = stringResource(R.string.conn_close))
                }
            }
        }
    }
}

@Composable
private fun DetailSheet(c: ConnView, config: EngineConfig, onClose: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 28.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            c.name, style = MaterialTheme.typography.titleLarge.copy(textDirection = TextDirection.Ltr), color = cs.onSurface
        )
        Text(
            stringResource(if (c.hasName) R.string.conn_kind_domain else R.string.conn_kind_ip) + "  ·  :${c.port}",
            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr),
            color = cs.onSurfaceVariant
        )
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        Text(stringResource(R.string.conn_path), style = MaterialTheme.typography.titleSmall, color = cs.primary)
        val hops = buildList {
            add(stringResource(R.string.path_app))
            add(stringResource(R.string.path_tun))
            when (c.route) {
                RouteAction.BLOCK -> add(stringResource(R.string.path_blocked))
                RouteAction.DIRECT -> add(stringResource(R.string.path_direct))
                RouteAction.PROXY -> {
                    when (config.privacyChain) {
                        PrivacyChain.PSIPHON -> add(stringResource(R.string.path_psiphon))
                        PrivacyChain.TOR -> add(stringResource(R.string.path_tor))
                        PrivacyChain.SINGBOX -> add(stringResource(R.string.path_singbox))
                        PrivacyChain.NONE -> {}
                    }
                    add(stringResource(R.string.path_warp))
                    add(stringResource(R.string.path_internet))
                }
            }
        }
        hops.forEachIndexed { i, h ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).clip(CircleShape).background(if (i == hops.lastIndex) routeColor(c.route) else cs.outline))
                Spacer(Modifier.width(12.dp))
                Text(h, style = MaterialTheme.typography.bodyMedium, color = cs.onSurface)
            }
        }
        if (c.route != RouteAction.BLOCK) {
            HorizontalDivider(Modifier.padding(vertical = 4.dp))
            Text(
                "↑ ${formatBytes(c.upBytes)}    ↓ ${formatBytes(c.downBytes)}    ${formatAge(c.ageMs)}",
                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFamily), color = cs.onSurfaceVariant
            )
            Button(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.conn_close)) }
        } else if (c.repeat > 1) {
            Text("× ${c.repeat}", style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant)
        }
    }
}
