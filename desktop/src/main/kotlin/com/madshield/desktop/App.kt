package com.madshield.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.madshield.app.core.Chain
import com.madshield.app.core.ConnSnapshot
import com.madshield.app.core.EngineKind
import com.madshield.app.core.PrivacyChain
import com.madshield.app.core.RouteTotals
import com.madshield.app.util.RingLogBuffer
import kotlinx.coroutines.delay

@Composable
fun t(key: String): String = Strings.get(LocalLang.current, key)

private enum class Page(val key: String, val icon: ImageVector) {
    HOME("nav.home", Icons.Filled.Home),
    ENGINE("nav.engine", Icons.Filled.Build),
    FOXY("nav.foxy", Icons.Filled.Person),
    RULES("nav.rules", Icons.Filled.Edit),
    CONNS("nav.conns", Icons.Filled.Share),
    LOGS("nav.logs", Icons.Filled.Info),
    SETTINGS("nav.settings", Icons.Filled.Settings)
}

private val Brand = Color(0xFF7C5CFF)
private val DarkScheme = darkColorScheme(primary = Brand, secondary = Color(0xFF3DD9B0), background = Color(0xFF111318), surface = Color(0xFF171A21))
private val LightScheme = lightColorScheme(primary = Brand, secondary = Color(0xFF008C70))

@Composable
fun App(conn: Connection, initial: DesktopSettings) {
    var settings by remember { mutableStateOf(initial) }
    var page by remember { mutableStateOf(Page.HOME) }
    fun update(new: DesktopSettings) { settings = new; SettingsStore.save(new) }

    val dark = androidx.compose.foundation.isSystemInDarkTheme()
    val rtl = settings.language == "fa"
    CompositionLocalProvider(
        LocalLang provides settings.language,
        LocalLayoutDirection provides if (rtl) LayoutDirection.Rtl else LayoutDirection.Ltr
    ) {
        MaterialTheme(colorScheme = if (dark) DarkScheme else LightScheme) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                Row(Modifier.fillMaxSize()) {
                    NavigationRail {
                        Spacer(Modifier.height(8.dp))
                        for (p in Page.entries) {
                            NavigationRailItem(
                                selected = page == p, onClick = { page = p },
                                icon = { Icon(p.icon, contentDescription = t(p.key)) },
                                label = { Text(t(p.key), fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                            )
                        }
                    }
                    Box(Modifier.fillMaxSize().padding(24.dp)) {
                        when (page) {
                            Page.HOME -> HomeScreen(conn, settings)
                            Page.ENGINE -> EngineScreen(settings, ::update)
                            Page.FOXY -> FoxyScreen(conn, settings, ::update)
                            Page.RULES -> RulesScreen(settings, ::update)
                            Page.CONNS -> ConnectionsScreen(conn)
                            Page.LOGS -> LogsScreen()
                            Page.SETTINGS -> SettingsScreen(settings, ::update)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Title(text: String) = Text(text, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 12.dp))

fun formatBytes(b: Long): String = when {
    b < 1024 -> "$b B"
    b < 1024L * 1024 -> "%.1f KB".format(b / 1024.0)
    b < 1024L * 1024 * 1024 -> "%.1f MB".format(b / 1048576.0)
    else -> "%.2f GB".format(b / 1073741824.0)
}

private fun formatDuration(ms: Long): String {
    val s = ms / 1000
    return "%d:%02d:%02d".format(s / 3600, (s / 60) % 60, s % 60)
}

// ------------------------------------------------------------------------------------------------------------- Home

@Composable
private fun HomeScreen(conn: Connection, settings: DesktopSettings) {
    val state by conn.state.collectAsState()
    var totals by remember { mutableStateOf(RouteTotals()) }
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(state) {
        while (true) {
            now = System.currentTimeMillis()
            conn.routeFront()?.let { totals = it.routeTotals() }
            delay(1000)
        }
    }
    val admin = remember { Elevation.isAdmin() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(24.dp))
        val s = state
        val connected = s is ConnState.Connected
        val busy = s is ConnState.Connecting || s is ConnState.Waiting || s is ConnState.Stopping
        Button(
            onClick = { if (connected || busy) conn.disconnect() else conn.connect(settings) },
            enabled = s !is ConnState.Stopping,
            shape = CircleShape,
            modifier = Modifier.size(168.dp),
            colors = ButtonDefaults.buttonColors(containerColor = if (connected) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.primary)
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Filled.PowerSettingsNew, null, Modifier.size(48.dp))
                Text(
                    when {
                        connected -> t("home.disconnect")
                        busy -> t("home.cancel")
                        else -> t("home.connect")
                    }
                )
            }
        }
        Spacer(Modifier.height(20.dp))
        val title = when (s) {
            ConnState.Idle -> t("home.idle")
            is ConnState.Connecting -> t("home.connecting")
            is ConnState.Connected -> t("home.connected")
            is ConnState.Waiting -> t("home.waiting").replace("%s", (s.retryInMs / 1000).toString())
            is ConnState.Failed -> t("home.failed")
            ConnState.Stopping -> t("home.stopping")
        }
        Text(title, style = MaterialTheme.typography.titleLarge)
        when (s) {
            is ConnState.Connecting -> Text(Strings.get(LocalLang.current, "step.${s.step}").let { if (it.startsWith("step.")) s.step else it }, color = MaterialTheme.colorScheme.onSurfaceVariant)
            is ConnState.Connected -> {
                val exit = s.exit
                if (exit != null) Text("${t("home.exit")}: ${exit.ip}" + (exit.country?.let { " ($it)" } ?: ""))
                Text(t("home.since").replace("%s", formatDuration(now - s.sinceMs)), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            is ConnState.Waiting -> Text(s.reason, color = MaterialTheme.colorScheme.error, maxLines = 3, overflow = TextOverflow.Ellipsis)
            is ConnState.Failed -> Text(s.reason, color = MaterialTheme.colorScheme.error)
            else -> Unit
        }
        if (!admin) {
            Spacer(Modifier.height(12.dp))
            Text(t("home.admin"), color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(24.dp))
        Text(
            (if (settings.engine == EngineKind.FIREFOX) t("home.engine.fx")
            else t("home.engine.warp") + " · " + t("proto.${settings.protocol.name}") +
                when (settings.chain) { PrivacyChain.NONE -> ""; PrivacyChain.PSIPHON -> " + Psiphon"; PrivacyChain.TOR -> " + Tor"; PrivacyChain.SINGBOX -> " + " + t("engine.chain.link") }),
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (connected) {
            Spacer(Modifier.height(16.dp))
            Card(Modifier.fillMaxWidth(0.7f)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("${t("home.vpn")}: ↑ ${formatBytes(totals.vpnUp)}  ↓ ${formatBytes(totals.vpnDown)}")
                    Text("${t("home.direct")}: ↑ ${formatBytes(totals.directUp)}  ↓ ${formatBytes(totals.directDown)}")
                    Text("${t("home.blocked")}: ${totals.blocked}")
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------- Engine

@Composable
fun <T> Choice(label: String, current: T, options: List<T>, text: @Composable (T) -> String, onPick: (T) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Box {
            OutlinedButton(onClick = { open = true }) { Text(text(current)) }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                for (o in options) DropdownMenuItem(text = { Text(text(o)) }, onClick = { open = false; onPick(o) })
            }
        }
    }
}

@Composable
private fun EngineScreen(settings: DesktopSettings, update: (DesktopSettings) -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Title(t("engine.title"))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(settings.engine == EngineKind.WARP, { update(settings.copy(engine = EngineKind.WARP)) }, { Text(t("home.engine.warp")) })
            FilterChip(settings.engine == EngineKind.FIREFOX, { update(settings.copy(engine = EngineKind.FIREFOX)) }, { Text(t("home.engine.fx")) })
        }
        Spacer(Modifier.height(8.dp))
        if (settings.engine == EngineKind.WARP) {
            Choice(t("engine.protocol"), settings.protocol, DesktopSettings.PROTOCOLS, { t("proto.${it.name}") }) { update(settings.copy(protocol = it)) }
            Choice(
                t("engine.chain"), settings.chain, PrivacyChain.entries.toList(),
                { when (it) { PrivacyChain.NONE -> t("engine.chain.none"); PrivacyChain.PSIPHON -> t("engine.chain.psiphon"); PrivacyChain.TOR -> t("engine.chain.tor"); PrivacyChain.SINGBOX -> t("engine.chain.link") } }
            ) { update(settings.copy(chain = it)) }
            if (settings.chain == PrivacyChain.PSIPHON) {
                Choice(t("engine.region"), settings.psiphonRegion, listOf<String?>(null) + Chain.REGIONS, { it ?: t("engine.region.auto") }) { update(settings.copy(psiphonRegion = it)) }
            }
            if (settings.chain == PrivacyChain.SINGBOX) {
                OutlinedTextField(
                    value = settings.link, onValueChange = { update(settings.copy(link = it.trim())) },
                    label = { Text(t("engine.link")) }, singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(0.9f)
                )
                Text(t("engine.link.hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Choice(t("engine.scan"), settings.scanMode, com.madshield.app.core.CoreChoices.SCAN_MODES, { it }) { update(settings.copy(scanMode = it)) }
            Choice(t("engine.noize"), settings.noizeProfile, com.madshield.app.core.CoreChoices.NOIZE_PROFILES, { it }) { update(settings.copy(noizeProfile = it)) }
        }
        Spacer(Modifier.height(12.dp))
        Text(t("engine.applies"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ----------------------------------------------------------------------------------------------------------- Rules

@Composable
private fun RulesScreen(settings: DesktopSettings, update: (DesktopSettings) -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Title(t("rules.title"))
        Text(t("rules.hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedTextField(settings.directRules, { update(settings.copy(directRules = it)) }, label = { Text(t("rules.direct")) }, minLines = 5, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(settings.blockRules, { update(settings.copy(blockRules = it)) }, label = { Text(t("rules.block")) }, minLines = 5, modifier = Modifier.fillMaxWidth())
    }
}

// ----------------------------------------------------------------------------------------------------- Connections

@Composable
private fun ConnectionsScreen(conn: Connection) {
    var snap by remember { mutableStateOf<ConnSnapshot?>(null) }
    LaunchedEffect(Unit) {
        while (true) { snap = conn.routeFront()?.connections(); delay(1000) }
    }
    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Title(t("conns.title"))
            Spacer(Modifier.width(16.dp))
            OutlinedButton(onClick = { conn.routeFront()?.closeAllConnections() }) { Text(t("conns.closeAll")) }
        }
        val s = snap
        if (s == null || (s.active.isEmpty() && s.blocked.isEmpty())) {
            Text(t("conns.none"), color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                items(s.active + s.blocked, key = { it.id.toString() + it.route.name + it.name }) { c ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("${c.name}:${c.port}", Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(t("conns.route.${c.route.name}"), color = MaterialTheme.colorScheme.secondary)
                        Text("↑ ${formatBytes(c.upBytes)} ↓ ${formatBytes(c.downBytes)}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------- Logs

@Composable
private fun LogsScreen() {
    var lines by remember { mutableStateOf(RingLogBuffer.snapshot()) }
    var seen by remember { mutableStateOf(-1L) }
    LaunchedEffect(Unit) {
        while (true) {
            val v = RingLogBuffer.version
            if (v != seen) { seen = v; lines = RingLogBuffer.snapshot() }
            delay(500)
        }
    }
    val clip = LocalClipboardManager.current
    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Title(t("logs.title"))
            OutlinedButton(onClick = { clip.setText(AnnotatedString(lines.joinToString("\n"))) }) { Text(t("logs.copy")) }
            OutlinedButton(onClick = { RingLogBuffer.clear() }) { Text(t("logs.clear")) }
        }
        LazyColumn(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surface)) {
            items(lines.takeLast(400)) { Text(it, style = MaterialTheme.typography.bodySmall.copy(fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)) }
        }
    }
}

// ------------------------------------------------------------------------------------------------------- Settings

@Composable
private fun SettingsScreen(settings: DesktopSettings, update: (DesktopSettings) -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Title(t("set.title"))
        Choice(t("set.language"), settings.language, listOf("fa", "en"), { if (it == "fa") "فارسی" else "English" }) { update(settings.copy(language = it)) }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Switch(settings.connectOnStart, { update(settings.copy(connectOnStart = it)) })
            Text(t("set.connectOnStart"))
        }
        OutlinedButton(onClick = { runCatching { java.awt.Desktop.getDesktop().open(DataDir.root) } }) { Text(t("set.folder")) }
        OutlinedButton(onClick = { runCatching { java.awt.Desktop.getDesktop().open(java.io.File(Kit.dir, "LICENSES")) } }) { Text(t("set.licenses")) }
        Text(t("set.about"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
