package com.madshield.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
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

private enum class Page(val key: String) {
    HOME("nav.home"), ENGINE("nav.engine"), FOXY("nav.foxy"), RULES("nav.rules"),
    CONNS("nav.conns"), LOGS("nav.logs"), SETTINGS("nav.settings")
}

@Composable
fun App(conn: Connection, initial: DesktopSettings, startPage: String = "") {
    var settings by remember { mutableStateOf(initial) }
    var page by remember { mutableStateOf(Page.entries.firstOrNull { it.name.equals(startPage, true) } ?: Page.HOME) }
    fun update(new: DesktopSettings) { settings = new; SettingsStore.save(new) }

    val dark = androidx.compose.foundation.isSystemInDarkTheme()
    val rtl = settings.language == "fa"
    CompositionLocalProvider(
        LocalLang provides settings.language,
        LocalLayoutDirection provides if (rtl) LayoutDirection.Rtl else LayoutDirection.Ltr
    ) {
        SpecTheme(dark = dark, fa = rtl) {
            val sp = LocalSpec.current
            Surface(Modifier.fillMaxSize(), color = sp.ground, contentColor = sp.ink) {
                Row(Modifier.fillMaxSize()) {
                    Sidebar(page, { page = it })
                    Box(Modifier.width(1.dp).fillMaxHeight().background(sp.hair))
                    Box(Modifier.fillMaxSize().padding(horizontal = 36.dp, vertical = 28.dp)) {
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

// ----------------------------------------------------------------------------------------------------------- Sidebar

@Composable
private fun Sidebar(page: Page, onPick: (Page) -> Unit) {
    val sp = LocalSpec.current
    Column(Modifier.width(208.dp).fillMaxHeight().background(sp.surface).padding(vertical = 22.dp)) {
        Row(Modifier.padding(horizontal = 20.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            BrandMark()
            Text("MadShield", style = MaterialTheme.typography.titleMedium.copy(fontFamily = Fonts.mono, fontWeight = FontWeight.Bold))
        }
        Spacer(Modifier.height(28.dp))
        Page.entries.forEachIndexed { i, p -> NavItem("%02d".format(i + 1), t(p.key), p == page) { onPick(p) } }
        Spacer(Modifier.weight(1f))
        Text("v1.0.0 · Windows", Modifier.padding(horizontal = 20.dp), style = MaterialTheme.typography.labelSmall.copy(fontFamily = Fonts.mono), color = sp.muted)
    }
}

@Composable
private fun NavItem(index: String, label: String, selected: Boolean, onClick: () -> Unit) {
    val sp = LocalSpec.current
    val src = remember { MutableInteractionSource() }
    val hovered by src.collectIsHoveredAsState()
    val focused by src.collectIsFocusedAsState()
    Row(
        Modifier.fillMaxWidth().height(40.dp)
            .background(if (selected) sp.tint else if (hovered) sp.ground else Color.Transparent)
            .border(if (focused) 2.dp else 0.dp, if (focused) sp.ink else Color.Transparent)
            .hoverable(src)
            .clickable(interactionSource = src, indication = null, role = Role.Tab, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.width(3.dp).fillMaxHeight().background(if (selected) sp.accent else Color.Transparent))
        Text(index, Modifier.padding(start = 17.dp, end = 12.dp), style = MaterialTheme.typography.labelSmall.copy(fontFamily = Fonts.mono), color = if (selected) sp.accentInk else sp.muted)
        Text(label, style = MaterialTheme.typography.labelLarge.copy(fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium), maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

fun formatBytes(b: Long): String = when {
    b < 1024 -> "$b B"
    b < 1024L * 1024 -> "%.1f KB".format(b / 1024.0)
    b < 1024L * 1024 * 1024 -> "%.1f MB".format(b / 1048576.0)
    else -> "%.2f GB".format(b / 1073741824.0)
}

private fun formatDuration(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return "%d:%02d:%02d".format(s / 3600, (s / 60) % 60, s % 60)
}

// ------------------------------------------------------------------------------------------------------------- Home

@Composable
private fun HomeScreen(conn: Connection, settings: DesktopSettings) {
    val sp = LocalSpec.current
    val state by conn.state.collectAsState()
    var totals by remember { mutableStateOf(RouteTotals()) }
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    var down by remember { mutableStateOf(listOf<Long>()) }
    var up by remember { mutableStateOf(listOf<Long>()) }
    LaunchedEffect(state) {
        var prev: RouteTotals? = null
        while (true) {
            now = System.currentTimeMillis()
            val rf = conn.routeFront()
            if (rf == null) { prev = null; down = emptyList(); up = emptyList() }
            else {
                val cur = rf.routeTotals()
                totals = cur
                val p = prev
                if (p != null) {
                    down = (down + (cur.vpnDown - p.vpnDown).coerceAtLeast(0)).takeLast(60)
                    up = (up + (cur.vpnUp - p.vpnUp).coerceAtLeast(0)).takeLast(60)
                }
                prev = cur
            }
            delay(1000)
        }
    }
    val admin = remember { Elevation.isAdmin() }
    val s = state
    val connected = s is ConnState.Connected
    val busy = s is ConnState.Connecting || s is ConnState.Waiting || s is ConnState.Stopping
    val ledColor = when (s) {
        is ConnState.Connected -> sp.accent
        is ConnState.Connecting, is ConnState.Waiting, ConnState.Stopping -> sp.amber
        is ConnState.Failed -> sp.warn
        else -> sp.muted
    }
    val title = when (s) {
        ConnState.Idle -> t("home.idle")
        is ConnState.Connecting -> t("home.connecting")
        is ConnState.Connected -> t("home.connected")
        is ConnState.Waiting -> t("home.waiting").replace("%s", (s.retryInMs / 1000).toString())
        is ConnState.Failed -> t("home.failed")
        ConnState.Stopping -> t("home.stopping")
    }
    val engineText = if (settings.engine == EngineKind.FIREFOX) t("home.engine.fx")
    else t("home.engine.warp") + " · " + t("proto.${settings.protocol.name}") +
        when (settings.chain) { PrivacyChain.NONE -> ""; PrivacyChain.PSIPHON -> " + Psiphon"; PrivacyChain.TOR -> " + Tor"; PrivacyChain.SINGBOX -> " + " + t("engine.chain.link") }

    Row(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(28.dp)) {
        // Left: the state, and the one action.
        Column(Modifier.weight(1.05f)) {
            Eyebrow(t("spec.status"))
            Spacer(Modifier.height(14.dp))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                StatusLed(ledColor, pulse = s is ConnState.Connecting || s is ConnState.Waiting || s === ConnState.Stopping)
                Text(title, style = MaterialTheme.typography.displaySmall, maxLines = 2)
            }
            Spacer(Modifier.height(10.dp))
            val detail: String? = when (s) {
                is ConnState.Connecting -> Strings.get(LocalLang.current, "step.${s.step}").let { if (it.startsWith("step.")) s.step else it }
                is ConnState.Waiting -> s.reason
                is ConnState.Failed -> s.reason
                else -> null
            }
            if (detail != null) {
                Text(detail, color = if (s is ConnState.Connecting) sp.muted else sp.warn, style = MaterialTheme.typography.bodyMedium, maxLines = 4, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.height(28.dp))
            ActionButton(
                text = when { connected -> t("home.disconnect"); busy -> t("home.cancel"); else -> t("home.connect") },
                onClick = { if (connected || busy) conn.disconnect() else conn.connect(settings) },
                modifier = Modifier.fillMaxWidth(),
                primary = !connected && !busy,
                enabled = s !is ConnState.Stopping,
                height = 56.dp
            )
            if (!admin) {
                Spacer(Modifier.height(16.dp))
                Text(t("home.admin"), color = sp.warn, style = MaterialTheme.typography.bodyMedium)
            }
        }

        // Right: the data sheet of the live connection.
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(20.dp)) {
            Panel(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(horizontal = 18.dp, vertical = 14.dp)) {
                    Eyebrow(t("spec.readout"))
                    Spacer(Modifier.height(4.dp))
                    val exit = (s as? ConnState.Connected)?.exit
                    SpecRow(t("spec.engine"), engineText, mono = false)
                    SpecRow(t("home.exit"), exit?.ip ?: "—")
                    SpecRow(t("spec.location"), if (exit != null) listOfNotNull(exit.country, exit.colo).joinToString(" · ").ifEmpty { "—" } else "—")
                    SpecRow(t("spec.uptime"), if (s is ConnState.Connected) formatDuration(now - s.sinceMs) else "—")
                    SpecRow(t("home.vpn"), if (connected) "↑ ${formatBytes(totals.vpnUp)}   ↓ ${formatBytes(totals.vpnDown)}" else "—")
                    SpecRow(t("home.direct"), if (connected) "↑ ${formatBytes(totals.directUp)}   ↓ ${formatBytes(totals.directDown)}" else "—")
                    SpecRow(t("home.blocked"), if (connected) totals.blocked.toString() else "—", last = true)
                }
            }
            Panel(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(18.dp)) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Eyebrow(t("spec.throughput"), Modifier.weight(1f))
                        Text(
                            "↓ " + formatBytes(down.lastOrNull() ?: 0) + "/s    ↑ " + formatBytes(up.lastOrNull() ?: 0) + "/s",
                            style = MaterialTheme.typography.labelMedium.copy(fontFamily = Fonts.mono), color = if (connected) sp.accentInk else sp.muted
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Sparkline(down, Modifier.fillMaxWidth().height(72.dp), color = sp.accentInk, base = sp.hair)
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------- Engine

/** Label on the start side, a drop-down on the end side. (The Foxy page uses this too.) */
@Composable
fun <T> Choice(label: String, current: T, options: List<T>, text: @Composable (T) -> String, onPick: (T) -> Unit) {
    FormRow(label) { Dropdown(current, options, text, onPick) }
}

@Composable
private fun EngineScreen(settings: DesktopSettings, update: (DesktopSettings) -> Unit) {
    val sp = LocalSpec.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        PageHeader(t("engine.title"), t("engine.applies"))
        Panel(Modifier.widthIn(max = 760.dp).fillMaxWidth()) {
            Column(Modifier.padding(horizontal = 18.dp, vertical = 6.dp)) {
                FormRow(t("engine.title"), last = settings.engine == EngineKind.FIREFOX) {
                    FilterChip(settings.engine == EngineKind.WARP, { update(settings.copy(engine = EngineKind.WARP)) }, { Text(t("home.engine.warp")) })
                    FilterChip(settings.engine == EngineKind.FIREFOX, { update(settings.copy(engine = EngineKind.FIREFOX)) }, { Text(t("home.engine.fx")) })
                }
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
                        Column(Modifier.padding(vertical = 12.dp)) {
                            OutlinedTextField(
                                value = settings.link, onValueChange = { update(settings.copy(link = it.trim())) },
                                label = { Text(t("engine.link")) }, singleLine = true, visualTransformation = PasswordVisualTransformation(),
                                modifier = Modifier.fillMaxWidth()
                            )
                            Text(t("engine.link.hint"), Modifier.padding(top = 6.dp), style = MaterialTheme.typography.bodySmall, color = sp.muted)
                        }
                        Hairline()
                    }
                    Choice(t("engine.scan"), settings.scanMode, com.madshield.app.core.CoreChoices.SCAN_MODES, { it }) { update(settings.copy(scanMode = it)) }
                    Choice(t("engine.noize"), settings.noizeProfile, com.madshield.app.core.CoreChoices.NOIZE_PROFILES, { it }) { update(settings.copy(noizeProfile = it)) }
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------- Rules

@Composable
private fun RulesScreen(settings: DesktopSettings, update: (DesktopSettings) -> Unit) {
    val mono = MaterialTheme.typography.bodyMedium.copy(fontFamily = Fonts.mono)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        PageHeader(t("rules.title"), t("rules.hint"))
        OutlinedTextField(settings.directRules, { update(settings.copy(directRules = it)) }, label = { Text(t("rules.direct")) }, minLines = 5, textStyle = mono, modifier = Modifier.widthIn(max = 760.dp).fillMaxWidth())
        OutlinedTextField(settings.blockRules, { update(settings.copy(blockRules = it)) }, label = { Text(t("rules.block")) }, minLines = 5, textStyle = mono, modifier = Modifier.widthIn(max = 760.dp).fillMaxWidth())
    }
}

// ----------------------------------------------------------------------------------------------------- Connections

@Composable
private fun ConnectionsScreen(conn: Connection) {
    val sp = LocalSpec.current
    var snap by remember { mutableStateOf<ConnSnapshot?>(null) }
    LaunchedEffect(Unit) {
        while (true) { snap = conn.routeFront()?.connections(); delay(1000) }
    }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
            Box(Modifier.weight(1f)) { PageHeader(t("conns.title")) }
            ActionButton(t("conns.closeAll"), { conn.routeFront()?.closeAllConnections() }, primary = false, height = 36.dp)
        }
        val sn = snap
        if (sn == null || (sn.active.isEmpty() && sn.blocked.isEmpty())) {
            Text(t("conns.none"), color = sp.muted)
        } else {
            Panel(Modifier.fillMaxSize()) {
                LazyColumn(Modifier.padding(horizontal = 18.dp, vertical = 6.dp)) {
                    items(sn.active + sn.blocked, key = { it.id.toString() + it.route.name + it.name }) { c ->
                        Column {
                            Row(Modifier.fillMaxWidth().padding(vertical = 9.dp), horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text("${c.name}:${c.port}", Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = Fonts.mono))
                                val rc = when (c.route.name) { "PROXY" -> sp.accentInk; "BLOCK" -> sp.warn; else -> sp.muted }
                                Text(t("conns.route.${c.route.name}"), color = rc, style = MaterialTheme.typography.labelMedium)
                                Text("↑ ${formatBytes(c.upBytes)}  ↓ ${formatBytes(c.downBytes)}", style = MaterialTheme.typography.bodySmall.copy(fontFamily = Fonts.mono), color = sp.muted)
                            }
                            Hairline()
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------- Logs

@Composable
private fun LogsScreen() {
    val sp = LocalSpec.current
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
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(Modifier.weight(1f)) { PageHeader(t("logs.title")) }
            ActionButton(t("logs.copy"), { clip.setText(AnnotatedString(lines.joinToString("\n"))) }, primary = false, height = 36.dp)
            ActionButton(t("logs.clear"), { RingLogBuffer.clear() }, primary = false, height = 36.dp)
        }
        Panel(Modifier.fillMaxSize()) {
            LazyColumn(Modifier.fillMaxSize().padding(14.dp)) {
                items(lines.takeLast(400)) { Text(it, style = MaterialTheme.typography.bodySmall.copy(fontFamily = Fonts.mono, fontSize = 12.sp, lineHeight = 18.sp)) }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------------- Settings

@Composable
private fun SettingsScreen(settings: DesktopSettings, update: (DesktopSettings) -> Unit) {
    val sp = LocalSpec.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        PageHeader(t("set.title"))
        Panel(Modifier.widthIn(max = 760.dp).fillMaxWidth()) {
            Column(Modifier.padding(horizontal = 18.dp, vertical = 6.dp)) {
                Choice(t("set.language"), settings.language, listOf("fa", "en"), { if (it == "fa") "فارسی" else "English" }) { update(settings.copy(language = it)) }
                FormRow(t("set.connectOnStart")) { Switch(settings.connectOnStart, { update(settings.copy(connectOnStart = it)) }) }
                FormRow(t("set.folder")) { ActionButton(t("set.folder"), { runCatching { java.awt.Desktop.getDesktop().open(DataDir.root) } }, primary = false, height = 36.dp) }
                FormRow(t("set.licenses"), last = true) { ActionButton(t("set.licenses"), { runCatching { java.awt.Desktop.getDesktop().open(java.io.File(Kit.dir, "LICENSES")) } }, primary = false, height = 36.dp) }
            }
        }
        Text(t("set.about"), Modifier.padding(top = 16.dp).widthIn(max = 760.dp), style = MaterialTheme.typography.bodySmall, color = sp.muted)
    }
}
