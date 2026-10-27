package com.aethershield.app.ui

import android.content.Intent
import android.os.SystemClock
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import com.aethershield.app.BuildConfig
import com.aethershield.app.R
import com.aethershield.app.core.*
import com.aethershield.app.ui.components.BackTopBar
import com.aethershield.app.ui.components.HelperText
import com.aethershield.app.ui.components.MonoFamily
import com.aethershield.app.ui.components.SectionCard
import com.aethershield.app.ui.components.SwitchRow
import com.aethershield.app.ui.components.rememberIsForeground
import com.aethershield.app.util.LogRedactor
import com.aethershield.app.util.RingLogBuffer
import com.aethershield.app.vpn.TProxyService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date
import java.util.Locale

/**
 * Plain-language health page. Nothing here runs by itself: the live measurement is a switch that is off
 * when the page opens, the connection tests run only when the button is pressed, and every loop stops when
 * the page is left or the app goes to the background. The shareable report has no log lines, IP addresses
 * or tokens unless the user turns the redacted log tail on, and even then it passes the redactor.
 */
@Composable
fun DiagnosticsScreen(config: EngineConfig, connectionState: ConnectionState, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val foreground by rememberIsForeground()
    val stats by AetherController.stats.collectAsState()
    val active by AetherController.active.collectAsState()
    val lastExit by DiagnosticsHub.lastExit.collectAsState()
    val scope = rememberCoroutineScope()

    val vpnMode = config.mode == ConnectionMode.VPN
    val port = (active ?: config).socksPort
    val kind = when (connectionState) {
        ConnectionState.Idle -> StateKind.IDLE
        ConnectionState.Connecting -> StateKind.CONNECTING
        is ConnectionState.Connected -> StateKind.CONNECTED
        ConnectionState.Disconnecting -> StateKind.DISCONNECTING
        is ConnectionState.Error -> StateKind.ERROR
    }

    var live by remember { mutableStateOf(false) }
    var withTail by remember { mutableStateOf(false) }
    var rates by remember { mutableStateOf<RateSummary?>(null) }
    var engineAlive by remember { mutableStateOf<Boolean?>(null) }
    var bridgeUp by remember { mutableStateOf<Boolean?>(null) }
    var probes by remember { mutableStateOf(ProbeResults()) }
    var testing by remember { mutableStateOf(false) }
    var meterRunning by remember { mutableStateOf(false) }
    var meterResult by remember { mutableStateOf<SpeedMeterCheck.Result?>(null) }
    var meterUnavailable by remember { mutableStateOf(false) }
    var signals by remember { mutableStateOf(LogSignals()) }
    var udpView by remember { mutableStateOf<DiagnosticsHub.UdpView?>(null) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val window = remember { RateWindow() }

    // One cheap look when the page opens (and when the state changes), so "engine not running" is never guessed.
    LaunchedEffect(kind) {
        val snap = withContext(Dispatchers.IO) {
            Triple(
                DiagnosticsHub.engineCpuTicks?.invoke() != null,
                if (vpnMode && TProxyService.available) runCatching { TProxyService.TProxyIsRunning() }.getOrNull() else null,
                LogSignals.scanRecent(RingLogBuffer.tail(200))
            )
        }
        engineAlive = snap.first
        bridgeUp = snap.second
        signals = snap.third
        now = System.currentTimeMillis()
    }

    // Keeps "for 2 min" style texts fresh, only while the page is visible.
    LaunchedEffect(foreground) {
        if (!foreground) return@LaunchedEffect
        while (true) {
            udpView = withContext(Dispatchers.IO) { DiagnosticsHub.udpView?.invoke() } // a few counters, no I/O
            delay(2_000)
            now = System.currentTimeMillis()
        }
    }

    // Live measurement: only when switched on, only while visible, every 3 seconds.
    LaunchedEffect(live, foreground, vpnMode) {
        window.clear()
        rates = null
        if (!live || !foreground) return@LaunchedEffect
        while (true) {
            val snap = withContext(Dispatchers.IO) {
                val ticks = DiagnosticsHub.engineCpuTicks?.invoke()
                val st = if (vpnMode && TProxyService.available) runCatching { TProxyService.TProxyGetStats() }.getOrNull() else null
                val up = if (vpnMode && TProxyService.available) runCatching { TProxyService.TProxyIsRunning() }.getOrNull() else null
                listOf(ticks, st, up, LogSignals.scanRecent(RingLogBuffer.tail(200)))
            }
            val ticks = snap[0] as Long?
            @Suppress("UNCHECKED_CAST")
            val st = snap[1] as LongArray?
            engineAlive = ticks != null
            bridgeUp = snap[2] as Boolean?
            signals = snap[3] as LogSignals
            val ok = st != null && st.size >= 4
            window.add(
                SystemClock.elapsedRealtime(), ticks, android.os.Process.getElapsedCpuTime(),
                if (ok) st!![1] else null, if (ok) st!![3] else null
            )
            rates = window.summary()
            now = System.currentTimeMillis()
            delay(3_000)
        }
    }

    val input = DiagInput(
        state = kind,
        engineAlive = engineAlive ?: true,
        bridgeUp = bridgeUp,
        probes = probes,
        rates = rates,
        screenOn = true,
        reconnectsLast10Min = stats.reconnectsWithin(now),
        signals = signals,
        chainOn = (active ?: config).effectiveChain != PrivacyChain.NONE
    )
    val findings = remember(input) { Diagnosis.diagnose(input) }
    // update20: UDP. Only meaningful while connected; the numbers come from the running front, if there is one.
    val udpState: UdpState? = if (kind == StateKind.CONNECTED) {
        val running = active ?: config
        UdpStatus.of(config.udpEnabled, running.effectiveChain, udpView?.carried != null, udpView?.carried == true, running.udpEnabled)
    } else null

    fun reportText(): String = DiagnosticsReport.render(
        appVersion = BuildConfig.VERSION_NAME,
        input = input,
        findings = findings,
        stats = stats,
        nowMs = now,
        rates = rates,
        includeLogTail = if (withTail) RingLogBuffer.tail(60) else null,
        redact = LogRedactor::redact,
        udp = UdpReport(config.udpEnabled, udpState ?: if (config.udpEnabled) UdpState.RELAY else UdpState.OFF, udpView?.stats)
    )

    val copiedText = stringResource(R.string.copied)
    Scaffold(topBar = {
        BackTopBar(stringResource(R.string.diag_title), onBack, actions = {
            IconButton(onClick = {
                clipboard.setText(AnnotatedString(reportText()))
                Toast.makeText(ctx, copiedText, Toast.LENGTH_SHORT).show()
            }) { Icon(Icons.Rounded.ContentCopy, contentDescription = stringResource(R.string.action_copy)) }
            IconButton(onClick = {
                val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, reportText())
                ctx.startActivity(Intent.createChooser(send, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }) { Icon(Icons.Rounded.Share, contentDescription = stringResource(R.string.diag_share)) }
        })
    }) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ------------------------------------------------------------ findings
            SectionCard(stringResource(R.string.diag_sec_findings)) {
                if (findings.isEmpty()) {
                    Text(stringResource(R.string.diag_not_connected), style = MaterialTheme.typography.bodyMedium)
                }
                findings.forEach { FindingCard(it) }
                HelperText(stringResource(R.string.diag_probable_note))
            }

            // ------------------------------------------------------------ overview
            SectionCard(stringResource(R.string.diag_sec_overview)) {
                StatLine(stringResource(R.string.diag_state), stateLabel(kind))
                StatLine(
                    stringResource(R.string.diag_since),
                    if (stats.stateSinceMs > 0) durationText(((now - stats.stateSinceMs) / 1000).coerceAtLeast(0)) else "-"
                )
                StatLine(stringResource(R.string.diag_retries), "${stats.retries}")
                StatLine(stringResource(R.string.diag_errors), "${stats.errors}")
                StatLine(stringResource(R.string.diag_reconnects10), "${stats.reconnectsWithin(now)}")
                StatLine(
                    stringResource(R.string.diag_integrity),
                    when (val r = EngineProcessManager.cachedIntegrity) {
                        null -> stringResource(R.string.diag_integrity_unchecked)
                        else -> if (r.ok) stringResource(R.string.diag_integrity_ok) else stringResource(R.string.diag_integrity_bad)
                    }
                )
            }

            // ------------------------------------------------------------ UDP
            SectionCard(stringResource(R.string.diag_sec_udp)) {
                StatLine(
                    stringResource(R.string.diag_udp_setting),
                    stringResource(if (config.udpEnabled) R.string.diag_udp_enabled else R.string.diag_udp_disabled)
                )
                if (udpState == null) {
                    HelperText(stringResource(R.string.diag_udp_not_connected))
                } else {
                    StatLine(stringResource(R.string.diag_udp_effect), stringResource(udpStateText(udpState)))
                    val u = udpView?.stats
                    if (u != null) {
                        StatLine(stringResource(R.string.diag_udp_active), "${u.active}")
                        StatLine(stringResource(R.string.diag_udp_refused), "${u.refusedAssociations}")
                        StatLine(stringResource(R.string.diag_udp_dropped), "${u.droppedTotal}")
                        if (u.droppedTotal > 0) {
                            HelperText(
                                stringResource(
                                    R.string.diag_udp_dropped_detail,
                                    u.droppedBlocked, u.droppedGuard, u.droppedBadPacket, u.droppedNoUpstream + u.droppedResolve, u.droppedFull
                                )
                            )
                        }
                    } else {
                        HelperText(stringResource(R.string.diag_udp_no_counters))
                    }
                }
            }

            // ------------------------------------------------------------ live usage
            SectionCard(stringResource(R.string.diag_sec_usage)) {
                SwitchRow(stringResource(R.string.diag_live), stringResource(R.string.diag_live_sub), live, { live = it })
                val r = rates
                if (live && r == null) HelperText(stringResource(R.string.diag_measuring))
                if (r != null) {
                    StatLine(
                        stringResource(R.string.diag_cpu_engine),
                        r.engineCpuPercent?.let { String.format(Locale.US, "%.0f%%", it) } ?: "-"
                    )
                    StatLine(stringResource(R.string.diag_cpu_app), String.format(Locale.US, "%.0f%%", r.appCpuPercent ?: 0.0))
                    if (r.throughputKnown) {
                        StatLine(stringResource(R.string.stat_download), Diagnosis.formatRate(r.downBps))
                        StatLine(stringResource(R.string.stat_upload), Diagnosis.formatRate(r.upBps))
                    } else {
                        HelperText(stringResource(R.string.diag_no_throughput))
                    }
                    HelperText(stringResource(R.string.diag_cpu_note))
                }
            }

            // ------------------------------------------------------------ speed meter check (update21)
            // Two reads of the phone's byte counters, ten seconds apart, only when the button is pressed.
            SectionCard(stringResource(R.string.diag_sec_meter)) {
                HelperText(stringResource(R.string.diag_meter_sub))
                Spacer(Modifier.height(6.dp))
                Button(
                    enabled = !meterRunning,
                    onClick = {
                        scope.launch {
                            meterRunning = true
                            meterUnavailable = false
                            meterResult = null
                            try {
                                val first = withContext(Dispatchers.IO) { SpeedMeterProbe.read(ctx) }
                                if (first == null) {
                                    meterUnavailable = true
                                } else {
                                    val startedAt = SystemClock.elapsedRealtime()
                                    delay(METER_WINDOW_MS)
                                    val second = withContext(Dispatchers.IO) { SpeedMeterProbe.read(ctx) }
                                    val elapsed = SystemClock.elapsedRealtime() - startedAt
                                    if (second == null) meterUnavailable = true
                                    else meterResult = SpeedMeterCheck.compute(
                                        first.readings, second.readings, first.system, second.system, elapsed
                                    )
                                }
                            } finally {
                                meterRunning = false
                            }
                        }
                    }
                ) { Text(stringResource(if (meterRunning) R.string.diag_meter_running else R.string.diag_meter_run)) }
                if (meterUnavailable) HelperText(stringResource(R.string.diag_meter_unavailable))
                meterResult?.let { r ->
                    when {
                        !r.linkSeen -> HelperText(stringResource(R.string.diag_meter_no_link))
                        r.countersHidden -> HelperText(stringResource(R.string.diag_meter_hidden))
                        !r.enough -> HelperText(stringResource(R.string.diag_meter_too_quiet))
                        else -> {
                            // Only the direction that carries the transfer: loopback counts bytes both ways, so the
                            // other direction's factors (mostly acks over a huge loopback figure) would be nonsense.
                            if (r.dominantIsDown) MeterFlow(R.string.stat_download, r.down) else MeterFlow(R.string.stat_upload, r.up)
                            HelperText(stringResource(R.string.diag_meter_note))
                        }
                    }
                    // The raw counters, whatever the verdict: a result that makes no sense can still be read from these.
                    Text(
                        stringResource(R.string.diag_meter_raw),
                        style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp)
                    )
                    r.rows.forEach { row ->
                        StatLine(
                            "${row.name} (${stringResource(meterKindLabel(row.kind))})",
                            "↓ ${Diagnosis.formatRate(row.downBps)}  ↑ ${Diagnosis.formatRate(row.upBps)}"
                        )
                    }
                    StatLine(
                        stringResource(R.string.diag_meter_total),
                        "↓ ${r.down.system?.let { Diagnosis.formatRate(it) } ?: "-"}  ↑ ${r.up.system?.let { Diagnosis.formatRate(it) } ?: "-"}"
                    )
                }
            }

            // ------------------------------------------------------------ on-demand tests
            SectionCard(stringResource(R.string.diag_sec_tests)) {
                HelperText(stringResource(R.string.diag_tests_sub))
                Spacer(Modifier.height(6.dp))
                Button(
                    enabled = !testing && kind == StateKind.CONNECTED,
                    onClick = {
                        scope.launch {
                            testing = true
                            val result = withContext(Dispatchers.IO) {
                                val host = TunnelConfig.SOCKS_HOST
                                ProbeResults(
                                    socksAnswers = SocksProbe.handshakeOk(host, port, 800, 1_200),
                                    tunnelByIp = SocksProbe.connectThrough(host, port, TEST_IP, 443, 6_000),
                                    tunnelByName = SocksProbe.connectThrough(host, port, TEST_NAME, 443, 6_000),
                                    directByIp = SocksProbe.directConnect(TEST_IP, 443, 4_000)
                                )
                            }
                            val snap = withContext(Dispatchers.IO) {
                                Triple(
                                    DiagnosticsHub.engineCpuTicks?.invoke() != null,
                                    if (vpnMode && TProxyService.available) runCatching { TProxyService.TProxyIsRunning() }.getOrNull() else null,
                                    LogSignals.scanRecent(RingLogBuffer.tail(200))
                                )
                            }
                            probes = result
                            engineAlive = snap.first
                            bridgeUp = snap.second
                            signals = snap.third
                            now = System.currentTimeMillis()
                            testing = false
                        }
                    }
                ) { Text(stringResource(if (testing) R.string.diag_testing else R.string.diag_run_tests)) }
                if (kind != StateKind.CONNECTED) HelperText(stringResource(R.string.diag_tests_need_connection))
                ProbeLine(R.string.diag_probe_socks, probes.socksAnswers)
                ProbeLine(R.string.diag_probe_tunnel_ip, probes.tunnelByIp)
                ProbeLine(R.string.diag_probe_tunnel_name, probes.tunnelByName)
                ProbeLine(R.string.diag_probe_direct, probes.directByIp)
            }

            // ------------------------------------------------------------ last unexpected stop
            lastExit?.let { exit ->
                SectionCard(stringResource(R.string.diag_sec_last_stop)) {
                    Text(exit.reason, style = MaterialTheme.typography.bodyMedium)
                    HelperText(DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(exit.atMs)))
                    Spacer(Modifier.height(6.dp))
                    exit.tail.takeLast(12).forEach {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr)
                        )
                    }
                    HelperText(stringResource(R.string.diag_last_stop_note))
                    TextButton(onClick = { DiagnosticsHub.clear() }) { Text(stringResource(R.string.action_clear)) }
                }
            }

            // ------------------------------------------------------------ report options
            SectionCard(stringResource(R.string.diag_sec_report)) {
                HelperText(stringResource(R.string.diag_report_note))
                SwitchRow(stringResource(R.string.diag_report_tail), stringResource(R.string.diag_report_tail_sub), withTail, { withTail = it })
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

private const val TEST_IP = "1.1.1.1"
private const val TEST_NAME = "cloudflare.com"
private const val METER_WINDOW_MS = 10_000L

/** One direction of the speed meter check: the rate on each interface, then the factors against the real link. */
@Composable
private fun MeterFlow(@StringRes title: Int, f: SpeedMeterCheck.Flow) {
    Text(stringResource(title), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
    StatLine(stringResource(R.string.diag_meter_link), Diagnosis.formatRate(f.physical))
    StatLine(stringResource(R.string.diag_meter_tunnel), Diagnosis.formatRate(f.tunnel))
    StatLine(stringResource(R.string.diag_meter_loopback), Diagnosis.formatRate(f.loopback))
    f.system?.let { StatLine(stringResource(R.string.diag_meter_total), Diagnosis.formatRate(it)) }
    f.tunnelPlusLink?.let { StatLine(stringResource(R.string.diag_meter_factor_tunnel), times(it)) }
    f.withLoopback?.let { StatLine(stringResource(R.string.diag_meter_factor_loopback), times(it)) }
    f.systemTotal?.let { StatLine(stringResource(R.string.diag_meter_factor_total), times(it)) }
}

private fun times(v: Double): String = String.format(Locale.US, "%.1f×", v)

private fun meterKindLabel(k: SpeedMeterCheck.Kind): Int = when (k) {
    SpeedMeterCheck.Kind.PHYSICAL -> R.string.diag_meter_link
    SpeedMeterCheck.Kind.TUNNEL -> R.string.diag_meter_tunnel
    SpeedMeterCheck.Kind.LOOPBACK -> R.string.diag_meter_loopback
}

private fun udpStateText(s: UdpState): Int = when (s) {
    UdpState.OFF -> R.string.diag_udp_state_off
    UdpState.RELAY -> R.string.diag_udp_state_relay
    UdpState.UPSTREAM_DIRECT -> R.string.diag_udp_state_direct
    UdpState.CHAIN_REFUSES -> R.string.diag_udp_state_chain
    UdpState.PENDING_ON -> R.string.diag_udp_state_pending_on
    UdpState.PENDING_OFF -> R.string.diag_udp_state_pending_off
}

@Composable
private fun StatLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Text(ltr(value), style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ProbeLine(@StringRes label: Int, result: Boolean?) {
    StatLine(
        stringResource(label),
        when (result) {
            null -> stringResource(R.string.diag_probe_not_run)
            true -> stringResource(R.string.diag_probe_ok)
            false -> stringResource(R.string.diag_probe_fail)
        }
    )
}

@Composable
private fun stateLabel(k: StateKind): String = stringResource(
    when (k) {
        StateKind.IDLE -> R.string.diag_state_idle
        StateKind.CONNECTING -> R.string.diag_state_connecting
        StateKind.CONNECTED -> R.string.diag_state_connected
        StateKind.DISCONNECTING -> R.string.diag_state_disconnecting
        StateKind.ERROR -> R.string.diag_state_error
    }
)

private fun durationText(totalSec: Long): String = when {
    totalSec >= 3600 -> String.format(Locale.US, "%dh %02dm", totalSec / 3600, (totalSec % 3600) / 60)
    totalSec >= 60 -> String.format(Locale.US, "%dm %02ds", totalSec / 60, totalSec % 60)
    else -> "${totalSec}s"
}

@Composable
private fun FindingCard(f: Finding) {
    val (title, body) = findingTexts(f.kind)
    val conf = stringResource(
        when (f.confidence) {
            Confidence.LOW -> R.string.diag_conf_low
            Confidence.MEDIUM -> R.string.diag_conf_medium
            Confidence.HIGH -> R.string.diag_conf_high
        }
    )
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
            Text(conf, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(body), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(6.dp))
            f.evidence.forEach {
                Text(
                    "• $it",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFamily, textDirection = TextDirection.Ltr),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

private fun findingTexts(k: DiagKind): Pair<Int, Int> = when (k) {
    DiagKind.ENGINE_DOWN -> R.string.diag_engine_down_t to R.string.diag_engine_down_b
    DiagKind.DNS_NOT_ANSWERING -> R.string.diag_dns_t to R.string.diag_dns_b
    DiagKind.TCP_FAILING -> R.string.diag_tcp_t to R.string.diag_tcp_b
    DiagKind.HANDSHAKE_FAILING -> R.string.diag_handshake_t to R.string.diag_handshake_b
    DiagKind.STALLED -> R.string.diag_stalled_t to R.string.diag_stalled_b
    DiagKind.FLAPPING -> R.string.diag_flapping_t to R.string.diag_flapping_b
    DiagKind.CPU_DURING_TRANSFER -> R.string.diag_cpu_transfer_t to R.string.diag_cpu_transfer_b
    DiagKind.CPU_WHILE_IDLE -> R.string.diag_cpu_idle_t to R.string.diag_cpu_idle_b
    DiagKind.CPU_HIGH_LOAD_UNKNOWN -> R.string.diag_cpu_unknown_t to R.string.diag_cpu_unknown_b
    DiagKind.NO_PROBLEM_SEEN -> R.string.diag_ok_t to R.string.diag_ok_b
}
