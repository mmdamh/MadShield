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
    var signals by remember { mutableStateOf(LogSignals()) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val window = remember { RateWindow() }

    // One cheap look when the page opens (and when the state changes), so "engine not running" is never guessed.
    LaunchedEffect(kind) {
        val snap = withContext(Dispatchers.IO) {
            Triple(
                DiagnosticsHub.engineCpuTicks?.invoke() != null,
                if (vpnMode && TProxyService.available) runCatching { TProxyService.TProxyIsRunning() }.getOrNull() else null,
                LogSignals.scan(RingLogBuffer.tail(200))
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
                listOf(ticks, st, up, LogSignals.scan(RingLogBuffer.tail(200)))
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

    fun reportText(): String = DiagnosticsReport.render(
        appVersion = BuildConfig.VERSION_NAME,
        input = input,
        findings = findings,
        stats = stats,
        nowMs = now,
        rates = rates,
        includeLogTail = if (withTail) RingLogBuffer.tail(60) else null,
        redact = LogRedactor::redact
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
                                    LogSignals.scan(RingLogBuffer.tail(200))
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
