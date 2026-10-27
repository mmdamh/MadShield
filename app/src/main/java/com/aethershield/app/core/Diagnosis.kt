package com.aethershield.app.core

import java.util.Locale

/**
 * Turns measurements into a plain-language probable cause, always with a confidence and the evidence it
 * rests on ("probably DNS", never "it is DNS"). Everything here is pure data in, data out, so it can be
 * tested off-device. Heavy measurements (DNS / reachability probes, CPU windows) are produced elsewhere,
 * only on request, and arrive here as nullable inputs: null means "not measured", never "fine".
 */
enum class Confidence { LOW, MEDIUM, HIGH }

enum class DiagKind {
    ENGINE_DOWN,
    DNS_NOT_ANSWERING,
    TCP_FAILING,
    HANDSHAKE_FAILING,
    STALLED,
    FLAPPING,
    CPU_DURING_TRANSFER,
    CPU_WHILE_IDLE,
    CPU_HIGH_LOAD_UNKNOWN,
    NO_PROBLEM_SEEN
}

data class Finding(val kind: DiagKind, val confidence: Confidence, val evidence: List<String>)

/** Which kinds of trouble the recent log lines mention. Counts only, never the lines themselves. */
data class LogSignals(val dns: Int = 0, val tcp: Int = 0, val handshake: Int = 0, val timeouts: Int = 0) {
    companion object {
        /**
         * Log lines that mean "the tunnel works again". Anything before the LAST one of these is history:
         * it was already recovered from and must not be blamed for the current state.
         */
        val RECOVERY_MARKERS = listOf("tunnel bridge running", "tunnel recovered", "[proxy] engine up")

        /** Only the lines since the last recovery (or all of them when there was none). */
        fun sinceLastRecovery(lines: List<String>): List<String> {
            val last = lines.indexOfLast { l ->
                val low = l.lowercase(Locale.ROOT)
                RECOVERY_MARKERS.any { it in low }
            }
            return if (last < 0) lines else lines.subList(last + 1, lines.size)
        }

        /** [scan] over [sinceLastRecovery]: what the Diagnostics page uses. */
        fun scanRecent(lines: List<String>): LogSignals = scan(sinceLastRecovery(lines))

        /** Lower-cased phrases; the core and the app are the only writers of these lines. */
        fun scan(lines: List<String>): LogSignals {
            var dns = 0; var tcp = 0; var hs = 0; var to = 0
            for (raw in lines) {
                val l = raw.lowercase(Locale.ROOT)
                val failed = "fail" in l || "error" in l || "refused" in l || "rejected" in l || "denied" in l
                val timedOut = "timed out" in l || "timeout" in l
                if (timedOut) to++
                if ("dns" in l && (failed || timedOut || "servfail" in l)) dns++
                // "broken pipe" is deliberately NOT here: it is what a connection that the other side closed
                // (or a stalled outer tunnel) looks like, not a sign that TCP through the tunnel is failing.
                if ("connection refused" in l || "connection reset" in l || "unreachable" in l ||
                    "tcp connect" in l && (failed || timedOut)
                ) tcp++
                // A lone TLS alert / BAD_DECRYPT line is normal noise when a connection is torn down, so TLS
                // alerts alone do not count; only a handshake, certificate or gateway failure does.
                if (("handshake" in l && (failed || timedOut)) || "certificate" in l && failed ||
                    "gateway scan failed" in l || "no gateway" in l
                ) hs++
            }
            return LogSignals(dns, tcp, hs, to)
        }
    }
}

enum class StateKind { IDLE, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

/** What the on-demand reachability probes found. Each is null when that probe was not run. */
data class ProbeResults(
    val socksAnswers: Boolean? = null,   // the local SOCKS5 port answers a handshake
    val tunnelByIp: Boolean? = null,     // TCP connect to a fixed IP through the tunnel
    val tunnelByName: Boolean? = null,   // TCP connect to a hostname through the tunnel (engine resolves it)
    val directByIp: Boolean? = null      // the same IP, from this app outside the tunnel
)

data class DiagInput(
    val state: StateKind,
    val engineAlive: Boolean,
    val bridgeUp: Boolean?,              // VPN mode only; null in proxy mode
    val probes: ProbeResults = ProbeResults(),
    val rates: RateSummary? = null,
    val screenOn: Boolean = true,
    val reconnectsLast10Min: Int = 0,
    val signals: LogSignals = LogSignals(),
    val chainOn: Boolean = false
)

object Diagnosis {
    const val CPU_HIGH_PERCENT = 25.0
    const val ACTIVE_BPS = 32L * 1024
    const val IDLE_BPS = 8L * 1024
    const val STALL_SAMPLES_MEDIUM = 3
    const val STALL_SAMPLES_HIGH = 6
    const val MIN_CPU_WINDOW_MS = 8_000L

    /** While connected, fewer failed-handshake lines than this are noise, not a finding. */
    const val HANDSHAKE_MIN_WHEN_CONNECTED = 3

    fun diagnose(i: DiagInput): List<Finding> {
        val out = mutableListOf<Finding>()
        val p = i.probes
        val connectedish = i.state == StateKind.CONNECTED || i.state == StateKind.ERROR || i.state == StateKind.CONNECTING

        if (connectedish && !i.engineAlive && i.state != StateKind.CONNECTING) {
            out += Finding(DiagKind.ENGINE_DOWN, Confidence.HIGH, listOf("engine process is not running", "state ${i.state.name.lowercase()}"))
        }

        // DNS: a measured result beats anything read from the log.
        if (p.tunnelByIp == true && p.tunnelByName == false) {
            out += Finding(DiagKind.DNS_NOT_ANSWERING, Confidence.HIGH,
                listOf("connect by IP through the tunnel works", "connect by hostname through the tunnel fails"))
        } else if (p.tunnelByName == null && i.signals.dns > 0) {
            out += Finding(DiagKind.DNS_NOT_ANSWERING, if (i.signals.dns >= 3) Confidence.MEDIUM else Confidence.LOW,
                listOf("${i.signals.dns} recent log lines mention a DNS failure", "not measured: run the test"))
        }

        // TCP through the tunnel
        if (i.engineAlive && p.socksAnswers == false) {
            out += Finding(DiagKind.TCP_FAILING, Confidence.HIGH, listOf("the local SOCKS5 port does not answer"))
        } else if (p.tunnelByIp == false && p.tunnelByName == false) {
            val net = if (p.directByIp == true) "direct connect outside the tunnel works" else if (p.directByIp == false) "direct connect outside the tunnel also fails" else "direct path not measured"
            out += Finding(DiagKind.TCP_FAILING, if (p.directByIp == true) Confidence.HIGH else Confidence.MEDIUM,
                listOf("TCP through the tunnel fails by IP and by name", net))
        } else if (p.tunnelByIp == null && i.signals.tcp >= 3) {
            out += Finding(DiagKind.TCP_FAILING, Confidence.MEDIUM, listOf("${i.signals.tcp} recent log lines mention refused/reset/unreachable"))
        }

        // Handshake with the gateway / WARP
        if (i.state != StateKind.IDLE && i.signals.handshake > 0) {
            val notUp = i.state != StateKind.CONNECTED
            if (notUp || i.signals.handshake >= HANDSHAKE_MIN_WHEN_CONNECTED) {
                val conf = when {
                    i.signals.handshake >= 5 && notUp -> Confidence.HIGH
                    i.signals.handshake >= 2 -> Confidence.MEDIUM
                    else -> Confidence.LOW
                }
                out += Finding(DiagKind.HANDSHAKE_FAILING, conf,
                    listOf("${i.signals.handshake} recent log lines mention a failed handshake or gateway search", "state ${i.state.name.lowercase()}"))
            }
        }

        // Tunnel up but data stopped
        val r = i.rates
        if (i.state == StateKind.CONNECTED && r != null && r.stalledSamples >= STALL_SAMPLES_MEDIUM) {
            val measuredBad = p.tunnelByIp == false || p.socksAnswers == false
            out += Finding(DiagKind.STALLED,
                if (r.stalledSamples >= STALL_SAMPLES_HIGH || measuredBad) Confidence.HIGH else Confidence.MEDIUM,
                listOf("apps send data but nothing comes back for ${r.stalledSamples} samples",
                    "bridge ${if (i.bridgeUp == true) "up" else if (i.bridgeUp == false) "down" else "n/a"}"))
        }

        // Repeated drops
        if (i.reconnectsLast10Min >= 3) {
            out += Finding(DiagKind.FLAPPING, if (i.reconnectsLast10Min >= 6) Confidence.HIGH else Confidence.MEDIUM,
                listOf("${i.reconnectsLast10Min} reconnects in the last 10 minutes"))
        }

        // CPU: tell real transfer apart from burning CPU while idle.
        val cpu = r?.engineCpuPercent
        if (r != null && cpu != null && cpu >= CPU_HIGH_PERCENT && r.windowMs >= MIN_CPU_WINDOW_MS && !r.throughputKnown) {
            out += Finding(DiagKind.CPU_HIGH_LOAD_UNKNOWN, Confidence.MEDIUM, listOf(
                "engine cpu %.0f%% of one core over %ds".format(Locale.US, cpu, r.windowMs / 1000),
                "throughput cannot be measured in proxy-only mode",
                "screen ${if (i.screenOn) "on" else "off"}"))
        } else if (r != null && cpu != null && cpu >= CPU_HIGH_PERCENT && r.windowMs >= MIN_CPU_WINDOW_MS) {
            val bps = r.downBps + r.upBps
            val ev = mutableListOf(
                "engine cpu %.0f%% of one core over %ds".format(Locale.US, cpu, r.windowMs / 1000),
                "throughput ${formatRate(bps)}",
                "screen ${if (i.screenOn) "on" else "off"}"
            )
            if (bps >= ACTIVE_BPS) {
                out += Finding(DiagKind.CPU_DURING_TRANSFER, Confidence.HIGH, ev)
            } else if (bps < IDLE_BPS) {
                if (i.chainOn) ev += "a Psiphon/Tor chain is on"
                if (i.reconnectsLast10Min > 0) ev += "${i.reconnectsLast10Min} reconnects recently"
                out += Finding(DiagKind.CPU_WHILE_IDLE, Confidence.HIGH, ev)
            } else {
                out += Finding(DiagKind.CPU_WHILE_IDLE, Confidence.LOW, ev + "light traffic, so the split is unclear")
            }
        }

        if (out.isEmpty() && i.state == StateKind.CONNECTED) {
            val measured = p.tunnelByIp == true || p.tunnelByName == true
            out += Finding(DiagKind.NO_PROBLEM_SEEN, if (measured) Confidence.MEDIUM else Confidence.LOW,
                if (measured) listOf("a test connection through the tunnel worked") else listOf("nothing measured yet: run the tests"))
        }
        return out.sortedWith(compareByDescending<Finding> { it.confidence.ordinal }.thenBy { it.kind.ordinal })
    }

    fun formatRate(bytesPerSec: Long): String = when {
        bytesPerSec >= 1024 * 1024 -> "%.1f MiB/s".format(Locale.US, bytesPerSec / 1048576.0)
        bytesPerSec >= 1024 -> "%.1f KiB/s".format(Locale.US, bytesPerSec / 1024.0)
        else -> "$bytesPerSec B/s"
    }
}

/** Averages over the window of recent samples. */
data class RateSummary(
    val windowMs: Long,
    val downBps: Long,
    val upBps: Long,
    val engineCpuPercent: Double?,
    val appCpuPercent: Double?,
    val stalledSamples: Int,
    /** False in proxy-only mode: there is no tunnel bridge, so the byte counters do not exist. */
    val throughputKnown: Boolean = true
)

/**
 * A short sliding window of samples: engine CPU ticks, this app's CPU time and the tunnel byte counters.
 * Fed every few seconds ONLY while the diagnostics screen is open, so measuring costs nothing otherwise.
 */
class RateWindow(private val maxSamples: Int = 6) {
    private data class Sample(
        val atMs: Long, val engineTicks: Long?, val appCpuMs: Long,
        val txBytes: Long, val rxBytes: Long, val known: Boolean
    )

    private val samples = ArrayDeque<Sample>()

    /** [txBytes] / [rxBytes] are null when no byte counters exist (proxy-only mode). */
    fun add(atMs: Long, engineTicks: Long?, appCpuMs: Long, txBytes: Long?, rxBytes: Long?) {
        val known = txBytes != null && rxBytes != null
        val tx = txBytes ?: 0L
        val rx = rxBytes ?: 0L
        // A counter that went backwards means the tunnel or engine restarted: start a new window.
        samples.lastOrNull()?.let { last ->
            if (tx < last.txBytes || rx < last.rxBytes || atMs <= last.atMs) samples.clear()
        }
        samples.addLast(Sample(atMs, engineTicks, appCpuMs, tx, rx, known))
        while (samples.size > maxSamples) samples.removeFirst()
    }

    fun clear() = samples.clear()

    fun summary(): RateSummary? {
        if (samples.size < 2) return null
        val first = samples.first()
        val last = samples.last()
        val ms = last.atMs - first.atMs
        if (ms <= 0) return null
        val sec = ms / 1000.0
        val cpu = if (first.engineTicks != null && last.engineTicks != null)
            CpuSampler.percent(first.engineTicks, last.engineTicks, ms) else null
        val app = ((last.appCpuMs - first.appCpuMs).coerceAtLeast(0) / 1000.0) / sec * 100.0
        // Consecutive trailing intervals in which apps sent data and received none.
        var stalled = 0
        val list = samples.toList()
        for (k in list.size - 1 downTo 1) {
            val tx = list[k].txBytes - list[k - 1].txBytes
            val rx = list[k].rxBytes - list[k - 1].rxBytes
            if (tx > 0 && rx == 0L) stalled++ else break
        }
        return RateSummary(
            windowMs = ms,
            downBps = ((last.rxBytes - first.rxBytes) / sec).toLong(),
            upBps = ((last.txBytes - first.txBytes) / sec).toLong(),
            engineCpuPercent = cpu,
            appCpuPercent = app,
            stalledSamples = if (samples.all { it.known }) stalled else 0,
            throughputKnown = samples.all { it.known }
        )
    }
}

/** Connection history: how often it failed or restarted and when the state last changed. */
data class ConnStats(
    val stateSinceMs: Long = 0L,
    val retries: Int = 0,
    val errors: Int = 0,
    val reconnectTimesMs: List<Long> = emptyList()
) {
    fun reconnectsWithin(nowMs: Long, windowMs: Long = 10 * 60_000L): Int =
        reconnectTimesMs.count { nowMs - it in 0..windowMs }
}

class ConnStatsTracker(private val maxEvents: Int = 50) {
    var stats = ConnStats()
        private set

    /** [from] and [to] are the previous and new state kinds. */
    fun onTransition(from: StateKind, to: StateKind, nowMs: Long): ConnStats {
        if (from == to) return stats
        var s = stats.copy(stateSinceMs = nowMs)
        if (to == StateKind.CONNECTING && from == StateKind.IDLE) {
            s = ConnStats(stateSinceMs = nowMs) // a fresh session starts clean
        } else if (to == StateKind.CONNECTING && (from == StateKind.CONNECTED || from == StateKind.ERROR)) {
            s = s.copy(retries = s.retries + 1, reconnectTimesMs = (s.reconnectTimesMs + nowMs).takeLast(maxEvents))
        }
        if (to == StateKind.ERROR) s = s.copy(errors = s.errors + 1)
        stats = s
        return s
    }
}

/**
 * The shareable report. By default it carries counters, states and the findings with their evidence, and
 * NOTHING else: no log lines, no IP addresses, no tokens, no traffic content. A redacted log tail is added
 * only when [includeLogTail] is given, and it still passes the redactor.
 */
/** The UDP part of the report: only counts, never an address or a name. */
class UdpReport(val settingOn: Boolean, val state: UdpState, val stats: UdpStats?)

object DiagnosticsReport {
    fun render(
        appVersion: String,
        input: DiagInput,
        findings: List<Finding>,
        stats: ConnStats,
        nowMs: Long,
        rates: RateSummary?,
        includeLogTail: List<String>? = null,
        redact: (String) -> String,
        udp: UdpReport? = null
    ): String {
        val sb = StringBuilder()
        sb.append("MadShield diagnostics, version ").append(appVersion).append('\n')
        sb.append("state: ").append(input.state.name.lowercase())
            .append(", for ").append(((nowMs - stats.stateSinceMs).coerceAtLeast(0)) / 1000).append(" s\n")
        sb.append("engine running: ").append(input.engineAlive)
            .append(", bridge: ").append(input.bridgeUp?.toString() ?: "n/a").append('\n')
        sb.append("retries: ").append(stats.retries).append(", errors: ").append(stats.errors)
            .append(", reconnects in 10 min: ").append(stats.reconnectsWithin(nowMs)).append('\n')
        if (rates != null) {
            sb.append("throughput: down ").append(Diagnosis.formatRate(rates.downBps))
                .append(", up ").append(Diagnosis.formatRate(rates.upBps)).append('\n')
            rates.engineCpuPercent?.let { sb.append("engine cpu: %.0f%% of one core\n".format(Locale.US, it)) }
            sb.append("app cpu: %.0f%% of one core\n".format(Locale.US, rates.appCpuPercent ?: 0.0))
        }
        sb.append("screen: ").append(if (input.screenOn) "on" else "off").append('\n')
        if (udp != null) {
            sb.append("udp support: ").append(if (udp.settingOn) "enabled" else "disabled")
                .append(", in effect: ").append(udp.state.name.lowercase()).append('\n')
            val u = udp.stats
            if (u != null) {
                sb.append("  udp associations: ").append(u.active).append(" active, ").append(u.opened).append(" opened, ")
                    .append(u.refusedAssociations).append(" refused\n")
                sb.append("  udp datagrams: ").append(u.toUpstream).append(" out / ").append(u.fromUpstream).append(" in via upstream, ")
                    .append(u.toDirect).append(" out / ").append(u.fromDirect).append(" in direct\n")
                sb.append("  udp dropped: ").append(u.droppedTotal).append(" (blocked by rule ").append(u.droppedBlocked)
                    .append(", guard ").append(u.droppedGuard).append(", bad packet ").append(u.droppedBadPacket)
                    .append(", no upstream ").append(u.droppedNoUpstream).append(", lookup failed ").append(u.droppedResolve)
                    .append(", queue full ").append(u.droppedFull).append(")\n")
            }
        }
        sb.append("findings:\n")
        if (findings.isEmpty()) sb.append("  none\n")
        for (f in findings) {
            sb.append("  - ").append(f.kind.name.lowercase()).append(" (").append(f.confidence.name.lowercase()).append(" confidence)\n")
            for (e in f.evidence) sb.append("      ").append(redact(e)).append('\n')
        }
        if (includeLogTail != null) {
            sb.append("log tail (redacted):\n")
            for (l in includeLogTail) sb.append("  ").append(redact(l)).append('\n')
        }
        return sb.toString()
    }
}
