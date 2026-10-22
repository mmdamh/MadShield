package com.aethershield.app.core

/**
 * Pure bookkeeping for "does the phone have any network at all", fed by the system's default-network
 * callbacks (see [NetworkWatcher]). No Android types, so it can be tested off-device.
 *
 * Why it exists: with no network the core cannot reach any WireGuard endpoint ("Network is unreachable"),
 * fails at once and starts its endpoint scan again, over and over, and Psiphon (which dials through the
 * core's SOCKS port) fails in step. That spins the CPU for nothing. While [online] is false the services
 * stop the engine instead and start it again when the network is back.
 *
 * Handover is the tricky part: Android normally announces the NEW network before the old one is lost, but
 * not on every device. [lost] ignores a network that is no longer the current one, and the services add a
 * short grace period ([PowerPolicy.OFFLINE_GRACE_MS]) before acting on a "no network" report.
 */
class OnlineTracker<T : Any> {
    @Volatile var online: Boolean = true
        private set
    private var current: T? = null

    /** A network became the default. @return true when it is a new one, or the link came back after "no network". */
    fun available(network: T): Boolean {
        online = true
        if (network == current) return false
        current = network
        return true
    }

    /** The system itself says a real network exists (see NetworkWatcher.awaitNetwork): that outranks a missed callback. */
    fun markOnline() { online = true }

    /** A network was lost. @return true only when it was the current one, i.e. the phone now has NO network. */
    fun lost(network: T): Boolean {
        if (network != current) return false // an old network going away after a newer one took over
        current = null
        online = false
        return true
    }
}

/**
 * Spots "the core process is alive, but its WireGuard tunnel is not" from the core's own log lines.
 *
 * Why it exists: the app's health probe only asks the local SOCKS port. With a chain on, that port belongs to
 * Psiphon's local proxy, which answers even when the tunnel underneath is dead, so the app kept saying
 * "connected" while the core scanned for an endpoint again and again (40-50% of a core, and Psiphon retrying
 * against a closed port hundreds of times). One failed scan can be a bad moment; [STALL_AFTER_SCANS] full scans
 * in a row with no working tunnel in between is an outage.
 *
 * Only the WireGuard lines are read. For other protocols nothing here ever fires, so they behave as before.
 * One instance per engine start (a restart begins with a clean count).
 */
class TunnelStallTracker {
    companion object {
        const val STALL_AFTER_SCANS = 2
        const val SCAN_FAILED = "no usable WireGuard endpoint found"
        const val TUNNEL_UP = "wireguard tunnel validated"

        /** Cheap pre-check so the log pump only calls [feed] for the two lines that matter. */
        fun isRelevant(line: String): Boolean = line.contains(SCAN_FAILED) || line.contains(TUNNEL_UP)
    }

    @Volatile var failedScans: Int = 0
        private set

    /** Called from the log pump thread only; [stalled] is read from the health loop. */
    fun feed(line: String) {
        if (line.contains(TUNNEL_UP)) failedScans = 0
        else if (line.contains(SCAN_FAILED)) failedScans = failedScans + 1
    }

    val stalled: Boolean get() = failedScans >= STALL_AFTER_SCANS
}

/**
 * Keeps two kinds of harmless, repetitive engine lines out of the in-app log.
 *
 * 1. Psiphon's `SOCKS proxy accept error: socks5ReadCommand: EOF`. Not a fault: with a chain on, the app's own
 *    health probe ([SocksProbe.handshakeOk]) opens Psiphon's local SOCKS port, reads the greeting and closes.
 * 2. Psiphon's `meek round trip failed` / `MeekConn relay` lines that end in `connection refused` or
 *    `context deadline exceeded`. They are what Psiphon says while the core's own SOCKS port (which it dials
 *    through) is closed because the WireGuard tunnel is down: hundreds per minute, all the same, and they
 *    pushed the useful lines out of the 500-entry log buffer. Psiphon lines with any other ending are kept.
 *
 * Per kind, the first line per engine start is kept and the rest are counted. A summary goes out once per
 * [SUMMARY_EVERY] folded lines, or before the next different line when at least [MIN_SUMMARY] were folded (a
 * handful stays in the count instead of printing a "folded 1 more" line each time). Only the in-app log
 * changes; the engine and the probe are untouched.
 */
class LogNoiseFolder {
    companion object {
        const val PROBE_EOF = "psiphon: SOCKS proxy accept error: socks5ReadCommand: EOF"
        const val SUMMARY_EVERY = 120
        const val MIN_SUMMARY = 10

        fun isOwnProbeNoise(line: String): Boolean = line.contains(PROBE_EOF)

        fun isChainRetryNoise(line: String): Boolean =
            (line.contains("psiphon: meek round trip failed") || line.contains("psiphon: psiphon.(*MeekConn).relay")) &&
                (line.contains("connect: connection refused") || line.trimEnd().endsWith("context deadline exceeded"))

        fun isNoise(line: String): Boolean = isOwnProbeNoise(line) || isChainRetryNoise(line)
    }

    private var shownProbe = false
    private var shownRetry = false
    private var hiddenProbe = 0
    private var hiddenRetry = 0

    /** The lines to put into the log for one line from the engine (empty = swallowed). */
    fun feed(line: String): List<String> {
        if (isOwnProbeNoise(line)) {
            if (!shownProbe) { shownProbe = true; return listOf(line) }
            hiddenProbe++
            return if (hiddenProbe >= SUMMARY_EVERY) listOf(probeSummary()) else emptyList()
        }
        if (isChainRetryNoise(line)) {
            if (!shownRetry) { shownRetry = true; return listOf(line) }
            hiddenRetry++
            return if (hiddenRetry >= SUMMARY_EVERY) listOf(retrySummary()) else emptyList()
        }
        val out = ArrayList<String>(3)
        if (hiddenProbe >= MIN_SUMMARY) out.add(probeSummary())
        if (hiddenRetry >= MIN_SUMMARY) out.add(retrySummary())
        out.add(line)
        return out
    }

    private fun probeSummary(): String {
        val n = hiddenProbe
        hiddenProbe = 0
        return "[engine] folded $n more \"SOCKS proxy accept error: EOF\" lines (the app's own health probe, harmless)"
    }

    private fun retrySummary(): String {
        val n = hiddenRetry
        hiddenRetry = 0
        return "[engine] folded $n more Psiphon retry lines (its meek dials failing while the core's tunnel is down)"
    }
}
