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

    /** A network was lost. @return true only when it was the current one, i.e. the phone now has NO network. */
    fun lost(network: T): Boolean {
        if (network != current) return false // an old network going away after a newer one took over
        current = null
        online = false
        return true
    }
}

/**
 * Keeps one particular line out of the in-app log: Psiphon's `SOCKS proxy accept error: socks5ReadCommand: EOF`.
 *
 * The line is not a fault. With a chain on, the app's own health probe ([SocksProbe.handshakeOk]) opens
 * Psiphon's local SOCKS port, reads the greeting reply and closes, so Psiphon logs an EOF for every probe:
 * every 5 s with the screen on. Those lines filled most of the 500-entry log buffer (timestamps differ, so
 * the buffer could not fold them) and pushed the useful lines out.
 *
 * The first one per engine start is kept, the rest are counted, and one summary line per
 * [SUMMARY_EVERY] lines (or before the next different line) says how many were folded. Only the in-app log
 * changes: the probe itself, the engine and [LogSignals] are untouched, and none of the counters in
 * [LogSignals.scan] looks at this line.
 */
class LogNoiseFolder {
    companion object {
        const val PROBE_EOF = "psiphon: SOCKS proxy accept error: socks5ReadCommand: EOF"
        const val SUMMARY_EVERY = 120

        fun isOwnProbeNoise(line: String): Boolean = line.contains(PROBE_EOF)
    }

    private var shownFirst = false
    private var hidden = 0

    /** The lines to put into the log for one line from the engine (empty = swallowed). */
    fun feed(line: String): List<String> {
        if (isOwnProbeNoise(line)) {
            if (!shownFirst) { shownFirst = true; return listOf(line) }
            if (++hidden >= SUMMARY_EVERY) return listOf(summary())
            return emptyList()
        }
        if (hidden == 0) return listOf(line)
        return listOf(summary(), line)
    }

    private fun summary(): String {
        val n = hidden
        hidden = 0
        return "[engine] folded $n more \"SOCKS proxy accept error: EOF\" lines (the app's own health probe, harmless)"
    }
}
