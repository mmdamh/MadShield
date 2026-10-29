package com.madshield.app.core

/**
 * "The speed in the status bar is several times the real speed." A status-bar meter (Good Lock Network Speed and
 * similar) reads the phone's byte counters, and the phone counts a byte once on EVERY interface it crosses:
 *
 *   physical  the real Wi-Fi / mobile link (what a speed test really moves)
 *   tunnel    the VPN interface the apps write into (counted once by every VPN app, sing-box included)
 *   loopback  traffic between the app's own parts on 127.0.0.1 (tunnel bridge -> front -> chain -> core)
 *
 * This turns two snapshots of those counters into rates and into factors against the real link, so the page can show
 * where the extra bytes come from. Pure maths, tested off-device; [SpeedMeterProbe] reads the counters on the phone.
 */
object SpeedMeterCheck {
    enum class Kind { PHYSICAL, TUNNEL, LOOPBACK }

    /** Bytes counted on one interface since boot. */
    class Reading(val name: String, val kind: Kind, val rxBytes: Long, val txBytes: Long)

    /** Below this much traffic on the real link (bytes per second) the factors mean nothing: no speed test ran. */
    const val MIN_BPS = 100_000L

    /**
     * One direction, in bytes per second, split by where the phone counted the bytes. [system] is the phone's own
     * total counter (TrafficStats.getTotal*Bytes), null when it is not available.
     */
    class Flow(val physical: Long, val tunnel: Long, val loopback: Long, val system: Long?) {
        /** What a meter shows that adds the VPN tunnel to the real link: about 2x for any VPN app. */
        val tunnelPlusLink: Double? get() = factor(physical + tunnel)

        /** The same, if the meter also counts loopback. */
        val withLoopback: Double? get() = factor(physical + tunnel + loopback)

        /** What the phone's total counter says, against the real link. */
        val systemTotal: Double? get() = system?.let { factor(it) }

        private fun factor(v: Long): Double? = if (physical <= 0) null else v.toDouble() / physical
    }

    /** One interface as the page lists it: the raw rates, so a result that makes no sense can still be read. */
    class Row(val name: String, val kind: Kind, val downBps: Long, val upBps: Long)

    /**
     * @param rows every interface present in both snapshots
     * @param linkSeen a real (Wi-Fi / mobile) interface was in both snapshots; false means its counters could not be
     *        read, or the phone switched network during the window
     */
    class Result(val seconds: Double, val down: Flow, val up: Flow, val rows: List<Row>, val linkSeen: Boolean) {
        /** Something moved on the real link, in either direction. */
        val enough: Boolean get() = maxOf(down.physical, up.physical) >= MIN_BPS

        /**
         * The phone-wide counter moved a lot while the real link's own counter did not: this phone does not give
         * apps usable per-interface counters, so the factors cannot be worked out here.
         */
        val countersHidden: Boolean get() = !enough && maxOf(down.system ?: 0L, up.system ?: 0L) >= MIN_BPS

        /**
         * Which direction carries the real transfer. Loopback counts every byte in BOTH directions (what a local hop
         * receives it also sends), so only this direction's factors mean anything: the other one is mostly acks.
         */
        val dominantIsDown: Boolean get() = down.physical >= up.physical
    }

    /**
     * @param before / @param after the interface counters at the start and at the end (an interface missing from one
     *        of them, for example after a Wi-Fi / mobile switch, is left out: its change is unknown)
     * @param systemBefore / @param systemAfter the phone's total counters as [rx, tx], or null; a negative value
     *        (the API's "unsupported") counts as null
     * @return null when [windowMs] is not positive
     */
    fun compute(
        before: List<Reading>, after: List<Reading>,
        systemBefore: LongArray?, systemAfter: LongArray?, windowMs: Long
    ): Result? {
        if (windowMs <= 0) return null
        val start = before.associateBy { it.name }
        val down = LongArray(Kind.values().size)
        val up = LongArray(Kind.values().size)
        fun perSec(bytes: Long) = (bytes * 1000.0 / windowMs).toLong()
        val rows = ArrayList<Row>()
        var linkSeen = false
        for (r in after) {
            val b = start[r.name] ?: continue
            // A counter that went back (interface recreated) is "no traffic", never a negative speed.
            val dRx = (r.rxBytes - b.rxBytes).coerceAtLeast(0)
            val dTx = (r.txBytes - b.txBytes).coerceAtLeast(0)
            down[r.kind.ordinal] += dRx
            up[r.kind.ordinal] += dTx
            rows += Row(r.name, r.kind, perSec(dRx), perSec(dTx))
            if (r.kind == Kind.PHYSICAL) linkSeen = true
        }
        fun system(i: Int): Long? {
            val a = systemBefore
            val z = systemAfter
            if (a == null || z == null || a.size <= i || z.size <= i || a[i] < 0 || z[i] < 0) return null
            return perSec((z[i] - a[i]).coerceAtLeast(0))
        }
        fun flow(d: LongArray, sys: Long?) = Flow(
            perSec(d[Kind.PHYSICAL.ordinal]), perSec(d[Kind.TUNNEL.ordinal]), perSec(d[Kind.LOOPBACK.ordinal]), sys
        )
        return Result(windowMs / 1000.0, flow(down, system(0)), flow(up, system(1)), rows, linkSeen)
    }
}
