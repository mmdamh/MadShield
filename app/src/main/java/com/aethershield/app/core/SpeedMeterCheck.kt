package com.aethershield.app.core

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

    class Result(val seconds: Double, val down: Flow, val up: Flow) {
        /** Something moved on the real link, in either direction. */
        val enough: Boolean get() = maxOf(down.physical, up.physical) >= MIN_BPS
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
        for (r in after) {
            val b = start[r.name] ?: continue
            // A counter that went back (interface recreated) is "no traffic", never a negative speed.
            down[r.kind.ordinal] += (r.rxBytes - b.rxBytes).coerceAtLeast(0)
            up[r.kind.ordinal] += (r.txBytes - b.txBytes).coerceAtLeast(0)
        }
        fun perSec(bytes: Long) = (bytes * 1000.0 / windowMs).toLong()
        fun system(i: Int): Long? {
            val a = systemBefore
            val z = systemAfter
            if (a == null || z == null || a.size <= i || z.size <= i || a[i] < 0 || z[i] < 0) return null
            return perSec((z[i] - a[i]).coerceAtLeast(0))
        }
        fun flow(d: LongArray, sys: Long?) = Flow(
            perSec(d[Kind.PHYSICAL.ordinal]), perSec(d[Kind.TUNNEL.ordinal]), perSec(d[Kind.LOOPBACK.ordinal]), sys
        )
        return Result(windowMs / 1000.0, flow(down, system(0)), flow(up, system(1)))
    }
}
