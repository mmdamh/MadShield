package com.aethershield.app.core

/**
 * How often the services poll while connected. Pattern from ZedSecure's PowerPolicy (which is how it
 * stopped heating phones): fast while the screen is on, slow while it is off, slower still once the
 * screen has been off and the tunnel quiet for a while ([IdleTracker]). Every poll wakes the CPU, and
 * with the screen off nothing is watching the result.
 */
object PowerPolicy {
    data class Cadence(val healthMs: Long, val logCountersEveryTicks: Int, val sampleCpu: Boolean)

    const val SCREEN_ON_HEALTH_MS = 5_000L
    const val SCREEN_OFF_HEALTH_MS = 30_000L

    /** Screen off AND quiet for [IdleTracker.IDLE_AFTER_MS]. Kept at 60 s: a dead engine is still noticed in ~2 min. */
    const val IDLE_HEALTH_MS = 60_000L

    fun cadence(screenOn: Boolean, idle: Boolean = false): Cadence = when {
        screenOn -> Cadence(SCREEN_ON_HEALTH_MS, 6, sampleCpu = true)
        idle -> Cadence(IDLE_HEALTH_MS, 0, sampleCpu = false)
        else -> Cadence(SCREEN_OFF_HEALTH_MS, 0, sampleCpu = false)
    }

    /** An outage needs ~2 failed probes on screen, but never less than this wall-clock time. */
    const val UNRESPONSIVE_RESTART_AFTER_MS = 60_000L
}

/**
 * Decides when the phone is "idle": screen off and (almost) no traffic through the tunnel for
 * [IDLE_AFTER_MS]. Pure logic, fed from the health tick that already exists, so it adds no timer and
 * no wake-up of its own.
 *
 * Quiet means less than [QUIET_BYTES_PER_MIN] between two ticks (background apps always send a little,
 * so "exactly zero" would almost never happen). Once idle, only more than [BUSY_BYTES_PER_MIN] ends it;
 * the gap between the two numbers stops it flapping. Anything that says "something is happening"
 * ([wake]: screen on, network change, a failed probe) ends it at once.
 *
 * [totalBytes] is tx+rx of the tunnel bridge, or null where no counters exist (proxy-only mode). Then
 * traffic is unknown and only the screen decides.
 */
class IdleTracker {
    companion object {
        const val IDLE_AFTER_MS = 120_000L
        const val QUIET_BYTES_PER_MIN = 8L * 1024
        const val BUSY_BYTES_PER_MIN = 32L * 1024
    }

    var idle = false
        private set
    private var quietSinceMs = -1L
    private var lastBytes: Long? = null
    private var lastAtMs = 0L

    /** Call once per health tick. Returns whether the NEXT wait should use the idle cadence. */
    fun onTick(nowMs: Long, screenOn: Boolean, totalBytes: Long?): Boolean {
        if (screenOn) { wake(); lastBytes = null; return false }

        val prev = lastBytes
        val prevAt = lastAtMs
        lastBytes = totalBytes
        lastAtMs = nowMs

        // Rate in bytes per minute since the last tick; null when we cannot tell.
        val perMin: Double? = when {
            totalBytes == null -> null                       // no counters: traffic unknown
            prev == null || nowMs <= prevAt -> null          // first sample: nothing to compare yet
            totalBytes < prev -> Double.MAX_VALUE            // counter went back: tunnel restarted, treat as activity
            else -> (totalBytes - prev).toDouble() * 60_000.0 / (nowMs - prevAt)
        }

        val busy = perMin != null && perMin >= (if (idle) BUSY_BYTES_PER_MIN else QUIET_BYTES_PER_MIN).toDouble()
        if (busy) { wake(); return false }

        // Quiet, or unknown-but-screen-off. The very first sample only starts the clock.
        if (quietSinceMs < 0) quietSinceMs = if (prevAt > 0) prevAt else nowMs
        if (!idle && nowMs - quietSinceMs >= IDLE_AFTER_MS) idle = true
        return idle
    }

    /** Screen on, network change, failed probe: back to the normal cadence right now. */
    fun wake() {
        idle = false
        quietSinceMs = -1L
    }
}

/** CPU use of a child process, from /proc/<pid>/stat (utime + stime, clock ticks). Pure parsing + maths. */
object CpuSampler {
    const val CLOCK_TICKS_PER_SEC = 100L // USER_HZ on Android/Linux

    /** utime+stime ticks from one /proc/<pid>/stat line, or null when it cannot be parsed. */
    fun parseTicks(stat: String): Long? {
        val rest = stat.substringAfterLast(')', "").trim()
        if (rest.isEmpty()) return null
        val f = rest.split(' ')
        // after ")" the fields start at #3 (state); utime is #14, stime #15 => indexes 11 and 12
        val u = f.getOrNull(11)?.toLongOrNull() ?: return null
        val s = f.getOrNull(12)?.toLongOrNull() ?: return null
        return u + s
    }

    /** Percent of ONE core used between two samples. */
    fun percent(ticksBefore: Long, ticksAfter: Long, elapsedMs: Long): Double {
        if (elapsedMs <= 0 || ticksAfter < ticksBefore) return 0.0
        val cpuSec = (ticksAfter - ticksBefore).toDouble() / CLOCK_TICKS_PER_SEC
        return cpuSec / (elapsedMs / 1000.0) * 100.0
    }
}

/** The core says "psiphon is ready;" / "tor is ready;" only when the chain really carries traffic. */
object ChainReady {
    fun isReadyLine(line: String): Boolean =
        line.contains("psiphon is ready;") || line.contains("tor is ready;")
}
