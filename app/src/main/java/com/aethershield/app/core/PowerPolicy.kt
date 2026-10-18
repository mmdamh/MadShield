package com.aethershield.app.core

/**
 * How often the services poll while connected. Pattern from ZedSecure's PowerPolicy (which is how it
 * stopped heating phones): fast while the screen is on, slow while it is off. Every poll wakes the CPU,
 * and with the screen off nothing is watching the result.
 */
object PowerPolicy {
    data class Cadence(val healthMs: Long, val logCountersEveryTicks: Int)

    const val SCREEN_ON_HEALTH_MS = 5_000L
    const val SCREEN_OFF_HEALTH_MS = 30_000L

    fun cadence(screenOn: Boolean): Cadence =
        if (screenOn) Cadence(SCREEN_ON_HEALTH_MS, 6) else Cadence(SCREEN_OFF_HEALTH_MS, 0)

    /** An outage needs ~2 failed probes on screen, but never less than this wall-clock time. */
    const val UNRESPONSIVE_RESTART_AFTER_MS = 60_000L
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
