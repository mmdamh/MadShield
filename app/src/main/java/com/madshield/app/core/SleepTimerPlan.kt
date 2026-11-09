package com.madshield.app.core

/** The arithmetic of the sleep timer (update41), kept apart from Android so it is tested without a phone. */
object SleepTimerPlan {
    val PRESET_MINUTES = listOf(15, 30, 60, 120, 240, 480)
    const val DEFAULT_MINUTES = 60
    const val EXTEND_MINUTES = 15
    const val MAX_MINUTES = 12 * 60

    private const val MINUTE_MS = 60_000L

    fun endAt(nowMs: Long, minutes: Int): Long = nowMs + minutes.coerceIn(1, MAX_MINUTES) * MINUTE_MS

    /** [EXTEND_MINUTES] more, counted from the planned end (or from now if that has passed), never beyond [MAX_MINUTES] from now. */
    fun extend(endAtMs: Long, nowMs: Long): Long =
        (maxOf(endAtMs, nowMs) + EXTEND_MINUTES * MINUTE_MS).coerceAtMost(nowMs + MAX_MINUTES * MINUTE_MS)

    fun remainingMs(endAtMs: Long, nowMs: Long): Long = (endAtMs - nowMs).coerceAtLeast(0L)

    /** "1:45" (hours:minutes), rounded UP to the minute, so 59 s left reads "0:01" and 0 reads "0:00". */
    fun format(remainingMs: Long): String {
        val minutes = (remainingMs.coerceAtLeast(0L) + MINUTE_MS - 1) / MINUTE_MS
        return "${minutes / 60}:${(minutes % 60).toString().padStart(2, '0')}"
    }

    /** A saved end time only counts while it is still ahead of us. */
    fun stillAhead(endAtMs: Long, nowMs: Long): Boolean = endAtMs > nowMs
}
