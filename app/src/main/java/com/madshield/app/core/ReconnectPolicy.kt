package com.madshield.app.core

/**
 * When to try again after the engine died. Starting values, not magic numbers for every network:
 * quick increasing retries first (1, 2, 4, 8, 16, 30 s), then a slow WAITING phase (2 minutes with the
 * screen on, 5 with it off) that continues indefinitely but never spins. A network change (Wi-Fi to
 * mobile, link back up) ends the wait at once and starts over with the quick phase.
 */
object ReconnectPolicy {
    enum class Phase { FAST, WAITING }

    private val FAST_DELAYS_MS = longArrayOf(1_000, 2_000, 4_000, 8_000, 16_000, 30_000)

    /**
     * When the failing part is the privacy chain (Psiphon / Tor) and not the WARP tunnel, retrying within seconds
     * cannot help: the network is blocking the chain, and every try costs a full engine start (gateway scan,
     * WireGuard check, chain start, ~2 minutes of CPU and radio). So the first retries are spaced out, then the
     * normal waiting phase takes over. A network change still ends the wait at once.
     */
    private val CHAIN_DELAYS_MS = longArrayOf(20_000, 60_000, 180_000)
    val FAST_ATTEMPTS: Int = FAST_DELAYS_MS.size
    const val WAIT_SCREEN_ON_MS = 120_000L
    const val WAIT_SCREEN_OFF_MS = 300_000L

    /**
     * A connection that stayed healthy this long counts as recovered: the attempt counter starts over.
     * Ten minutes, not one: a tunnel that dies every few minutes used to reset the counter each time, so it
     * retried at the fastest pace forever ("retry #1" in every cycle of the log) and never reached the slow phase.
     */
    const val STABLE_AFTER_MS = 600_000L

    private const val JITTER_FRACTION = 0.2

    /** [attempt] counts from 1. */
    fun phase(attempt: Int): Phase = if (attempt <= FAST_ATTEMPTS) Phase.FAST else Phase.WAITING

    /**
     * Pause before attempt number [attempt]. [jitter] is a number in -1..1 supplied by the caller (random in
     * production, fixed in tests) that spreads retries by up to +-20% so many phones do not retry in step.
     */
    fun delayMs(attempt: Int, screenOn: Boolean, jitter: Double = 0.0, chainFailure: Boolean = false): Long {
        val base = when {
            chainFailure && attempt in 1..CHAIN_DELAYS_MS.size -> CHAIN_DELAYS_MS[attempt - 1]
            chainFailure && attempt > CHAIN_DELAYS_MS.size -> if (screenOn) WAIT_SCREEN_ON_MS else WAIT_SCREEN_OFF_MS
            attempt < 1 -> FAST_DELAYS_MS[0]
            attempt <= FAST_ATTEMPTS -> FAST_DELAYS_MS[attempt - 1]
            screenOn -> WAIT_SCREEN_ON_MS
            else -> WAIT_SCREEN_OFF_MS
        }
        val j = jitter.coerceIn(-1.0, 1.0)
        return (base * (1.0 + j * JITTER_FRACTION)).toLong().coerceAtLeast(500L)
    }
}
