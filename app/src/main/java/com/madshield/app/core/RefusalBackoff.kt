package com.madshield.app.core

import java.util.concurrent.atomic.AtomicInteger

/**
 * An app that is told "no" (a name its DNS blocks, a host the block rules refuse) usually asks again at once, over
 * and over, and every try wakes the phone's CPU and radio. This remembers, per host name, how many refusals came in
 * a row; once a host has been refused often enough, the next refusals are ANSWERED LATE ([holdMs]) instead of at
 * once. Most apps wait for the connection and ask again only after it fails or times out, so their retry rate drops
 * from one a second to one every few seconds, and nothing else is asked of the network meanwhile.
 *
 * Only real "no" answers count: the name does not exist / has no address / resolves to 0.0.0.0 (a DNS block), or a
 * block rule matched. A lookup that could not reach the resolver, or a connection that failed, is NOT a refusal (the
 * network may simply be down, and every host would then be punished). One success for a host forgets its streak, and a
 * streak also ends by itself when the host is not asked for [windowMs].
 *
 * Pure (the clock is a parameter) and thread-safe. Keeps at most [capacity] hosts, oldest dropped first. At most
 * [maxHolds] answers are held at the same time (each holds one thread), so a flood cannot pile threads up.
 */
class RefusalBackoff(
    private val clock: () -> Long = { System.currentTimeMillis() },
    val windowMs: Long = 60_000L,
    /** Refusals in a row before a name that does not resolve is answered late. */
    val nameThreshold: Int = 3,
    /** Same for a host a block rule matches: higher, because one page can legitimately ask a tracker a few times. */
    val ruleThreshold: Int = 10,
    val holdMs: Long = 8_000L,
    val maxHolds: Int = 48,
    private val capacity: Int = 512
) {
    private class Streak(var count: Int, var lastMs: Long)

    private val map = object : LinkedHashMap<String, Streak>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Streak>?): Boolean = size > capacity
    }
    private val holding = AtomicInteger()

    /** Notes one refusal of [host]; returns how long to wait before answering it (0 = answer now). */
    @Synchronized
    fun refused(host: String, byRule: Boolean): Long {
        val now = clock()
        val s = map[host]
        val count = if (s == null || now - s.lastMs > windowMs) 1 else s.count + 1
        if (s == null) map[host] = Streak(count, now) else { s.count = count; s.lastMs = now }
        return if (count >= (if (byRule) ruleThreshold else nameThreshold)) holdMs else 0L
    }

    /** [host] worked: its streak is over. */
    @Synchronized
    fun succeeded(host: String) { map.remove(host) }

    /** True when one more answer may be held (the caller must then call [release]). */
    fun tryHold(): Boolean {
        while (true) {
            val n = holding.get()
            if (n >= maxHolds) return false
            if (holding.compareAndSet(n, n + 1)) return true
        }
    }

    fun release() { holding.decrementAndGet() }

    val heldNow: Int get() = holding.get()

    @Synchronized
    fun clear() { map.clear() }
}
