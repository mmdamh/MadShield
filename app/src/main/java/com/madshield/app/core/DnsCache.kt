package com.madshield.app.core

/**
 * What one DNS question resolved to. [addresses] empty with [nxdomain] false means NODATA (the name exists,
 * it just has no record of that type).
 */
class Resolved(val addresses: List<ByteArray>, val nxdomain: Boolean) {
    val isNegative: Boolean get() = addresses.isEmpty()
}

/**
 * Small LRU cache for the local DoH resolver. Pure (the clock is a parameter), thread-safe.
 *
 * - key: (lower-case name, query type); capacity [capacity] entries, least recently used goes first;
 * - positive TTL = the smallest record TTL, kept within [MIN_TTL_S]..[MAX_TTL_S];
 * - negative answers (NXDOMAIN / NODATA) live [MIN_NEG_TTL_S]..[MAX_NEG_TTL_S] seconds (from the SOA);
 * - an expired entry is NOT removed on lookup: [getStale] may still hand a positive one out when the
 *   resolver is unreachable (serve-stale). Nothing refreshes in the background, ever.
 */
class DnsCache(private val capacity: Int = 1024) {
    companion object {
        const val MIN_TTL_S = 10L
        const val MAX_TTL_S = 3600L
        const val MIN_NEG_TTL_S = 5L
        const val MAX_NEG_TTL_S = 300L
        const val MAX_STALE_MS = 10 * 60 * 1000L

        fun positiveTtl(recordTtls: List<Long>): Long =
            (recordTtls.minOrNull() ?: MIN_TTL_S).coerceIn(MIN_TTL_S, MAX_TTL_S)

        fun negativeTtl(soaTtl: Long?): Long = (soaTtl ?: MIN_NEG_TTL_S).coerceIn(MIN_NEG_TTL_S, MAX_NEG_TTL_S)
    }

    data class Key(val name: String, val type: Int)
    private class Slot(val value: Resolved, val expiresAtMs: Long)

    private val map = object : LinkedHashMap<Key, Slot>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, Slot>?): Boolean = size > capacity
    }

    val size: Int @Synchronized get() = map.size

    /** A fresh entry, or null (missing or expired). */
    @Synchronized
    fun get(key: Key, nowMs: Long): Resolved? {
        val e = map[key] ?: return null
        return if (nowMs < e.expiresAtMs) e.value else null
    }

    /** An expired POSITIVE entry no older than [maxStaleMs], used only after the resolver failed. */
    @Synchronized
    fun getStale(key: Key, nowMs: Long, maxStaleMs: Long = MAX_STALE_MS): Resolved? {
        val e = map[key] ?: return null
        if (e.value.isNegative) return null
        if (nowMs < e.expiresAtMs) return e.value
        if (nowMs - e.expiresAtMs > maxStaleMs) { map.remove(key); return null }
        return e.value
    }

    /** [ttlSeconds] must already be clamped (see [positiveTtl] / [negativeTtl]). */
    @Synchronized
    fun put(key: Key, value: Resolved, ttlSeconds: Long, nowMs: Long) {
        map[key] = Slot(value, nowMs + ttlSeconds * 1000L)
    }

    @Synchronized
    fun clear() = map.clear()
}
