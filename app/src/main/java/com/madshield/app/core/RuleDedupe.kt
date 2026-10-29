package com.madshield.app.core

/**
 * Exact-duplicate filter for very long rule lists without keeping the strings: 64-bit FNV-1a hashes in an
 * open-addressing table (8 MB for the default 2^20 slots, enough for 500k rules at half load). A hash
 * collision (about 1 in 10^8 at this size) would drop one rule, which is harmless for block/bypass lists.
 */
class RuleDedupe(slotsPow2: Int = 20) {
    private val table = LongArray(1 shl slotsPow2)
    private val mask = table.size - 1
    var size = 0
        private set

    /** True if [rule] was new (and is now remembered), false if it was already there or the table is full. */
    fun add(rule: String): Boolean {
        if (size >= table.size / 2) return false
        var h = hash(rule)
        if (h == 0L) h = 1L
        var i = ((h xor (h ushr 32)).toInt()) and mask
        while (true) {
            val cur = table[i]
            if (cur == 0L) { table[i] = h; size++; return true }
            if (cur == h) return false
            i = (i + 1) and mask
        }
    }

    companion object {
        fun hash(s: String): Long {
            var h = -3750763034362895579L // FNV-1a offset basis 0xcbf29ce484222325
            for (c in s) {
                h = h xor c.code.toLong()
                h *= 1099511628211L       // FNV prime
            }
            return h
        }
    }
}
