package com.aethershield.app.util

import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicLong

/**
 * Zero-log design, spelled out:
 *
 * - This buffer lives ONLY in process memory. It is never written to a file, never written to
 *   SharedPreferences/DataStore, and never sent anywhere over the network (there is no analytics or
 *   crash-reporting SDK in this app to send it to in the first place; see app/build.gradle.kts).
 * - It is bounded twice: at most [CAPACITY] entries, and each entry at most [MAX_LINE] characters,
 *   so even a flood of messages (1000 a second, say) cannot grow it. The oldest entry is dropped first.
 * - Identical consecutive lines are folded into one entry with a repeat count, so a repeating error does
 *   not push the useful lines out of the buffer. Nothing is lost silently: the count is shown.
 * - It is cleared on every VPN/engine stop and implicitly on process death.
 * - android.util.Log calls are stripped from release builds by ProGuard as an independent second layer.
 *
 * Cost model: [append] is O(1) and does NOT publish anything. A screen that wants to show the log polls
 * [version] and takes a [snapshot] only when it changed, and only while it is visible. With the log
 * screen closed nothing runs per line except this append.
 *
 * Honest limitation: this controls what THIS APP does. It cannot control whether the Android OS itself
 * writes low-level system log lines to the system logcat; `adb logcat` on your own device is how to check.
 */
object RingLogBuffer {
    const val CAPACITY = 500
    const val MAX_LINE = 600

    private class Entry(val text: String, var count: Int)

    private val buffer = ArrayDeque<Entry>(CAPACITY + 1)
    private val versionCounter = AtomicLong(0)

    /** Changes whenever the visible content changes. Cheap to read from any thread. */
    val version: Long get() = versionCounter.get()

    @Synchronized
    fun append(line: String) {
        val text = clip(line)
        val last = buffer.peekLast()
        if (last != null && last.text == text) {
            last.count++
        } else {
            if (buffer.size >= CAPACITY) buffer.removeFirst()
            buffer.addLast(Entry(text, 1))
        }
        versionCounter.incrementAndGet()
    }

    /** The lines as shown to the user, oldest first; repeats carry a trailing count. */
    @Synchronized
    fun snapshot(): List<String> = buffer.map(::render)

    /** The newest [n] lines, for keeping the reason of a stop before the buffer is cleared. */
    @Synchronized
    fun tail(n: Int): List<String> {
        if (n <= 0) return emptyList()
        val skip = (buffer.size - n).coerceAtLeast(0)
        return buffer.asSequence().drop(skip).map(::render).toList()
    }

    @Synchronized
    fun size(): Int = buffer.size

    @Synchronized
    fun clear() {
        buffer.clear()
        versionCounter.incrementAndGet()
    }

    private fun render(e: Entry): String = if (e.count > 1) "${e.text}  (x${e.count})" else e.text

    private fun clip(line: String): String {
        val oneLine = if (line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0) line.replace('\r', ' ').replace('\n', ' ') else line
        return if (oneLine.length <= MAX_LINE) oneLine else oneLine.substring(0, MAX_LINE) + "..."
    }
}
