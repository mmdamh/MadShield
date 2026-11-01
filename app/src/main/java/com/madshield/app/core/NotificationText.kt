package com.madshield.app.core

import java.util.Locale

/** Text for the status notification. Pure, so it can be tested off-device. */
object NotificationText {
    private const val LRM = "‎" // keeps "↑ 1.2 MB/s ↓ ..." in order inside right-to-left UI

    /** Compact rate like sing-box shows it: "12 KB/s", "1.2 MB/s". */
    fun rate(bytesPerSec: Long): String {
        val b = bytesPerSec.coerceAtLeast(0)
        return when {
            b >= 1024L * 1024 * 1024 -> String.format(Locale.US, "%.1f GB/s", b / 1073741824.0)
            b >= 1024L * 1024 -> String.format(Locale.US, "%.1f MB/s", b / 1048576.0)
            b >= 1024 -> String.format(Locale.US, "%.0f KB/s", b / 1024.0)
            else -> "$b B/s"
        }
    }

    /** Very short download speed for the status-bar chip of a Live update ("↓850K", "↓1.2M"): under 7 characters. */
    fun chip(downBps: Long): String {
        val b = downBps.coerceAtLeast(0)
        return when {
            b >= 1024L * 1024 * 1024 -> String.format(Locale.US, "↓%.1fG", b / 1073741824.0)
            b >= 10L * 1024 * 1024 -> String.format(Locale.US, "↓%.0fM", b / 1048576.0)
            b >= 1024L * 1024 -> String.format(Locale.US, "↓%.1fM", b / 1048576.0)
            b >= 1024 -> String.format(Locale.US, "↓%.0fK", b / 1024.0)
            else -> "↓${b}B"
        }
    }

    fun speedLine(upBps: Long, downBps: Long): String =
        "$LRM↑ ${rate(upBps)}   ↓ ${rate(downBps)}"

    /** Bytes per second between two counter readings; 0 when the counter went backwards or no time passed. */
    fun bps(prevBytes: Long, nowBytes: Long, elapsedMs: Long): Long {
        if (elapsedMs <= 0 || nowBytes < prevBytes) return 0
        return ((nowBytes - prevBytes) * 1000.0 / elapsedMs).toLong()
    }
}
