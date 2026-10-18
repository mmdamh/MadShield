package com.aethershield.app.core

import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Ownership checks and bounded shutdown for the engine child process.
 *
 * Pattern taken from AetherGUI's CoreProcessGuard, re-written here: a core left
 * behind by a previous session (or by a process death) keeps the SOCKS port and
 * its upstream sockets, so the next Connect "succeeds" instantly against the
 * WRONG process and carries nothing. Before every start we therefore terminate
 * leftovers -- but only ones that are provably ours:
 *   * the executable path must be exactly our own libaether.so, AND
 *   * all four UIDs in /proc/<pid>/status must equal our app UID.
 * A command-line substring match would not establish ownership and is never used.
 */
object CoreProcessGuard {

    private val UID_LINE = Regex("(?m)^Uid:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)")

    fun isOwnedExecutable(executable: String, expected: Set<String>, procStatus: String, appUid: Int): Boolean {
        if (executable !in expected) return false
        val m = UID_LINE.find(procStatus) ?: return false
        return (1..4).all { i -> m.groupValues[i].toIntOrNull() == appUid }
    }

    /**
     * Kills our own leftover engine processes. [kill] is injected so this stays
     * testable (on Android pass `android.os.Process::killProcess`).
     * @return how many processes were terminated.
     */
    fun reapOrphans(
        expectedExecutables: Set<String>,
        selfPid: Int,
        appUid: Int,
        kill: (Int) -> Unit,
        log: (String) -> Unit,
        procRoot: File = File("/proc")
    ): Int {
        val canonicalExpected = expectedExecutables.mapNotNull {
            try { File(it).canonicalPath } catch (_: IOException) { null }
        }.toSet()
        if (canonicalExpected.isEmpty()) return 0
        val entries = procRoot.listFiles() ?: return 0
        var killed = 0
        for (entry in entries) {
            val pid = entry.name.toIntOrNull() ?: continue
            if (pid == selfPid) continue
            try {
                val exe = File(entry, "exe").canonicalPath
                if (!isOwnedExecutable(exe, canonicalExpected, readHead(File(entry, "status")), appUid)) continue
                kill(pid)
                killed++
                log("[guard] cleared a leftover engine process (pid $pid)")
            } catch (_: IOException) {
                // not ours / not readable: leave it alone
            } catch (_: SecurityException) {
            }
        }
        return killed
    }

    /** PIDs of our own running processes whose executable is one of [expectedExecutables]. */
    fun findOwnPids(
        expectedExecutables: Set<String>,
        selfPid: Int,
        appUid: Int,
        procRoot: File = File("/proc")
    ): List<Int> {
        val canonicalExpected = expectedExecutables.mapNotNull {
            try { File(it).canonicalPath } catch (_: IOException) { null }
        }.toSet()
        if (canonicalExpected.isEmpty()) return emptyList()
        val found = ArrayList<Int>()
        for (entry in procRoot.listFiles() ?: return emptyList()) {
            val pid = entry.name.toIntOrNull() ?: continue
            if (pid == selfPid) continue
            try {
                val exe = File(entry, "exe").canonicalPath
                if (isOwnedExecutable(exe, canonicalExpected, readHead(File(entry, "status")), appUid)) found += pid
            } catch (_: IOException) {
            } catch (_: SecurityException) {
            }
        }
        return found
    }

    private fun readHead(file: File): String = try {
        file.inputStream().use { input ->
            val buf = ByteArray(1024)
            val n = input.read(buf)
            if (n <= 0) "" else String(buf, 0, n, Charsets.UTF_8).replace('\u0000', ' ')
        }
    } catch (_: IOException) {
        ""
    }

    /** destroy(), then destroyForcibly() if it lingers. @return true once the process is gone. */
    fun stop(process: Process, graceMs: Long): Boolean {
        var interrupted = false
        try {
            process.destroy()
            try {
                if (process.waitFor(graceMs, TimeUnit.MILLISECONDS)) return true
            } catch (_: InterruptedException) {
                interrupted = true
            }
            process.destroyForcibly()
            return try {
                process.waitFor(graceMs, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                interrupted = true
                !process.isAlive
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}
