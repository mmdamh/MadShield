package com.madshield.desktop

import com.madshield.app.core.EngineEnvironment
import com.madshield.app.util.LogRedactor
import com.madshield.app.util.RingLogBuffer
import java.io.File
import java.io.IOException

/**
 * One engine program: starts it, pumps its output into the in-memory log (never a file) and stops it with everything it
 * started (aether starts Psiphon and Tor as children).
 */
class ManagedProcess(val name: String) {
    @Volatile private var p: Process? = null
    private val tail = ArrayDeque<String>()
    @Volatile var exitCode: Int? = null
        private set

    val alive: Boolean get() = p?.isAlive == true

    /** The last lines it printed, for the reason when it died. */
    fun lastLines(): List<String> = synchronized(tail) { tail.toList() }

    /**
     * @param stdin null: stdin stays open (Foxy ends when it closes); "": closed at once (Aether must never wait on a prompt);
     *  otherwise the text is written and stdin is closed (sing-box reads its configuration from it).
     */
    fun start(exe: File, args: List<String>, env: Map<String, String>, dir: File, stdin: String?, onLine: (String) -> Unit = {}) {
        val pb = ProcessBuilder(listOf(exe.absolutePath) + args).directory(dir).redirectErrorStream(true)
        pb.environment().apply {
            keys.removeAll { EngineEnvironment.isInherited(it) }
            putAll(env)
        }
        synchronized(tail) { tail.clear() }
        exitCode = null
        val proc = pb.start()
        p = proc
        if (stdin != null) {
            try {
                if (stdin.isNotEmpty()) proc.outputStream.write(stdin.toByteArray(Charsets.UTF_8))
                proc.outputStream.close()
            } catch (_: IOException) { /* it already ended; the reader below reports why */ }
        }
        Thread {
            try {
                proc.inputStream.bufferedReader(Charsets.UTF_8).use { r ->
                    while (true) {
                        val line = r.readLine() ?: break
                        val shown = LogRedactor.redact(line)
                        RingLogBuffer.append("[$name] $shown")
                        synchronized(tail) {
                            if (tail.size >= 20) tail.removeFirst()
                            tail.addLast(shown)
                        }
                        onLine(line)
                    }
                }
            } catch (_: IOException) { /* closed on stop */ }
            exitCode = try { proc.waitFor() } catch (_: InterruptedException) { -1 }
        }.apply { isDaemon = true; this.name = "pump-$name" }.start()
    }

    /** Never throws. Children first, then the program itself. */
    fun stop() {
        val proc = p ?: return
        p = null
        try {
            proc.destroy()
            if (!proc.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) {
                proc.descendants().forEach { it.destroyForcibly() }
                proc.destroyForcibly()
                proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
            } else {
                proc.descendants().forEach { it.destroyForcibly() }
            }
        } catch (_: Exception) { /* nothing more can be done */ }
    }
}
