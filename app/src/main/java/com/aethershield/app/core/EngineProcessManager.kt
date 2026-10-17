package com.aethershield.app.core

import android.content.Context
import android.os.Build
import com.aethershield.app.util.RingLogBuffer
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader

object EngineEnv {
    const val ENGINE_BIN = "libaether.so"
}

/** Thrown BEFORE the engine is launched when the shipped binary cannot possibly start. */
class EnginePreflightException(message: String) : IllegalStateException(message)

/** How the last engine process ended, kept so the UI can show the real reason. */
data class EngineExit(val code: Int, val lastLines: List<String>)

/**
 * Launches Aether core v2.3.0 and supervises it. The environment it gets is
 * built by [EngineEnvironment]; this class owns the process lifecycle:
 *
 *  1. PRE-FLIGHT: the binary must be a valid ELF for this device and must not
 *     depend on a shared libc++ the APK does not carry. Otherwise Android's
 *     linker kills it instantly with "CANNOT LINK EXECUTABLE", which used to
 *     look like an endless "Connecting".
 *  2. CLEAN SLATE: leftover engine processes of ours are terminated and the
 *     SOCKS port must be free, so a new core can never be confused with an old one.
 *  3. SUPERVISION: output goes to the in-memory log only, and the exit code plus
 *     the last lines are remembered ([lastExit]) so a crash is explained.
 */
class EngineProcessManager(private val context: Context) {

    @Volatile private var process: Process? = null
    @Volatile private var dying: Process? = null
    @Volatile var lastExit: EngineExit? = null
        private set
    private var pumpJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tail = ArrayDeque<String>()

    val isRunning: Boolean get() = process?.isAlive == true

    fun start(config: EngineConfig, ruleWriter: RuleFileWriter, secretEnv: Map<String, String>) {
        stop()
        waitForPreviousToDie()

        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val bin = File(nativeDir, EngineEnv.ENGINE_BIN)
        preflight(bin, nativeDir)

        // Clean slate (pattern from AetherGUI): remove our own leftovers, then make
        // sure the port is really free before binding a new core to it.
        val reaped = CoreProcessGuard.reapOrphans(
            expectedExecutables = setOf(bin.absolutePath),
            selfPid = android.os.Process.myPid(),
            appUid = android.os.Process.myUid(),
            kill = { android.os.Process.killProcess(it) },
            log = { RingLogBuffer.append(it) }
        )
        if (!SocksProbe.awaitPortFree(config.socksPort, if (reaped > 0) 3_000 else 1_500)) {
            throw IllegalStateException(
                "Port ${config.socksPort} is still in use by another process. " +
                    "Close the app that holds it, or change the SOCKS port in Settings."
            )
        }

        val env = EngineEnvironment.build(
            config = config,
            configFilePath = File(context.filesDir, "aether.toml").absolutePath,
            tmpDirPath = context.cacheDir.absolutePath,
            routesFilePath = ruleWriter.writeRoutesFile(config.directRules, config.blockRules)?.absolutePath,
            secretEnv = secretEnv
        )

        val pb = ProcessBuilder(bin.absolutePath)
            .directory(context.filesDir)
            .redirectErrorStream(true)
        pb.environment().apply {
            keys.removeAll { EngineEnvironment.isInherited(it) }
            putAll(env)
        }

        // Log the NON-secret part of the configuration only.
        RingLogBuffer.append(
            "[engine] starting ${bin.name} " +
                env.filterKeys { it.startsWith("AETHER_") && !it.contains("SECRET") && !it.contains("TOKEN") }
                    .entries.joinToString(" ") { "${it.key}=${it.value}" }
        )

        synchronized(tail) { tail.clear() }
        lastExit = null
        val p = pb.start()
        runCatching { p.outputStream.close() } // closed stdin => EOF, never a blocked prompt
        process = p

        pumpJob = scope.launch {
            try {
                BufferedReader(InputStreamReader(p.inputStream)).use { reader ->
                    while (isActive) {
                        val line = reader.readLine() ?: break
                        RingLogBuffer.append(line) // memory only -- see RingLogBuffer
                        synchronized(tail) {
                            if (tail.size >= 20) tail.removeFirst()
                            tail.addLast(line)
                        }
                    }
                }
            } catch (_: IOException) {
                // pipe closed on stop()
            }
            // Output ended => the process is gone (or about to be). Record how.
            val code = try { p.waitFor() } catch (_: InterruptedException) { -1 }
            if (process === p) { // exited on its own, not because stop() was called
                val lines = synchronized(tail) { tail.toList() }
                lastExit = EngineExit(code, lines)
                RingLogBuffer.append("[engine] exited unexpectedly with code $code")
            }
        }
    }

    /** A one-line, human-readable reason the engine is not running, or null if there is none. */
    fun failureReason(): String? {
        // The output pump records the exit a moment AFTER the process dies; give it a short
        // moment so the real reason is not missed. Call from a background thread only.
        if (lastExit == null && process?.isAlive == false) {
            val deadline = System.currentTimeMillis() + 1_500
            while (lastExit == null && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(25) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        }
        val exit = lastExit ?: return null
        val joined = exit.lastLines.joinToString("\n")
        return when {
            joined.contains("libc++_shared.so") ->
                "The engine needs libc++_shared.so, which is missing from this build. " +
                    "Rebuild the APK with the updated CI workflow (static libc++)."
            joined.contains("ECH key", ignoreCase = true) ->
                "ECH is on but its key lookup failed (the ECH resolver is not reachable from this network). " +
                    "Turn ECH off in Settings or pick another ECH resolver in the DNS tab. " +
                    (exit.lastLines.lastOrNull()?.takeIf { it.isNotBlank() }?.let { "[${it.take(140)}]" } ?: "")
            joined.contains("CANNOT LINK EXECUTABLE") ->
                "Android could not load the engine binary: " +
                    (exit.lastLines.firstOrNull { it.contains("CANNOT LINK") } ?: "link error")
            else -> "The engine stopped (exit code ${exit.code})" +
                (exit.lastLines.lastOrNull()?.takeIf { it.isNotBlank() }?.let { ": ${it.take(160)}" } ?: "")
        }
    }

    fun stop() {
        pumpJob?.cancel()
        pumpJob = null
        val p = process ?: return
        process = null
        RingLogBuffer.append("[engine] stopping")
        dying = p
        p.destroy() // SIGTERM now, never block the caller (may be the main thread)
        scope.launch {
            // Escalate if it lingers; start() also waits for this before reusing the port.
            CoreProcessGuard.stop(p, 750)
        }
    }

    private fun waitForPreviousToDie() {
        val prev = dying ?: return
        if (prev.isAlive && !CoreProcessGuard.stop(prev, 1_000)) {
            throw IllegalStateException("The previous engine process has not shut down yet. Try again in a moment.")
        }
        dying = null
    }

    /** See the class comment, step 1. */
    private fun preflight(bin: File, nativeDir: File) {
        if (!bin.isFile) {
            throw EnginePreflightException(
                "Engine binary not found at ${bin.absolutePath} -- the APK was built without the engine for this CPU."
            )
        }
        val info = try {
            ElfInspector.inspect(bin)
        } catch (e: IOException) {
            throw EnginePreflightException("The engine binary is not a valid executable (${e.message}).")
        }
        if (info.machineName !in Build.SUPPORTED_ABIS) {
            throw EnginePreflightException(
                "The engine was built for ${info.machineName}, but this device runs ${Build.SUPPORTED_ABIS.joinToString()}."
            )
        }
        val missing = info.needed.filter { it == "libc++_shared.so" && !File(nativeDir, it).isFile }
        if (missing.isNotEmpty()) {
            throw EnginePreflightException(
                "The engine needs libc++_shared.so, which is not included in this APK. " +
                    "Rebuild with the updated CI workflow (it links libc++ statically and fails the build otherwise)."
            )
        }
    }
}
