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
    const val PSIPHON_BIN = "libpsiphon.so"
    const val SINGBOX_BIN = "libsingbox.so"
}

/** Thrown BEFORE the engine is launched when the shipped binary cannot possibly start. */
class EnginePreflightException(message: String) : IllegalStateException(message)

/**
 * Result of a live switch of the custom-chain link ([EngineProcessManager.swapChainLink]).
 * [ok] false + [restored] true: the new link did not work and the previous one is running again.
 * [ok] false + [restored] false: nothing was changed (bad link, no chain running) or the old link could not be restored either.
 */
data class SwapOutcome(val ok: Boolean, val restored: Boolean, val reason: String? = null)

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

    companion object {
        private const val HASH_ASSET = "native_hashes.properties"

        /**
         * What the custom-chain end-to-end check asks: a literal address (no name lookup), plain HTTP, port 80.
         * The FIRST is deliberately NOT Cloudflare: a VLESS/Trojan server that lives on Cloudflare Workers cannot open
         * connections to Cloudflare addresses (platform rule), so a probe made only of 1.1.1.1 / 1.0.0.1 could never succeed
         * for it and the link looked "never connecting" although it carried every other site. 13.107.4.52 is Microsoft's
         * long-lived connectivity-check address; the Cloudflare ones stay as fallbacks. One answer from any of them is enough.
         */
        private val E2E_TARGETS = listOf("13.107.4.52" to 80, "1.1.1.1" to 80, "1.0.0.1" to 80)
        private const val E2E_TARGET_TIMEOUT_MS = 6_000
        /** How long a switched link gets to prove itself before the previous one is restored. */
        private const val SWAP_VERIFY_MS = 25_000L
        private const val CANCELLED = "\u0000cancelled"
        private const val E2E_EVERY_MS = 90_000L
        /** Result of the integrity check of this process; null until the first engine start. */
        @Volatile var cachedIntegrity: BinaryIntegrity.Result? = null
            private set
    }

    @Volatile private var process: Process? = null
    @Volatile private var dying: Process? = null
    @Volatile var lastExit: EngineExit? = null
        private set

    /** True once the core announced that its Psiphon/Tor chain really carries traffic. */
    @Volatile var chainReady: Boolean = false
        private set
    @Volatile private var nativeDirPath: String? = null
    private var pumpJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tail = ArrayDeque<String>()

    @Volatile private var front: RouteFront? = null

    // ---- custom chain (sing-box), see SingBoxConfig. All null/false unless the chain is SINGBOX.
    @Volatile private var singbox: Process? = null
    @Volatile private var singboxExit: EngineExit? = null
    private var singboxPump: Job? = null
    private var singboxReadyJob: Job? = null
    private val singboxTail = ArrayDeque<String>()
    @Volatile private var singboxPort: Int = 0
    // Live link switch (update18): what is needed to restart ONLY sing-box, and who may touch its fields.
    @Volatile private var singboxBinFile: File? = null
    @Volatile private var singboxCorePort: Int = 0
    @Volatile private var chainLinkRaw: String? = null
    private val chainLock = Any()
    /** Bumped by every start() and stop(): a swap that sees it change knows the engine was restarted or stopped under it. */
    @Volatile private var generation = 0
    @Volatile private var swapInProgress = false
    @Volatile private var swapEndedAt = -1_000_000L

    /**
     * True while sing-box is being replaced, and for a few seconds after: the health loops skip their checks then (the
     * chain is down for a moment on purpose, and a probe that started inside that window must not count as a failure).
     */
    val swapping: Boolean
        get() = swapInProgress || android.os.SystemClock.elapsedRealtime() - swapEndedAt < 4_000L
    private var e2eFailures = 0
    private var nextE2eAt = 0L
    @Volatile private var e2eOk = true

    /** A custom chain is in use for the running engine. */
    val singboxActive: Boolean get() = singbox != null

    /** The custom chain stopped carrying traffic (two end-to-end checks failed in a row) while its processes are alive. */
    val chainBroken: Boolean get() = singboxActive && !e2eOk

    /** Counts failed WireGuard scans from the core's log; a new one for every engine start. */
    @Volatile private var stall = TunnelStallTracker()

    /** True when the core is up but has found no working WireGuard endpoint in several full scans in a row. */
    fun tunnelStalled(): Boolean = stall.stalled

    /**
     * The port that really belongs to the engine side (the core, or the chain), set by [start]. Health probes
     * must ask THIS port: RouteFront answers the SOCKS greeting on the public port by itself, even before the
     * core is ready or after it hung.
     */
    @Volatile var probePort: Int = TunnelConfig.SOCKS_PORT
        private set

    /** The core is alive and, with a custom chain, so is sing-box (a dead chain process means a dead chain). */
    val isRunning: Boolean get() = process?.isAlive == true && (singbox?.isAlive != false)

    /** [chainLink] is the share link of the custom chain; only read when the chain is [PrivacyChain.SINGBOX]. */
    fun start(config: EngineConfig, ruleWriter: RuleFileWriter, secretEnv: Map<String, String>, chainLink: String? = null) {
        stop()
        waitForPreviousToDie()
        chainReady = false
        synchronized(chainLock) { generation++ }

        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        nativeDirPath = nativeDir.absolutePath
        val bin = File(nativeDir, EngineEnv.ENGINE_BIN)
        preflight(bin, nativeDir)
        checkIntegrity(nativeDir)

        val chain = config.effectiveChain
        val psiphonBin = File(nativeDir, EngineEnv.PSIPHON_BIN)
        if (chain == PrivacyChain.PSIPHON && !psiphonBin.isFile) {
            throw EnginePreflightException(
                "This build has no Psiphon engine for this CPU (libpsiphon.so missing). " +
                    "Rebuild with the updated CI workflow, or turn the chain off in Settings."
            )
        }
        // Custom chain: everything that can be wrong with the link or the binary is reported BEFORE anything starts.
        val singboxBin = File(nativeDir, EngineEnv.SINGBOX_BIN)
        var singboxLink: LinkParse.Ok? = null
        if (chain == PrivacyChain.SINGBOX) {
            if (!singboxBin.isFile) {
                throw EnginePreflightException(
                    "This build has no sing-box engine for this CPU (libsingbox.so missing). " +
                        "Rebuild with the updated CI workflow, or turn the chain off in Settings."
                )
            }
            preflight(singboxBin, nativeDir)
            singboxLink = when (val r = ProxyLink.parse(chainLink ?: "")) {
                is LinkParse.Ok -> r
                is LinkParse.Err -> throw EnginePreflightException("Custom chain (sing-box): " + LinkMessages.english(r))
            }
        }
        val chainDir = when (chain) {
            PrivacyChain.PSIPHON -> File(context.filesDir, "psiphon")
            PrivacyChain.TOR -> File(context.filesDir, "tor")
            PrivacyChain.NONE, PrivacyChain.SINGBOX -> null
        }?.also { it.mkdirs() }

        // Clean slate (pattern from AetherGUI): remove our own leftovers, then make
        // sure the port is really free before binding a new core to it.
        val reaped = CoreProcessGuard.reapOrphans(
            expectedExecutables = setOf(bin.absolutePath, psiphonBin.absolutePath, singboxBin.absolutePath),
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

        val routesFile = ruleWriter.writeRoutesFile(config.directRules, config.blockRules)
        // Who owns which port, and whether RouteFront runs at all (see FrontPlan). With a chain on and no local
        // DoH this is exactly update10: the front only exists when routing rules need it.
        val dohActive = config.dohActive
        val ruleMatcher = if (routesFile != null && (chain != PrivacyChain.NONE || dohActive)) RouteMatcher.fromFile(routesFile) else null
        val plan = FrontPlan.of(chain, dohActive, ruleMatcher != null && !ruleMatcher.isEmpty, config.socksPort)
        probePort = plan.upstreamPort

        // DoH resolvers are built BEFORE the engine is launched, so a bad setting can never leave a process behind.
        val frontOptions: RouteFront.Options? = if (!plan.frontOn) null else if (!plan.localDoh) RouteFront.Options() else {
            val specs = DohSpec.parseList(config.dohResolvers.joinToString("\n")).valid
            if (specs.isEmpty()) {
                throw IllegalStateException("Local DoH is on but none of the resolvers is valid. Fix them in the DNS tab.")
            }
            RouteFront.Options(
                resolver = FrontResolver(DohTransports.create(specs, plan.upstreamPort), config.ipMode, config.dohServeStale),
                directResolver = if (config.dohForDirect) {
                    FrontResolver(DohTransports.create(specs, null), config.ipMode, config.dohServeStale)
                } else null,
                udpPassThrough = plan.udpPassThrough,
                guardFakeIps = true,
                allowOnion = chain == PrivacyChain.TOR
            )
        }

        val env = EngineEnvironment.build(
            config = config,
            configFilePath = File(context.filesDir, "aether.toml").absolutePath,
            tmpDirPath = context.cacheDir.absolutePath,
            // With a chain the core never sees app traffic, so the rules are applied by RouteFront instead.
            routesFilePath = if (plan.coreGetsRoutes) routesFile?.absolutePath else null,
            secretEnv = secretEnv,
            chainBinPath = if (chain == PrivacyChain.PSIPHON) psiphonBin.absolutePath else null,
            chainDirPath = chainDir?.absolutePath,
            plan = plan
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

        if (frontOptions != null) {
            val f = RouteFront(config.socksPort, plan.upstreamPort, ruleMatcher ?: RouteMatcher.parse(""), frontOptions) { RingLogBuffer.append(it) }
            try {
                f.start()
                front = f
            } catch (e: IOException) {
                frontOptions.resolver?.clear()
                frontOptions.directResolver?.clear()
                p.destroy()
                process = null
                dying = p
                throw IllegalStateException("Could not start the routing front on port ${config.socksPort}: ${e.message}")
            }
        }

        val sbLink = singboxLink
        if (sbLink != null) {
            try {
                startSingBox(singboxBin, sbLink, chainLink ?: "", corePort = plan.corePort, listenPort = plan.chainPort ?: config.socksPort)
            } catch (t: Throwable) {
                // Nothing may be left running behind a failed start.
                front?.stop(); front = null
                p.destroy(); process = null; dying = p
                throw if (t is IOException) IllegalStateException("Could not start sing-box: ${t.message}") else t
            }
        }

        val stallTracker = TunnelStallTracker()
        stall = stallTracker
        pumpJob = scope.launch {
            val folder = LogNoiseFolder() // Psiphon's EOF line for every health probe of ours, see LogNoiseFolder
            try {
                BufferedReader(InputStreamReader(p.inputStream)).use { reader ->
                    while (isActive) {
                        val line = reader.readLine() ?: break
                        if (ChainReady.isReadyLine(line)) chainReady = true
                        if (TunnelStallTracker.isRelevant(line)) stallTracker.feed(line)
                        for (out in folder.feed(line)) RingLogBuffer.append(out) // memory only -- see RingLogBuffer
                        // The exit reason is read from the last lines: probe noise must not push them out.
                        if (!LogNoiseFolder.isNoise(line)) synchronized(tail) {
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
                // Keep the reason (redacted, in memory) before anything restarts the engine or clears the log.
                DiagnosticsHub.recordExit("engine exited unexpectedly with code $code", lines)
            }
        }
    }

    /**
     * With a chain on, the SOCKS port answers as soon as Psiphon/Tor's own local proxy is up, which is
     * BEFORE the chain is connected. Waits (up to [timeoutMs]) for the core's "is ready" announcement, so
     * the tunnel bridge is not attached to a chain that cannot carry anything yet.
     * @return null when ready, or a reason when the engine died / the time ran out / the user cancelled.
     */
    fun awaitChainReady(timeoutMs: Long, cancelled: () -> Boolean): String? {
        val startedAt = System.currentTimeMillis()
        val deadline = startedAt + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (chainReady) return null
            if (cancelled()) return "cancelled"
            if (!isRunning) return failureReason() ?: "the engine process exited"
            // A chain can take minutes to start; poll slower the longer it takes instead of 6 times a second throughout.
            try { Thread.sleep(PowerPolicy.readyPollMs(System.currentTimeMillis() - startedAt)) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); return "cancelled" }
        }
        return if (singboxActive) {
            "the custom chain (sing-box) did not carry traffic in ${timeoutMs / 1000}s: check the link, and that the server is reachable" +
                (singboxLastLine()?.let { " [$it]" } ?: "")
        } else {
            "the privacy chain (Psiphon/Tor) did not become ready in ${timeoutMs / 1000}s"
        }
    }

    // ------------------------------------------------------------------------------------ custom chain

    private fun startSingBox(bin: File, link: LinkParse.Ok, rawLink: String, corePort: Int, listenPort: Int) {
        singboxBinFile = bin
        singboxCorePort = corePort
        chainLinkRaw = rawLink
        launchSingBox(bin, link, corePort, listenPort, null)
    }

    /**
     * Starts one sing-box process and its pump and readiness job. [gen] (swap only) is the generation the caller started
     * under: when start()/stop() ran meanwhile the new process is killed again and null is returned.
     */
    private fun launchSingBox(bin: File, link: LinkParse.Ok, corePort: Int, listenPort: Int, gen: Int?): Process? {
        val json = SingBoxConfig.build(link, corePort, listenPort)
        val dir = File(context.cacheDir, "singbox").also { it.mkdirs() }
        // The configuration (it holds your UUID / password) goes in through STDIN: it is never written to a file.
        val pb = ProcessBuilder(bin.absolutePath, "run", "-c", "stdin", "-D", dir.absolutePath, "--disable-color")
            .directory(dir)
            .redirectErrorStream(true)
        pb.environment().apply {
            keys.removeAll { EngineEnvironment.isInherited(it) }
            put("TMPDIR", context.cacheDir.absolutePath)
            put("GOMAXPROCS", Chain.GO_MAX_PROCS)   // same caps as Psiphon: a burst must not spread over every big core
            put("GOMEMLIMIT", Chain.GO_MEMORY_LIMIT)
        }
        RingLogBuffer.append("[singbox] starting ${link.summary} through the core on 127.0.0.1:$corePort, listening on $listenPort")
        synchronized(singboxTail) { singboxTail.clear() }
        singboxExit = null
        e2eFailures = 0; e2eOk = true; nextE2eAt = 0L
        val sp = pb.start()
        try {
            sp.outputStream.use { it.write(json.toByteArray(Charsets.UTF_8)) } // closing it = EOF, which ends the config read
        } catch (e: IOException) {
            sp.destroy() // never leave a process behind that has no configuration
            throw e
        }
        synchronized(chainLock) {
            if (gen != null && gen != generation) {
                sp.destroy()
                return null
            }
            singbox = sp
            singboxPort = listenPort
        }

        singboxPump = scope.launch {
            try {
                BufferedReader(InputStreamReader(sp.inputStream)).use { reader ->
                    while (isActive) {
                        val line = reader.readLine() ?: break
                        RingLogBuffer.append("[singbox] $line")
                        synchronized(singboxTail) {
                            if (singboxTail.size >= 20) singboxTail.removeFirst()
                            singboxTail.addLast(line)
                        }
                    }
                }
            } catch (_: IOException) {
            }
            val code = try { sp.waitFor() } catch (_: InterruptedException) { -1 }
            if (singbox === sp) {
                val lines = synchronized(singboxTail) { singboxTail.toList() }
                singboxExit = EngineExit(code, lines)
                RingLogBuffer.append("[singbox] exited unexpectedly with code $code")
                DiagnosticsHub.recordExit("sing-box exited unexpectedly with code $code", lines)
            }
        }

        // "Ready" for a custom chain means data really flows end to end. sing-box's own SOCKS port answers at once,
        // long before the WARP tunnel is up or the server was ever contacted, so it proves nothing.
        singboxReadyJob = scope.launch {
            var pause = 1_500L
            while (isActive && singbox === sp && sp.isAlive) {
                if (e2eProbe(listenPort)) {
                    chainReady = true
                    RingLogBuffer.append("[singbox] the custom chain carries traffic end to end")
                    return@launch
                }
                delay(pause)
                pause = minOf(pause * 2, 10_000L)
            }
        }
        return sp
    }

    // ------------------------------------------------------------------------------------ live link switch

    /** The link sing-box is running with right now (null: no custom chain). Compared with the saved one by the swapper. */
    fun chainLinkInUse(): String? = if (singbox != null || swapInProgress) chainLinkRaw else null

    /**
     * Switches the custom chain to [newRaw] WITHOUT touching the core: only the sing-box process is replaced, so the
     * WARP tunnel, its endpoint and the TUN bridge stay exactly as they are. Connections that were open through the old
     * server drop (they have to: they belong to it); new ones go through the new server within a second or two.
     * The new link must carry traffic end to end within [SWAP_VERIFY_MS]; if it does not, the previous link is started
     * again and [SwapOutcome.restored] says so. Blocking: call from a background thread.
     */
    fun swapChainLink(newRaw: String): SwapOutcome {
        val bin = singboxBinFile
        val oldRaw = chainLinkRaw
        val old = singbox
        if (bin == null || oldRaw == null || old == null || process?.isAlive != true) {
            return SwapOutcome(false, false, "no custom chain is running")
        }
        val fresh = when (val r = ProxyLink.parse(newRaw)) {
            is LinkParse.Ok -> r
            is LinkParse.Err -> return SwapOutcome(false, false, "Custom chain (sing-box): " + LinkMessages.english(r))
        }
        if (newRaw == oldRaw) return SwapOutcome(true, false, null)
        val oldParsed = ProxyLink.parse(oldRaw) as? LinkParse.Ok
            ?: return SwapOutcome(false, false, "the running link cannot be read back")
        val gen = generation
        val port = singboxPort
        val corePort = singboxCorePort
        if (swapInProgress) return SwapOutcome(false, false, "a switch is already in progress")
        swapInProgress = true
        try {
            RingLogBuffer.append("[singbox] switching link without reconnecting: ${fresh.summary}")
            // 1. the old process goes away and frees the port (the core and WARP are not touched)
            if (!retireSingBox(old, port, gen)) return SwapOutcome(false, false, "cancelled")
            // 2. the new one starts and has to prove itself
            val failure = startAndVerify(bin, fresh, corePort, port, gen)
            if (failure == null) {
                chainLinkRaw = newRaw
                RingLogBuffer.append("[singbox] link switched; the tunnel stayed up")
                return SwapOutcome(true, false, null)
            }
            if (failure == CANCELLED) return SwapOutcome(false, false, "cancelled")
            // 3. it did not work: bring the previous link back
            RingLogBuffer.append("[singbox] the new link failed ($failure); restoring the previous one")
            val dead = singbox
            if (dead != null && !retireSingBox(dead, port, gen)) return SwapOutcome(false, false, "cancelled")
            val back = launchSingBox(bin, oldParsed, corePort, port, gen)
            return SwapOutcome(false, back != null, failure)
        } finally {
            swapEndedAt = android.os.SystemClock.elapsedRealtime()
            swapInProgress = false
        }
    }

    /** Detaches [sp] from the bookkeeping (so its exit is not reported as a crash), stops it and waits for the port. */
    private fun retireSingBox(sp: Process, port: Int, gen: Int): Boolean {
        synchronized(chainLock) {
            if (gen != generation) return false
            singboxReadyJob?.cancel(); singboxReadyJob = null
            singboxPump?.cancel(); singboxPump = null
            if (singbox === sp) singbox = null
        }
        sp.destroy()
        CoreProcessGuard.stop(sp, 1_500)
        SocksProbe.awaitPortFree(port, 3_000)
        return gen == generation
    }

    /** null = the new process carries traffic end to end; otherwise why not (or [CANCELLED]). */
    private fun startAndVerify(bin: File, link: LinkParse.Ok, corePort: Int, port: Int, gen: Int): String? {
        val sp = launchSingBox(bin, link, corePort, port, gen) ?: return CANCELLED
        val deadline = System.currentTimeMillis() + SWAP_VERIFY_MS
        while (System.currentTimeMillis() < deadline) {
            if (gen != generation) return CANCELLED
            if (!sp.isAlive) return "sing-box stopped" + (singboxLastLine()?.let { ": $it" } ?: "")
            if (e2eProbe(port)) return null
            try { Thread.sleep(700) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); return CANCELLED }
        }
        return "the new link did not carry traffic in ${SWAP_VERIFY_MS / 1000}s" + (singboxLastLine()?.let { " [$it]" } ?: "")
    }

    private fun e2eProbe(port: Int): Boolean =
        E2E_TARGETS.any { (host, p) -> SocksProbe.httpAnswersThrough(TunnelConfig.SOCKS_HOST, port, host, p, E2E_TARGET_TIMEOUT_MS) }

    /** Last line sing-box printed (it does not log the UUID / password), for failure messages. */
    private fun singboxLastLine(): String? =
        synchronized(singboxTail) { singboxTail.lastOrNull { it.isNotBlank() } }?.take(160)

    /**
     * Called by the health loops. With a custom chain on, and ONLY while the screen is on (nobody is waiting for the
     * answer otherwise, and every check wakes the radio), it makes one end-to-end request about every 90 s. The chain
     * counts as broken after two failures in a row (the second comes 10 s after the first), so one slow moment
     * is not an outage. Always true when there is no custom chain.
     */
    fun chainStillWorks(screenOn: Boolean): Boolean {
        if (!singboxActive) return true
        if (!screenOn || !chainReady) return e2eOk
        val now = android.os.SystemClock.elapsedRealtime()
        if (now < nextE2eAt) return e2eOk
        val ok = e2eProbe(singboxPort)
        e2eFailures = if (ok) 0 else e2eFailures + 1
        e2eOk = e2eFailures < 2
        nextE2eAt = now + if (ok) E2E_EVERY_MS else 10_000L
        if (!ok) RingLogBuffer.append("[singbox] end-to-end check failed ($e2eFailures of 2)")
        return e2eOk
    }

    /** Cumulative CPU ticks (utime+stime) of the engine and its Psiphon child, or null when unavailable. */
    fun cpuTicks(): Long? {
        val dir = nativeDirPath ?: return null
        val pids = CoreProcessGuard.findOwnPids(
            setOf(
                File(dir, EngineEnv.ENGINE_BIN).absolutePath, File(dir, EngineEnv.PSIPHON_BIN).absolutePath,
                File(dir, EngineEnv.SINGBOX_BIN).absolutePath
            ),
            android.os.Process.myPid(), android.os.Process.myUid()
        )
        if (pids.isEmpty()) return null
        var total = 0L
        for (pid in pids) {
            val text = try { File("/proc/$pid/stat").readText() } catch (_: IOException) { continue }
            total += CpuSampler.parseTicks(text) ?: 0L
        }
        return total
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
        // A custom chain that died while the core is fine is the more useful thing to report.
        if (singboxExit == null && singbox?.isAlive == false) {
            val deadline = System.currentTimeMillis() + 1_500
            while (singboxExit == null && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(25) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        }
        singboxExit?.let { sb ->
            return "The custom chain (sing-box) stopped (exit code ${sb.code})" +
                (sb.lastLines.lastOrNull()?.takeIf { it.isNotBlank() }?.let { ": ${it.take(160)}" } ?: "")
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
            joined.contains("psiphon needs the psiphon-tunnel-core", ignoreCase = true) ->
                "The Psiphon engine is missing from this build. Rebuild with the updated CI workflow or turn the chain off in Settings."
            joined.contains("no tor support", ignoreCase = true) ->
                "This build has no Tor support. Rebuild with the updated CI workflow or turn the chain off in Settings."
            joined.contains("psiphon did not come up", ignoreCase = true) ->
                "Psiphon could not connect through this network. Try another protocol underneath, or turn the chain off. " +
                    (exit.lastLines.lastOrNull()?.takeIf { it.isNotBlank() }?.let { "[${it.take(140)}]" } ?: "")
            joined.contains("CANNOT LINK EXECUTABLE") ->
                "Android could not load the engine binary: " +
                    (exit.lastLines.firstOrNull { it.contains("CANNOT LINK") } ?: "link error")
            else -> "The engine stopped (exit code ${exit.code})" +
                (exit.lastLines.lastOrNull()?.takeIf { it.isNotBlank() }?.let { ": ${it.take(160)}" } ?: "")
        }
    }

    /** Screen off and the tunnel quiet: lets the local DoH client drop its idle connection. Starts no timer. */
    fun onIdle() { front?.onIdle() }

    fun stop() {
        pumpJob?.cancel()
        pumpJob = null
        val sbToStop: Process?
        synchronized(chainLock) {
            generation++ // a live link switch in progress sees this and gives up
            singboxReadyJob?.cancel(); singboxReadyJob = null
            singboxPump?.cancel(); singboxPump = null
            sbToStop = singbox
            singbox = null
            chainLinkRaw = null
        }
        sbToStop?.let { sp ->
            RingLogBuffer.append("[singbox] stopping")
            sp.destroy()
            scope.launch { CoreProcessGuard.stop(sp, 750) }
        }
        front?.stop()
        front = null
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

    /**
     * Compares the installed native files with the hashes CI stamped into the APK (see [BinaryIntegrity]).
     * Done once per process: hashing a few MB is cheap, but not worth repeating on every reconnect.
     */
    private fun checkIntegrity(nativeDir: File) {
        val result = cachedIntegrity ?: run {
            val expected = runCatching {
                context.assets.open(HASH_ASSET).bufferedReader().use { NativeHashes.parse(it.readText()) }
            }.map { NativeHashes.forDevice(it, Build.SUPPORTED_ABIS.toList()) }.getOrDefault(emptyMap())
            BinaryIntegrity.verifyDir(nativeDir, expected).also {
                cachedIntegrity = it
                RingLogBuffer.append("[integrity] " + if (it.ok) "native files match the CI build (${expected.size} checked)"
                    else it.details.filter { d -> !d.endsWith(": ok") }.joinToString("; "))
            }
        }
        if (!result.ok) {
            throw EnginePreflightException(
                "A native file of this app does not match what the build produced " +
                    "(${result.details.filter { !it.endsWith(": ok") }.joinToString("; ")}). " +
                    "Reinstall the app from your own build."
            )
        }
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
