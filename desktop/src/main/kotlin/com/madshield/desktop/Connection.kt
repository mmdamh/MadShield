package com.madshield.desktop

import com.madshield.app.core.Chain
import com.madshield.app.core.ConnectPolicy
import com.madshield.app.core.ConnectionMode
import com.madshield.app.core.EngineConfig
import com.madshield.app.core.EngineEnvironment
import com.madshield.app.core.EngineKind
import com.madshield.app.core.ExitInfo
import com.madshield.app.core.FrontPlan
import com.madshield.app.core.FxClient
import com.madshield.app.core.FxErrors
import com.madshield.app.core.FxProgress
import com.madshield.app.core.FxVerdict
import com.madshield.app.core.FxVpn
import com.madshield.app.core.LinkMessages
import com.madshield.app.core.LinkParse
import com.madshield.app.core.PortGate
import com.madshield.app.core.PrivacyChain
import com.madshield.app.core.ProxyLink
import com.madshield.app.core.Protocol
import com.madshield.app.core.ReconnectPolicy
import com.madshield.app.core.RouteFront
import com.madshield.app.core.RouteMatcher
import com.madshield.app.core.RuleParser
import com.madshield.app.core.SingBoxConfig
import com.madshield.app.core.SocksProbe
import com.madshield.app.core.UpstreamLogin
import com.madshield.app.util.RingLogBuffer
import java.io.File
import java.io.IOException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed class ConnState {
    object Idle : ConnState()
    data class Connecting(val step: String, val attempt: Int) : ConnState()
    data class Connected(val exit: ExitInfo?, val sinceMs: Long) : ConnState()
    /** The connection was lost or failed for a reason that may pass: the next try is [retryInMs] away. */
    data class Waiting(val reason: String, val retryInMs: Long) : ConnState()
    /** Needs the user (no account, a bad link, no administrator rights): nothing is retried. */
    data class Failed(val reason: String) : ConnState()
    object Stopping : ConnState()
}

/**
 * One connection, the way the Android service does it, for Windows (update45):
 *
 *   routing front (1819) -> sing-box TUN (system-wide, strict) -> engine(s): Aether [+ Psiphon / Tor / sing-box link] or Foxy
 *
 * The order is on purpose: the TUN comes up BEFORE the engine. Until the engine answers, everything fails closed (nothing is
 * sent outside), and an engine that is started afterwards opens its own connections under the final routes (an open QUIC
 * connection did not survive the routes changing: measured in phase 0). The engines and this app are routed "direct" by
 * process name (see [TunConfig]), so there is no loop. A guardian process stops the engines if this app dies.
 */
class Connection {
    private val _state = MutableStateFlow<ConnState>(ConnState.Idle)
    val state: StateFlow<ConnState> = _state.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var job: Job? = null
    @Volatile private var wanted = false

    private val tun = ManagedProcess("tun")
    private val engine = ManagedProcess("engine")
    private val chainSb = ManagedProcess("singbox")
    @Volatile private var front: RouteFront? = null
    @Volatile private var foxy = false
    @Volatile private var lastStep = ""
    @Volatile private var fxLocation = ""

    /** The live routing front, for the Connections and Usage pages (null when not connected). */
    fun routeFront(): RouteFront? = front

    fun isBusy(): Boolean = job?.isActive == true

    fun connect(s: DesktopSettings) {
        synchronized(this) {
            if (job?.isActive == true) return
            wanted = true
            _state.value = ConnState.Connecting("…", 1)
            job = scope.launch { supervise(s) }
        }
    }

    fun disconnect() {
        wanted = false
        if (job?.isActive == true) _state.value = ConnState.Stopping
        else { stopAll(); _state.value = ConnState.Idle }
    }

    /** Blocking: stops everything and waits for the supervisor. Used when the app closes. */
    fun shutdownBlocking() {
        wanted = false
        val j = job
        if (j != null && j.isActive) {
            val end = System.currentTimeMillis() + 15_000
            while (j.isActive && System.currentTimeMillis() < end) Thread.sleep(100)
        }
        stopAll()
    }

    // ---------------------------------------------------------------------------------------------- the supervisor

    private class Failure(val reason: String, val lasting: Boolean, val chain: Boolean = false)

    private suspend fun supervise(s: DesktopSettings) {
        var attempt = 0
        try {
            while (wanted) {
                attempt++
                _state.value = ConnState.Connecting(lastStep.ifEmpty { "…" }, attempt)
                val failure = withContext(Dispatchers.IO) { startAll(s, attempt) }
                if (!wanted) break
                val reason: String
                var chainFailure = false
                if (failure == null) {
                    val startedAt = System.currentTimeMillis()
                    reason = monitor()
                    if (!wanted) break
                    if (System.currentTimeMillis() - startedAt >= ReconnectPolicy.STABLE_AFTER_MS) attempt = 0
                    RingLogBuffer.append("[app] connection lost: $reason")
                } else {
                    reason = failure.reason
                    chainFailure = failure.chain
                    RingLogBuffer.append("[app] connect failed: $reason")
                    if (failure.lasting) {
                        withContext(Dispatchers.IO) { stopAll() }
                        _state.value = ConnState.Failed(reason)
                        wanted = false
                        return
                    }
                }
                withContext(Dispatchers.IO) { stopAll() }
                val wait = ReconnectPolicy.delayMs(attempt.coerceAtLeast(1), true, Math.random() * 2 - 1, chainFailure)
                _state.value = ConnState.Waiting(reason, wait)
                var left = wait
                while (wanted && left > 0) { delay(500); left -= 500 }
            }
        } finally {
            withContext(kotlinx.coroutines.NonCancellable + Dispatchers.IO) { stopAll() }
            if (_state.value !is ConnState.Failed) _state.value = ConnState.Idle
        }
    }

    /** Returns when the connection is lost (the reason) or the user disconnects (""). */
    private suspend fun monitor(): String {
        var lastTick = System.currentTimeMillis()
        var nextProbe = lastTick + 30_000
        var fails = 0
        while (wanted) {
            delay(3_000)
            val now = System.currentTimeMillis()
            val resumed = now - lastTick > 30_000 // the PC slept: the network under the engine changed
            lastTick = now
            if (resumed) nextProbe = now + 6_000
            if (!tun.alive) return "the tunnel program stopped" + tailOf(tun)
            if (foxy) { if (!FoxyCore.alive) return "the Foxy core stopped" + tailOf(FoxyCore.lastLines()) }
            else {
                if (!engine.alive) return "the engine stopped" + tailOf(engine)
                if (_chainSbStarted && !chainSb.alive) return "the sing-box link program stopped" + tailOf(chainSb)
            }
            if (now >= nextProbe) {
                nextProbe = now + 30_000
                val ok = withContext(Dispatchers.IO) { probe() }
                if (ok) fails = 0 else if (++fails >= 2) return "no traffic goes through the tunnel"
            }
        }
        return ""
    }

    @Volatile private var _chainSbStarted = false

    private fun probe(): Boolean = SocksProbe.httpAnswersThrough(TunnelPorts.PUBLIC_HOST, TunnelPorts.PUBLIC, "1.1.1.1", 80, 8_000)

    private fun tailOf(p: ManagedProcess): String = tailOf(p.lastLines())
    private fun tailOf(lines: List<String>): String = lines.lastOrNull { it.isNotBlank() }?.let { ": ${it.take(160)}" } ?: ""

    // ---------------------------------------------------------------------------------------------- one start

    private fun step(text: String) {
        lastStep = text
        val cur = _state.value
        if (cur is ConnState.Connecting) _state.value = cur.copy(step = text)
    }

    private fun toConfig(s: DesktopSettings): EngineConfig = EngineConfig(
        mode = ConnectionMode.VPN,
        protocol = s.protocol,
        socksPort = TunnelPorts.PUBLIC,
        scanMode = s.scanMode,
        noizeProfile = s.noizeProfile,
        masqueHttp2 = s.protocol == Protocol.GOOL, // HTTP/3 is not offered on the desktop
        privacyChain = s.chain,
        psiphonRegion = s.psiphonRegion,
        directRules = RuleParser.normalizeManual(s.directRules),
        blockRules = RuleParser.normalizeManual(s.blockRules),
        powerSaver = false,
        engineKind = s.engine,
        fxPortPolicy = s.fxPortPolicy
    )

    private fun planFor(chain: PrivacyChain, fox: Boolean): FrontPlan {
        val chainPort = if (chain == PrivacyChain.NONE) null else Chain.CHAIN_PORT
        return FrontPlan(
            frontOn = true, corePort = Chain.UNDERLAY_PORT, chainPort = chainPort,
            upstreamPort = chainPort ?: Chain.UNDERLAY_PORT,
            udpRelay = !fox && (chain == PrivacyChain.NONE || chain == PrivacyChain.SINGBOX),
            mappedDns = fox || chain != PrivacyChain.NONE,
            coreGetsRoutes = false, localDoh = false
        )
    }

    private fun startAll(s: DesktopSettings, attempt: Int): Failure? {
        step("check")
        val fox = s.engine == EngineKind.FIREFOX
        val needed = if (fox) listOf(Kit.singBox, Kit.fx)
        else listOf(Kit.singBox, Kit.aether) + (if (s.chain == PrivacyChain.PSIPHON) listOf(Kit.psiphon) else emptyList())
        Kit.missing(*needed.toTypedArray())?.let { return Failure(it, true) }
        if (!Elevation.isAdmin()) return Failure("MadShield needs administrator rights to create the tunnel adapter. Start it with \"Run as administrator\".", true)
        val link: LinkParse.Ok? = if (!fox && s.chain == PrivacyChain.SINGBOX) {
            when (val r = ProxyLink.parse(s.link)) {
                is LinkParse.Ok -> r
                is LinkParse.Err -> return Failure("Personal link: " + LinkMessages.english(r), true)
            }
        } else null

        fxLocation = s.fxLocation
        val cfg = toConfig(s)
        var failure = startOnce(cfg, link)
        if (failure != null && wanted && !failure.lasting && ConnectPolicy.shouldTryHardened(cfg, failure.reason)) {
            RingLogBuffer.append("[app] trying again with the hardened settings")
            failure = startOnce(cfg.hardened(), link)
        }
        return failure
    }

    private fun startOnce(cfg: EngineConfig, link: LinkParse.Ok?): Failure? {
        stopAll()
        if (!wanted) return Failure("cancelled", false)
        val fox = cfg.engineKind == EngineKind.FIREFOX
        foxy = fox
        val chain = if (fox) PrivacyChain.NONE else cfg.effectiveChain
        val plan = planFor(chain, fox)
        val mapped = plan.mappedDns

        Reaper.killLeftovers()
        for (port in listOf(TunnelPorts.PUBLIC, Chain.UNDERLAY_PORT, Chain.CHAIN_PORT)) {
            if (!SocksProbe.awaitPortFree(port, 2_000)) return Failure("Port $port is used by another program. Close it, then try again.", true)
        }
        Guardian.arm()

        // 1. Foxy's core first: the front needs its login
        if (fox) {
            step("engine")
            try {
                val ep = FoxyCore.start(plan.corePort)
                UpstreamLogin.set(plan.corePort, ep.auth)
            } catch (e: IOException) { return Failure("Could not start the Foxy core: ${e.message}", false) }
        }

        // 2. the routing front on the public port
        step("front")
        val matcher = RouteMatcher.parse(
            "[block]\n" + cfg.blockRules.joinToString("\n") + "\n[direct]\n" + cfg.directRules.joinToString("\n") + "\n"
        )
        val options = RouteFront.Options(
            udpCapable = plan.udpRelay, udpOn = plan.udpRelay, guardFakeIps = mapped,
            allowOnion = chain == PrivacyChain.TOR,
            portGate = if (fox) PortGate(FxVpn.ALLOWED_TCP_PORTS, cfg.fxPortPolicy.action) else null
        )
        val f = RouteFront(TunnelPorts.PUBLIC, plan.upstreamPort, matcher, options) { RingLogBuffer.append(it) }
        try { f.start(); front = f } catch (e: IOException) { return Failure("Could not start the routing front: ${e.message}", false) }

        // 3. the TUN, before any engine connection exists
        step("tun")
        val tunJson = TunConfig.render(TunnelPorts.PUBLIC, mapped, Own.processNames, mtu = cfg.effectiveMtu, extraDirectDomains = listOfNotNull(link?.server))
        val runDir = DataDir.sub("run")
        val tunFile = File(runDir, "tun.json")
        try { tunFile.writeText(tunJson, Charsets.UTF_8) } catch (e: IOException) { return Failure("Could not write the tunnel configuration: ${e.message}", false) }
        try {
            tun.start(Kit.singBox, listOf("run", "-c", tunFile.absolutePath), emptyMap(), runDir, stdin = "")
        } catch (e: IOException) { return Failure("Could not start the tunnel program: ${e.message}", false) }
        if (!awaitAdapter(30_000)) {
            return Failure("The tunnel adapter did not appear" + tailOf(tun), false)
        }
        sleepWanted(4_000)

        // 4. the engines
        step("engine")
        _chainSbStarted = false
        if (!fox) {
            val chainDir = when (chain) {
                PrivacyChain.PSIPHON -> DataDir.sub("psiphon")
                PrivacyChain.TOR -> DataDir.sub("tor")
                else -> null
            }
            val env = EngineEnvironment.build(
                config = cfg,
                configFilePath = File(DataDir.sub("aether"), "aether.toml").absolutePath,
                tmpDirPath = DataDir.sub("tmp").absolutePath,
                routesFilePath = null,
                secretEnv = emptyMap(),
                chainBinPath = if (chain == PrivacyChain.PSIPHON) Kit.psiphon.absolutePath else null,
                chainDirPath = chainDir?.absolutePath,
                plan = plan
            )
            RingLogBuffer.append(
                "[app] starting aether " + env.filterKeys { it.startsWith("AETHER_") }.entries.joinToString(" ") { "${it.key}=${it.value}" }
            )
            try { engine.start(Kit.aether, emptyList(), env, Kit.dir, stdin = "") }
            catch (e: IOException) { return Failure("Could not start the engine: ${e.message}", false) }
            if (link != null) {
                try {
                    chainSb.start(
                        Kit.singBox, listOf("run", "-c", "stdin"), emptyMap(), runDir,
                        stdin = SingBoxConfig.build(link, plan.corePort, plan.chainPort ?: Chain.CHAIN_PORT)
                    )
                    _chainSbStarted = true
                } catch (e: IOException) { return Failure("Could not start the link program: ${e.message}", false) }
            }
        }

        // 5. wait until traffic really flows
        step("wait")
        return if (fox) awaitFoxy(cfg) else awaitTraffic(cfg, chain)
    }

    private fun awaitTraffic(cfg: EngineConfig, chain: PrivacyChain): Failure? {
        val deadline = System.currentTimeMillis() + ConnectPolicy.firstPassTimeoutMs(cfg)
        while (wanted && System.currentTimeMillis() < deadline) {
            if (!engine.alive) return Failure("The engine stopped" + tailOf(engine), false, chain != PrivacyChain.NONE)
            if (_chainSbStarted && !chainSb.alive) return Failure("The link program stopped" + tailOf(chainSb), false, true)
            if (!tun.alive) return Failure("The tunnel program stopped" + tailOf(tun), false)
            if (probe()) return connected()
            sleepWanted(1_000)
        }
        if (!wanted) return Failure("cancelled", false)
        return Failure("The tunnel did not come up in time" + tailOf(engine), false, chain != PrivacyChain.NONE)
    }

    private fun awaitFoxy(cfg: EngineConfig): Failure? {
        val ep = FoxyCore.endpoint ?: return Failure("The Foxy core is not running", false)
        val client: FxClient = ep.client()
        try {
            FoxyCore.awaitApi(ep, FxVpn.START_ALLOWANCE_MS)
            if (fxLocation.isNotBlank()) runCatching { client.setLocation(fxLocation) }
            client.power(true)
        } catch (e: IOException) { return Failure("The Foxy core did not start: ${e.message}", false) }
        val deadline = System.currentTimeMillis() + ConnectPolicy.firstPassTimeoutMs(cfg)
        while (wanted && System.currentTimeMillis() < deadline) {
            if (!FoxyCore.alive) return Failure("The Foxy core stopped" + tailOf(FoxyCore.lastLines()), false)
            val st = try { client.status() } catch (_: IOException) { null }
            if (st != null) {
                (FxProgress.fromStatus(st) as? FxVerdict.Failed)?.let { return Failure(FxErrors.english(it.code, it.detail), FxErrors.isLasting(it.code)) }
                if (st.proxyUp) break
            }
            sleepWanted(300)
        }
        if (!wanted) return Failure("cancelled", false)
        return try {
            when (val v = FxProgress.fromTest(client.test())) {
                FxVerdict.Ready -> connected()
                is FxVerdict.Failed -> Failure(FxErrors.english(v.code, v.detail), FxErrors.isLasting(v.code))
            }
        } catch (e: FxClient.ApiException) {
            Failure(FxErrors.english("", e.message ?: ""), false)
        } catch (e: IOException) {
            Failure("The Foxy core did not answer the connection test (${e.message})", false)
        }
    }

    private fun connected(): Failure? {
        val probe = DesktopExitProbe.run(TunnelPorts.PUBLIC)
        val exit = probe.info
        if (exit == null) RingLogBuffer.append("[app] exit lookup: $probe")
        _state.value = ConnState.Connected(exit, System.currentTimeMillis())
        RingLogBuffer.append("[app] connected" + (exit?.let { " (exit ${it.country ?: "?"})" } ?: ""))
        return null
    }

    private fun awaitAdapter(timeoutMs: Long): Boolean {
        val end = System.currentTimeMillis() + timeoutMs
        while (wanted && System.currentTimeMillis() < end) {
            if (!tun.alive) return false
            val up = try {
                val p = ProcessBuilder("netsh", "interface", "show", "interface", "name=${TunConfig.TUN_NAME}").redirectErrorStream(true).start()
                p.inputStream.readBytes()
                p.waitFor() == 0
            } catch (_: Exception) { false }
            if (up) return true
            Thread.sleep(500)
        }
        return false
    }

    private fun sleepWanted(ms: Long) {
        var left = ms
        while (wanted && left > 0) { Thread.sleep(minOf(left, 250)); left -= 250 }
    }

    /** Engines and front first (everything fails closed meanwhile), then the TUN, which gives the network back. */
    @Synchronized
    private fun stopAll() {
        runCatching { front?.stop() }
        front = null
        engine.stop()
        chainSb.stop()
        _chainSbStarted = false
        if (foxy) FoxyCore.stop()
        UpstreamLogin.clear()
        tun.stop()
        Guardian.disarm()
    }
}

object TunnelPorts {
    const val PUBLIC_HOST = "127.0.0.1"
    const val PUBLIC = 1819
}

/** Stops engine programs of this kit that an earlier run (or a crash) left behind. */
object Reaper {
    fun killLeftovers() {
        val kit = Kit.dir.absolutePath.lowercase().trimEnd('\\') + "\\"
        val me = ProcessHandle.current().pid()
        try {
            ProcessHandle.allProcesses().filter { it.pid() != me }.forEach { h ->
                val cmd = h.info().command().orElse(null)?.lowercase() ?: return@forEach
                if (cmd.startsWith(kit)) { h.descendants().forEach { it.destroyForcibly() }; h.destroyForcibly() }
            }
        } catch (_: Exception) { /* best effort */ }
    }
}
