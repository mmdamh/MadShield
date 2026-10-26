package com.aethershield.app.vpn

import android.app.*
import android.content.Intent
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.aethershield.app.MainActivity
import com.aethershield.app.R
import com.aethershield.app.core.*
import com.aethershield.app.util.RingLogBuffer
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.File

/**
 * Full-device VPN mode. Data path:
 *   apps -> Android TUN (this service) -> TProxyService (JNI bridge, hev-socks5-tunnel)
 *        -> 127.0.0.1:<socksPort> -> EngineProcessManager (aether core) -> internet
 *   (with a chain, or with local DoH, RouteFront owns <socksPort>; see FrontPlan)
 *
 * Connection logic follows the pattern of the field-tested AetherGUI reference
 * (re-implemented here, not copied):
 *  - The engine is only called "up" after a real SOCKS5 handshake succeeds, and
 *    the wait stops AT ONCE if the engine process dies (so a crash is reported
 *    with its real reason instead of an endless "Connecting").
 *  - Leftover engines are cleared and the port released before every start
 *    (see EngineProcessManager) -- the documented cause of "needs several
 *    Connect attempts".
 *  - Timeouts are generous (45 s per pass): the first scan/handshake on a
 *    filtered mobile network is slow, and giving up early is what made good
 *    connections look broken.
 *  - A dead engine is restarted automatically (bounded, with a debounce)
 *    when "quick reconnect" is on, and the TUN bridge is re-attached.
 *  - hev's native thread is waited for before it is started again, because
 *    starting while the old one is still alive is a silent no-op that would
 *    publish a tunnel carrying nothing.
 *
 * Two earlier bugs that stay fixed:
 *  1. CRASH: native-layer UnsatisfiedLinkError is an Error, not an Exception;
 *     every native call is wrapped with Throwable.
 *  2. "Connects but nothing loads": the TUN address and hev's tunnel.ipv4/ipv6
 *     must match exactly -- both come from TunnelConfig.
 *
 * Kill switch semantics (config.killSwitchEnabled):
 *   ON  -> the TUN interface is established FIRST, so traffic is captured
 *          (and held/dropped) while connecting or if the tunnel drops, instead
 *          of ever silently falling back to the raw network.
 *   OFF -> the TUN only exists while the tunnel is healthy; if it drops, the
 *          TUN is released so apps fall back to the normal network.
 * A START-UP failure (engine cannot even launch) always releases the TUN
 * either way: there was never a tunnel, and holding the phone offline for a
 * problem the user must fix in the app would just look like a broken phone.
 */
class AetherVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.aethershield.app.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.aethershield.app.vpn.DISCONNECT"
        private const val NOTIF_ID = 1
        private const val CHANNEL_ID = "tunnel_status"
        private const val HEALTH_CHECK_INTERVAL_MS = 5_000L
        private const val HARDENED_PASS_TIMEOUT_MS = 60_000L
        private const val RECOVERY_TIMEOUT_MS = 30_000L
        private const val BRIDGE_STOP_TIMEOUT_MS = 4_000L

        /** Re-attach attempts of the tunnel bridge while the engine is healthy, before giving up (no endless 5-second loop). */
        private const val MAX_BRIDGE_RETRIES = 3
    }

    private sealed interface Attempt {
        data object Ready : Attempt
        data class Failed(val reason: String) : Attempt
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var connectJob: Job? = null
    @Volatile private var userRequestedStop = false
    /** update19: this start captured the traffic because the Kill Switch is on; a startup error must not hand it back. */
    @Volatile private var killSwitchHeld = false
    private var tunFd: ParcelFileDescriptor? = null
    private var healthJob: Job? = null
    private lateinit var engine: EngineProcessManager
    private lateinit var ruleWriter: RuleFileWriter
    private lateinit var chainSwapper: ChainLinkSwapper

    /** The last failed start was the privacy chain (Psiphon/Tor), not the WARP tunnel: retry slowly, see [ReconnectPolicy]. */
    @Volatile private var lastFailureWasChain = false
    private lateinit var settingsStore: SettingsStore
    private lateinit var netWatcher: NetworkWatcher
    private lateinit var screen: ScreenWatcher
    private var speedJob: Job? = null
    private var statusText: String = ""
    @Volatile private var speedText: String? = null

    override fun onCreate() {
        super.onCreate()
        engine = EngineProcessManager(this)
        ruleWriter = RuleFileWriter(this)
        settingsStore = SettingsStore(this)
        netWatcher = NetworkWatcher(this)
        screen = ScreenWatcher(this)
        DiagnosticsHub.engineCpuTicks = { engine.cpuTicks() }
        // Live switch between saved custom links: only sing-box is replaced, the tunnel stays up (see ChainLinkSwapper).
        chainSwapper = ChainLinkSwapper(engine, settingsStore)
        scope.launch { AetherController.linkSwapRequests.collect { chainSwapper.reconcile() } }
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            userRequestedStop = true
            teardownAndStop()
            return START_NOT_STICKY
        }
        userRequestedStop = false
        netWatcher.onChanged = { screen.poke() }
        netWatcher.onOffline = { screen.poke() } // the health loop looks at the network at once, not at the next tick
        netWatcher.onDefaultNetwork = { applyUnderlyingNetwork(it) }
        netWatcher.start()
        screen.start()
        // Must happen within seconds of startForegroundService(); do it here,
        // not later inside the coroutine.
        AetherController.setState(ConnectionState.Connecting)
        startForeground(NOTIF_ID, buildNotification(getString(R.string.notif_connecting)))
        startSpeedLoop()

        healthJob?.cancel()
        connectJob?.cancel()
        connectJob = scope.launch {
            try {
                connect()
            } catch (c: CancellationException) {
                throw c // a user cancel is not an error
            } catch (t: Throwable) {
                // Throwable on purpose: UnsatisfiedLinkError is an Error and would
                // otherwise take the whole process down.
                RingLogBuffer.append("[vpn] connect failed: ${t::class.java.simpleName}: ${t.message}")
                failStartup(t.message ?: getString(R.string.state_error))
            }
        }
        return START_STICKY
    }

    // ---------------------------------------------------------------- connect

    private suspend fun connect() {
        val baseConfig = settingsStore.configFlow.first()

        if (!TProxyService.available) {
            throw IllegalStateException(
                "native tunnel bridge unavailable: ${TProxyService.loadFailure ?: "unknown"}"
            )
        }
        // Android treats "allow only these apps" with an empty list as "allow every app". Starting anyway would
        // capture the whole phone although the user asked for a handful of apps (or none), so refuse with a reason.
        if (baseConfig.appSelectionMode == AppSelectionMode.INCLUDE_ONLY_SELECTED && baseConfig.selectedPackages.isEmpty()) {
            throw IllegalStateException(getString(R.string.err_include_only_empty))
        }

        killSwitchHeld = false
        if (baseConfig.killSwitchEnabled) {
            establishTun(baseConfig) // capture traffic immediately; nothing bridged yet
            killSwitchHeld = true
            reportLockdown()
        }

        // Connect in up to three steps, each only when the previous one failed:
        //  1. exactly what the user configured;
        //  2. the same without ECH, if the failure was the ECH key lookup (that
        //     lookup is blocked on many networks and makes the core refuse to start);
        //  3. with anti-DPI hardening (see EngineConfig.hardened()).
        var active = baseConfig
        var attempt = attemptConnect(active, ConnectPolicy.firstPassTimeoutMs(active))
        if (attempt is Attempt.Failed && active.ech && EchFallback.isEchFailure(attempt.reason)) {
            RingLogBuffer.append("[vpn] ECH key lookup failed; retrying without ECH")
            engine.stop()
            active = active.copy(ech = false)
            attempt = attemptConnect(active, ConnectPolicy.firstPassTimeoutMs(active))
        }
        if (attempt is Attempt.Failed && ConnectPolicy.shouldTryGoolH2(active, attempt.reason)) {
            RingLogBuffer.append("[vpn] Gool over HTTP/3 did not connect (${attempt.reason}); trying the HTTP/2 (TCP) carrier")
            engine.stop()
            active = active.copy(masqueHttp2 = true)
            attempt = attemptConnect(active, ConnectPolicy.firstPassTimeoutMs(active))
        }
        if (attempt is Attempt.Failed && ConnectPolicy.shouldTryClassicGool(active, attempt.reason)) {
            RingLogBuffer.append("[vpn] Gool over MASQUE found no gateway (${attempt.reason}); trying classic Gool (no MASQUE gateway needed)")
            engine.stop()
            active = active.copy(protocol = Protocol.GOOL_CLASSIC)
            attempt = attemptConnect(active, ConnectPolicy.firstPassTimeoutMs(active))
        }
        if (attempt is Attempt.Failed && ConnectPolicy.shouldTryHardened(active, attempt.reason)) {
            RingLogBuffer.append("[vpn] first pass failed (${attempt.reason}); retrying with anti-DPI hardening")
            engine.stop()
            active = active.hardened()
            attempt = attemptConnect(active, HARDENED_PASS_TIMEOUT_MS + ConnectPolicy.chainAllowanceMs(active))
        }
        if (userRequestedStop) return

        if (attempt is Attempt.Failed) {
            RingLogBuffer.append("[vpn] engine did not become healthy: ${attempt.reason}")
            lastFailureWasChain = ConnectPolicy.isChainFailure(attempt.reason)
            // Nothing is bridged anyway; do not leave the WireGuard tunnel and a blocked Psiphon spinning through the wait.
            if (lastFailureWasChain) engine.stop()
            if (!baseConfig.killSwitchEnabled) {
                failStartup(attempt.reason)
                return
            }
            // Fail-closed: TUN stays up but nothing is bridged, so traffic is held.
            // The health loop keeps trying to bring the engine back; the user can
            // also press Disconnect, which releases everything.
            AetherController.setState(ConnectionState.Error(attempt.reason))
            updateNotification(getString(R.string.state_error))
        } else {
            if (!baseConfig.killSwitchEnabled) establishTun(baseConfig)
            if (bridgeTunToEngine(active)) markConnected(active)
        }

        startHealthLoop(active)
    }

    private fun isScreenOn(): Boolean =
        runCatching { (getSystemService(POWER_SERVICE) as android.os.PowerManager).isInteractive }.getOrDefault(true)

    private fun markConnected(config: EngineConfig) {
        if (userRequestedStop) return
        AetherController.setActive(config)
        AetherController.setState(ConnectionState.Connected("${TunnelConfig.SOCKS_HOST}:${config.socksPort}"))
        updateNotification(getString(R.string.state_connected))
    }

    /** Starts the engine with [config] and waits for a real SOCKS5 answer, up to [timeoutMs]. */
    private suspend fun attemptConnect(config: EngineConfig, timeoutMs: Long): Attempt =
        withContext(Dispatchers.IO) {
            // Keystore is read only when a Zero Trust team is set, and a Keystore failure means "no secret", never a crash.
            val secretEnv = settingsStore.secretEnvFor(config)
            val job = currentCoroutineContext()[Job]
            ensureActive() // never launch an engine after the user already pressed Disconnect
            // EnginePreflightException propagates on purpose: it cannot work no matter
            // how often we retry, so connect() surfaces it as-is.
            engine.start(config, ruleWriter, secretEnv, settingsStore.chainLinkFor(config))
            val deadlineMs = System.currentTimeMillis() + timeoutMs
            when (SocksProbe.awaitReady(
                host = TunnelConfig.SOCKS_HOST,
                // the engine side's own port: RouteFront (public port) greets before the core is ready
                port = engine.probePort,
                timeoutMs = timeoutMs,
                engineAlive = { engine.isRunning },
                cancelled = { job?.isActive == false }
            )) {
                SocksProbe.Wait.READY -> {
                    // With a chain on, the port answers before Psiphon/Tor are connected: wait for the
                    // core's own "is ready" announcement before the tunnel bridge is attached.
                    if (config.effectiveChain == PrivacyChain.NONE) Attempt.Ready
                    else {
                        val left = (deadlineMs - System.currentTimeMillis()).coerceAtLeast(10_000L)
                        engine.awaitChainReady(left) { job?.isActive == false }
                            ?.let { if (it == "cancelled") throw CancellationException("connect cancelled") else Attempt.Failed(it) }
                            ?: Attempt.Ready
                    }
                }
                SocksProbe.Wait.ENGINE_DIED ->
                    Attempt.Failed(engine.failureReason() ?: "the engine process exited")
                SocksProbe.Wait.TIMEOUT ->
                    Attempt.Failed("no answer from the engine after ${timeoutMs / 1000}s")
                SocksProbe.Wait.CANCELLED -> throw CancellationException("connect cancelled")
            }
        }

    /** Startup failed for good: release everything so the phone's normal internet works again. */
    private fun failStartup(reason: String) {
        if (userRequestedStop) return
        healthJob?.cancel()
        stopBridge()
        engine.stop()
        if (killSwitchHeld && tunFd != null) {
            // update19: Kill Switch ON. A startup error (missing or altered file, failed preflight) is NOT a reason to
            // give the raw network back: the engine attempts that fail already keep the TUN (see connect()), and this
            // path now does the same. Nothing runs here (no engine, no health loop, no polling), so it costs no battery.
            // The Error card offers Retry and Stop; Stop releases everything.
            RingLogBuffer.append("[vpn] startup failed ($reason); Kill Switch keeps traffic held until Retry or Stop")
            AetherController.setState(ConnectionState.Error(reason))
            updateNotification(getString(R.string.state_error))
            return
        }
        releaseTun()
        AetherController.setState(ConnectionState.Error(reason))
        updateNotification(getString(R.string.state_error))
        // The error stays visible in the UI (state lives in AetherController), so stop
        // the service without resetting it: onDestroy keeps an Error state.
        stopSelfSafely()
    }

    // -------------------------------------------------------------------- TUN

    private fun establishTun(config: EngineConfig) {
        if (tunFd != null) return
        val builder = Builder()
            .setSession("MadShield")
            .setMtu(config.effectiveMtu)
            .addAddress(TunnelConfig.TUN_IPV4, TunnelConfig.TUN_IPV4_PREFIX)
            .addAddress(TunnelConfig.TUN_IPV6, TunnelConfig.TUN_IPV6_PREFIX)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .setBlocking(false)

        // DNS: the user's resolvers (bare IPs; the VPN API takes no port) or a safe default.
        // With a chain on (Psiphon/Tor carry TCP only) the only DNS server is hev's mapped DNS,
        // so name lookups are answered locally and resolved at the chain's exit over TCP.
        // With local DoH (update11) it is hev's mapped DNS in EVERY mode: apps get a fake address, RouteFront
        // receives the NAME and resolves it through DoH. With DoH off, behaviour is exactly update10.
        val dnsToUse = if (config.effectiveChain != PrivacyChain.NONE || config.dohActive) {
            listOf(Chain.MAPDNS_ADDRESS)
        } else {
            config.dnsResolvers.mapNotNull { DnsConfig.vpnAddress(it) }.distinct()
                .ifEmpty { TunnelConfig.DNS_SERVERS }
        }
        dnsToUse.forEach { runCatching { builder.addDnsServer(it) } }

        // Per-app split tunneling -- enforced HERE, at the OS VPN layer,
        // never by the engine (which cannot see per-app identity in tun mode).
        when (config.appSelectionMode) {
            AppSelectionMode.EXCLUDE_SELECTED -> config.selectedPackages.forEach {
                runCatching { builder.addDisallowedApplication(it) }
            }
            AppSelectionMode.INCLUDE_ONLY_SELECTED -> {
                var added = 0
                config.selectedPackages.forEach { if (runCatching { builder.addAllowedApplication(it) }.isSuccess) added++ }
                // Every selected app was uninstalled: an empty allow-list would capture ALL apps.
                if (added == 0) throw IllegalStateException(getString(R.string.err_include_only_empty))
            }
            AppSelectionMode.NONE -> {}
        }
        // Our own process (the engine child) must never be captured by its own tunnel.
        runCatching { builder.addDisallowedApplication(packageName) }

        tunFd = builder.establish()
            ?: throw IllegalStateException("Android could not create the VPN interface (permission revoked?)")
        RingLogBuffer.append("[vpn] TUN established (mtu=${config.effectiveMtu}, killSwitch=${config.killSwitchEnabled})")
        applyUnderlyingNetwork(netWatcher.currentDefault)
    }

    /**
     * Tells Android which real network carries the tunnel's traffic. Without it the system cannot match the
     * tunnel interface to the physical one, and traffic meters that read system statistics (for example
     * Samsung's Good Lock network speed) may count the same bytes more than once. Called after the TUN exists and
     * on every default-network change; a no-op while there is no TUN. null = let the system choose.
     */
    private fun applyUnderlyingNetwork(network: Network?) {
        if (tunFd == null) return
        runCatching { setUnderlyingNetworks(if (network != null) arrayOf(network) else null) }
            .onFailure { RingLogBuffer.append("[vpn] setUnderlyingNetworks failed: ${it::class.java.simpleName}") }
    }

    /** One read per connect: tells the Settings page whether lockdown (Always-on + block without VPN) is on. */
    private fun reportLockdown() {
        val v = if (android.os.Build.VERSION.SDK_INT >= 29) runCatching { isLockdownEnabled }.getOrNull() else null
        AetherController.setLockdown(v)
        if (v == false) RingLogBuffer.append("[vpn] Android's \"Block connections without VPN\" is off: if Android kills this app, traffic can leave unprotected")
    }

    private fun releaseTun() {
        tunFd?.let { runCatching { it.close() } }
        tunFd = null
    }

    /**
     * hev config: tunnel.ipv4/ipv6 MUST equal the VpnService addAddress values
     * above -- both come from TunnelConfig. The SOCKS port is the one the
     * engine is actually bound to (config.socksPort), not a constant.
     */
    private fun writeHevConfig(config: EngineConfig): File {
        val file = File(cacheDir, "hev.yaml")
        // Same keys and values as ZedSecure's field-tested hev config (hev's own defaults for
        // everything else; no stack-size or timeout overrides that could starve a session).
        val mapdns = if (config.effectiveChain == PrivacyChain.NONE && !config.dohActive) "" else """

            mapdns:
              address: ${Chain.MAPDNS_ADDRESS}
              port: 53
              network: 100.64.0.0
              netmask: 255.192.0.0
              cache-size: 10000"""
        val yaml = """
            tunnel:
              mtu: ${config.effectiveMtu}
              ipv4: ${TunnelConfig.TUN_IPV4}
              ipv6: '${TunnelConfig.TUN_IPV6}'
            socks5:
              port: ${config.socksPort}
              address: ${TunnelConfig.SOCKS_HOST}
              udp: 'udp'
            misc:
              tcp-buffer-size: 131072
              udp-recv-buffer-size: 262144
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-level: warn
        """.trimIndent() + mapdns.trimIndent().let { if (it.isEmpty()) "" else "\n\n$it" }
        file.writeText(yaml)
        return file
    }

    /**
     * Asks hev to stop, but only when it is running. hev REMEMBERS a stop request that arrives while it is
     * not running and then ends the NEXT start immediately: that was the "tunnel bridge stopped right after
     * start" on the first connect of a session (seen after every earlier disconnect or failed connect), which
     * only worked on Retry. The native thread flag is exact, so this never races a start.
     */
    private fun stopBridge() {
        if (runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)) {
            runCatching { TProxyService.TProxyStopService() }
        }
    }

    /** @return true if hev accepted the TUN fd. Sets the Error state itself on failure. */
    private suspend fun bridgeTunToEngine(config: EngineConfig): Boolean {
        val fd = tunFd ?: return false
        val cfgFile = writeHevConfig(config)
        return try {
            // A previous hev thread that is still shutting down would make the start a
            // silent no-op (tunnel published, nothing carried): wait for it first.
            if (!awaitBridgeStopped()) {
                RingLogBuffer.append("[vpn] previous tunnel bridge has not shut down yet")
                AetherController.setState(ConnectionState.Error("previous tunnel bridge still shutting down"))
                return false
            }
            // Two tries: if the first one ends at once (a stop request left over from an earlier session
            // is consumed by it), the second one starts cleanly.
            var up = false
            for (attempt in 1..2) {
                val started = TProxyService.TProxyStartService(cfgFile.absolutePath, fd.fd)
                if (!started) {
                    RingLogBuffer.append("[vpn] hev refused to start (config/fd rejected)")
                    AetherController.setState(ConnectionState.Error("tunnel start refused"))
                    return false
                }
                // The native start only schedules a thread. If that thread exits at once the tunnel
                // would be reported "connected" while carrying nothing ("connected, no internet").
                delay(700)
                up = runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
                if (up) break
                RingLogBuffer.append("[vpn] tunnel bridge ended right after start (attempt $attempt/2)")
                if (!awaitBridgeStopped()) break
            }
            if (!up) {
                RingLogBuffer.append("[vpn] tunnel bridge stopped right after start (config: ${cfgFile.readText().replace('\n', ' ')})")
                AetherController.setState(ConnectionState.Error("the tunnel bridge stopped right after starting"))
                return false
            }
            RingLogBuffer.append("[vpn] tunnel bridge running (mtu=${config.effectiveMtu}, socks=${config.socksPort})")
            true
        } catch (t: Throwable) {
            RingLogBuffer.append("[vpn] hev start failed: ${t.message}")
            AetherController.setState(ConnectionState.Error(t.message ?: "tunnel start failed"))
            false
        }
    }

    private suspend fun awaitBridgeStopped(): Boolean {
        val deadline = System.currentTimeMillis() + BRIDGE_STOP_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val running = runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
            if (!running) return true
            delay(100)
        }
        return false
    }

    // ----------------------------------------------------------------- health

    private fun startHealthLoop(config: EngineConfig) {
        healthJob?.cancel()
        healthJob = scope.launch {
            var consecutiveFailures = 0
            var recoveries = 0
            var wasDown = false
            var tick = 0
            var lastCpuAt = 0L
            var lastCpuTicks = 0L
            var firstFailAt = 0L
            var healthySince = 0L
            var bridgeRetries = 0
            val idleTracker = IdleTracker()
            var idle = false
            screen.drain()
            while (isActive) {
                // Sleep; a screen-on or a network change cuts the sleep short and ends idle mode at once.
                if (screen.sleep(PowerPolicy.cadence(isScreenOn(), idle).healthMs)) idleTracker.wake()
                if (engine.swapping) continue // the custom link is being switched on purpose: not an outage
                val screenNow = isScreenOn()
                // Traffic counters are only read with the screen off (that is when idle is decided).
                val idleBytes = if (screenNow) null else runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                    ?.takeIf { it.size >= 4 }?.let { it[1] + it[3] }
                val wasIdle = idle
                idle = idleTracker.onTick(android.os.SystemClock.elapsedRealtime(), screenNow, idleBytes)
                if (idle && !wasIdle) engine.onIdle() // screen off + quiet: the DoH client drops its idle connection
                val cadence = PowerPolicy.cadence(screenNow, idle)
                try {
                    // No network at all: nothing the engine does can work, and it would only keep scanning and
                    // failing. Stop it, keep the TUN as it is (Kill Switch unchanged), and start again when the
                    // system reports a network. Event-driven: no timer runs while it waits.
                    if (netWatcher.isOffline()) {
                        delay(PowerPolicy.OFFLINE_GRACE_MS) // a handover can say "no network" for a moment
                        if (netWatcher.isOffline()) {
                            RingLogBuffer.append("[vpn] no network: engine paused until the network returns")
                            if (!wasDown) {
                                wasDown = true
                                stopBridge()
                                if (!config.killSwitchEnabled) releaseTun() // same as any other outage: fail-open until it recovers
                            }
                            engine.stop()
                            AetherController.setState(ConnectionState.Error(getString(R.string.state_no_network)))
                            updateNotification(getString(R.string.notif_no_network))
                            idleTracker.wake(); idle = false
                            netWatcher.awaitNetwork { PowerPolicy.offlinePollMs(isScreenOn()) }
                            ensureActive()
                            RingLogBuffer.append("[vpn] network is back, restarting engine")
                            recoveries = 0; consecutiveFailures = 0; healthySince = 0L; bridgeRetries = 0
                            AetherController.setState(ConnectionState.Connecting)
                            updateNotification(getString(R.string.notif_connecting))
                            when (val r = attemptConnect(config, RECOVERY_TIMEOUT_MS + ConnectPolicy.chainAllowanceMs(config))) {
                                is Attempt.Ready -> lastFailureWasChain = false // the next healthy probe re-attaches the bridge
                                is Attempt.Failed -> {
                                    AetherController.setState(ConnectionState.Error(r.reason))
                                    lastFailureWasChain = ConnectPolicy.isChainFailure(r.reason)
                                    if (lastFailureWasChain) engine.stop()
                                }
                            }
                            continue
                        }
                    }
                    // Alive, but no WireGuard endpoint found in several full scans in a row: the local SOCKS port
                    // (Psiphon's, with a chain) would still answer, so the probe alone cannot see this outage.
                    val stalled = engine.isRunning && engine.tunnelStalled()
                    val ok = engine.isRunning && !stalled &&
                        SocksProbe.handshakeOk(
                            TunnelConfig.SOCKS_HOST, engine.probePort,
                            PowerPolicy.HEALTH_CONNECT_TIMEOUT_MS, PowerPolicy.HEALTH_READ_TIMEOUT_MS
                        ) &&
                        engine.chainStillWorks(screenNow) // custom chain only: a rare end-to-end check, screen on
                    if (!ok && engine.swapping) continue // a switch started while this probe was running
                    if (ok) {
                        // Packet counters from the tunnel bridge, for diagnosing "connected but no traffic":
                        // all zero => nothing enters the tunnel; tx only => nothing comes back.
                        if (cadence.logCountersEveryTicks > 0 && tick++ % cadence.logCountersEveryTicks == 1) {
                            val s = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                            if (s != null && s.size >= 4) {
                                RingLogBuffer.append("[vpn] tunnel counters: ${s[0]} / ${s[1]} B / ${s[2]} / ${s[3]} B (hev order: tx pkts, tx bytes, rx pkts, rx bytes)")
                            }
                        }
                        // CPU use of the engine (and Psiphon), about once a minute, so heat/battery
                        // complaints can be traced to a process instead of guessed.
                        val now = android.os.SystemClock.elapsedRealtime()
                        // Screen off / idle: no CPU sampling at all, and the baseline is dropped so the next
                        // sample (screen on again) measures a clean window.
                        if (!cadence.sampleCpu) lastCpuAt = 0L
                        else if (now - lastCpuAt >= 60_000L) {
                            val ticks = engine.cpuTicks()
                            if (ticks != null && lastCpuAt != 0L) {
                                val pct = CpuSampler.percent(lastCpuTicks, ticks, now - lastCpuAt)
                                RingLogBuffer.append("[power] engine cpu %.1f%% of one core over the last %ds (screen %s)".format(
                                    pct, (now - lastCpuAt) / 1000, if (isScreenOn()) "on" else "off"))
                            }
                            if (ticks != null) { lastCpuTicks = ticks; lastCpuAt = now }
                        }
                        consecutiveFailures = 0
                        // Healthy for a full minute: the outage is over, so the next one starts the
                        // retry schedule from the beginning instead of continuing the slow phase.
                        if (healthySince == 0L) healthySince = now
                        else if (now - healthySince >= ReconnectPolicy.STABLE_AFTER_MS) recoveries = 0
                        // The engine is fine, but is the bridge to the TUN still running? hev can end on its own (or
                        // never have started: the first attach in connect() failed), and nothing else ever noticed:
                        // the app stayed on "connected" (or "error") with no traffic until the user reconnected.
                        if (!wasDown && tunFd != null && !userRequestedStop &&
                            !runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(true)) {
                            RingLogBuffer.append("[vpn] tunnel bridge is not running although the engine is healthy: re-attaching it")
                            stopBridge()
                            wasDown = true
                        }
                        if (wasDown && bridgeRetries < MAX_BRIDGE_RETRIES) { // came back (core replaced its tunnel, or we restarted it)
                            if (tunFd == null) establishTun(config)
                            if (bridgeTunToEngine(config)) {
                                wasDown = false
                                bridgeRetries = 0
                                markConnected(config)
                                RingLogBuffer.append("[vpn] tunnel recovered")
                            } else if (++bridgeRetries >= MAX_BRIDGE_RETRIES) {
                                RingLogBuffer.append("[vpn] the tunnel bridge would not start $MAX_BRIDGE_RETRIES times in a row: giving up until you reconnect")
                            }
                        }
                        continue
                    }
                    // One failed probe is a blip (the core may be swapping tunnels); two in a row is an outage.
                    healthySince = 0L
                    idleTracker.wake(); idle = false // a failed probe: back to normal checking at once
                    if (++consecutiveFailures == 1) firstFailAt = android.os.SystemClock.elapsedRealtime()
                    if (consecutiveFailures < 2 && !stalled) continue // a stalled tunnel is already proven by several scans
                    if (engine.chainBroken) lastFailureWasChain = true // a dead custom link: retry on the slow chain schedule

                    if (!wasDown) {
                        wasDown = true
                        bridgeRetries = 0
                        RingLogBuffer.append("[vpn] health check failed, tunnel considered down")
                        AetherController.setState(
                            ConnectionState.Error(
                                engine.failureReason()
                                    ?: if (stalled) getString(R.string.state_no_endpoint)
                                    else if (engine.chainBroken) getString(R.string.state_chain_broken)
                                    else getString(R.string.state_error)
                            )
                        )
                        stopBridge()
                        if (!config.killSwitchEnabled) releaseTun() // fail-open until it recovers
                    }

                    // Stop the scanning core and retry on the back-off schedule below, instead of letting it
                    // scan non-stop (and Psiphon hammer a closed port) until a network happens to return.
                    if (stalled && config.quickReconnect) {
                        RingLogBuffer.append("[vpn] no WARP endpoint found in ${TunnelStallTracker.STALL_AFTER_SCANS} full scans in a row: stopping the engine, retrying on the back-off schedule")
                        engine.stop()
                    }

                    // An engine that is alive but has not answered for a full minute is hung.
                    if (engine.isRunning && config.quickReconnect &&
                        android.os.SystemClock.elapsedRealtime() - firstFailAt >= PowerPolicy.UNRESPONSIVE_RESTART_AFTER_MS) {
                        RingLogBuffer.append("[vpn] engine unresponsive for 60s, restarting it")
                        engine.stop()
                    }

                    if (!engine.isRunning && config.quickReconnect) {
                        recoveries++
                        // Increasing pauses (1, 2, 4, 8, 16, 30 s), then a slow waiting phase that goes on
                        // for as long as it takes but never spins. A network change ends the pause at once.
                        val pause = ReconnectPolicy.delayMs(recoveries, isScreenOn(), kotlin.random.Random.nextDouble(-1.0, 1.0), lastFailureWasChain)
                        val waiting = ReconnectPolicy.phase(recoveries) == ReconnectPolicy.Phase.WAITING
                        RingLogBuffer.append("[vpn] ${if (waiting) "waiting" else "retry"} #$recoveries in ${pause / 1000}s (or when the network changes)")
                        if (waiting) {
                            AetherController.setState(ConnectionState.Error(getString(R.string.state_waiting_retry, (pause / 60_000L).coerceAtLeast(1L).toInt())))
                            updateNotification(getString(R.string.notif_waiting))
                        }
                        netWatcher.drain()
                        if (netWatcher.isOffline()) {
                            netWatcher.awaitNetwork { PowerPolicy.offlinePollMs(isScreenOn()) } // no network: a retry now could only fail
                            RingLogBuffer.append("[vpn] network is back, retrying now")
                            recoveries = 1
                        } else if (netWatcher.awaitChangeOrTimeout(pause)) {
                            RingLogBuffer.append("[vpn] network changed, retrying now")
                            recoveries = 1
                        }
                        ensureActive()
                        RingLogBuffer.append("[vpn] restarting engine (attempt $recoveries)")
                        AetherController.setState(ConnectionState.Connecting)
                        updateNotification(getString(R.string.notif_connecting))
                        when (val r = attemptConnect(config, RECOVERY_TIMEOUT_MS + ConnectPolicy.chainAllowanceMs(config))) {
                            is Attempt.Ready -> { consecutiveFailures = 0; lastFailureWasChain = false } // next healthy probe re-attaches the bridge
                            is Attempt.Failed -> {
                                AetherController.setState(ConnectionState.Error(r.reason))
                                lastFailureWasChain = ConnectPolicy.isChainFailure(r.reason)
                                if (lastFailureWasChain) engine.stop()
                            }
                        }
                    }
                } catch (c: CancellationException) {
                    throw c
                } catch (t: Throwable) {
                    // A crash in here must never take the process down.
                    RingLogBuffer.append("[vpn] health loop error: ${t::class.java.simpleName}: ${t.message}")
                    AetherController.setState(ConnectionState.Error(t.message ?: getString(R.string.state_error)))
                }
            }
        }
    }

    // --------------------------------------------------------------- teardown

    override fun onDestroy() {
        // Cancel first so an in-flight connect() cannot start an engine after we stop it.
        healthJob?.cancel()
        connectJob?.cancel()
        speedJob?.cancel()
        scope.cancel()
        netWatcher.onChanged = null
        netWatcher.onOffline = null
        netWatcher.onDefaultNetwork = null
        netWatcher.stop()
        screen.stop()
        DiagnosticsHub.engineCpuTicks = null
        stopBridge()
        engine.stop()
        releaseTun()
        AetherController.setLockdown(null)
        RouteMatcher.clearCache()
        // A startup failure stops the service on purpose and must leave its Error visible;
        // a user-requested stop (or a revoke) always returns to Idle.
        val keepError = !userRequestedStop && AetherController.state.value is ConnectionState.Error
        if (!keepError) AetherController.setState(ConnectionState.Idle)
        RingLogBuffer.append("[vpn] service destroyed, all state torn down")
        // Zero-log: nothing survives the session. The one exception is the log of a failed
        // start, kept in memory only, so the user can read why it failed.
        if (!keepError) { RingLogBuffer.clear(); DiagnosticsHub.clear() }
        super.onDestroy()
    }

    override fun onRevoke() {
        userRequestedStop = true
        stopSelfSafely()
        super.onRevoke()
    }

    /**
     * User pressed Disconnect. Tears everything down itself and then reports Idle
     * explicitly, instead of relying only on onDestroy() running: the UI must never
     * be left on "Disconnecting". Runs off the main thread so a slow step cannot freeze the app.
     */
    private fun teardownAndStop() {
        speedJob?.cancel()
        healthJob?.cancel()
        connectJob?.cancel()
        Thread {
            stopBridge()
            runCatching { engine.stop() }
            runCatching { releaseTun() }
            AetherController.setLockdown(null)
            AetherController.setState(ConnectionState.Idle)
            RingLogBuffer.clear()
            DiagnosticsHub.clear()
            stopSelf()
        }.start()
    }

    private fun stopSelfSafely() {
        Thread { stopSelf() }.start()
    }

    // ----------------------------------------------------------- notification

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, getString(R.string.notif_channel_tunnel), NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        statusText = text
        return buildNotification()
    }

    private fun buildNotification(): Notification {
        val speed = speedText
        return StatusNotification.build(
            this, CHANNEL_ID,
            text = speed ?: statusText,
            subText = if (speed != null) statusText else null,
            stopIntent = Intent(this, AetherVpnService::class.java).setAction(ACTION_DISCONNECT)
        )
    }

    private fun updateNotification(text: String) {
        statusText = text
        // The speed line is NOT cleared here: [startSpeedLoop] owns it (a "0 B/s" line while not connected, like sing-box).
        postNotification()
    }

    private fun postNotification() {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification())
    }

    private enum class SpeedMode { OFF, ZERO, LIVE }

    /**
     * sing-box style speed line in the notification. sing-box counts the bytes in the core and keeps the line while
     * the service is up, so an outage simply reads "0 B/s" and the numbers return by themselves. Same here:
     *  - LIVE: connected, screen on, wanted: real rates, read from the tunnel bridge every 2 s.
     *  - ZERO: wanted and screen on, but not connected (no network, retrying, connecting): a fixed "0 B/s" line,
     *    no polling at all. The status ("Waiting for network...") shows as the sub text.
     *  - OFF: screen off or switched off in the settings: no line, and no timer (the job is just suspended).
     */
    private fun startSpeedLoop() {
        speedJob?.cancel()
        speedJob = scope.launch {
            val wantSpeed = settingsStore.configFlow.map { it.notifSpeed }.distinctUntilChanged()
            combine(screen.screenOn, wantSpeed, AetherController.state) { on, want, st ->
                when {
                    !on || !want -> SpeedMode.OFF
                    st is ConnectionState.Connected -> SpeedMode.LIVE
                    else -> SpeedMode.ZERO
                }
            }.distinctUntilChanged().collectLatest { mode ->
                if (mode == SpeedMode.LIVE) {
                    runLiveSpeed()
                } else if (mode == SpeedMode.ZERO) {
                    speedText = NotificationText.speedLine(0L, 0L)
                    postNotification()
                } else if (speedText != null) {
                    speedText = null
                    postNotification()
                }
            }
        }
    }

    /** Runs until the collector cancels it (state, screen or setting changed). */
    private suspend fun runLiveSpeed() {
        var prev: LongArray? = null
        var prevAt = 0L
        while (true) {
            val s = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            val now = android.os.SystemClock.elapsedRealtime()
            if (s != null && s.size >= 4) {
                val p = prev
                if (p != null) {
                    val line = NotificationText.speedLine(
                        upBps = NotificationText.bps(p[1], s[1], now - prevAt),
                        downBps = NotificationText.bps(p[3], s[3], now - prevAt)
                    )
                    // Same text as before (an idle tunnel reads "0 B/s" again and again): do not re-post it.
                    if (line != speedText) {
                        speedText = line
                        postNotification()
                    }
                }
                prev = s; prevAt = now
            }
            delay(2_000)
        }
    }
}
