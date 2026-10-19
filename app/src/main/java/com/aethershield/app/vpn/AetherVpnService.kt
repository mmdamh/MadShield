package com.aethershield.app.vpn

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.aethershield.app.MainActivity
import com.aethershield.app.R
import com.aethershield.app.core.*
import com.aethershield.app.util.RingLogBuffer
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import java.io.File

/**
 * Full-device VPN mode. Data path:
 *   apps -> Android TUN (this service) -> TProxyService (JNI bridge, hev-socks5-tunnel)
 *        -> 127.0.0.1:<socksPort> -> EngineProcessManager (aether core) -> internet
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
    }

    private sealed interface Attempt {
        data object Ready : Attempt
        data class Failed(val reason: String) : Attempt
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var connectJob: Job? = null
    @Volatile private var userRequestedStop = false
    private var tunFd: ParcelFileDescriptor? = null
    private var healthJob: Job? = null
    private lateinit var engine: EngineProcessManager
    private lateinit var ruleWriter: RuleFileWriter
    private lateinit var settingsStore: SettingsStore
    private lateinit var netWatcher: NetworkWatcher

    override fun onCreate() {
        super.onCreate()
        engine = EngineProcessManager(this)
        ruleWriter = RuleFileWriter(this)
        settingsStore = SettingsStore(this)
        netWatcher = NetworkWatcher(this)
        DiagnosticsHub.engineCpuTicks = { engine.cpuTicks() }
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            userRequestedStop = true
            teardownAndStop()
            return START_NOT_STICKY
        }
        userRequestedStop = false
        netWatcher.start()
        // Must happen within seconds of startForegroundService(); do it here,
        // not later inside the coroutine.
        AetherController.setState(ConnectionState.Connecting)
        startForeground(NOTIF_ID, buildNotification(getString(R.string.notif_connecting)))

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

        if (baseConfig.killSwitchEnabled) {
            establishTun(baseConfig) // capture traffic immediately; nothing bridged yet
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
            val secretEnv = settingsStore.getServiceTokenSecret()
                ?.let { mapOf("AETHER_ACCESS_CLIENT_SECRET" to it) }
                ?: emptyMap()
            val job = currentCoroutineContext()[Job]
            ensureActive() // never launch an engine after the user already pressed Disconnect
            // EnginePreflightException propagates on purpose: it cannot work no matter
            // how often we retry, so connect() surfaces it as-is.
            engine.start(config, ruleWriter, secretEnv)
            val deadlineMs = System.currentTimeMillis() + timeoutMs
            when (SocksProbe.awaitReady(
                host = TunnelConfig.SOCKS_HOST,
                port = config.socksPort,
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
            .setSession("AetherShield")
            .setMtu(config.effectiveMtu)
            .addAddress(TunnelConfig.TUN_IPV4, TunnelConfig.TUN_IPV4_PREFIX)
            .addAddress(TunnelConfig.TUN_IPV6, TunnelConfig.TUN_IPV6_PREFIX)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .setBlocking(false)

        // DNS: the user's resolvers (bare IPs; the VPN API takes no port) or a safe default.
        // With a chain on (Psiphon/Tor carry TCP only) the only DNS server is hev's mapped DNS,
        // so name lookups are answered locally and resolved at the chain's exit over TCP.
        val dnsToUse = if (config.effectiveChain != PrivacyChain.NONE) {
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
            AppSelectionMode.INCLUDE_ONLY_SELECTED -> config.selectedPackages.forEach {
                runCatching { builder.addAllowedApplication(it) }
            }
            AppSelectionMode.NONE -> {}
        }
        // Our own process (the engine child) must never be captured by its own tunnel.
        runCatching { builder.addDisallowedApplication(packageName) }

        tunFd = builder.establish()
            ?: throw IllegalStateException("Android could not create the VPN interface (permission revoked?)")
        RingLogBuffer.append("[vpn] TUN established (mtu=${config.effectiveMtu}, killSwitch=${config.killSwitchEnabled})")
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
        val mapdns = if (config.effectiveChain == PrivacyChain.NONE) "" else """

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
            while (isActive) {
                val cadence = PowerPolicy.cadence(isScreenOn())
                delay(cadence.healthMs)
                try {
                    val ok = engine.isRunning &&
                        SocksProbe.handshakeOk(TunnelConfig.SOCKS_HOST, config.socksPort)
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
                        if (now - lastCpuAt >= 60_000L) {
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
                        if (wasDown) { // came back (core replaced its tunnel, or we restarted it)
                            wasDown = false
                            if (tunFd == null) establishTun(config)
                            if (bridgeTunToEngine(config)) markConnected(config)
                        }
                        continue
                    }
                    // One failed probe is a blip (the core may be swapping tunnels); two in a row is an outage.
                    healthySince = 0L
                    if (++consecutiveFailures == 1) firstFailAt = android.os.SystemClock.elapsedRealtime()
                    if (consecutiveFailures < 2) continue

                    if (!wasDown) {
                        wasDown = true
                        RingLogBuffer.append("[vpn] health check failed, tunnel considered down")
                        AetherController.setState(
                            ConnectionState.Error(engine.failureReason() ?: getString(R.string.state_error))
                        )
                        stopBridge()
                        if (!config.killSwitchEnabled) releaseTun() // fail-open until it recovers
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
                        val pause = ReconnectPolicy.delayMs(recoveries, isScreenOn(), kotlin.random.Random.nextDouble(-1.0, 1.0))
                        val waiting = ReconnectPolicy.phase(recoveries) == ReconnectPolicy.Phase.WAITING
                        RingLogBuffer.append("[vpn] ${if (waiting) "waiting" else "retry"} #$recoveries in ${pause / 1000}s (or when the network changes)")
                        if (waiting) {
                            AetherController.setState(ConnectionState.Error(getString(R.string.state_waiting_retry, (pause / 60_000L).coerceAtLeast(1L).toInt())))
                            updateNotification(getString(R.string.notif_waiting))
                        }
                        netWatcher.drain()
                        if (netWatcher.awaitChangeOrTimeout(pause)) {
                            RingLogBuffer.append("[vpn] network changed, retrying now")
                            recoveries = 1
                        }
                        ensureActive()
                        RingLogBuffer.append("[vpn] restarting engine (attempt $recoveries)")
                        AetherController.setState(ConnectionState.Connecting)
                        updateNotification(getString(R.string.notif_connecting))
                        when (val r = attemptConnect(config, RECOVERY_TIMEOUT_MS + ConnectPolicy.chainAllowanceMs(config))) {
                            is Attempt.Ready -> consecutiveFailures = 0 // next healthy probe re-attaches the bridge
                            is Attempt.Failed -> AetherController.setState(ConnectionState.Error(r.reason))
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
        scope.cancel()
        netWatcher.stop()
        DiagnosticsHub.engineCpuTicks = null
        stopBridge()
        engine.stop()
        releaseTun()
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
        healthJob?.cancel()
        connectJob?.cancel()
        Thread {
            stopBridge()
            runCatching { engine.stop() }
            runCatching { releaseTun() }
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
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(text))
    }
}
