package com.aethershield.app.core

import android.app.*
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.aethershield.app.MainActivity
import com.aethershield.app.R
import com.aethershield.app.util.RingLogBuffer
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first

/**
 * Proxy-only mode: runs just the engine, no VpnService, no system-wide
 * capture, no VPN-permission dialog. Point individual apps at
 * socks5h://127.0.0.1:<port> yourself. This is the right choice when you only
 * need one or two apps proxied and don't want a full-device tunnel.
 *
 * Same connection discipline as the VPN service: the engine counts as up only
 * after a real SOCKS5 handshake, the wait ends the moment the engine dies (with
 * its real reason shown), and a started-then-cancelled connect can never leave
 * an engine running behind.
 */
class ProxyOnlyService : Service() {

    companion object {
        const val ACTION_START = "com.aethershield.app.core.PROXY_START"
        const val ACTION_STOP = "com.aethershield.app.core.PROXY_STOP"
        private const val NOTIF_ID = 2
        private const val CHANNEL_ID = "proxy_status"
        private const val HEALTH_CHECK_INTERVAL_MS = 5_000L
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var job: Job? = null
    @Volatile private var userRequestedStop = false
    private lateinit var engine: EngineProcessManager
    private lateinit var ruleWriter: RuleFileWriter
    private lateinit var chainSwapper: ChainLinkSwapper
    private lateinit var settingsStore: SettingsStore
    private lateinit var netWatcher: NetworkWatcher
    private lateinit var screen: ScreenWatcher

    /** The last failed restart was the privacy chain (Psiphon/Tor), not the WARP tunnel: retry slowly, see [ReconnectPolicy]. */
    @Volatile private var lastFailureWasChain = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        engine = EngineProcessManager(this)
        ruleWriter = RuleFileWriter(this)
        settingsStore = SettingsStore(this)
        netWatcher = NetworkWatcher(this)
        screen = ScreenWatcher(this)
        DiagnosticsHub.engineCpuTicks = { engine.cpuTicks() }
        // Live switch between saved custom links: only sing-box is replaced, the proxy stays up (see ChainLinkSwapper).
        chainSwapper = ChainLinkSwapper(engine, settingsStore)
        scope.launch { AetherController.linkSwapRequests.collect { chainSwapper.reconcile() } }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.notif_channel_proxy), NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            userRequestedStop = true
            job?.cancel()
            Thread {
                runCatching { engine.stop() }
                AetherController.setState(ConnectionState.Idle)
                RingLogBuffer.clear()
                DiagnosticsHub.clear()
                stopSelf()
            }.start()
            return START_NOT_STICKY
        }
        userRequestedStop = false
        netWatcher.onChanged = { screen.poke() }
        netWatcher.onOffline = { screen.poke() }
        netWatcher.start()
        screen.start()
        AetherController.setState(ConnectionState.Connecting)
        startForeground(NOTIF_ID, notification(getString(R.string.notif_connecting)))

        job?.cancel()
        job = scope.launch {
            try {
                val config = settingsStore.configFlow.first()
                // Keystore is read only when a Zero Trust team is set; a Keystore failure means "no secret", not a crash.
                val secretEnv = settingsStore.secretEnvFor(config)
                val chainLink = settingsStore.chainLinkFor(config)
                val self = currentCoroutineContext()[Job]
                var active = config
                suspend fun startAndWait(c: EngineConfig): SocksProbe.Wait {
                    ensureActive()
                    active = c
                    engine.start(c, ruleWriter, secretEnv, chainLink)
                    val timeout = ConnectPolicy.firstPassTimeoutMs(c)
                    val t0 = System.currentTimeMillis()
                    val w = SocksProbe.awaitReady(
                        TunnelConfig.SOCKS_HOST, engine.probePort, timeout,
                        engineAlive = { engine.isRunning }, cancelled = { self?.isActive == false }
                    )
                    if (w != SocksProbe.Wait.READY || c.effectiveChain == PrivacyChain.NONE) return w
                    // Psiphon/Tor's local proxy answers before the chain is connected: wait for "is ready".
                    val left = (timeout - (System.currentTimeMillis() - t0)).coerceAtLeast(10_000L)
                    return when (val r = engine.awaitChainReady(left) { self?.isActive == false }) {
                        null -> SocksProbe.Wait.READY
                        "cancelled" -> SocksProbe.Wait.CANCELLED
                        else -> { RingLogBuffer.append("[proxy] chain not ready: $r"); SocksProbe.Wait.TIMEOUT }
                    }
                }
                var wait = startAndWait(config)
                if (wait == SocksProbe.Wait.ENGINE_DIED && config.ech && EchFallback.isEchFailure(engine.failureReason())) {
                    RingLogBuffer.append("[proxy] ECH key lookup failed; retrying without ECH")
                    wait = startAndWait(config.copy(ech = false))
                }
                if (wait != SocksProbe.Wait.READY && wait != SocksProbe.Wait.CANCELLED &&
                    ConnectPolicy.shouldTryGoolH2(
                        active,
                        if (wait == SocksProbe.Wait.TIMEOUT) "no answer from the engine" else engine.failureReason()
                    )
                ) {
                    RingLogBuffer.append("[proxy] Gool over HTTP/3 did not connect; trying the HTTP/2 (TCP) carrier")
                    wait = startAndWait(active.copy(masqueHttp2 = true))
                }
                if (wait != SocksProbe.Wait.READY && wait != SocksProbe.Wait.CANCELLED &&
                    ConnectPolicy.shouldTryClassicGool(
                        active,
                        if (wait == SocksProbe.Wait.TIMEOUT) "no answer from the engine" else engine.failureReason()
                    )
                ) {
                    RingLogBuffer.append("[proxy] Gool over MASQUE found no gateway; trying classic Gool")
                    wait = startAndWait(active.copy(protocol = Protocol.GOOL_CLASSIC))
                }
                when (wait) {
                    SocksProbe.Wait.READY -> {
                        AetherController.setActive(active)
                        RingLogBuffer.append("[proxy] engine up")
                        AetherController.setState(
                            ConnectionState.Connected("${TunnelConfig.SOCKS_HOST}:${config.socksPort}")
                        )
                        postNotification(getString(R.string.proxy_running, "${TunnelConfig.SOCKS_HOST}:${config.socksPort}"))
                        watch(active, secretEnv, chainLink)
                    }
                    SocksProbe.Wait.ENGINE_DIED -> fail(engine.failureReason() ?: "the engine process exited")
                    SocksProbe.Wait.TIMEOUT -> fail("no answer from the engine after ${ConnectPolicy.firstPassTimeoutMs(config) / 1000}s")
                    SocksProbe.Wait.CANCELLED -> Unit
                }
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                fail(t.message ?: getString(R.string.state_error))
            }
        }
        return START_STICKY
    }

    /**
     * Watches the engine after it came up. If it dies, the same retry schedule as the VPN mode applies
     * (see [ReconnectPolicy]) when "quick reconnect" is on; otherwise the proxy is only marked as failed.
     */
    private suspend fun watch(config: EngineConfig, secretEnv: Map<String, String>, chainLink: String?) {
        var misses = 0
        var recoveries = 0
        var healthySince = 0L
        var firstMissAt = 0L
        val idleTracker = IdleTracker()
        var idle = false
        screen.drain()
        while (currentCoroutineContext().isActive) {
            // Long sleep while idle (screen off, quiet); a screen-on or network change cuts it short.
            if (screen.sleep(PowerPolicy.cadence(isScreenOn(), idle).healthMs)) idleTracker.wake()
            if (engine.swapping) continue // the custom link is being switched on purpose: not an outage
            // No byte counters in proxy-only mode, so only the screen decides.
            val wasIdle = idle
            idle = idleTracker.onTick(android.os.SystemClock.elapsedRealtime(), isScreenOn(), null)
            if (idle && !wasIdle) engine.onIdle() // screen off: the DoH client drops its idle connection
            // No network at all: stop the engine instead of letting it scan and fail in a loop (same rule as the VPN mode).
            if (netWatcher.isOffline()) {
                delay(PowerPolicy.OFFLINE_GRACE_MS) // a handover can say "no network" for a moment
                if (netWatcher.isOffline()) {
                    RingLogBuffer.append("[proxy] no network: engine paused until the network returns")
                    engine.stop()
                    AetherController.setState(ConnectionState.Error(getString(R.string.state_no_network)))
                    postNotification(getString(R.string.notif_no_network))
                    idleTracker.wake(); idle = false
                    netWatcher.awaitNetwork { PowerPolicy.offlinePollMs(isScreenOn()) }
                    currentCoroutineContext().ensureActive()
                    RingLogBuffer.append("[proxy] network is back, restarting engine")
                    recoveries = 0; misses = 0; healthySince = 0L
                    AetherController.setState(ConnectionState.Connecting)
                    postNotification(getString(R.string.notif_connecting))
                    if (restartEngine(config, secretEnv, chainLink)) {
                        RingLogBuffer.append("[proxy] engine up")
                        AetherController.setState(ConnectionState.Connected("${TunnelConfig.SOCKS_HOST}:${config.socksPort}"))
                        postNotification(getString(R.string.proxy_running, "${TunnelConfig.SOCKS_HOST}:${config.socksPort}"))
                    } else {
                        AetherController.setState(ConnectionState.Error(engine.failureReason() ?: getString(R.string.state_error)))
                    }
                    continue
                }
            }
            // Alive, but no WireGuard endpoint found in several full scans in a row (the local SOCKS port would still answer).
            val stalled = engine.isRunning && engine.tunnelStalled()
            // With a chain the local port is Psiphon's/Tor's and answers before the chain really carries traffic, so
            // "healthy" also needs the core's own "is ready" announcement (otherwise a failed restart showed "Connected").
            val ok = engine.isRunning && !stalled &&
                SocksProbe.handshakeOk(
                    TunnelConfig.SOCKS_HOST, engine.probePort,
                    PowerPolicy.HEALTH_CONNECT_TIMEOUT_MS, PowerPolicy.HEALTH_READ_TIMEOUT_MS
                ) &&
                (config.effectiveChain == PrivacyChain.NONE || engine.chainReady) &&
                engine.chainStillWorks(isScreenOn()) // custom chain only: a rare end-to-end check, screen on
            if (!ok && engine.swapping) continue // a switch started while this probe was running
            if (ok) {
                val now = android.os.SystemClock.elapsedRealtime()
                if (healthySince == 0L) healthySince = now
                else if (now - healthySince >= ReconnectPolicy.STABLE_AFTER_MS) recoveries = 0
                if (misses >= 2) {
                    AetherController.setState(
                        ConnectionState.Connected("${TunnelConfig.SOCKS_HOST}:${config.socksPort}")
                    )
                }
                misses = 0
                continue
            }
            healthySince = 0L
            idleTracker.wake(); idle = false
            if (misses == 0) firstMissAt = android.os.SystemClock.elapsedRealtime()
            if (engine.chainBroken) lastFailureWasChain = true // a dead custom link: retry on the slow chain schedule
            if (++misses == 2) {
                RingLogBuffer.append("[proxy] health check failed")
                AetherController.setState(ConnectionState.Error(engine.failureReason() ?: getString(R.string.state_error)))
            }
            if (stalled && config.quickReconnect) {
                RingLogBuffer.append("[proxy] no WARP endpoint found in ${TunnelStallTracker.STALL_AFTER_SCANS} full scans in a row: stopping the engine, retrying on the back-off schedule")
                engine.stop()
            }
            // An engine that is alive but has not answered for a full minute is hung (same rule as the VPN mode).
            if (engine.isRunning && config.quickReconnect &&
                android.os.SystemClock.elapsedRealtime() - firstMissAt >= PowerPolicy.UNRESPONSIVE_RESTART_AFTER_MS) {
                RingLogBuffer.append("[proxy] engine unresponsive for 60s, restarting it")
                engine.stop()
            }
            if (misses < 2 || engine.isRunning || !config.quickReconnect) continue

            recoveries++
            val pause = ReconnectPolicy.delayMs(recoveries, isScreenOn(), kotlin.random.Random.nextDouble(-1.0, 1.0), lastFailureWasChain)
            val waiting = ReconnectPolicy.phase(recoveries) == ReconnectPolicy.Phase.WAITING
            RingLogBuffer.append("[proxy] ${if (waiting) "waiting" else "retry"} #$recoveries in ${pause / 1000}s (or when the network changes)")
            if (waiting) {
                AetherController.setState(ConnectionState.Error(getString(R.string.state_waiting_retry, (pause / 60_000L).coerceAtLeast(1L).toInt())))
                postNotification(getString(R.string.notif_waiting))
            }
            netWatcher.drain()
            if (netWatcher.isOffline()) {
                netWatcher.awaitNetwork { PowerPolicy.offlinePollMs(isScreenOn()) } // no network: a retry now could only fail
                RingLogBuffer.append("[proxy] network is back, retrying now")
                recoveries = 1
            } else if (netWatcher.awaitChangeOrTimeout(pause)) {
                RingLogBuffer.append("[proxy] network changed, retrying now")
                recoveries = 1
            }
            currentCoroutineContext().ensureActive()
            AetherController.setState(ConnectionState.Connecting)
            postNotification(getString(R.string.notif_connecting))
            if (restartEngine(config, secretEnv, chainLink)) {
                misses = 0
                RingLogBuffer.append("[proxy] engine up")
                AetherController.setState(ConnectionState.Connected("${TunnelConfig.SOCKS_HOST}:${config.socksPort}"))
                postNotification(getString(R.string.proxy_running, "${TunnelConfig.SOCKS_HOST}:${config.socksPort}"))
            } else {
                AetherController.setState(ConnectionState.Error(engine.failureReason() ?: getString(R.string.state_error)))
            }
        }
    }

    private suspend fun restartEngine(c: EngineConfig, secretEnv: Map<String, String>, chainLink: String?): Boolean {
        val self = currentCoroutineContext()[Job]
        try {
            // The saved link is read again: the user may have switched it while connected (the live switch updates it).
            engine.start(c, ruleWriter, secretEnv, settingsStore.chainLinkFor(c) ?: chainLink)
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            RingLogBuffer.append("[proxy] restart failed: ${t.message}")
            return false
        }
        val timeout = 30_000L + ConnectPolicy.chainAllowanceMs(c)
        val w = SocksProbe.awaitReady(
            TunnelConfig.SOCKS_HOST, engine.probePort, timeout,
            engineAlive = { engine.isRunning }, cancelled = { self?.isActive == false }
        )
        if (w != SocksProbe.Wait.READY) { lastFailureWasChain = false; return false }
        if (c.effectiveChain == PrivacyChain.NONE) { lastFailureWasChain = false; return true }
        val reason = engine.awaitChainReady(timeout) { self?.isActive == false }
        if (reason == null) { lastFailureWasChain = false; return true }
        if (reason == "cancelled") throw CancellationException("restart cancelled")
        // The chain (Psiphon/Tor) did not come up. Stop the engine: it would otherwise keep a WARP tunnel and a
        // blocked Psiphon running through the wait, and the next retry follows the slow chain schedule.
        RingLogBuffer.append("[proxy] chain not ready: $reason")
        lastFailureWasChain = ConnectPolicy.isChainFailure(reason)
        if (lastFailureWasChain) engine.stop()
        return false
    }

    private fun isScreenOn(): Boolean =
        runCatching { (getSystemService(POWER_SERVICE) as android.os.PowerManager).isInteractive }.getOrDefault(true)

    private fun fail(reason: String) {
        RingLogBuffer.append("[proxy] start failed: $reason")
        engine.stop()
        AetherController.setState(ConnectionState.Error(reason))
        postNotification(getString(R.string.state_error))
        Thread { stopSelf() }.start() // onDestroy keeps this Error visible
    }

    override fun onDestroy() {
        job?.cancel()
        scope.cancel()
        netWatcher.onChanged = null
        netWatcher.onOffline = null
        netWatcher.stop()
        screen.stop()
        DiagnosticsHub.engineCpuTicks = null
        engine.stop()
        RouteMatcher.clearCache()
        val keepError = !userRequestedStop && AetherController.state.value is ConnectionState.Error
        if (!keepError) AetherController.setState(ConnectionState.Idle)
        RingLogBuffer.append("[proxy] service destroyed")
        if (!keepError) { RingLogBuffer.clear(); DiagnosticsHub.clear() }
        super.onDestroy()
    }

    private fun notification(text: String): Notification =
        StatusNotification.build(
            this, CHANNEL_ID, text = text, subText = null,
            stopIntent = Intent(this, ProxyOnlyService::class.java).setAction(ACTION_STOP)
        )

    private fun postNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notification(text))
    }
}
