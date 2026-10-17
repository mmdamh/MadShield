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
        private const val FIRST_PASS_TIMEOUT_MS = 45_000L
        private const val HARDENED_PASS_TIMEOUT_MS = 45_000L
        private const val RECOVERY_TIMEOUT_MS = 30_000L
        private const val MAX_RECOVERIES = 5
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

    override fun onCreate() {
        super.onCreate()
        engine = EngineProcessManager(this)
        ruleWriter = RuleFileWriter(this)
        settingsStore = SettingsStore(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            userRequestedStop = true
            teardownAndStop()
            return START_NOT_STICKY
        }
        userRequestedStop = false
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
        var attempt = attemptConnect(active, FIRST_PASS_TIMEOUT_MS)
        if (attempt is Attempt.Failed && active.ech && EchFallback.isEchFailure(attempt.reason)) {
            RingLogBuffer.append("[vpn] ECH key lookup failed; retrying without ECH")
            engine.stop()
            active = active.copy(ech = false)
            attempt = attemptConnect(active, FIRST_PASS_TIMEOUT_MS)
        }
        if (attempt is Attempt.Failed) {
            RingLogBuffer.append("[vpn] first pass failed (${attempt.reason}); retrying with anti-DPI hardening")
            engine.stop()
            active = active.hardened()
            attempt = attemptConnect(active, HARDENED_PASS_TIMEOUT_MS)
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

    private fun markConnected(config: EngineConfig) {
        if (userRequestedStop) return
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
            when (SocksProbe.awaitReady(
                host = TunnelConfig.SOCKS_HOST,
                port = config.socksPort,
                timeoutMs = timeoutMs,
                engineAlive = { engine.isRunning },
                cancelled = { job?.isActive == false }
            )) {
                SocksProbe.Wait.READY -> Attempt.Ready
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
        runCatching { TProxyService.TProxyStopService() }
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
        val dnsToUse = config.dnsResolvers.mapNotNull { DnsConfig.vpnAddress(it) }.distinct()
            .ifEmpty { TunnelConfig.DNS_SERVERS }
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
        val yaml = """
            misc:
              task-stack-size: 32768
              connect-timeout: 15000
              tcp-read-write-timeout: 60000
              udp-read-write-timeout: 60000
              log-level: warn
            tunnel:
              mtu: ${config.effectiveMtu}
              ipv4: ${TunnelConfig.TUN_IPV4}
              ipv6: '${TunnelConfig.TUN_IPV6}'
              icmp: 'reply'
            socks5:
              address: ${TunnelConfig.SOCKS_HOST}
              port: ${config.socksPort}
              udp: 'udp'
        """.trimIndent()
        file.writeText(yaml)
        return file
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
            val started = TProxyService.TProxyStartService(cfgFile.absolutePath, fd.fd)
            if (!started) {
                RingLogBuffer.append("[vpn] hev refused to start (config/fd rejected)")
                AetherController.setState(ConnectionState.Error("tunnel start refused"))
            }
            started
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
            while (isActive) {
                delay(HEALTH_CHECK_INTERVAL_MS)
                try {
                    val ok = engine.isRunning &&
                        SocksProbe.handshakeOk(TunnelConfig.SOCKS_HOST, config.socksPort)
                    if (ok) {
                        consecutiveFailures = 0
                        if (wasDown) { // came back (core replaced its tunnel, or we restarted it)
                            wasDown = false
                            if (tunFd == null) establishTun(config)
                            if (bridgeTunToEngine(config)) markConnected(config)
                        }
                        continue
                    }
                    // One failed probe is a blip (the core may be swapping tunnels); two in a row is an outage.
                    if (++consecutiveFailures < 2) continue

                    if (!wasDown) {
                        wasDown = true
                        RingLogBuffer.append("[vpn] health check failed, tunnel considered down")
                        AetherController.setState(
                            ConnectionState.Error(engine.failureReason() ?: getString(R.string.state_error))
                        )
                        runCatching { TProxyService.TProxyStopService() }
                        if (!config.killSwitchEnabled) releaseTun() // fail-open until it recovers
                    }

                    // An engine that is alive but has not answered for a full minute is hung.
                    if (engine.isRunning && consecutiveFailures >= 12 && config.quickReconnect) {
                        RingLogBuffer.append("[vpn] engine unresponsive for 60s, restarting it")
                        engine.stop()
                    }

                    if (!engine.isRunning && config.quickReconnect && recoveries < MAX_RECOVERIES) {
                        recoveries++
                        RingLogBuffer.append("[vpn] restarting engine (attempt $recoveries/$MAX_RECOVERIES)")
                        AetherController.setState(ConnectionState.Connecting)
                        updateNotification(getString(R.string.notif_connecting))
                        when (val r = attemptConnect(config, RECOVERY_TIMEOUT_MS)) {
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
        runCatching { TProxyService.TProxyStopService() }
        engine.stop()
        releaseTun()
        // A startup failure stops the service on purpose and must leave its Error visible;
        // a user-requested stop (or a revoke) always returns to Idle.
        val keepError = !userRequestedStop && AetherController.state.value is ConnectionState.Error
        if (!keepError) AetherController.setState(ConnectionState.Idle)
        RingLogBuffer.append("[vpn] service destroyed, all state torn down")
        // Zero-log: nothing survives the session. The one exception is the log of a failed
        // start, kept in memory only, so the user can read why it failed.
        if (!keepError) RingLogBuffer.clear()
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
            runCatching { TProxyService.TProxyStopService() }
            runCatching { engine.stop() }
            runCatching { releaseTun() }
            AetherController.setState(ConnectionState.Idle)
            RingLogBuffer.clear()
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
