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
        private const val CONNECT_TIMEOUT_MS = 45_000L
        private const val HEALTH_CHECK_INTERVAL_MS = 5_000L
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var job: Job? = null
    @Volatile private var userRequestedStop = false
    private lateinit var engine: EngineProcessManager
    private lateinit var ruleWriter: RuleFileWriter
    private lateinit var settingsStore: SettingsStore

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        engine = EngineProcessManager(this)
        ruleWriter = RuleFileWriter(this)
        settingsStore = SettingsStore(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.notif_channel_proxy), NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            userRequestedStop = true
            stopSelf()
            return START_NOT_STICKY
        }
        userRequestedStop = false
        AetherController.setState(ConnectionState.Connecting)
        startForeground(NOTIF_ID, notification(getString(R.string.notif_connecting)))

        job?.cancel()
        job = scope.launch {
            try {
                val config = settingsStore.configFlow.first()
                val secretEnv = settingsStore.getServiceTokenSecret()
                    ?.let { mapOf("AETHER_ACCESS_CLIENT_SECRET" to it) } ?: emptyMap()
                engine.start(config, ruleWriter, secretEnv)

                val self = currentCoroutineContext()[Job]
                when (SocksProbe.awaitReady(
                    TunnelConfig.SOCKS_HOST, config.socksPort, CONNECT_TIMEOUT_MS,
                    engineAlive = { engine.isRunning }, cancelled = { self?.isActive == false }
                )) {
                    SocksProbe.Wait.READY -> {
                        AetherController.setState(
                            ConnectionState.Connected("${TunnelConfig.SOCKS_HOST}:${config.socksPort}")
                        )
                        postNotification(getString(R.string.proxy_running, "${TunnelConfig.SOCKS_HOST}:${config.socksPort}"))
                        watch(config)
                    }
                    SocksProbe.Wait.ENGINE_DIED -> fail(engine.failureReason() ?: "the engine process exited")
                    SocksProbe.Wait.TIMEOUT -> fail("no answer from the engine after ${CONNECT_TIMEOUT_MS / 1000}s")
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

    /** Marks the proxy as failed when the engine dies later on (the core handles its own tunnel swaps). */
    private suspend fun watch(config: EngineConfig) {
        var misses = 0
        while (currentCoroutineContext().isActive) {
            delay(HEALTH_CHECK_INTERVAL_MS)
            val ok = engine.isRunning && SocksProbe.handshakeOk(TunnelConfig.SOCKS_HOST, config.socksPort)
            if (ok) {
                if (misses >= 2) {
                    AetherController.setState(
                        ConnectionState.Connected("${TunnelConfig.SOCKS_HOST}:${config.socksPort}")
                    )
                }
                misses = 0
            } else if (++misses == 2) {
                RingLogBuffer.append("[proxy] health check failed")
                AetherController.setState(ConnectionState.Error(engine.failureReason() ?: getString(R.string.state_error)))
            }
        }
    }

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
        engine.stop()
        val keepError = !userRequestedStop && AetherController.state.value is ConnectionState.Error
        if (!keepError) AetherController.setState(ConnectionState.Idle)
        RingLogBuffer.append("[proxy] service destroyed")
        if (!keepError) RingLogBuffer.clear()
        super.onDestroy()
    }

    private fun notification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun postNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, notification(text))
    }
}
