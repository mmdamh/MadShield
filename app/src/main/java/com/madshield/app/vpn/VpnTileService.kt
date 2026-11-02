package com.madshield.app.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.madshield.app.MainActivity
import com.madshield.app.R
import com.madshield.app.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first

/**
 * Quick Settings tile: switches the connection on and off from the notification shade, without opening
 * the app. It only listens to [AetherController] while the shade is open (onStartListening ..
 * onStopListening), so it costs nothing otherwise.
 *
 * Turning ON in VPN mode needs the system's one-time VPN permission; if it has not been granted yet, the
 * tile opens the app instead of failing silently.
 */
class VpnTileService : TileService() {
    private var scope: CoroutineScope? = null

    override fun onTileAdded() {
        super.onTileAdded()
        runCatching { render(AetherController.state.value) }
    }

    override fun onStartListening() {
        super.onStartListening()
        // Draw the current state first, so the tile is right even if the collector below never gets to run.
        runCatching { render(AetherController.state.value) }
        val s = CoroutineScope(Dispatchers.Main.immediate + SupervisorJob())
        scope = s
        s.launch { AetherController.state.collect { runCatching { render(it) } } }
    }

    override fun onStopListening() {
        scope?.cancel()
        scope = null
        super.onStopListening()
    }

    private fun render(state: ConnectionState) {
        val tile = qsTile ?: return
        when (state) {
            is ConnectionState.Connected -> { tile.state = Tile.STATE_ACTIVE; sub(tile, getString(R.string.tile_on)) }
            ConnectionState.Connecting -> { tile.state = Tile.STATE_ACTIVE; sub(tile, getString(R.string.notif_connecting)) }
            is ConnectionState.Error -> { tile.state = Tile.STATE_ACTIVE; sub(tile, getString(R.string.state_error)) }
            // Never STATE_UNAVAILABLE: Android does not deliver taps to such a tile, so a tile left in that state (shade closed
            // before the final "Off" was drawn) looked dimmed and did nothing. INACTIVE stays tappable.
            ConnectionState.Disconnecting -> { tile.state = Tile.STATE_INACTIVE; sub(tile, getString(R.string.status_disconnecting)) }
            ConnectionState.Idle -> { tile.state = Tile.STATE_INACTIVE; sub(tile, getString(R.string.tile_off)) }
        }
        tile.label = getString(R.string.app_name)
        tile.updateTile()
    }

    private fun sub(tile: Tile, text: String?) {
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = text
    }

    override fun onClick() {
        super.onClick()
        val state = AetherController.state.value
        // Its own scope: closing the shade right after the tap (onStopListening) must not cancel the tap's work half way.
        CoroutineScope(Dispatchers.Main.immediate + SupervisorJob()).launch {
            // A failed settings read must never end in a silent no-op (or a crash): tell the user by opening the app.
            val config = runCatching { withContext(Dispatchers.IO) { SettingsStore(applicationContext).configFlow.first() } }
                .getOrNull()
            if (config == null) { runCatching { openApp() }; return@launch }
            runCatching {
                when (state) {
                    ConnectionState.Idle -> connect(config)
                    // A second tap while it is shutting down sends the stop again instead of being ignored.
                    else -> disconnect(config)
                }
            }.onFailure { runCatching { openApp() } }
        }
    }

    private fun connect(config: EngineConfig) {
        val proxyOnly = config.mode == ConnectionMode.PROXY_ONLY
        // VPN mode needs the system permission first; the app has the dialog for it.
        if (!proxyOnly && VpnService.prepare(this) != null) { openApp(); return }
        AetherController.setState(ConnectionState.Connecting)
        val intent = if (proxyOnly) Intent(this, ProxyOnlyService::class.java).setAction(ProxyOnlyService.ACTION_START)
        else Intent(this, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_CONNECT)
        val started = runCatching { startForegroundService(intent) }.isSuccess
        if (!started) { AetherController.setState(ConnectionState.Idle); openApp() }
    }

    private fun disconnect(config: EngineConfig) {
        AetherController.setState(ConnectionState.Disconnecting)
        val intent = if (config.mode == ConnectionMode.PROXY_ONLY)
            Intent(this, ProxyOnlyService::class.java).setAction(ProxyOnlyService.ACTION_STOP)
        else Intent(this, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_DISCONNECT)
        val ok = runCatching { startService(intent) }.isSuccess
        // If the service cannot be reached the state must not stay on "Disconnecting".
        if (!ok) {
            runCatching { stopService(Intent(this, AetherVpnService::class.java)) }
            runCatching { stopService(Intent(this, ProxyOnlyService::class.java)) }
            AetherController.setState(ConnectionState.Idle)
            return
        }
        // Same safety net as the app's own Disconnect button: if the service never reports back, do not stay stuck.
        Handler(Looper.getMainLooper()).postDelayed({
            if (AetherController.state.value == ConnectionState.Disconnecting) AetherController.setState(ConnectionState.Idle)
        }, DISCONNECT_FALLBACK_MS)
    }

    private companion object {
        const val DISCONNECT_FALLBACK_MS = 6_000L
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 2, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
