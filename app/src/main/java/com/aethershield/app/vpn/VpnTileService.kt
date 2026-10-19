package com.aethershield.app.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.aethershield.app.MainActivity
import com.aethershield.app.R
import com.aethershield.app.core.*
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

    override fun onStartListening() {
        super.onStartListening()
        val s = CoroutineScope(Dispatchers.Main.immediate + SupervisorJob())
        scope = s
        s.launch { AetherController.state.collect { render(it) } }
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
            ConnectionState.Disconnecting -> { tile.state = Tile.STATE_UNAVAILABLE; sub(tile, null) }
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
        val s = scope ?: CoroutineScope(Dispatchers.Main.immediate + SupervisorJob()).also { scope = it }
        s.launch {
            val config = withContext(Dispatchers.IO) { SettingsStore(applicationContext).configFlow.first() }
            when (state) {
                ConnectionState.Idle -> connect(config)
                ConnectionState.Disconnecting -> Unit
                else -> disconnect(config)
            }
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
        }
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
