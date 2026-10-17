package com.aethershield.app.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Disabled in the manifest by default (android:enabled="false"). If you add a
 * "connect on boot" toggle in SettingsScreen, flip the component's enabled
 * state via PackageManager.setComponentEnabledSetting from there instead of
 * enabling this receiver unconditionally -- opt-in, not default-on.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        // VpnService.prepare() cannot be silently granted after boot without
        // the user having approved it in a prior foreground session, so this
        // only re-starts the service; Android will no-op it if consent isn't
        // already recorded for this app.
        val svcIntent = Intent(context, AetherVpnService::class.java)
            .setAction(AetherVpnService.ACTION_CONNECT)
        runCatching { context.startForegroundService(svcIntent) }
    }
}
