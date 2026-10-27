package com.aethershield.app.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.os.Build

/**
 * Reads the phone's byte counters for [SpeedMeterCheck]: one read of every interface the system knows about, plus the
 * phone-wide total. Runs only when the user presses the button on the Diagnostics page (two reads, ten seconds apart);
 * nothing runs in the background. No permission beyond the network-state one the app already has.
 */
object SpeedMeterProbe {
    class Snapshot(val readings: List<SpeedMeterCheck.Reading>, /** [rx, tx] phone-wide, negative = unsupported */ val system: LongArray)

    /**
     * @return null where the phone does not give this app per-interface counters: they are public from Android 12
     *         (API 31), and any failure reading them counts as "not available" rather than an error.
     */
    @Suppress("DEPRECATION")
    fun read(context: Context): Snapshot? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return try {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
            val names = LinkedHashMap<String, SpeedMeterCheck.Kind>()
            names["lo"] = SpeedMeterCheck.Kind.LOOPBACK
            for (n in cm.allNetworks) {
                val iface = cm.getLinkProperties(n)?.interfaceName ?: continue
                val vpn = cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                names.putIfAbsent(iface, if (vpn) SpeedMeterCheck.Kind.TUNNEL else SpeedMeterCheck.Kind.PHYSICAL)
            }
            val readings = names.mapNotNull { (name, kind) ->
                val rx = TrafficStats.getRxBytes(name)
                val tx = TrafficStats.getTxBytes(name)
                if (rx < 0 || tx < 0) null else SpeedMeterCheck.Reading(name, kind, rx, tx)
            }
            Snapshot(readings, longArrayOf(TrafficStats.getTotalRxBytes(), TrafficStats.getTotalTxBytes()))
        } catch (_: Throwable) {
            null
        }
    }
}
