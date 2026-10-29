package com.madshield.app.core

/**
 * Which program reads the TUN device the VPN service owns (update24, EXPERIMENTAL).
 *
 *  - [HEV]: hev-socks5-tunnel through our JNI bridge, inside the app process. The default and the only engine
 *    before update24; behaviour with it selected is unchanged.
 *  - [SINGBOX_TUN]: a separate sing-box process (libsingtun.so, sing-box 1.15 with sing-tun's own TCP/IP stack)
 *    that receives the TUN fd from the app and forwards to the same SOCKS port hev uses.
 *
 * The VpnService.Builder (Kill Switch, per-app split, DNS server) is NOT part of an engine: the service builds the
 * TUN either way and an engine only receives its file descriptor.
 */
enum class TunEngineId(val stored: String) {
    HEV("hev"),
    SINGBOX_TUN("singbox_tun");

    companion object {
        /** Unknown or missing values mean the default, so a damaged or future setting can never select nothing. */
        fun fromStored(s: String?): TunEngineId = entries.firstOrNull { it.stored == s } ?: HEV
    }
}

/**
 * Bytes (and, where the engine knows them, packets) that crossed the tunnel since the engine started. Packets are null
 * for an engine that only has interface byte counters.
 */
data class TunCounters(val txPackets: Long?, val txBytes: Long, val rxPackets: Long?, val rxBytes: Long) {
    val totalBytes: Long get() = txBytes + rxBytes
}

/** [TunCounters] from a pair of interface counters, or null when either is negative (`TrafficStats.UNSUPPORTED` is -1). */
fun countersOrNull(txBytes: Long, rxBytes: Long): TunCounters? =
    if (txBytes < 0 || rxBytes < 0) null else TunCounters(null, txBytes, null, rxBytes)

sealed interface StartResult {
    data object Ok : StartResult
    /** [reason] is shown to the user as the connection error. */
    data class Failed(val reason: String) : StartResult
}

sealed interface EngineSelection {
    data class Use(val id: TunEngineId) : EngineSelection
    data class Unavailable(val reason: String) : EngineSelection
}

/**
 * Which engine this connection uses. hev is always available. A requested sing-box TUN engine without its binary in the
 * build is reported, never replaced by hev behind the user's back.
 */
fun selectTunEngine(requested: TunEngineId, singTunInBuild: Boolean): EngineSelection = when {
    requested == TunEngineId.SINGBOX_TUN && !singTunInBuild ->
        EngineSelection.Unavailable("This build has no sing-box TUN engine (libsingtun.so missing). Choose hev in Settings, or rebuild with the updated CI workflow.")
    else -> EngineSelection.Use(requested)
}
