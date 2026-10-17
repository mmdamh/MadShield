package com.aethershield.app.core

enum class ConnectionMode { VPN, PROXY_ONLY }

/**
 * Protocol choices, mapped to Aether core v2.3.0's AETHER_PROTOCOL values
 * (verified against how the official-core-tested AetherGUI drives it):
 *
 *  SMART        -> "smart"   the core picks and verifies a working transport itself
 *  MASQUE_H3    -> "masque"  CONNECT-IP over HTTP/3 (QUIC/UDP)
 *  MASQUE_H2    -> "masque"  same, over HTTP/2 (TCP) -- for networks that
 *                            throttle or block UDP/QUIC
 *  WIREGUARD    -> "wg"      plain WARP WireGuard
 *  GOOL         -> "gool"    v2.3.0 default: a WireGuard WARP identity carried
 *                            INSIDE the MASQUE tunnel, so the exit address is
 *                            foreign rather than your local one (this is the
 *                            warp-in-warp mode for changing an Iranian exit IP)
 *  GOOL_CLASSIC -> "gool" + AETHER_GOOL_MODE=classic: the older
 *                            WireGuard-in-WireGuard topology
 */
enum class Protocol {
    SMART, MASQUE_H3, MASQUE_H2, WIREGUARD, GOOL, GOOL_CLASSIC;

    companion object {
        /** Older builds stored "AUTO"; treat it as SMART instead of resetting the user's choice. */
        fun fromStored(name: String?): Protocol = when (name) {
            null, "AUTO" -> SMART
            else -> runCatching { valueOf(name) }.getOrDefault(SMART)
        }
    }
}

enum class AppSelectionMode { NONE, EXCLUDE_SELECTED, INCLUDE_ONLY_SELECTED }

/** Values the core accepts for AETHER_SCAN / AETHER_IP / AETHER_NOIZE (checked against cli.rs, v2.3.0). */
object CoreChoices {
    val SCAN_MODES = listOf("turbo", "balanced", "thorough", "verified", "ironclad")
    val IP_MODES = listOf("v4", "v6", "both")
    val NOIZE_PROFILES = listOf("off", "light", "firewall", "balanced", "gfw", "aggressive")

    const val DEFAULT_SCAN = "turbo"
    const val DEFAULT_IP = "v4"
    const val DEFAULT_NOIZE = "balanced"

    const val MIN_MTU = 1280
    const val DEFAULT_MTU = 1280
    const val MAX_MTU = 1420

    fun scanOrDefault(v: String?) = v?.takeIf { it in SCAN_MODES } ?: DEFAULT_SCAN
    fun ipOrDefault(v: String?) = v?.takeIf { it in IP_MODES } ?: DEFAULT_IP
    fun noizeOrDefault(v: String?) = v?.takeIf { it in NOIZE_PROFILES } ?: DEFAULT_NOIZE
}

data class EngineConfig(
    val mode: ConnectionMode = ConnectionMode.PROXY_ONLY,
    val protocol: Protocol = Protocol.SMART,
    val socksPort: Int = 1819,

    // Engine tuning exposed to the user (same knobs AetherGUI offers).
    // Defaults mirror AetherGUI's field-tested defaults (turbo scan + balanced
    // noize), because that combination is what connects on Iranian networks.
    val scanMode: String = CoreChoices.DEFAULT_SCAN,
    val ipMode: String = CoreChoices.DEFAULT_IP,

    // Anti-DPI hardening (AETHER_NOIZE / AETHER_MASQUE_H2_FRAGMENT / AETHER_ECH).
    // The user can set these directly; they are ALSO applied automatically as
    // a second-pass retry when a plain attempt fails -- see hardened().
    val noizeProfile: String = CoreChoices.DEFAULT_NOIZE,
    val fragment: Boolean = false,
    val ech: Boolean = false,

    // Optional resolver used by the core to fetch ECH keys (AETHER_ECH_DNS).
    // Accepts udp://ip[:port], tcp://ip[:port] or https://host[/path][@address=IP][@sni=NAME].
    val echDns: String? = null,

    // For gool only: force the HTTP/2 (TCP) carrier instead of HTTP/3.
    // (MASQUE_H2 implies this on its own.) Set by hardened().
    val masqueHttp2: Boolean = false,

    // Tunnel MTU (VpnService + hev + the MASQUE outer budget). 1280 is the
    // conservative value that survives Iranian mobile networks; see TunnelConfig.
    val mtu: Int = CoreChoices.DEFAULT_MTU,

    // Let the core replace a dead tunnel by itself (AETHER_QUICK_RECONNECT).
    val quickReconnect: Boolean = true,

    // AETHER_EXIT_LOC policy, e.g. "!IR" = refuse any tunnel whose exit
    // country is Iran. The core checks this through the finished tunnel
    // before SOCKS5 opens and again every minute, dropping and replacing a
    // tunnel that lands on a rejected country. null = off.
    val exitLoc: String? = null,

    // Plain "ip" / "ip:port" resolvers (IPv6 as "addr" or "[addr]:port").
    // The stock v2.3.0 core only understands plain addresses for AETHER_DNS;
    // DoH is supported by the core ONLY for ECH key lookups (see echDns).
    // Entries are normalised/validated by DnsConfig before they get here.
    val dnsResolvers: List<String> = emptyList(),

    // Domains/CIDRs that bypass the tunnel (e.g. Iranian sites that reject
    // foreign IPs). Written into a [block]/[direct] file and passed through
    // AETHER_ROUTES_FILE (see RuleFileWriter).
    val directRules: List<String> = emptyList(),
    val blockRules: List<String> = emptyList(),

    // Per-app split tunneling, enforced by AetherVpnService at the OS VPN
    // layer (the engine cannot see per-app identity in tun mode).
    val appSelectionMode: AppSelectionMode = AppSelectionMode.NONE,
    val selectedPackages: Set<String> = emptySet(),

    // If true and the tunnel is not confirmed healthy, traffic is held
    // instead of falling back to the raw network.
    val killSwitchEnabled: Boolean = true,

    // Optional Cloudflare Zero Trust team. The secret lives in
    // Keystore-backed EncryptedSharedPreferences and reaches the core only
    // through its environment, never argv.
    val zeroTrustTeam: String? = null
) {
    /**
     * Tunnel MTU after clamping to what the chosen transport can carry
     * (caps copied from AetherGUI: nested WireGuard 1360, WireGuard 1420,
     * MASQUE 1400; floor 1280, the IPv6 minimum).
     */
    val effectiveMtu: Int
        get() {
            val cap = when (protocol) {
                Protocol.GOOL, Protocol.GOOL_CLASSIC -> 1360
                Protocol.WIREGUARD -> 1420
                else -> 1400
            }
            return mtu.coerceIn(CoreChoices.MIN_MTU, cap)
        }

    /**
     * Second-pass configuration for when a plain attempt fails or times out --
     * most commonly because QUIC/UDP (MASQUE h3) is throttled. Switches the
     * MASQUE carrier to HTTP/2 over TCP, fragments the ClientHello and uses the
     * firewall noize profile. WireGuard gets noize only (it has no h2/h3 choice
     * and no ClientHello to fragment).
     *
     * ECH is deliberately NOT switched on here: it needs a DoH/DNS lookup of the
     * ECH key that is itself blocked on many networks, and when that lookup fails
     * the core refuses to start at all ("ECH is on but there is no ECH key to
     * offer"). A fallback that can make things worse is not a fallback. The user's
     * own ECH choice is kept as it is.
     */
    fun hardened(): EngineConfig = when (protocol) {
        Protocol.SMART, Protocol.MASQUE_H3, Protocol.MASQUE_H2 -> copy(
            protocol = Protocol.MASQUE_H2,
            noizeProfile = "firewall", fragment = true
        )
        Protocol.GOOL -> copy(
            masqueHttp2 = true,
            noizeProfile = "firewall", fragment = true
        )
        Protocol.WIREGUARD, Protocol.GOOL_CLASSIC -> copy(noizeProfile = "firewall")
    }
}

/**
 * The core exits with an "ECH ... no ECH key" error when ECH is on but the key
 * lookup (AETHER_ECH_DNS) cannot be completed. That is recoverable: connect
 * again without ECH instead of leaving the user with a dead connection.
 */
object EchFallback {
    fun isEchFailure(reason: String?): Boolean =
        reason != null && reason.contains("ECH", ignoreCase = true)
}
