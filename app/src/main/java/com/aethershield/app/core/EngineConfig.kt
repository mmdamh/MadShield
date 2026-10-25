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

/**
 * Privacy chain carried on top of the WARP tunnel (core: AETHER_PSIPHON=chain / AETHER_TOR=chain):
 *   NONE     the tunnel's own exit is the exit
 *   PSIPHON  app -> WARP -> Psiphon -> internet   (exit country selectable, see [Chain.REGIONS])
 *   TOR      app -> WARP -> Tor -> internet       (slow; first start downloads the consensus)
 *   SINGBOX  app -> WARP -> your own server       (a vless/vmess/trojan/ss link run by sing-box, see [SingBoxConfig])
 * All chains carry TCP only. Not offered with SMART (the core decides the transport itself,
 * and AetherGUI deliberately has no "smart + chain" entry either).
 */
enum class PrivacyChain {
    NONE, PSIPHON, TOR, SINGBOX;

    companion object {
        fun fromStored(name: String?): PrivacyChain =
            name?.let { n -> entries.firstOrNull { it.name == n } } ?: NONE
    }
}

object Chain {
    /** Where the core's own (WARP) SOCKS listens when a chain is on; the chain takes the public port. */
    const val UNDERLAY_PORT = 1823

    /** Where Psiphon/Tor listen when [RouteFront] owns the public port (routing rules + chain). */
    const val CHAIN_PORT = 1824
    const val GO_MAX_PROCS = "2"
    const val GO_MEMORY_LIMIT = "256MiB"

    /** hev "mapped DNS": answers app DNS locally with fake IPs so no UDP has to cross the chain. */
    const val MAPDNS_ADDRESS = "198.18.0.2"

    /** Psiphon exit countries offered in the UI (the core logs what is really on offer). */
    val REGIONS = listOf(
        "AT", "BE", "BG", "BR", "CA", "CH", "CZ", "DE", "DK", "ES", "FI", "FR", "GB",
        "HU", "IE", "IN", "IT", "JP", "NL", "NO", "PL", "RO", "RS", "SE", "SG", "SK", "US"
    )

    /** Two letters A-Z, upper-cased; anything else means "automatic" (null). */
    fun normalizeRegion(v: String?): String? =
        v?.trim()?.uppercase()?.takeIf { it.length == 2 && it.all { c -> c in 'A'..'Z' } }
}

/** Values the core accepts for AETHER_SCAN / AETHER_IP / AETHER_NOIZE (checked against cli.rs, v2.3.0). */
object CoreChoices {
    val SCAN_MODES = listOf("turbo", "balanced", "thorough", "verified", "ironclad")
    val IP_MODES = listOf("v4", "v6", "both")
    val NOIZE_PROFILES = listOf("off", "light", "firewall", "balanced", "gfw", "aggressive")

    /** AETHER_PERF_PROFILE: "auto" leaves it to the core, which picks "high" on an 8-core phone. */
    val PERF_PROFILES = listOf("auto", "medium", "low")
    const val DEFAULT_PERF = "medium"
    fun perfOrDefault(v: String?) = v?.takeIf { it in PERF_PROFILES } ?: DEFAULT_PERF

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
    val zeroTrustTeam: String? = null,

    // Chain WARP -> Psiphon / Tor. psiphonRegion = two-letter exit country, null = automatic.
    val privacyChain: PrivacyChain = PrivacyChain.NONE,
    val psiphonRegion: String? = null,

    // Core resource profile (AETHER_PERF_PROFILE). Lighter than the core's own pick on big phones:
    // smaller buffers and a capped scan, which means less heat and battery use.
    val perfProfile: String = CoreChoices.DEFAULT_PERF,

    /** Show upload/download speed in the status notification (VPN mode, only while the screen is on). */
    val notifSpeed: Boolean = true,

    /**
     * Battery saver (update15): fewer keepalive and health packets, and a stale limit that no longer kills a working
     * tunnel after one lost probe. See [BatterySaver]. On by default; turn it off to get the core's own timings.
     */
    val powerSaver: Boolean = true,

    // Local DoH (update11): names are resolved by the app itself through DoH, in every mode, instead of by
    // the core. Off by default; with it off the behaviour is exactly that of update10.
    val dohOn: Boolean = false,
    /** DohSpec strings, tried in order; plain DNS is never a fallback. */
    val dohResolvers: List<String> = emptyList(),
    /** With a Tor chain: ALSO resolve through DoH (the resolver you chose then sees the names, not Tor's exit). */
    val dohViaTor: Boolean = true,
    /** Answer from a recently expired cache entry when no DoH resolver can be reached (max 10 minutes). */
    val dohServeStale: Boolean = false,
    /** Also resolve names of DIRECT rules with DoH (from the phone's own network, outside the tunnel). */
    val dohForDirect: Boolean = false,

    // update19 (advanced, off by default; with the defaults no new variable reaches the core):
    /** MASQUE server name in the ClientHello (AETHER_MASQUE_SNI). "" = the core's own www.cloudflare.com. See [MasqueSni]. */
    val masqueSni: String = "",
    /** One-choice TLS fingerprint tuning for the handshakes (see [TlsPreset]). */
    val tlsPreset: TlsPreset = TlsPreset.DEFAULT
) {
    /** DoH switched on AND at least one resolver written. */
    val dohEnabled: Boolean get() = dohOn && dohResolvers.isNotEmpty()

    /**
     * DoH that will really run for this connection: not for Tor when the user turned "DoH through Tor" off
     * (Tor then resolves the names at its exit, as before).
     */
    val dohActive: Boolean
        get() = dohEnabled && !(effectiveChain == PrivacyChain.TOR && !dohViaTor)

    /** The chain that will really run (none for SMART). */
    val effectiveChain: PrivacyChain
        get() = if (protocol == Protocol.SMART) PrivacyChain.NONE else privacyChain

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
    // "ECH" as a word of its own. A plain substring test also matched words such as "technical" or "detected"
    // and switched ECH off for failures that had nothing to do with it.
    private val ECH_WORD = Regex("\\bECH\\b", RegexOption.IGNORE_CASE)

    fun isEchFailure(reason: String?): Boolean = reason != null && ECH_WORD.containsMatchIn(reason)
}

/**
 * Connect timing and the Gool fallback, shared by the VPN and proxy services.
 *
 * AetherGUI gives a scanned connect 90 s (its default "stall timeout"), because the core's own
 * gateway scan alone has a 45 s budget and the tunnel is verified AFTER it. A 45 s wait here
 * therefore gave up at the very moment the core was about to answer.
 *
 * AetherGUI also falls back from the MASQUE-carried Gool to the classic WireGuard-in-WireGuard
 * Gool when the core reports "gateway scan failed": the classic topology needs no MASQUE
 * gateway at all, so a network that filters the MASQUE scan still connects.
 */
object ConnectPolicy {
    const val SCANNED_PASS_MS = 90_000L
    const val SIMPLE_PASS_MS = 45_000L

    /** Extra startup time per chain (AetherGUI: psiphon 120 s for its server list, tor 300 s for the consensus). */
    const val PSIPHON_ALLOWANCE_MS = 120_000L
    const val TOR_ALLOWANCE_MS = 300_000L
    /** sing-box starts in about a second; the time is for the WARP tunnel to come up and the first end-to-end check. */
    const val SINGBOX_ALLOWANCE_MS = 45_000L

    fun chainAllowanceMs(c: EngineConfig): Long = when (c.effectiveChain) {
        PrivacyChain.PSIPHON -> PSIPHON_ALLOWANCE_MS
        PrivacyChain.TOR -> TOR_ALLOWANCE_MS
        PrivacyChain.SINGBOX -> SINGBOX_ALLOWANCE_MS
        PrivacyChain.NONE -> 0L
    }

    fun firstPassTimeoutMs(c: EngineConfig): Long =
        (if (c.protocol == Protocol.WIREGUARD) SIMPLE_PASS_MS else SCANNED_PASS_MS) + chainAllowanceMs(c)

    fun isScanFailure(reason: String?): Boolean =
        reason != null && reason.contains("gateway scan failed", ignoreCase = true)

    /** The failure came from the chain helper (psiphon/tor), not from the WARP transport. */
    fun isChainFailure(reason: String?): Boolean =
        reason != null && Regex("\\b(psiphon|tor|sing-box)\\b", RegexOption.IGNORE_CASE).containsMatchIn(reason)

    /**
     * Gool over MASQUE failed in the way the classic topology can avoid. With a chain on, a plain
     * timeout may just be a slow Psiphon/Tor start, so only an explicit scan failure counts.
     */
    fun shouldTryClassicGool(c: EngineConfig, reason: String?): Boolean =
        c.protocol == Protocol.GOOL && reason != null &&
            (isScanFailure(reason) ||
                (c.effectiveChain == PrivacyChain.NONE && reason.startsWith("no answer from the engine")))

    /**
     * Gool over MASQUE is first tried with HTTP/3 (QUIC, UDP). Where UDP is throttled that scan/handshake
     * never completes, while the HTTP/2 (TCP) carrier of the very same Gool works. So HTTP/2 comes BEFORE
     * the classic fallback (which gives a plain WARP exit, i.e. the Iranian one).
     */
    fun shouldTryGoolH2(c: EngineConfig, reason: String?): Boolean =
        c.protocol == Protocol.GOOL && !c.masqueHttp2 && reason != null &&
            (isScanFailure(reason) ||
                (c.effectiveChain == PrivacyChain.NONE && reason.startsWith("no answer from the engine")))

    /** The anti-DPI retry changes the WARP transport; it cannot fix a failing chain helper. */
    fun shouldTryHardened(c: EngineConfig, reason: String?): Boolean =
        !(c.effectiveChain != PrivacyChain.NONE && isChainFailure(reason))
}
