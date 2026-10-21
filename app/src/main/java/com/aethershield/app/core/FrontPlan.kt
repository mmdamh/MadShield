package com.aethershield.app.core

/**
 * Which ports and helpers a connection uses. Pure, so the topology can be checked without a phone.
 *
 *   front OFF   (update10 behaviour, no routing front)
 *       no chain:  hev -> core on the PUBLIC port
 *       chain:     hev -> Psiphon/Tor on the PUBLIC port, core on UNDERLAY_PORT
 *   front ON    ([RouteFront] owns the PUBLIC port; the core ALWAYS sits on UNDERLAY_PORT)
 *       no chain:  hev -> front -> core (UNDERLAY_PORT)                  UDP is passed through to the core
 *       chain:     hev -> front -> Psiphon/Tor (CHAIN_PORT) -> core      UDP is refused (chains carry TCP only)
 *
 * The front is on when local DoH is active (it must see every name), or, as in update10, when a chain is on
 * and routing rules exist (the core would otherwise never see app traffic).
 */
data class FrontPlan(
    val frontOn: Boolean,
    /** Port of the core's own SOCKS listener (AETHER_SOCKS). */
    val corePort: Int,
    /** Port Psiphon/Tor bind to, or null without a chain. */
    val chainPort: Int?,
    /** Where the front sends proxied connections and where DoH connects: the chain, or the core without one. */
    val upstreamPort: Int,
    /** UDP ASSOCIATE is relayed byte-for-byte to the core (only possible without a chain). */
    val udpPassThrough: Boolean,
    /** The core gets AETHER_ROUTES_FILE. See [of] for why that also holds with the front on and no chain. */
    val coreGetsRoutes: Boolean,
    /** Names are resolved by the local DoH client. */
    val localDoh: Boolean
) {
    companion object {
        fun of(chain: PrivacyChain, dohActive: Boolean, rulesNonEmpty: Boolean, publicPort: Int): FrontPlan {
            val front = dohActive || (chain != PrivacyChain.NONE && rulesNonEmpty)
            val corePort = if (chain == PrivacyChain.NONE && !front) publicPort else Chain.UNDERLAY_PORT
            val chainPort = when {
                chain == PrivacyChain.NONE -> null
                front -> Chain.CHAIN_PORT
                else -> publicPort
            }
            return FrontPlan(
                frontOn = front,
                corePort = corePort,
                chainPort = chainPort,
                upstreamPort = chainPort ?: corePort,
                udpPassThrough = front && chain == PrivacyChain.NONE,
                // Without a chain the core still sees the UDP the front passes through and every IP the front
                // connects to, so it keeps enforcing block/direct for UDP and for IP-based rules, exactly as in
                // update10. With a chain the core never sees app traffic and the front is the only rule engine.
                coreGetsRoutes = chain == PrivacyChain.NONE || !front,
                localDoh = dohActive
            )
        }
    }
}

/**
 * Destinations the front must never forward when hev's mapped DNS is in use (see [FrontPlan.localDoh]).
 * Pure address tests on the raw bytes of a SOCKS request.
 */
object FrontGuard {
    enum class Verdict { OK, STALE_FAKE_IP, RESERVED }

    /** 100.64.0.0/10: the network hev hands fake addresses out of (mapdns network/netmask in hev.yaml). */
    fun inMapNetwork(a: ByteArray): Boolean =
        a.size == 4 && (a[0].toInt() and 0xff) == 100 && (a[1].toInt() and 0xc0) == 64

    /** 198.18.0.0/15: benchmarking range that holds hev's DNS address (198.18.0.2). */
    fun inDnsRange(a: ByteArray): Boolean =
        a.size == 4 && (a[0].toInt() and 0xff) == 198 && (a[1].toInt() and 0xfe) == 18

    /**
     * A fake address that reaches the front as an IP means hev no longer remembers its name (hev was
     * restarted): the connection is refused instead of being sent anywhere. 198.18.0.0/15 is refused at once
     * so Android's Private DNS probe (DoT on 198.18.0.2:853) gives up immediately and falls back to UDP 53.
     */
    fun check(a: ByteArray): Verdict = when {
        inMapNetwork(a) -> Verdict.STALE_FAKE_IP
        inDnsRange(a) -> Verdict.RESERVED
        else -> Verdict.OK
    }

    /** SOCKS5 reply code to send for a refused destination. */
    fun replyCode(v: Verdict): Int = when (v) {
        Verdict.OK -> 0x00
        Verdict.STALE_FAKE_IP -> 0x04 // host unreachable
        Verdict.RESERVED -> 0x05      // connection refused
    }
}
