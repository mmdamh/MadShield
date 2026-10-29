package com.madshield.app.core

/**
 * Single source of truth for tunnel plumbing constants shared between the
 * VpnService (which builds the TUN interface) and the hev config writer.
 *
 * TUN_IPV4/TUN_IPV6 MUST be written into BOTH the VpnService interface
 * address AND hev-socks5-tunnel's `tunnel.ipv4`/`tunnel.ipv6` config fields.
 * If they don't match, hev's internal netif has no address to route packets
 * to -- the classic "tunnel connects but no site ever loads" symptom, which
 * is a different bug from (and can hide behind) the native-library-crash bug
 * -- fixing one without the other still doesn't produce a working tunnel.
 */
object TunnelConfig {
    const val SOCKS_HOST = "127.0.0.1"
    const val SOCKS_PORT = 1819

    const val TUN_IPV4 = "10.10.14.1"
    const val TUN_IPV4_PREFIX = 30
    const val TUN_IPV6 = "fc00::10:10:14:1"
    const val TUN_IPV6_PREFIX = 126

    // 8500 (this app's original value) causes path-MTU/fragmentation failures
    // on Iranian mobile networks specifically -- "connects but some
    // sites/Telegram won't open." 1280 is conservative but reliable.
    const val MTU = 1280

    val DNS_SERVERS = listOf("1.1.1.1", "8.8.8.8")
}
