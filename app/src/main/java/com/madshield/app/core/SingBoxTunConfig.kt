package com.madshield.app.core

/**
 * The sing-box configuration for the experimental "sing-box TUN" tunnel engine. Written against sing-box
 * v1.15.0-alpha.13 (native/singbox-tun.pin); the golden files in tests/pure/golden-singtun/ are validated by the real
 * `sing-box check` of that pin in CI.
 *
 *   apps -> Android TUN (the app's VpnService; the fd is handed over, see TunFdChannel)
 *        -> sing-box `tun` inbound, sing-tun's own TCP/IP stack
 *        -> `upstream` outbound = SOCKS5 on 127.0.0.1:<socksPort>  (the SAME port hev uses: the front, the chain or the core)
 *
 *  - No `stack` key: it is deprecated in 1.15 and removed in 1.17.0; leaving it out selects sing-tun's own stack.
 *  - `auto_route` is off and the addresses/MTU equal the VpnService.Builder values (TunnelConfig): with an fd handed over,
 *    sing-tun configures nothing itself, so these only have to be right.
 *  - Mapped DNS (what hev's `mapdns` does): the Builder's DNS server is [Chain.MAPDNS_ADDRESS]; queries to it are
 *    hijacked into a fakeip DNS server (pool 100.64.0.0/10, like hev) and the connection that follows carries the NAME to
 *    the SOCKS outbound, so the front can apply DoH and domain rules. IPv4 only, like hev's mapped DNS.
 *  - Log level `warn`: at `info` sing-box logs every connection (destinations), which this app never keeps.
 *  - The first outbound is the default, so `route.final` is spelled out anyway.
 */
object SingBoxTunConfig {
    const val TUN_TAG = "tun-in"
    const val UPSTREAM_TAG = "upstream"
    const val FAKEIP_TAG = "fakeip"
    const val DNS_VOID_TAG = "dns-void"
    /** The pool hev's mapdns hands fake addresses out of (hev.yaml: network 100.64.0.0, netmask 255.192.0.0). */
    const val FAKEIP_RANGE = "100.64.0.0/10"

    fun render(mtu: Int, socksPort: Int, mappedDns: Boolean): String {
        require(socksPort in 1..65535) { "bad port" }
        require(mtu in 576..65535) { "bad mtu" }
        val root = linkedMapOf<String, Any?>(
            "log" to linkedMapOf("level" to "warn", "timestamp" to false)
        )
        if (mappedDns) {
            // sing-box refuses a fakeip server as the default one, so a placeholder default comes first. Nothing ever reaches it:
            // the rules below answer every query (A -> fakeip, anything else -> an empty NOERROR, like hev's IPv4-only mapdns).
            root["dns"] = linkedMapOf<String, Any?>(
                "servers" to listOf(
                    linkedMapOf<String, Any?>("type" to "udp", "tag" to DNS_VOID_TAG, "server" to Chain.MAPDNS_ADDRESS),
                    linkedMapOf<String, Any?>("type" to "fakeip", "tag" to FAKEIP_TAG, "inet4_range" to FAKEIP_RANGE)
                ),
                "rules" to listOf(
                    linkedMapOf<String, Any?>("query_type" to listOf("A"), "action" to "route", "server" to FAKEIP_TAG),
                    linkedMapOf<String, Any?>("action" to "predefined", "rcode" to "NOERROR")
                ),
                "final" to DNS_VOID_TAG,
                "strategy" to "ipv4_only"
            )
        }
        root["inbounds"] = listOf(
            linkedMapOf<String, Any?>(
                "type" to "tun", "tag" to TUN_TAG,
                "address" to listOf(
                    "${TunnelConfig.TUN_IPV4}/${TunnelConfig.TUN_IPV4_PREFIX}",
                    "${TunnelConfig.TUN_IPV6}/${TunnelConfig.TUN_IPV6_PREFIX}"
                ),
                "mtu" to mtu,
                "auto_route" to false
            )
        )
        root["outbounds"] = listOf(
            linkedMapOf<String, Any?>(
                "type" to "socks", "tag" to UPSTREAM_TAG,
                "server" to TunnelConfig.SOCKS_HOST, "server_port" to socksPort, "version" to "5"
            )
        )
        val route = linkedMapOf<String, Any?>()
        if (mappedDns) {
            route["rules"] = listOf(
                linkedMapOf<String, Any?>(
                    "ip_cidr" to listOf("${Chain.MAPDNS_ADDRESS}/32"),
                    "port" to listOf(53),
                    "action" to "hijack-dns"
                )
            )
        }
        route["final"] = UPSTREAM_TAG
        root["route"] = route
        return MiniJson.write(root) + "\n"
    }
}
