package com.madshield.desktop

import com.madshield.app.core.MiniJson

/**
 * The sing-box configuration of the Windows TUN (sing-box 1.14, native/singbox.pin). Proven in phase 0 on a Windows runner
 * (update45): a program that knows nothing about the tunnel goes out through the engine, with no traffic loop.
 *
 *   apps -> wintun adapter (auto_route, strict_route) -> sing-box -> SOCKS outbound on 127.0.0.1:<socksPort> (the front)
 *
 *  - The engine programs and this app are routed "direct" by process name (and their DNS goes to the plain resolver):
 *    they carry the tunnel, so they must never enter it. auto_detect_interface binds sing-box's own sockets to the real
 *    network for the same reason.
 *  - strict_route: other adapters' DNS is blocked, so names cannot be asked outside the tunnel (DNS leak).
 *  - [mappedDns]: names are answered with fake addresses and the connection that follows carries the NAME to the front,
 *    which is what the TCP-only engines (Psiphon, Tor, Foxy) need. Otherwise the DNS goes over the engine as TCP.
 *  - Private networks stay outside the tunnel (printers, the router's page); the order TUN first, engine second matters
 *    (an open QUIC connection does not survive the routes changing underneath it).
 */
object TunConfig {
    const val TUN_NAME = "MadShieldTun"
    const val UPSTREAM = "upstream"
    private const val FAKEIP = "fakeip"
    private const val DNS_VOID = "dns-void"
    private const val DNS_REMOTE = "dns-remote"
    private const val DNS_DIRECT = "dns-direct"

    /**
     * Names the engines must resolve BEFORE any tunnel exists. Windows sends every program's DNS question through its
     * own DNS Client service (svchost), not through the program, so the "this process goes direct" rule does not cover
     * it: without these names answered directly, the question is hijacked, sent into the tunnel, and refused because
     * the engine that would carry it is waiting for this very answer. (Seen in CI: Aether lost ~25 s to
     * "No such host is known" before its fallback addresses worked.) Only the engines' own service names, never
     * anything a user program asks.
     */
    val BOOTSTRAP_DOMAINS = listOf(
        "cloudflareclient.com", "cloudflare.com", "cloudflareaccess.com", "cloudflare-dns.com",
        "mozilla.org", "mozilla.com", "mozilla.net", "firefox.com", "mozaws.net", "mozgcp.net"
    )

    fun render(
        socksPort: Int, mappedDns: Boolean, directProcesses: List<String>, mtu: Int = 1400, strictRoute: Boolean = true,
        extraDirectDomains: List<String> = emptyList()
    ): String {
        require(socksPort in 1..65535) { "bad port" }
        require(mtu in 576..65535) { "bad mtu" }
        val direct = linkedMapOf<String, Any?>("process_name" to directProcesses, "action" to "route", "server" to DNS_DIRECT)
        val bootstrap = linkedMapOf<String, Any?>(
            "domain_suffix" to (BOOTSTRAP_DOMAINS + extraDirectDomains.filter { it.isNotBlank() && !it.contains(':') && it.any { c -> c.isLetter() } }).distinct(),
            "action" to "route", "server" to DNS_DIRECT
        )

        val dns = linkedMapOf<String, Any?>()
        if (mappedDns) {
            dns["servers"] = listOf(
                linkedMapOf<String, Any?>("type" to "udp", "tag" to DNS_DIRECT, "server" to "1.1.1.1"),
                linkedMapOf<String, Any?>("type" to "udp", "tag" to DNS_VOID, "server" to "198.18.0.2"),
                linkedMapOf<String, Any?>("type" to "fakeip", "tag" to FAKEIP, "inet4_range" to "100.64.0.0/10")
            )
            dns["rules"] = listOf(
                direct,
                bootstrap,
                linkedMapOf<String, Any?>("query_type" to listOf("A"), "action" to "route", "server" to FAKEIP),
                linkedMapOf<String, Any?>("action" to "predefined", "rcode" to "NOERROR")
            )
            dns["final"] = DNS_VOID
        } else {
            dns["servers"] = listOf(
                linkedMapOf<String, Any?>("type" to "tcp", "tag" to DNS_REMOTE, "server" to "1.1.1.1", "detour" to UPSTREAM),
                linkedMapOf<String, Any?>("type" to "udp", "tag" to DNS_DIRECT, "server" to "1.1.1.1")
            )
            dns["rules"] = listOf(direct, bootstrap)
            dns["final"] = DNS_REMOTE
        }
        dns["strategy"] = "ipv4_only"

        val root = linkedMapOf<String, Any?>(
            "log" to linkedMapOf("level" to "warn", "timestamp" to true),
            "dns" to dns,
            "inbounds" to listOf(
                linkedMapOf<String, Any?>(
                    "type" to "tun", "tag" to "tun-in", "interface_name" to TUN_NAME,
                    "address" to listOf("198.18.0.1/30", "fdfe:dcba:9876::1/126"),
                    "mtu" to mtu, "auto_route" to true, "strict_route" to strictRoute, "stack" to "system",
                    "route_exclude_address" to listOf(
                        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "168.63.129.16/32", "224.0.0.0/4"
                    )
                )
            ),
            "outbounds" to listOf(
                linkedMapOf<String, Any?>("type" to "socks", "tag" to UPSTREAM, "server" to "127.0.0.1", "server_port" to socksPort, "version" to "5"),
                linkedMapOf<String, Any?>("type" to "direct", "tag" to "direct")
            ),
            "route" to linkedMapOf<String, Any?>(
                "auto_detect_interface" to true,
                "default_domain_resolver" to DNS_DIRECT,
                "rules" to listOf(
                    linkedMapOf<String, Any?>("process_name" to directProcesses, "action" to "route", "outbound" to "direct"),
                    linkedMapOf<String, Any?>("action" to "sniff"),
                    linkedMapOf<String, Any?>("protocol" to "dns", "action" to "hijack-dns")
                ),
                "final" to UPSTREAM
            )
        )
        return MiniJson.write(root) + "\n"
    }
}
