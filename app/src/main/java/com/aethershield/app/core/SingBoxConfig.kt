package com.aethershield.app.core

/**
 * The sing-box configuration for the "custom link" chain. Written against sing-box v1.14.3
 * (native/singbox.pin): option names checked in that source's option/ directory (the .go files), and the golden files in
 * tests/pure/golden/ are validated by the real `sing-box check` in CI.
 *
 * Shape (the same idea as Psiphon on top of WARP):
 *
 *   apps -> [front] -> 127.0.0.1:<listenPort> (sing-box SOCKS inbound)
 *        -> "proxy" outbound (your VLESS / VMess / Trojan / Shadowsocks server)
 *             dialled THROUGH the "warp" outbound = the Aether core's own SOCKS on 127.0.0.1:<corePort>
 *        -> WARP tunnel -> your server -> internet
 *
 * Details that matter:
 *  - `detour` makes sing-box hand the server address to the core still unresolved, so the server's NAME is
 *    looked up at the WARP exit (not by this phone's own resolver) and the first hop of your link is carried by
 *    the tunnel too.
 *  - `certificate.store = mozilla` uses the root list built into sing-box. A plain Linux Go binary does not know
 *    where Android keeps its roots, and without this every TLS server would fail verification.
 *  - No DNS, no TUN, no rules: sing-box here is only a protocol converter. Routing rules and DoH stay in the app.
 *  - The configuration is given to sing-box on STDIN (`run -c stdin`): the link's credential is never written to disk.
 */
object SingBoxConfig {
    const val PROXY_TAG = "proxy"
    const val WARP_TAG = "warp"
    const val LISTEN_HOST = "127.0.0.1"

    fun build(link: LinkParse.Ok, corePort: Int, listenPort: Int, logLevel: String = "warn"): String {
        require(corePort in 1..65535 && listenPort in 1..65535) { "bad port" }
        val proxy = linkedMapOf<String, Any?>("type" to link.outbound["type"], "tag" to PROXY_TAG)
        for ((k, v) in link.outbound) if (k != "type") proxy[k] = v
        proxy["detour"] = WARP_TAG

        val root = linkedMapOf<String, Any?>(
            "log" to linkedMapOf("level" to logLevel, "timestamp" to false),
            "certificate" to linkedMapOf("store" to "mozilla"),
            "inbounds" to listOf(
                linkedMapOf<String, Any?>(
                    "type" to "socks", "tag" to "in", "listen" to LISTEN_HOST, "listen_port" to listenPort
                )
            ),
            "outbounds" to listOf(
                proxy,
                linkedMapOf<String, Any?>(
                    "type" to "socks", "tag" to WARP_TAG, "server" to LISTEN_HOST, "server_port" to corePort, "version" to "5"
                )
            ),
            "route" to linkedMapOf("final" to PROXY_TAG)
        )
        return MiniJson.write(root) + "\n"
    }
}

/** Why a custom link cannot be used, in words for the UI (the tests check every [LinkError] has one). */
object LinkMessages {
    fun english(e: LinkParse.Err): String {
        val d = if (e.detail.isNotEmpty()) " (${e.detail})" else ""
        return when (e.error) {
            LinkError.EMPTY -> "Paste a link first."
            LinkError.SCHEME -> "This kind of link is not supported$d. Supported: vless://, vmess://, trojan://, ss://."
            LinkError.MALFORMED -> "The link is damaged$d."
            LinkError.PORT -> "The link has no valid port."
            LinkError.CREDENTIAL -> "The link has no valid user id or password$d."
            LinkError.XHTTP -> "XHTTP is not supported by the official sing-box. Use a link with ws, grpc, httpupgrade or tcp."
            LinkError.TRANSPORT -> "This transport is not supported$d."
            LinkError.SECURITY -> "This security setting is not supported$d."
            LinkError.METHOD -> "This cipher is not supported$d."
            LinkError.PLUGIN -> "Shadowsocks plugins are not supported$d."
            LinkError.ENCRYPTION -> "VLESS encryption other than none is not supported$d."
        }
    }
}
