package com.aethershield.app.core

/**
 * Turns a share link (`vless://`, `vmess://`, `trojan://`, `ss://`) into the matching sing-box OUTBOUND object.
 * Pure Kotlin, no Android types, so every rule below is covered by tests that run without a phone.
 *
 * What it will NOT do, on purpose, is guess: anything sing-box cannot carry (XHTTP, mKCP, plugin-based
 * Shadowsocks, VLESS encryption other than "none", ...) is refused with a reason ([LinkError]) instead of being
 * silently dropped, because a dropped option means a connection that quietly works differently from what the
 * link says. The link is secret material (it holds the UUID / password): this class never logs it, and
 * [LinkParse.Ok.summary] contains no credential.
 */
enum class LinkError {
    EMPTY, SCHEME, MALFORMED, PORT, CREDENTIAL, XHTTP, TRANSPORT, SECURITY, METHOD, PLUGIN, ENCRYPTION
}

sealed interface LinkParse {
    /**
     * @property outbound the sing-box outbound (type, server, server_port, credentials, tls, transport), WITHOUT
     *   tag or detour: [SingBoxConfig] adds those.
     * @property summary one line for the UI, never containing the credential, e.g. "VLESS · WebSocket + TLS · 203.0.113.7:443".
     */
    data class Ok(
        val outbound: Map<String, Any?>,
        val protocol: String,
        val server: String,
        val port: Int,
        val name: String,
        val summary: String
    ) : LinkParse

    data class Err(val error: LinkError, val detail: String = "") : LinkParse
}

object ProxyLink {

    fun parse(raw: String): LinkParse {
        val text = raw.trim()
        if (text.isEmpty()) return LinkParse.Err(LinkError.EMPTY)
        val sep = text.indexOf("://")
        if (sep <= 0) return LinkParse.Err(LinkError.SCHEME)
        return try {
            when (val scheme = text.substring(0, sep).lowercase()) {
                "vless" -> vless(Url.parse(text, sep))
                "trojan" -> trojan(Url.parse(text, sep))
                "vmess" -> vmess(text, sep)
                "ss" -> shadowsocks(text, sep)
                else -> LinkParse.Err(LinkError.SCHEME, scheme)
            }
        } catch (e: LinkFailure) {
            LinkParse.Err(e.error, e.detail)
        }
    }

    // ---------------------------------------------------------------------------------------------- protocols

    private fun vless(u: Url): LinkParse {
        val uuid = Text.decode(u.userinfo ?: throw LinkFailure(LinkError.CREDENTIAL, "missing id"))
        if (!Text.isUuid(uuid)) throw LinkFailure(LinkError.CREDENTIAL, "the id is not a UUID")
        val enc = u.q("encryption")
        if (enc.isNotEmpty() && !enc.equals("none", ignoreCase = true)) throw LinkFailure(LinkError.ENCRYPTION, enc)
        val port = u.requirePort()
        val security = u.q("security").lowercase()
        val net = u.q("type").lowercase().ifEmpty { "tcp" }
        val out = linkedMapOf<String, Any?>("type" to "vless", "server" to u.host, "server_port" to port, "uuid" to uuid)
        u.q("flow").takeIf { it.isNotEmpty() }?.let { out["flow"] = it }
        applySecurityAndTransport(
            out, u.host, security, net,
            sni = u.q("sni"), hostParam = u.q("host"), path = u.q("path"), serviceName = u.q("serviceName"),
            alpn = u.q("alpn"), fp = u.q("fp"), insecure = u.flag("allowInsecure") || u.flag("insecure"),
            pbk = u.q("pbk"), sid = u.q("sid"), headerType = u.q("headerType"), tlsDefault = false
        )
        return ok(out, "vless", u.host, port, u.fragment, net, security)
    }

    private fun trojan(u: Url): LinkParse {
        val password = Text.decode(u.userinfo ?: throw LinkFailure(LinkError.CREDENTIAL, "missing password"))
        if (password.isEmpty()) throw LinkFailure(LinkError.CREDENTIAL, "missing password")
        val port = u.requirePort()
        val security = u.q("security").lowercase().ifEmpty { "tls" } // trojan is TLS unless the link says otherwise
        val net = u.q("type").lowercase().ifEmpty { "tcp" }
        val out = linkedMapOf<String, Any?>("type" to "trojan", "server" to u.host, "server_port" to port, "password" to password)
        applySecurityAndTransport(
            out, u.host, security, net,
            sni = u.q("sni").ifEmpty { u.q("peer") }, hostParam = u.q("host"), path = u.q("path"), serviceName = u.q("serviceName"),
            alpn = u.q("alpn"), fp = u.q("fp"), insecure = u.flag("allowInsecure") || u.flag("insecure"),
            pbk = u.q("pbk"), sid = u.q("sid"), headerType = u.q("headerType"), tlsDefault = true
        )
        return ok(out, "trojan", u.host, port, u.fragment, net, security)
    }

    private fun vmess(text: String, sep: Int): LinkParse {
        val body = text.substring(sep + 3)
        if (body.contains('@')) {
            // the URI form (vmess://uuid@host:port?type=ws&security=tls...), same query names as VLESS
            val u = Url.parse(text, sep)
            val uuid = Text.decode(u.userinfo ?: throw LinkFailure(LinkError.CREDENTIAL, "missing id"))
            if (!Text.isUuid(uuid)) throw LinkFailure(LinkError.CREDENTIAL, "the id is not a UUID")
            val port = u.requirePort()
            val security = u.q("security").lowercase()
            val net = u.q("type").lowercase().ifEmpty { "tcp" }
            val out = linkedMapOf<String, Any?>(
                "type" to "vmess", "server" to u.host, "server_port" to port, "uuid" to uuid,
                "security" to vmessSecurity(u.q("encryption"))
            )
            applySecurityAndTransport(
                out, u.host, security, net,
                sni = u.q("sni"), hostParam = u.q("host"), path = u.q("path"), serviceName = u.q("serviceName"),
                alpn = u.q("alpn"), fp = u.q("fp"), insecure = u.flag("allowInsecure") || u.flag("insecure"),
                pbk = u.q("pbk"), sid = u.q("sid"), headerType = u.q("headerType"), tlsDefault = false
            )
            return ok(out, "vmess", u.host, port, u.fragment, net, security)
        }
        // v2rayN form: vmess://BASE64(JSON)
        val cut = body.indexOfAny(charArrayOf('#', '?')).let { if (it < 0) body.length else it }
        val json = Base64Lite.decode(Text.decode(body.substring(0, cut)))
            ?.let { String(it, Charsets.UTF_8) }
            ?.let { MiniJson.parseObject(it) }
            ?: throw LinkFailure(LinkError.MALFORMED, "vmess body is not base64 JSON")
        fun str(k: String): String = when (val v = json[k]) { null -> ""; is String -> v.trim(); is Double -> v.toLong().toString(); else -> v.toString() }
        val server = str("add")
        if (server.isEmpty()) throw LinkFailure(LinkError.MALFORMED, "missing server")
        val port = str("port").toIntOrNull()?.takeIf { it in 1..65535 } ?: throw LinkFailure(LinkError.PORT)
        val uuid = str("id")
        if (!Text.isUuid(uuid)) throw LinkFailure(LinkError.CREDENTIAL, "the id is not a UUID")
        val net = str("net").lowercase().ifEmpty { "tcp" }
        val security = if (str("tls").equals("tls", ignoreCase = true)) "tls" else "none"
        val out = linkedMapOf<String, Any?>(
            "type" to "vmess", "server" to server, "server_port" to port, "uuid" to uuid,
            "security" to vmessSecurity(str("scy"))
        )
        str("aid").toIntOrNull()?.takeIf { it > 0 }?.let { out["alter_id"] = it }
        applySecurityAndTransport(
            out, server, security, net,
            sni = str("sni"), hostParam = str("host"), path = str("path"), serviceName = str("path"),
            alpn = str("alpn"), fp = str("fp"),
            insecure = str("allowInsecure").let { it == "1" || it.equals("true", true) } ||
                str("insecure").let { it == "1" || it.equals("true", true) },
            pbk = "", sid = "", headerType = str("type"), tlsDefault = false
        )
        val name = str("ps").ifEmpty { Text.decode(body.substringAfter('#', "")) }
        return ok(out, "vmess", server, port, name, net, security)
    }

    private fun vmessSecurity(v: String): String {
        val s = v.lowercase()
        return when (s) {
            "", "auto" -> "auto"
            "none", "zero", "aes-128-gcm", "chacha20-poly1305" -> s
            "chacha20-ietf-poly1305" -> "chacha20-poly1305"
            else -> throw LinkFailure(LinkError.METHOD, v)
        }
    }

    private val SS_METHODS = setOf(
        "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "rc4-md5", "chacha20-ietf", "xchacha20"
    )
    private val SS_ALIASES = mapOf("chacha20-poly1305" to "chacha20-ietf-poly1305", "xchacha20-poly1305" to "xchacha20-ietf-poly1305")

    private fun shadowsocks(text: String, sep: Int): LinkParse {
        val body = text.substring(sep + 3)
        val fragCut = body.indexOf('#')
        val name = if (fragCut >= 0) Text.decode(body.substring(fragCut + 1)) else ""
        val noFrag = if (fragCut >= 0) body.substring(0, fragCut) else body
        val queryCut = noFrag.indexOf('?')
        val query = if (queryCut >= 0) Url.parseQuery(noFrag.substring(queryCut + 1)) else emptyMap()
        val main = if (queryCut >= 0) noFrag.substring(0, queryCut) else noFrag

        if (query["plugin"]?.isNotEmpty() == true) throw LinkFailure(LinkError.PLUGIN, query["plugin"]!!.substringBefore(';'))

        val methodPassword: String
        val hostPort: String
        val at = main.lastIndexOf('@')
        if (at >= 0) {
            val userinfo = main.substring(0, at)
            hostPort = main.substring(at + 1).trimEnd('/')
            methodPassword = if (':' in Text.decode(userinfo)) Text.decode(userinfo) // plain "method:password"
            else String(Base64Lite.decode(Text.decode(userinfo)) ?: throw LinkFailure(LinkError.MALFORMED, "userinfo is not base64"), Charsets.UTF_8)
        } else {
            // legacy: ss://BASE64(method:password@host:port)
            val all = String(Base64Lite.decode(Text.decode(main.trimEnd('/'))) ?: throw LinkFailure(LinkError.MALFORMED, "not base64"), Charsets.UTF_8)
            val i = all.lastIndexOf('@')
            if (i < 0) throw LinkFailure(LinkError.MALFORMED, "no host")
            methodPassword = all.substring(0, i)
            hostPort = all.substring(i + 1)
        }
        val colon = methodPassword.indexOf(':')
        if (colon <= 0) throw LinkFailure(LinkError.CREDENTIAL, "expected method:password")
        val methodRaw = methodPassword.substring(0, colon).lowercase()
        val method = SS_ALIASES[methodRaw] ?: methodRaw
        if (method !in SS_METHODS) throw LinkFailure(LinkError.METHOD, methodRaw)
        val password = methodPassword.substring(colon + 1)
        if (password.isEmpty() && method != "none") throw LinkFailure(LinkError.CREDENTIAL, "missing password")
        val (host, portOrNull) = Url.splitHostPort(hostPort)
        if (host.isEmpty()) throw LinkFailure(LinkError.MALFORMED, "missing server")
        val port = portOrNull?.takeIf { it in 1..65535 } ?: throw LinkFailure(LinkError.PORT)
        val out = linkedMapOf<String, Any?>(
            "type" to "shadowsocks", "server" to host, "server_port" to port, "method" to method, "password" to password
        )
        return LinkParse.Ok(out, "shadowsocks", host, port, name, "Shadowsocks · $method · ${Text.hostPort(host, port)}")
    }

    // ------------------------------------------------------------------------------------- tls and transport

    private val FINGERPRINTS = setOf("chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized")

    @Suppress("LongParameterList")
    private fun applySecurityAndTransport(
        out: MutableMap<String, Any?>, server: String, security: String, net: String,
        sni: String, hostParam: String, path: String, serviceName: String, alpn: String, fp: String,
        insecure: Boolean, pbk: String, sid: String, headerType: String, tlsDefault: Boolean
    ) {
        val sec = if (security.isEmpty()) (if (tlsDefault) "tls" else "none") else security
        if (sec != "none" && sec != "tls" && sec != "reality") throw LinkFailure(LinkError.SECURITY, sec)

        // transport first: it decides which name is the best default for the TLS server name
        val transport = transport(net, hostParam, path, serviceName, headerType)

        if (sec != "none") {
            val serverName = sni.ifEmpty { hostParam.substringBefore(',').trim() }.ifEmpty { if (Text.isIp(server)) "" else server }
            val tls = linkedMapOf<String, Any?>("enabled" to true)
            if (serverName.isNotEmpty()) tls["server_name"] = serverName
            if (insecure) tls["insecure"] = true
            val alpnList = alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            if (alpnList.isNotEmpty()) tls["alpn"] = alpnList
            val fingerprint = normalizeFingerprint(fp) ?: if (sec == "reality") "chrome" else null // Reality needs uTLS
            if (fingerprint != null) tls["utls"] = linkedMapOf("enabled" to true, "fingerprint" to fingerprint)
            if (sec == "reality") {
                if (pbk.isEmpty()) throw LinkFailure(LinkError.SECURITY, "reality without a public key (pbk)")
                // sing-box decodes it as unpadded URL-safe base64 of 32 bytes and refuses to start otherwise.
                if (Base64Lite.decode(pbk)?.size != 32) throw LinkFailure(LinkError.SECURITY, "the reality public key (pbk) is not valid")
                tls["reality"] = linkedMapOf<String, Any?>("enabled" to true, "public_key" to pbk, "short_id" to sid)
            }
            out["tls"] = tls
        }
        if (transport != null) out["transport"] = transport
    }

    private fun normalizeFingerprint(fp: String): String? {
        val f = fp.trim().lowercase()
        return when {
            f.isEmpty() || f == "none" -> null
            f == "randomizedalpn" || f == "randomizednoalpn" -> "randomized"
            f in FINGERPRINTS -> f
            else -> null
        }
    }

    private fun transport(net: String, hostParam: String, rawPath: String, serviceName: String, headerType: String): Map<String, Any?>? {
        when (net) {
            "xhttp", "splithttp" -> throw LinkFailure(LinkError.XHTTP)
            "tcp", "raw", "" -> {
                if (headerType.equals("http", ignoreCase = true)) throw LinkFailure(LinkError.TRANSPORT, "tcp with an http header")
                return null
            }
            "ws", "websocket" -> {
                var path = rawPath
                val t = linkedMapOf<String, Any?>("type" to "ws")
                val early = Regex("""[?&]ed=(\d{1,6})""").find(path) // v2rayN early data: "/path?ed=2048"
                if (early != null) path = path.removeRange(early.range).let { if (it.endsWith("?")) it.dropLast(1) else it }
                if (path.isNotEmpty()) t["path"] = path
                val host = hostParam.substringBefore(',').trim()
                if (host.isNotEmpty()) t["headers"] = linkedMapOf("Host" to listOf(host))
                if (early != null) {
                    t["max_early_data"] = early.groupValues[1].toInt()
                    t["early_data_header_name"] = "Sec-WebSocket-Protocol"
                }
                return t
            }
            "grpc", "gun" -> {
                val t = linkedMapOf<String, Any?>("type" to "grpc")
                if (serviceName.isNotEmpty()) t["service_name"] = serviceName
                return t
            }
            "http", "h2" -> {
                val t = linkedMapOf<String, Any?>("type" to "http")
                val hosts = hostParam.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                if (hosts.isNotEmpty()) t["host"] = hosts
                if (rawPath.isNotEmpty()) t["path"] = rawPath
                return t
            }
            "httpupgrade" -> {
                val t = linkedMapOf<String, Any?>("type" to "httpupgrade")
                val host = hostParam.substringBefore(',').trim()
                if (host.isNotEmpty()) t["host"] = host
                if (rawPath.isNotEmpty()) t["path"] = rawPath
                return t
            }
            else -> throw LinkFailure(LinkError.TRANSPORT, net)
        }
    }

    // ----------------------------------------------------------------------------------------------- helpers

    private fun ok(out: Map<String, Any?>, protocol: String, host: String, port: Int, name: String, net: String, security: String): LinkParse.Ok {
        val tls = out["tls"] != null
        val netName = when (net) {
            "ws", "websocket" -> "WebSocket"; "grpc", "gun" -> "gRPC"; "http", "h2" -> "HTTP/2"
            "httpupgrade" -> "HTTPUpgrade"; else -> "TCP"
        }
        val sec = when { !tls -> ""; security == "reality" -> " + Reality"; else -> " + TLS" }
        return LinkParse.Ok(out, protocol, host, port, name, "${protocol.uppercase()} · $netName$sec · ${Text.hostPort(host, port)}")
    }

    private class LinkFailure(val error: LinkError, val detail: String = "") : Exception(error.name)

    /** A share link split into its parts. Not java.net.URI: that rejects many links people really use. */
    private class Url(
        val scheme: String, val userinfo: String?, val host: String, val port: Int?,
        val query: Map<String, String>, val fragment: String
    ) {
        fun q(key: String): String = query[key]?.trim() ?: ""
        fun flag(key: String): Boolean = q(key).let { it == "1" || it.equals("true", ignoreCase = true) }
        fun requirePort(): Int = port?.takeIf { it in 1..65535 } ?: throw LinkFailure(LinkError.PORT)

        companion object {
            fun parse(text: String, sep: Int): Url {
                val scheme = text.substring(0, sep).lowercase()
                var rest = text.substring(sep + 3)
                var fragment = ""
                rest.indexOf('#').let { if (it >= 0) { fragment = Text.decode(rest.substring(it + 1)); rest = rest.substring(0, it) } }
                var query = emptyMap<String, String>()
                rest.indexOf('?').let { if (it >= 0) { query = parseQuery(rest.substring(it + 1)); rest = rest.substring(0, it) } }
                rest.indexOf('/').let { if (it >= 0) rest = rest.substring(0, it) } // a path before the query is ignored
                val at = rest.lastIndexOf('@')
                val userinfo = if (at >= 0) rest.substring(0, at) else null
                val (host, port) = splitHostPort(if (at >= 0) rest.substring(at + 1) else rest)
                if (host.isEmpty()) throw LinkFailure(LinkError.MALFORMED, "missing server")
                return Url(scheme, userinfo, host, port, query, fragment)
            }

            fun parseQuery(q: String): Map<String, String> {
                val m = linkedMapOf<String, String>()
                for (pair in q.split('&')) {
                    if (pair.isEmpty()) continue
                    val eq = pair.indexOf('=')
                    val k = Text.decode(if (eq >= 0) pair.substring(0, eq) else pair)
                    val v = if (eq >= 0) Text.decode(pair.substring(eq + 1)) else ""
                    if (k !in m) m[k] = v // first one wins
                }
                return m
            }

            /** "host:443", "[2001:db8::1]:443", "host". The port is null when absent or not a number. */
            fun splitHostPort(s: String): Pair<String, Int?> {
                val t = s.trim()
                if (t.startsWith("[")) {
                    val end = t.indexOf(']')
                    if (end < 0) throw LinkFailure(LinkError.MALFORMED, "bad IPv6 address")
                    val host = t.substring(1, end)
                    val port = t.substring(end + 1).removePrefix(":").takeIf { it.isNotEmpty() }?.toIntOrNull()
                    return host to port
                }
                val colon = t.lastIndexOf(':')
                if (colon < 0) return t to null
                return t.substring(0, colon) to t.substring(colon + 1).toIntOrNull()
            }
        }
    }

    internal object Text {
        private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        private val V4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

        fun isUuid(s: String) = UUID.matches(s)
        fun isIp(s: String) = V4.matches(s) || s.contains(':')
        fun hostPort(host: String, port: Int) = if (host.contains(':')) "[$host]:$port" else "$host:$port"

        /** Percent-decoding as UTF-8. A broken sequence is kept as written instead of failing the link. */
        fun decode(s: String): String {
            if (!s.contains('%')) return s
            val out = java.io.ByteArrayOutputStream(s.length)
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '%' && i + 2 < s.length) {
                    val h = s.substring(i + 1, i + 3).toIntOrNull(16)
                    if (h != null) { out.write(h); i += 3; continue }
                }
                val cp = s.codePointAt(i)
                out.write(String(Character.toChars(cp)).toByteArray(Charsets.UTF_8))
                i += Character.charCount(cp)
            }
            return String(out.toByteArray(), Charsets.UTF_8)
        }
    }
}

/** Base64 that accepts the standard and the URL-safe alphabet, with or without padding. null when the text is not base64. */
object Base64Lite {
    fun decode(input: String): ByteArray? {
        val clean = input.filter { !it.isWhitespace() }.trimEnd('=')
        if (clean.isEmpty()) return ByteArray(0)
        if (clean.length % 4 == 1) return null
        val out = java.io.ByteArrayOutputStream(clean.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (c in clean) {
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '+', '-' -> 62
                '/', '_' -> 63
                else -> return null
            }
            buffer = (buffer shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buffer shr bits) and 0xff)
                buffer = buffer and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }
}
