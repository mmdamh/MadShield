package com.madshield.app.core

/**
 * One DoH resolver for the local DoH client, written as
 *
 *     https://host[:port][/path]@address=IP[@sni=NAME]
 *
 * (the same notation the core accepts for ECH lookups, see [DnsConfig.isValidEchResolver]).
 *
 * The IP is mandatory for a host NAME. The app never uses ordinary DNS to find its own resolver: that
 * lookup would leave the phone in the clear, which is exactly what DoH is meant to avoid. A resolver written
 * as a literal IP needs no `@address=`.
 *
 * Pure Kotlin, covered by tests/pure.
 */
data class DohSpec(
    val host: String,
    val port: Int,
    val path: String,
    /** Literal IPv4 or IPv6 address (no brackets) the TCP connection goes to. */
    val address: String,
    /** TLS server name when it must differ from [host]; null = use [host]. */
    val sni: String?
) {
    /** What the user sees and what is stored: parses back to the same spec. */
    val canonical: String
        get() {
            val h = if (host.contains(':')) "[$host]" else host
            val p = if (port == 443) "" else ":$port"
            val pathPart = if (path == DEFAULT_PATH) (if (hostIsLiteral) "" else DEFAULT_PATH) else path
            val addr = if (hostIsLiteral && address == host && sni == null) "" else "@address=${if (address.contains(':')) "[$address]" else address}"
            val s = if (sni != null) "@sni=$sni" else ""
            return "https://$h$p$pathPart$addr$s"
        }

    private val hostIsLiteral: Boolean get() = DnsMessage.parseIpLiteral(host) != null

    /** Raw bytes of [address]; never null for a spec that came out of [parse]. */
    fun addressBytes(): ByteArray = DnsMessage.parseIpLiteral(address) ?: ByteArray(4)

    /** The name the TLS certificate is checked against (and sent as SNI). */
    val tlsName: String get() = sni ?: host

    class Result(val spec: DohSpec?, val error: String?)
    class ListResult(val valid: List<DohSpec>, val errors: List<Pair<String, String>>)

    companion object {
        const val DEFAULT_PATH = "/dns-query"
        const val MAX_RESOLVERS = 3
        const val NEED_ADDRESS =
            "Pin the IP address (…@address=1.1.1.1): ordinary DNS is never used to find the resolver."

        private val hostChars = Regex("^[A-Za-z0-9.-]+$")
        private val pathChars = Regex("^/[A-Za-z0-9._~!$&'()*+;=:@%/-]*$")

        fun parse(raw: String): Result {
            val v = raw.trim()
            if (!v.startsWith("https://", ignoreCase = true)) return err("Only https:// links work for DoH.")
            val body = v.substring(8)
            if (body.isEmpty()) return err("The link has no host.")
            val firstAt = body.indexOf('@')
            val main = if (firstAt >= 0) body.substring(0, firstAt) else body
            val optionText = if (firstAt >= 0) body.substring(firstAt) else ""
            if (main.isEmpty()) return err("The link has no host.")
            if (main.any { it.isWhitespace() || it == '?' || it == '#' || it == '\\' }) return err("Remove spaces, ? and # from the link.")

            // authority = host[:port] ; path starts at the first '/'
            val slash = main.indexOf('/')
            val authority = if (slash >= 0) main.substring(0, slash) else main
            val path = if (slash >= 0) main.substring(slash) else DEFAULT_PATH
            if (!pathChars.matches(path)) return err("The path contains characters that are not allowed.")

            val host: String
            var port = 443
            if (authority.startsWith("[")) {
                val close = authority.indexOf(']')
                if (close < 0) return err("Unclosed [ in the host.")
                host = authority.substring(1, close).lowercase()
                if (!DnsConfig.isIpv6(host)) return err("Not a valid IPv6 address.")
                val rest = authority.substring(close + 1)
                if (rest.isNotEmpty()) {
                    if (!rest.startsWith(":")) return err("Unexpected text after the IPv6 address.")
                    port = parsePort(rest.substring(1)) ?: return err("Port must be 1-65535.")
                }
            } else {
                val colon = authority.indexOf(':')
                val h = if (colon >= 0) authority.substring(0, colon) else authority
                if (colon >= 0) port = parsePort(authority.substring(colon + 1)) ?: return err("Port must be 1-65535.")
                host = h.lowercase()
                if (!validHostName(host)) return err("The host name is not valid (ASCII letters, digits, dots and hyphens; use punycode for non-ASCII).")
            }

            var address: String? = null
            var sni: String? = null
            if (optionText.isNotEmpty()) {
                for (opt in optionText.split('@').drop(1)) {
                    val eq = opt.indexOf('=')
                    if (eq <= 0) return err("Unknown option “@$opt”. Use @address=IP and @sni=NAME.")
                    val key = opt.substring(0, eq).lowercase()
                    val value = opt.substring(eq + 1)
                    when (key) {
                        "address" -> {
                            if (address != null) return err("@address is given twice.")
                            val ip = value.removePrefix("[").removeSuffix("]").lowercase()
                            if (DnsMessage.parseIpLiteral(ip) == null) return err("@address must be a literal IP address.")
                            address = ip
                        }
                        "sni" -> {
                            if (sni != null) return err("@sni is given twice.")
                            val n = value.lowercase()
                            if (!validHostName(n)) return err("@sni is not a valid host name.")
                            sni = n
                        }
                        else -> return err("Unknown option “@$key”. Use @address=IP and @sni=NAME.")
                    }
                }
            }

            val hostLiteral = DnsMessage.parseIpLiteral(host) != null
            if (address == null) {
                if (!hostLiteral) return err(NEED_ADDRESS)
                address = host
            }
            return Result(DohSpec(host, port, path, address, sni), null)
        }

        /**
         * Parses the text box: one resolver per line/space/comma. At most [MAX_RESOLVERS] are accepted; the
         * order is the order they are tried in (fallback is between DoH resolvers only, never plain DNS).
         */
        fun parseList(text: String): ListResult {
            val valid = ArrayList<DohSpec>()
            val errors = ArrayList<Pair<String, String>>()
            val seen = HashSet<String>()
            text.split('\n', '\r', ',', ';', ' ', '\t').map { it.trim() }.filter { it.isNotEmpty() }.forEach { token ->
                val r = parse(token)
                when {
                    r.spec == null -> errors += token to (r.error ?: "invalid")
                    valid.size >= MAX_RESOLVERS -> errors += token to "At most $MAX_RESOLVERS resolvers."
                    seen.add(r.spec.canonical) -> valid += r.spec
                }
            }
            return ListResult(valid, errors)
        }

        private fun err(msg: String) = Result(null, msg)

        private fun parsePort(s: String): Int? {
            if (s.isEmpty() || s.length > 5 || s.any { it !in '0'..'9' }) return null
            return s.toInt().takeIf { it in 1..65535 }
        }

        private fun validHostName(h: String): Boolean {
            if (h.isEmpty() || h.length > 253 || !hostChars.matches(h)) return false
            val labels = h.split('.')
            return labels.all { it.isNotEmpty() && it.length <= 63 && !it.startsWith('-') && !it.endsWith('-') }
        }
    }
}

/** One-tap DoH resolvers, all pinned to an IP so the app never needs plain DNS to reach them. */
object DohPresets {
    val ALL: List<Pair<String, String>> = listOf(
        "Cloudflare" to "https://cloudflare-dns.com/dns-query@address=1.1.1.1",
        "Google" to "https://dns.google/dns-query@address=8.8.8.8",
        "Quad9" to "https://dns.quad9.net/dns-query@address=9.9.9.9",
    )
}
