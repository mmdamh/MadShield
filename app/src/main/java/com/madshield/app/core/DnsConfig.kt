package com.madshield.app.core

/**
 * Everything about DNS settings that can be decided without Android:
 * parsing/normalising what the user typed, ready-made resolver presets and
 * validation of the ECH resolver string. Kept free of Android types on purpose
 * so it can be unit-tested on the JVM.
 *
 * What the pinned core (Aether v2.3.0) really supports -- checked in
 * aether/src/socks.rs::resolver_addresses() and dns.rs::EchDns::parse():
 *  - AETHER_DNS     : plain IP or ip:port only. Anything else is silently
 *                     dropped by the core, so we reject it here instead and
 *                     tell the user, rather than letting it vanish.
 *  - AETHER_ECH_DNS : udp://ip[:port], tcp://ip[:port], or an https:// DoH URL
 *                     (optionally with @address=IP and @sni=NAME). This is the
 *                     only place v2.3.0 speaks DoH, and only for ECH key lookups.
 */
data class DnsEntry(val ip: String, val port: Int?, val isIpv6: Boolean) {
    /** Exactly what AETHER_DNS wants: bare IP, "ip:port", or "[v6]:port". */
    val canonical: String
        get() = when {
            port == null -> ip
            isIpv6 -> "[$ip]:$port"
            else -> "$ip:$port"
        }
}

data class DnsParseResult(val valid: List<DnsEntry>, val rejected: List<String>)

object DnsConfig {

    /** Parses one resolver. Returns null if it is not a literal IP / IP:port. */
    fun parse(raw: String): DnsEntry? {
        val s = raw.trim()
        if (s.isEmpty()) return null

        // [v6]:port  or  [v6]
        if (s.startsWith("[")) {
            val close = s.indexOf(']')
            if (close < 0) return null
            val ip = s.substring(1, close)
            if (!isIpv6(ip)) return null
            val rest = s.substring(close + 1)
            if (rest.isEmpty()) return DnsEntry(ip.lowercase(), null, true)
            if (!rest.startsWith(":")) return null
            val port = parsePort(rest.substring(1)) ?: return null
            return DnsEntry(ip.lowercase(), port, true)
        }

        val colons = s.count { it == ':' }
        return when {
            colons == 0 -> if (isIpv4(s)) DnsEntry(s, null, false) else null
            colons == 1 -> {
                val ip = s.substringBefore(':')
                val port = parsePort(s.substringAfter(':')) ?: return null
                if (isIpv4(ip)) DnsEntry(ip, port, false) else null
            }
            else -> if (isIpv6(s)) DnsEntry(s.lowercase(), null, true) else null // bare v6 has no port
        }
    }

    /** Splits on newlines/commas/semicolons/spaces, drops blanks and duplicates. */
    fun parseList(text: String): DnsParseResult {
        val valid = LinkedHashMap<String, DnsEntry>()
        val rejected = ArrayList<String>()
        text.split('\n', '\r', ',', ';', ' ', '\t')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { token ->
                val e = parse(token)
                if (e == null) rejected += token else valid.putIfAbsent(e.canonical, e)
            }
        return DnsParseResult(valid.values.toList(), rejected)
    }

    /** The bare address VpnService.Builder.addDnsServer() needs (it takes no port). */
    fun vpnAddress(canonicalEntry: String): String? = parse(canonicalEntry)?.ip

    fun isIpv4(s: String): Boolean {
        val parts = s.split('.')
        if (parts.size != 4) return false
        return parts.all { p ->
            p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } &&
                p.toInt() in 0..255 && (p.length == 1 || p[0] != '0')
        }
    }

    fun isIpv6(s: String): Boolean {
        if (s.isEmpty() || s.contains('%') || s.contains('.')) return false // no zone ids / v4-mapped tails
        if (s.any { it != ':' && !it.isHexDigit() }) return false
        val doubleColon = s.indexOf("::")
        if (doubleColon != s.lastIndexOf("::")) return false // at most one "::"
        if (s.contains(":::")) return false
        fun groupsOk(part: String): Int? {
            if (part.isEmpty()) return 0
            val groups = part.split(':')
            if (groups.any { it.isEmpty() || it.length > 4 }) return null
            return groups.size
        }
        return if (doubleColon >= 0) {
            val head = groupsOk(s.substring(0, doubleColon)) ?: return false
            val tail = groupsOk(s.substring(doubleColon + 2)) ?: return false
            head + tail <= 7
        } else {
            groupsOk(s) == 8
        }
    }

    private fun Char.isHexDigit() = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private fun parsePort(s: String): Int? {
        if (s.isEmpty() || s.length > 5 || s.any { it !in '0'..'9' }) return null
        return s.toInt().takeIf { it in 1..65535 }
    }

    // ---- ECH resolver ---------------------------------------------------------

    private val echHost = Regex("""^[A-Za-z0-9.\-]+$""")
    private val echOption = Regex("""^@(address|sni)=[A-Za-z0-9.\-:\[\]]+$""", RegexOption.IGNORE_CASE)

    /**
     * Mirrors dns.rs::EchDns::parse closely enough to catch typos before the
     * core sees them. The core stays the final judge.
     */
    fun isValidEchResolver(raw: String): Boolean {
        val v = raw.trim()
        val lower = v.lowercase()
        return when {
            lower.startsWith("udp://") -> hostPortOk(v.substring(6).trimEnd('/'))
            lower.startsWith("tcp://") -> hostPortOk(v.substring(6).trimEnd('/'))
            lower.startsWith("https://") -> {
                // https://host[:port][/path][@address=..][@sni=..]
                val body = v.substring(8)
                val firstAt = body.indexOf('@')
                val main = if (firstAt >= 0) body.substring(0, firstAt) else body
                val options = if (firstAt >= 0) body.substring(firstAt) else ""
                val authority = main.substringBefore('/')
                val path = if (main.contains('/')) main.substring(main.indexOf('/')) else ""
                if (path.any { it.isWhitespace() }) return false
                val hostOk = authority.substringBefore(':').let { it.isNotEmpty() && echHost.matches(it) } &&
                    (!authority.contains(':') || parsePort(authority.substringAfter(':')) != null)
                val optionsOk = options.isEmpty() ||
                    options.split('@').drop(1).all { echOption.matches("@$it") }
                hostOk && optionsOk
            }
            else -> false
        }
    }

    /** udp://1.1.1.1  udp://[2606::1]:53  -- the host must be a literal IP. */
    private fun hostPortOk(hostPort: String): Boolean {
        if (hostPort.isEmpty()) return false
        if (hostPort.startsWith("[")) return parse(hostPort) != null
        if (hostPort.count { it == ':' } > 1) return isIpv6(hostPort)
        return parse(hostPort) != null
    }
}

/** One-tap resolver sets. All plain IPs, so they work with the stock core. */
object DnsPresets {
    data class Preset(val id: String, val name: String, val servers: List<String>)

    val ALL: List<Preset> = listOf(
        Preset("cloudflare", "Cloudflare", listOf("1.1.1.1", "1.0.0.1")),
        Preset("google", "Google", listOf("8.8.8.8", "8.8.4.4")),
        Preset("quad9", "Quad9", listOf("9.9.9.9", "149.112.112.112")),
        Preset("adguard", "AdGuard", listOf("94.140.14.14", "94.140.15.15")),
        Preset("opendns", "OpenDNS", listOf("208.67.222.222", "208.67.220.220")),
        Preset("mullvad", "Mullvad", listOf("194.242.2.2")),
    )

    /** Suggestions for the ECH resolver field. Pinned to an IP so lookup needs no DNS of its own. */
    val ECH_RESOLVERS: List<Pair<String, String>> = listOf(
        "Cloudflare" to "https://cloudflare-dns.com/dns-query@address=1.1.1.1",
        "Google" to "https://dns.google/dns-query@address=8.8.8.8",
        "Quad9" to "https://dns.quad9.net/dns-query@address=9.9.9.9",
        "Cloudflare (UDP)" to "udp://1.1.1.1",
    )

    fun matching(servers: List<String>): Preset? =
        ALL.firstOrNull { it.servers == servers }
}
