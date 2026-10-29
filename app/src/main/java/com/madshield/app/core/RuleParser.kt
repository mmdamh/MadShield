package com.madshield.app.core

import java.util.Locale

/**
 * Turns the lines of any popular list format into rules the engine understands. No Android types, so it
 * is covered by tests/pure.
 *
 * Understood input:
 *  - hosts files:          0.0.0.0 ads.example.com   (127.0.0.1, ::, ::1 too; several names per line)
 *  - AdGuard / ABP rules:  ||ads.example.com^        (plain domain rules, a few safe options; see [abpDomain])
 *  - plain domain lists:   ads.example.com, *.ads.example.com
 *  - engine syntax:        full:, exact:, keyword:, regexp:, regex:, ip:, cidr:, port:, bare CIDR, "private"
 *
 * Everything else (comments, headers, cosmetic filters "##", exceptions "@@", path or option rules) is
 * dropped, because it cannot be expressed as "refuse/bypass this domain".
 *
 * A bare domain in the engine also matches its subdomains, so hosts and AdGuard entries become bare
 * domains. [collapse] then removes entries that a parent domain in the same list already covers, which
 * shrinks big lists a lot (less memory and a faster engine start).
 */
object RuleParser {

    private val PREFIXES = listOf("full:", "exact:", "keyword:", "regexp:", "regex:", "ip:", "cidr:", "port:")
    private val LOWERCASE_PREFIXES = setOf("full:", "exact:", "keyword:")
    private val HOSTS_SINKS = setOf("0.0.0.0", "127.0.0.1", "127.0.0.2", "::", "::1", "::0", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1")
    private val SKIP_NAMES = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"
    )
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?$")
    private val IPV6 = Regex("^[0-9a-fA-F:.]+(/\\d{1,3})?$")
    private val COSMETIC_MARKERS = listOf("##", "#@#", "#?#", "#\$#", "#%#")

    /** True for blank lines, comments and list headers: lines that are not rules and not worth keeping. */
    fun isIgnorable(raw: String): Boolean {
        val s = raw.trim().trimStart('\uFEFF')
        return s.isEmpty() || s[0] == '#' || s[0] == '!' || s[0] == '['
    }

    /** Calls [sink] once for every rule found in [raw] (a hosts line can carry several). */
    fun parse(raw: String, sink: (String) -> Unit) {
        var s = raw.trim().trimStart('\uFEFF')
        if (s.isEmpty() || s.length > 2000) return
        val c0 = s[0]
        if (c0 == '#' || c0 == '!' || c0 == '[') return
        if (s.startsWith("@@")) return
        if (COSMETIC_MARKERS.any { s.contains(it) }) return

        val lower = s.lowercase(Locale.ROOT)

        // Engine syntax passes through untouched (the engine owns that grammar).
        for (p in PREFIXES) {
            if (lower.startsWith(p)) {
                val body = s.substring(p.length).trim()
                if (body.isEmpty()) return
                sink(if (p in LOWERCASE_PREFIXES) p + body.lowercase(Locale.ROOT) else p + body)
                return
            }
        }
        if (lower == "private") { sink("private"); return }

        // Inline comment ("0.0.0.0 host # note"). Done after the checks above so regexp: keeps its '#'.
        val hash = s.indexOf('#')
        if (hash > 0) s = s.substring(0, hash).trim()
        if (s.isEmpty()) return

        // AdGuard / Adblock Plus network rule.
        if (s.startsWith("||")) {
            abpDomain(s.substring(2))?.let(sink)
            return
        }
        if (s[0] == '|' || s[0] == '/' || s[0] == '*' && !s.startsWith("*.")) return

        // hosts line: "<sink ip> name [name ...]"
        val tokens = s.split(' ', '\t').filter { it.isNotEmpty() }
        if (tokens.size >= 2) {
            if (tokens[0] in HOSTS_SINKS) {
                for (i in 1 until tokens.size) domain(tokens[i])?.let(sink)
            }
            return
        }

        val token = tokens[0]
        if (IPV4.matches(token)) {
            if (token !in HOSTS_SINKS) sink(token)
            return
        }
        if (token.indexOf(':') >= 0) {
            // A bare IPv6 address / CIDR; anything else with a colon (URLs, ports) is not a rule.
            if (IPV6.matches(token) && token !in HOSTS_SINKS) sink(token.lowercase(Locale.ROOT))
            return
        }
        domain(token)?.let(sink)
    }

    /** The first rule [raw] yields, or null. */
    fun parseLine(raw: String): String? {
        var first: String? = null
        parse(raw) { if (first == null) first = it }
        return first
    }

    /**
     * Modifiers after "$" that still describe "this whole domain": "$important", "$third-party" (a tracker domain is
     * third-party everywhere), "$popup" and "$document" (page-level blocks of an ad domain), "$all". Everything
     * else is narrower than a domain ("$script", "$image", "$domain=...", "$redirect=...") and is skipped, because
     * turning it into a domain rule would block far more than the list intends.
     */
    private val ABP_DOMAIN_OPTIONS = setOf("important", "third-party", "3p", "all", "popup", "document", "doc")

    /**
     * "||example.com^" with optional "$important,third-party,popup,..." (see [ABP_DOMAIN_OPTIONS]) is a domain
     * block. A path, wildcard, port or any other option makes the rule more specific than a domain, so it is
     * not turned into a (much broader) domain rule.
     */
    private fun abpDomain(body: String): String? {
        var end = body.length
        for (i in body.indices) {
            val ch = body[i]
            if (ch == '^' || ch == '/' || ch == '$' || ch == '*' || ch == '|' || ch == ':' || ch == '?') { end = i; break }
        }
        var rest = body.substring(end)
        var options: String? = null
        val dollar = rest.indexOf('$')
        if (dollar >= 0) {
            options = rest.substring(dollar + 1)
            rest = rest.substring(0, dollar)
        }
        if (!(rest.isEmpty() || rest == "^" || rest == "^|")) return null
        if (options != null) {
            if (options.isEmpty()) return null
            for (o in options.split(',')) {
                if (o.trim().lowercase(Locale.ROOT) !in ABP_DOMAIN_OPTIONS) return null
            }
        }
        return domain(body.substring(0, end))
    }

    /** A valid, lowercase, punycode hostname with at least one dot; otherwise null. */
    fun domain(h0: String): String? {
        var h = h0.trim().lowercase(Locale.ROOT).trimEnd('.')
        if (h.startsWith("*.")) h = h.substring(2)
        if (h.isEmpty() || h.length > 253) return null
        if (h in SKIP_NAMES) return null
        if (h.any { it.code > 127 }) {
            h = try { java.net.IDN.toASCII(h) } catch (e: Exception) { return null }
        }
        for (ch in h) {
            if (!(ch in 'a'..'z' || ch in '0'..'9' || ch == '-' || ch == '.' || ch == '_')) return null
        }
        if (h.indexOf('.') < 0 || h[0] == '.' || h[0] == '-') return null
        if (h.all { it in '0'..'9' || it == '.' }) return null // a numeric address, not a name
        for (label in h.split('.')) {
            if (label.isEmpty() || label.length > 63) return null
        }
        return h
    }

    /** A bare domain rule (the only kind that a parent domain can make redundant). */
    fun isBareDomain(rule: String): Boolean =
        rule.indexOf('.') >= 0 && rule.indexOf(':') < 0 && rule.indexOf('/') < 0 && rule.any { it in 'a'..'z' }

    /**
     * Drops bare domains already covered by a parent in the same collection ("a.b.com" when "b.com" is
     * there). The engine matches a bare entry together with its subdomains, so the result blocks exactly
     * the same hosts. Keeps the original order.
     */
    fun collapse(rules: Collection<String>): List<String> {
        val bare = HashSet<String>()
        for (r in rules) if (isBareDomain(r)) bare.add(r)
        val out = ArrayList<String>(rules.size)
        for (r in rules) {
            if (isBareDomain(r) && hasParent(r, bare)) continue
            out.add(r)
        }
        return out
    }

    private fun hasParent(d: String, set: Set<String>): Boolean {
        var i = d.indexOf('.')
        while (i >= 0 && i < d.length - 1) {
            if (d.substring(i + 1) in set) return true
            i = d.indexOf('.', i + 1)
        }
        return false
    }

    /** Parses a block of text (the manual box) into unique rules; lines the parser cannot read are kept as typed. */
    fun normalizeManual(text: String): List<String> {
        val out = LinkedHashSet<String>()
        for (line in text.lineSequence()) {
            var any = false
            parse(line) { out.add(it); any = true }
            if (!any && !isIgnorable(line)) out.add(line.trim())
        }
        return out.toList()
    }
}
