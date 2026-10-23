package com.aethershield.app.core

import java.io.File
import java.net.InetAddress
import java.util.Locale

enum class RouteAction { PROXY, DIRECT, BLOCK }

/**
 * In-app routing decision engine (no Android types, covered by tests/pure).
 *
 * WHY IT EXISTS: with a Psiphon/Tor chain the chain owns the public SOCKS port, so app traffic never passes
 * through the core's own routing (routing.rs) and the rules silently did nothing. [RouteFront] sits on the
 * public port, asks this class what to do with each connection, and only then forwards to the chain.
 *
 * It reads the SAME routes file the core reads and follows the grammar of routing.rs (Aether v2.3.0):
 * "[block]"/"[direct]" sections, bare domain = domain + subdomains, full:/exact:, keyword:, regexp:/regex:,
 * ip:/cidr:/bare CIDR or address, port:N or port:N-M, "private". Block wins over direct.
 *
 * Data structures (nothing is scanned linearly per connection, except keyword/regexp, which are rare):
 *  - exact names:    HashSet
 *  - domain suffixes: HashSet probed once per label of the name (same cost as walking a reverse trie)
 *  - IPv4 / IPv6 networks: one HashSet per prefix length that actually occurs, probed with the masked address
 *  - keyword / regexp: small lists, only consulted after the hash lookups missed
 */
class RouteMatcher private constructor(private val block: Side, private val direct: Side) {

    val isEmpty: Boolean get() = block.count == 0 && direct.count == 0
    val blockCount: Int get() = block.count
    val directCount: Int get() = direct.count

    fun decideDomain(name: String, port: Int): RouteAction {
        val lower = name.lowercase(Locale.ROOT)
        if (block.matchesDomain(name, lower, port)) return RouteAction.BLOCK
        if (direct.matchesDomain(name, lower, port)) return RouteAction.DIRECT
        return RouteAction.PROXY
    }

    /** [addr] is the raw 4 or 16 byte address from the SOCKS request. */
    fun decideIp(addr: ByteArray, port: Int): RouteAction {
        if (addr.size != 4 && addr.size != 16) return RouteAction.PROXY
        if (block.matchesIp(addr, port)) return RouteAction.BLOCK
        if (direct.matchesIp(addr, port)) return RouteAction.DIRECT
        return RouteAction.PROXY
    }

    internal class Key6(val hi: Long, val lo: Long) {
        override fun equals(other: Any?): Boolean = other is Key6 && other.hi == hi && other.lo == lo
        override fun hashCode(): Int = (hi xor (hi ushr 32) xor (lo * 31) xor (lo ushr 29)).toInt()
    }

    internal class Side {
        val full = HashSet<String>()
        val suffix = HashSet<String>()
        val keywords = ArrayList<String>()
        val regexes = ArrayList<Regex>()
        val v4 = arrayOfNulls<HashSet<Int>>(33)
        val v6 = arrayOfNulls<HashSet<Key6>>(129)
        var v4Prefixes = IntArray(0)
        var v6Prefixes = IntArray(0)
        val ports = ArrayList<IntArray>()
        var priv = false
        var count = 0

        fun freeze() {
            v4Prefixes = (0..32).filter { v4[it] != null }.toIntArray()
            v6Prefixes = (0..128).filter { v6[it] != null }.toIntArray()
        }

        private fun portHit(port: Int): Boolean {
            for (r in ports) if (port >= r[0] && port <= r[1]) return true
            return false
        }

        fun matchesDomain(name: String, lower: String, port: Int): Boolean {
            if (count == 0) return false
            if (portHit(port)) return true
            if (priv && lower == "localhost") return true
            if (full.contains(lower)) return true
            if (suffix.isNotEmpty()) {
                if (suffix.contains(lower)) return true
                var i = lower.indexOf('.')
                while (i >= 0) {
                    if (suffix.contains(lower.substring(i + 1))) return true
                    i = lower.indexOf('.', i + 1)
                }
            }
            for (k in keywords) if (lower.contains(k)) return true
            for (r in regexes) if (r.containsMatchIn(name)) return true
            return false
        }

        fun matchesIp(addr: ByteArray, port: Int): Boolean {
            if (count == 0) return false
            if (portHit(port)) return true
            if (priv && isPrivate(addr)) return true
            if (addr.size == 4) {
                val a = v4Int(addr)
                for (p in v4Prefixes) if (v4[p]!!.contains(mask4(a, p))) return true
            } else {
                for (p in v6Prefixes) if (v6[p]!!.contains(mask6(addr, p))) return true
            }
            return false
        }
    }

    companion object {
        private data class CacheKey(val path: String, val modified: Long, val length: Long)
        @Volatile private var cacheKey: CacheKey? = null
        @Volatile private var cached: RouteMatcher? = null

        /** Parses the routes file once and keeps the result until the file really changes (reconnects reuse it). */
        @Synchronized
        fun fromFile(file: File): RouteMatcher {
            val key = CacheKey(file.absolutePath, file.lastModified(), file.length())
            cached?.let { if (key == cacheKey) return it }
            val m = file.bufferedReader().use { parse(it.lineSequence()) }
            cacheKey = key
            cached = m
            return m
        }

        /** Drops the cached parse (it can hold tens of thousands of rules). Called when a service shuts down, so an idle app keeps no copy. */
        @Synchronized
        fun clearCache() {
            cacheKey = null
            cached = null
        }

        fun parse(text: String): RouteMatcher = parse(text.lineSequence())

        /** Same sectioning as routing.rs::split_sections: unknown "[section]" headers drop their lines. */
        fun parse(lines: Sequence<String>): RouteMatcher {
            val block = Side()
            val direct = Side()
            var current: Side? = null
            for (line in lines) {
                val t = line.trim()
                if (t.isEmpty() || t.startsWith("#")) continue
                val lowered = t.lowercase(Locale.ROOT)
                if (lowered == "[block]") { current = block; continue }
                if (lowered == "[direct]") { current = direct; continue }
                if (lowered.startsWith("[")) { current = null; continue }
                val target = current ?: continue
                for (piece in t.split(',', ';')) addEntry(target, piece)
            }
            block.freeze()
            direct.freeze()
            return RouteMatcher(block, direct)
        }

        private fun addEntry(side: Side, raw: String) {
            val entry = raw.trim()
            if (entry.isEmpty() || entry.startsWith("#")) return
            var kind = ""
            var value = entry
            val idx = entry.indexOf(':')
            if (idx >= 0) {
                val k = entry.substring(0, idx)
                if (!k.contains('.') && !k.contains('/')) {
                    kind = k.trim().lowercase(Locale.ROOT)
                    value = entry.substring(idx + 1).trim()
                }
            }
            when (kind) {
                "domain", "suffix" -> normalizeDomain(value)?.let { side.suffix.add(it); side.count++ }
                "full", "exact" -> normalizeDomain(value)?.let { side.full.add(it); side.count++ }
                "keyword" -> {
                    val needle = value.trim().lowercase(Locale.ROOT)
                    if (needle.isNotEmpty()) { side.keywords.add(needle); side.count++ }
                }
                "regexp", "regex" -> runCatching { Regex(value) }.getOrNull()?.let { side.regexes.add(it); side.count++ }
                "ip", "cidr" -> addNet(side, value)
                "port" -> parsePorts(value)?.let { side.ports.add(it); side.count++ }
                "geoip", "geosite" -> if (value.equals("private", ignoreCase = true)) { side.priv = true; side.count++ }
                "" -> when {
                    value.equals("private", ignoreCase = true) -> { side.priv = true; side.count++ }
                    addNet(side, value) -> Unit
                    else -> normalizeDomain(value)?.let { side.suffix.add(it); side.count++ }
                }
                else -> Unit
            }
        }

        private fun normalizeDomain(value: String): String? {
            val cleaned = value.trim().trimStart('*').trimStart('.').trimEnd('.').lowercase(Locale.ROOT)
            return cleaned.ifEmpty { null }
        }

        private fun parsePorts(value: String): IntArray? {
            val v = value.trim()
            fun one(s: String): Int? = s.trim().takeIf { it.isNotEmpty() && it.all { c -> c in '0'..'9' } }?.toIntOrNull()?.takeIf { it in 0..65535 }
            val dash = v.indexOf('-')
            if (dash < 0) { val p = one(v) ?: return null; return intArrayOf(p, p) }
            val lo = one(v.substring(0, dash)) ?: return null
            val hi = one(v.substring(dash + 1)) ?: return null
            return if (hi < lo) intArrayOf(hi, lo) else intArrayOf(lo, hi)
        }

        /** Adds a CIDR or a single address. Returns false when [value] is not an address at all. */
        private fun addNet(side: Side, value: String): Boolean {
            val v = value.trim()
            val slash = v.indexOf('/')
            val host = if (slash >= 0) v.substring(0, slash) else v
            val bytes = parseIpLiteral(host) ?: return false
            val max = bytes.size * 8
            val prefix = if (slash < 0) max else {
                val ps = v.substring(slash + 1)
                if (ps.isEmpty() || !ps.all { it in '0'..'9' }) return false
                ps.toIntOrNull()?.takeIf { it in 0..max } ?: return false
            }
            if (bytes.size == 4) {
                val set = side.v4[prefix] ?: HashSet<Int>().also { side.v4[prefix] = it }
                set.add(mask4(v4Int(bytes), prefix))
            } else {
                val set = side.v6[prefix] ?: HashSet<Key6>().also { side.v6[prefix] = it }
                set.add(mask6(bytes, prefix))
            }
            side.count++
            return true
        }

        /** Literal IPv4 (no leading zeros) or IPv6 only; never triggers a DNS lookup. */
        internal fun parseIpLiteral(s: String): ByteArray? {
            if (s.isEmpty()) return null
            if (s.contains(':')) {
                if (!s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return null
                val a = runCatching { InetAddress.getByName(s) }.getOrNull() ?: return null
                return a.address.takeIf { it.size == 16 }
            }
            val parts = s.split('.')
            if (parts.size != 4) return null
            val out = ByteArray(4)
            for (i in 0..3) {
                val p = parts[i]
                if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' } || (p.length > 1 && p[0] == '0')) return null
                val n = p.toInt()
                if (n > 255) return null
                out[i] = n.toByte()
            }
            return out
        }

        internal fun v4Int(b: ByteArray): Int =
            ((b[0].toInt() and 0xff) shl 24) or ((b[1].toInt() and 0xff) shl 16) or
                ((b[2].toInt() and 0xff) shl 8) or (b[3].toInt() and 0xff)

        internal fun mask4(a: Int, prefix: Int): Int = if (prefix == 0) 0 else a and (-1 shl (32 - prefix))

        internal fun mask6(b: ByteArray, prefix: Int): Key6 {
            var hi = 0L
            var lo = 0L
            for (i in 0 until 8) hi = (hi shl 8) or (b[i].toLong() and 0xff)
            for (i in 8 until 16) lo = (lo shl 8) or (b[i].toLong() and 0xff)
            return when {
                prefix == 0 -> Key6(0L, 0L)
                prefix < 64 -> Key6(hi and (-1L shl (64 - prefix)), 0L)
                prefix == 64 -> Key6(hi, 0L)
                prefix < 128 -> Key6(hi, lo and (-1L shl (128 - prefix)))
                else -> Key6(hi, lo)
            }
        }

        /** Same ranges as routing.rs::is_private (LAN, loopback, link-local, CGNAT, documentation, ULA). */
        internal fun isPrivate(addr: ByteArray): Boolean {
            if (addr.size == 4) {
                val b0 = addr[0].toInt() and 0xff
                val b1 = addr[1].toInt() and 0xff
                val b2 = addr[2].toInt() and 0xff
                return b0 == 10 ||
                    (b0 == 172 && b1 in 16..31) ||
                    (b0 == 192 && b1 == 168) ||
                    b0 == 127 ||
                    (b0 == 169 && b1 == 254) ||
                    (b0 == 255 && b1 == 255 && b2 == 255 && (addr[3].toInt() and 0xff) == 255) ||
                    (b0 == 192 && b1 == 0 && b2 == 2) ||
                    (b0 == 198 && b1 == 51 && b2 == 100) ||
                    (b0 == 203 && b1 == 0 && b2 == 113) ||
                    (b0 == 0 && b1 == 0 && b2 == 0 && (addr[3].toInt() and 0xff) == 0) ||
                    (b0 == 100 && b1 in 64..127)
            }
            val seg0 = ((addr[0].toInt() and 0xff) shl 8) or (addr[1].toInt() and 0xff)
            val allZeroButLast = (0 until 15).all { addr[it].toInt() == 0 }
            val last = addr[15].toInt() and 0xff
            return (allZeroButLast && (last == 0 || last == 1)) ||
                (seg0 and 0xfe00) == 0xfc00 ||
                (seg0 and 0xffc0) == 0xfe80
        }
    }
}
