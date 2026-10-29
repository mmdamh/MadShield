package com.madshield.app.core

/**
 * DNS wire format for the local DoH client (RFC 1035 / RFC 8484). Pure Kotlin: no Android types, covered by
 * tests/pure.
 *
 * Nothing in here throws on bad input. A malformed or hostile response is simply `null`: the bytes come from
 * a network and every offset is checked before it is used.
 */
object DnsMessage {
    const val TYPE_A = 1
    const val TYPE_CNAME = 5
    const val TYPE_SOA = 6
    const val TYPE_AAAA = 28

    const val RCODE_NOERROR = 0
    const val RCODE_NXDOMAIN = 3

    /** A name pointer chain longer than this is a loop or an attack. */
    const val MAX_POINTER_HOPS = 128
    private const val HEADER = 12
    private const val MAX_NAME_WIRE = 255

    class Question(val name: String, val type: Int, val clazz: Int)

    /**
     * One resource record the resolver cares about. [address] is the raw 4 or 16 bytes for A/AAAA,
     * [target] the canonical name for CNAME; both are null for anything else.
     */
    class Record(val name: String, val type: Int, val ttl: Long, val address: ByteArray?, val target: String?)

    class Response(
        val id: Int,
        val rcode: Int,
        val truncated: Boolean,
        val question: Question,
        val answers: List<Record>,
        /** min(SOA ttl, SOA minimum) from the authority section (RFC 2308), or null when there is none. */
        val negativeTtl: Long?
    )

    // ---------------------------------------------------------------- query

    /**
     * A standard query: Id 0 (RFC 8484 asks for it, it makes the HTTP body cacheable), RD set, no EDNS at all
     * (so no client-subnet option can ever be attached). Returns null for a name that cannot be sent:
     * empty, an empty label, a label over 63 bytes, more than 253 characters, or anything outside
     * letters/digits/hyphen/underscore (an IDN has to arrive as punycode already).
     */
    fun buildQuery(name: String, qtype: Int): ByteArray? {
        val n = normalize(name) ?: return null
        val out = java.io.ByteArrayOutputStream(HEADER + n.length + 6)
        out.write(0); out.write(0)          // id
        out.write(0x01); out.write(0x00)    // flags: RD
        out.write(0); out.write(1)          // QDCOUNT
        out.write(0); out.write(0)          // ANCOUNT
        out.write(0); out.write(0)          // NSCOUNT
        out.write(0); out.write(0)          // ARCOUNT
        for (label in n.split('.')) {
            out.write(label.length)
            for (ch in label) out.write(ch.code)
        }
        out.write(0)
        out.write(qtype shr 8); out.write(qtype and 0xff)
        out.write(0); out.write(1)          // class IN
        return out.toByteArray()
    }

    /** Lower-case, no trailing dot; null when the name is not a sendable host name. */
    fun normalize(name: String): String? {
        var n = name.trim()
        if (n.endsWith(".")) n = n.dropLast(1)
        if (n.isEmpty() || n.length > 253) return null
        n = n.lowercase(java.util.Locale.ROOT)
        var labelLen = 0
        for (ch in n) {
            if (ch == '.') {
                if (labelLen == 0) return null
                labelLen = 0
            } else {
                val ok = ch in 'a'..'z' || ch in '0'..'9' || ch == '-' || ch == '_'
                if (!ok) return null
                if (++labelLen > 63) return null
            }
        }
        return if (labelLen == 0) null else n
    }

    // ------------------------------------------------------------- response

    fun parseResponse(b: ByteArray): Response? {
        try {
            if (b.size < HEADER) return null
            val id = u16(b, 0)
            val flags = u16(b, 2)
            if (flags and 0x8000 == 0) return null            // not a response
            if (flags and 0x7800 != 0) return null            // opcode must be QUERY
            val rcode = flags and 0x000f
            val truncated = flags and 0x0200 != 0
            val qd = u16(b, 4)
            val an = u16(b, 6)
            val ns = u16(b, 8)
            if (qd != 1) return null

            var off = HEADER
            val q = readName(b, off) ?: return null
            off = q.second
            if (off + 4 > b.size) return null
            val question = Question(q.first, u16(b, off), u16(b, off + 2))
            off += 4

            val answers = ArrayList<Record>(minOf(an, 32))
            for (i in 0 until an) {
                val r = readRecord(b, off) ?: return null
                off = r.second
                answers.add(r.first.rec)
            }
            var negTtl: Long? = null
            for (i in 0 until ns) {
                val r = readRecord(b, off) ?: return null
                off = r.second
                val soa = r.first.soaMinimum
                if (r.first.rec.type == TYPE_SOA && soa != null) {
                    val t = minOf(r.first.rec.ttl, soa)
                    negTtl = if (negTtl == null) t else minOf(negTtl, t)
                }
            }
            // The additional section (OPT and glue) is not needed and is not read.
            return Response(id, rcode, truncated, question, answers, negTtl)
        } catch (_: RuntimeException) {
            return null // belt and braces: an index bug must never take the resolver down
        }
    }

    private class Parsed(val rec: Record, val soaMinimum: Long?)

    private fun readRecord(b: ByteArray, start: Int): Pair<Parsed, Int>? {
        val nm = readName(b, start) ?: return null
        var off = nm.second
        if (off + 10 > b.size) return null
        val type = u16(b, off)
        val ttl = u32(b, off + 4)
        val rdlen = u16(b, off + 8)
        off += 10
        if (off + rdlen > b.size) return null
        val end = off + rdlen
        var address: ByteArray? = null
        var target: String? = null
        var soaMin: Long? = null
        when (type) {
            TYPE_A -> { if (rdlen != 4) return null; address = b.copyOfRange(off, end) }
            TYPE_AAAA -> { if (rdlen != 16) return null; address = b.copyOfRange(off, end) }
            TYPE_CNAME -> {
                val t = readName(b, off) ?: return null
                if (t.second > end) return null
                target = t.first
            }
            TYPE_SOA -> {
                val m = readName(b, off) ?: return null
                val r = readName(b, m.second) ?: return null
                // serial, refresh, retry, expire, minimum: five 32-bit numbers
                if (r.second + 20 > end) return null
                soaMin = u32(b, r.second + 16)
            }
        }
        return Pair(Parsed(Record(nm.first, type, ttl, address, target), soaMin), end)
    }

    /**
     * Reads a (possibly compressed) name that starts at [start]. Returns the dotted lower-case name and the
     * offset just after the name in the ORIGINAL position (after the first pointer, not after its target).
     */
    internal fun readName(b: ByteArray, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var pos = start
        var next = -1
        var hops = 0
        var wire = 0
        while (true) {
            if (pos < 0 || pos >= b.size) return null
            val len = b[pos].toInt() and 0xff
            when {
                len == 0 -> {
                    if (next < 0) next = pos + 1
                    return Pair(sb.toString(), next)
                }
                len and 0xc0 == 0xc0 -> {
                    if (pos + 1 >= b.size) return null
                    if (++hops > MAX_POINTER_HOPS) return null
                    val target = ((len and 0x3f) shl 8) or (b[pos + 1].toInt() and 0xff)
                    if (next < 0) next = pos + 2
                    pos = target
                }
                len and 0xc0 != 0 -> return null // 01/10 label types are reserved
                else -> {
                    if (pos + 1 + len > b.size) return null
                    wire += len + 1
                    if (wire > MAX_NAME_WIRE) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    for (i in 1..len) {
                        var c = b[pos + i].toInt() and 0xff
                        if (c in 'A'.code..'Z'.code) c += 32
                        sb.append(c.toChar())
                    }
                    pos += 1 + len
                }
            }
        }
    }

    // ---------------------------------------------------------------- misc

    /** Raw address bytes of a literal IPv4/IPv6 address, or null when [s] is not one (a name is never resolved here). */
    fun parseIpLiteral(s: String): ByteArray? {
        val t = if (s.startsWith("[") && s.endsWith("]")) s.substring(1, s.length - 1) else s
        if (DnsConfig.isIpv4(t)) return t.split('.').map { it.toInt().toByte() }.toByteArray()
        if (DnsConfig.isIpv6(t)) return ipv6Bytes(t)
        return null
    }

    private fun ipv6Bytes(s: String): ByteArray? {
        val dc = s.indexOf("::")
        val head = (if (dc >= 0) s.substring(0, dc) else s).split(':').filter { it.isNotEmpty() }
        val tail = if (dc >= 0) s.substring(dc + 2).split(':').filter { it.isNotEmpty() } else emptyList()
        val missing = 8 - head.size - tail.size
        if (missing < 0 || (dc < 0 && missing != 0)) return null
        val groups = head + List(missing) { "0" } + tail
        if (groups.size != 8) return null
        val out = ByteArray(16)
        for ((i, g) in groups.withIndex()) {
            val v = g.toIntOrNull(16) ?: return null
            out[i * 2] = (v shr 8).toByte()
            out[i * 2 + 1] = (v and 0xff).toByte()
        }
        return out
    }

    private fun u16(b: ByteArray, o: Int): Int = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)
    private fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xff) shl 24) or ((b[o + 1].toLong() and 0xff) shl 16) or
            ((b[o + 2].toLong() and 0xff) shl 8) or (b[o + 3].toLong() and 0xff)
}
