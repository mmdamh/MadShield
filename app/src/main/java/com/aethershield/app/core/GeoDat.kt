package com.aethershield.app.core

import java.io.IOException
import java.util.Locale

/**
 * Reader for the v2ray "geoip.dat" / "geosite.dat" format (Chocolate4U/Iran-v2ray-rules and others), which is
 * a small protobuf. No library: the messages are tiny and only a few fields matter.
 *
 *   GeoIPList   { repeated GeoIP   entry = 1 }   GeoIP   { string country_code = 1; repeated CIDR   cidr   = 2 }
 *   GeoSiteList { repeated GeoSite entry = 1 }   GeoSite { string country_code = 1; repeated Domain domain = 2 }
 *   CIDR        { bytes ip = 1; uint32 prefix = 2 }
 *   Domain      { Type type = 1 (0 plain, 1 regex, 2 domain, 3 full); string value = 2; repeated Attribute = 3 }
 *
 * A GeoIP item and a GeoSite item are told apart by the wire type of field 1 (bytes vs varint), so the same
 * code reads both files. Only the entries named in [codes] are converted, into the engine's own rule syntax.
 * Pure Kotlin (no Android types), covered by tests/pure.
 */
object GeoDat {

    /** Chocolate4U: geoip.dat has "ir"; geosite.dat has "ir" and "category-ir". */
    val IRAN_CODES: Set<String> = setOf("IR", "CATEGORY-IR")

    fun isGeoFile(nameOrUrl: String): Boolean =
        nameOrUrl.substringBefore('?').substringBefore('#').lowercase(Locale.ROOT).endsWith(".dat")

    /** Rules for every entry whose country code is in [codes] (case-insensitive). Throws IOException if malformed. */
    fun extract(data: ByteArray, codes: Set<String>): List<String> {
        val wanted = codes.map { it.uppercase(Locale.ROOT) }.toSet()
        val out = ArrayList<String>()
        try {
            var pos = 0
            while (pos < data.size) {
                val r = Cursor(data, pos, data.size)
                val tag = r.varint().toInt()
                val wire = tag and 7
                if ((tag ushr 3) == 1 && wire == 2) {
                    val len = r.varint().toInt()
                    val start = r.pos
                    if (len < 0 || start + len > data.size) throw IOException("damaged file")
                    readEntry(data, start, start + len, wanted, out)
                    pos = start + len
                } else {
                    r.skip(wire)
                    pos = r.pos
                }
            }
        } catch (e: IndexOutOfBoundsException) {
            throw IOException("damaged file")
        }
        return out
    }

    private fun readEntry(d: ByteArray, from: Int, to: Int, wanted: Set<String>, out: MutableList<String>) {
        // Pass 1: the country code (normally the first field, but do not rely on it).
        var code: String? = null
        var c = Cursor(d, from, to)
        while (c.pos < to) {
            val tag = c.varint().toInt()
            if ((tag ushr 3) == 1 && (tag and 7) == 2) {
                val len = c.varint().toInt()
                code = String(d, c.pos, len, Charsets.UTF_8).uppercase(Locale.ROOT)
                c.pos += len
            } else c.skip(tag and 7)
        }
        if (code == null || code !in wanted) return

        // Pass 2: the items.
        c = Cursor(d, from, to)
        while (c.pos < to) {
            val tag = c.varint().toInt()
            if ((tag ushr 3) == 2 && (tag and 7) == 2) {
                val len = c.varint().toInt()
                readItem(d, c.pos, c.pos + len, out)
                c.pos += len
            } else c.skip(tag and 7)
        }
    }

    private fun readItem(d: ByteArray, from: Int, to: Int, out: MutableList<String>) {
        var f1Varint = 0L
        var f1Bytes: IntArray? = null      // offset, length
        var f2Varint = 0L
        var f2Bytes: IntArray? = null
        val c = Cursor(d, from, to)
        while (c.pos < to) {
            val tag = c.varint().toInt()
            val field = tag ushr 3
            val wire = tag and 7
            when {
                field == 1 && wire == 0 -> f1Varint = c.varint()
                field == 1 && wire == 2 -> { val l = c.varint().toInt(); f1Bytes = intArrayOf(c.pos, l); c.pos += l }
                field == 2 && wire == 0 -> f2Varint = c.varint()
                field == 2 && wire == 2 -> { val l = c.varint().toInt(); f2Bytes = intArrayOf(c.pos, l); c.pos += l }
                else -> c.skip(wire)
            }
        }
        val ip = f1Bytes
        val value = f2Bytes
        if (ip != null) {
            cidr(d, ip[0], ip[1], f2Varint.toInt())?.let { out.add(it) }
        } else if (value != null) {
            val v = String(d, value[0], value[1], Charsets.UTF_8)
            domainRule(f1Varint.toInt(), v)?.let { out.add(it) }
        }
    }

    /** Domain type -> engine syntax. A single label such as "ir" is valid: it means the whole TLD. */
    private fun domainRule(type: Int, raw: String): String? {
        val v = raw.trim()
        if (v.isEmpty()) return null
        return when (type) {
            1 -> "regexp:$v"
            0 -> "keyword:" + v.lowercase(Locale.ROOT)
            2 -> hostLike(v)
            3 -> hostLike(v)?.let { "full:$it" }
            else -> null
        }
    }

    private fun hostLike(raw: String): String? {
        var h = raw.lowercase(Locale.ROOT).trimEnd('.')
        if (h.isEmpty() || h.length > 253) return null
        if (h.any { it.code > 127 }) h = try { java.net.IDN.toASCII(h) } catch (e: Exception) { return null }
        for (ch in h) if (!(ch in 'a'..'z' || ch in '0'..'9' || ch == '-' || ch == '.' || ch == '_')) return null
        if (h[0] == '.' || h.contains("..")) return null
        return h
    }

    private fun cidr(d: ByteArray, off: Int, len: Int, prefix: Int): String? {
        if (len == 4) {
            if (prefix < 0 || prefix > 32) return null
            return "${d[off].toInt() and 0xFF}.${d[off + 1].toInt() and 0xFF}.${d[off + 2].toInt() and 0xFF}.${d[off + 3].toInt() and 0xFF}/$prefix"
        }
        if (len == 16) {
            if (prefix < 0 || prefix > 128) return null
            val sb = StringBuilder()
            for (i in 0 until 8) {
                if (i > 0) sb.append(':')
                val g = ((d[off + 2 * i].toInt() and 0xFF) shl 8) or (d[off + 2 * i + 1].toInt() and 0xFF)
                sb.append(Integer.toHexString(g))
            }
            return sb.append('/').append(prefix).toString()
        }
        return null
    }

    /** Position-tracking protobuf reader. */
    private class Cursor(val b: ByteArray, var pos: Int, val end: Int) {
        fun varint(): Long {
            var shift = 0
            var result = 0L
            while (true) {
                if (pos >= end) throw IOException("damaged file")
                val x = b[pos++].toInt() and 0xFF
                result = result or ((x and 0x7F).toLong() shl shift)
                if (x and 0x80 == 0) return result
                shift += 7
                if (shift > 63) throw IOException("damaged file")
            }
        }

        fun skip(wire: Int) {
            when (wire) {
                0 -> varint()
                1 -> pos += 8
                2 -> { val l = varint().toInt(); if (l < 0 || pos + l > end) throw IOException("damaged file"); pos += l }
                5 -> pos += 4
                else -> throw IOException("damaged file")
            }
            if (pos > end) throw IOException("damaged file")
        }
    }
}
