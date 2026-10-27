package com.aethershield.app.core

/**
 * The SOCKS5 UDP request/reply header (RFC 1928, section 7) and the address checks the UDP relay applies.
 * Pure byte handling, no sockets, so every edge case is tested off-device.
 *
 *   +-----+------+------+----------+----------+----------+
 *   | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *   |  2  |  1   |  1   | variable |    2     | variable |
 *   +-----+------+------+----------+----------+----------+
 *
 * hev-socks5-tunnel puts the NAME (ATYP 3) of a mapped-DNS address in this header instead of the fake IP
 * (checked in hev's source at the pinned commit: hev_socks5_addr_from_lwip), so domain rules can be applied to
 * UDP straight from the header.
 */
object UdpPacket {
    const val ATYP_V4 = 1
    const val ATYP_NAME = 3
    const val ATYP_V6 = 4

    /** Largest header we ever write: 4 + 16 + 2 (IPv6). A name header is parsed, never written by us. */
    const val MAX_WRITE_HEADER = 22

    enum class Result { OK, FRAGMENTED, MALFORMED }

    /** Where the parts of a parsed datagram are. One instance is reused by the relay thread (no allocation per datagram). */
    class Header {
        var atyp = 0
        /** Offset and length of the address bytes (for a name: the name itself, without its length byte). */
        var addrOff = 0
        var addrLen = 0
        var port = 0
        var dataOff = 0
    }

    fun parse(buf: ByteArray, len: Int, h: Header): Result {
        if (len < 4 || len > buf.size) return Result.MALFORMED
        if (buf[0].toInt() != 0 || buf[1].toInt() != 0) return Result.MALFORMED
        if (buf[2].toInt() != 0) return Result.FRAGMENTED // fragments are not reassembled; hev never sends them
        val atyp = buf[3].toInt() and 0xff
        var pos = 4
        when (atyp) {
            ATYP_V4 -> { h.addrOff = pos; h.addrLen = 4; pos += 4 }
            ATYP_V6 -> { h.addrOff = pos; h.addrLen = 16; pos += 16 }
            ATYP_NAME -> {
                if (len < 5) return Result.MALFORMED
                val n = buf[4].toInt() and 0xff
                if (n == 0) return Result.MALFORMED
                h.addrOff = 5; h.addrLen = n; pos = 5 + n
            }
            else -> return Result.MALFORMED
        }
        if (len < pos + 2) return Result.MALFORMED
        h.atyp = atyp
        h.port = ((buf[pos].toInt() and 0xff) shl 8) or (buf[pos + 1].toInt() and 0xff)
        h.dataOff = pos + 2
        return Result.OK
    }

    /** The name of a parsed ATYP 3 header (Latin-1, like the TCP path). */
    fun nameOf(buf: ByteArray, h: Header): String = String(buf, h.addrOff, h.addrLen, Charsets.ISO_8859_1)

    /** The address bytes of a parsed IPv4/IPv6 header, as a fresh array. */
    fun addrBytes(buf: ByteArray, h: Header): ByteArray = buf.copyOfRange(h.addrOff, h.addrOff + h.addrLen)

    /**
     * Writes an IP header (IPv4 or IPv6, by the size of [addr]) into [out] at [at] and returns the number of bytes
     * written. The caller puts the payload right behind it.
     */
    fun writeIpHeader(out: ByteArray, at: Int, addr: ByteArray, port: Int): Int {
        require(addr.size == 4 || addr.size == 16) { "address must be 4 or 16 bytes" }
        out[at] = 0; out[at + 1] = 0; out[at + 2] = 0
        out[at + 3] = (if (addr.size == 4) ATYP_V4 else ATYP_V6).toByte()
        System.arraycopy(addr, 0, out, at + 4, addr.size)
        out[at + 4 + addr.size] = (port shr 8).toByte()
        out[at + 5 + addr.size] = (port and 0xff).toByte()
        return 6 + addr.size
    }

    /** Header size for an address of [addrSize] bytes. */
    fun ipHeaderSize(addrSize: Int): Int = 6 + addrSize
}

/**
 * Destinations the UDP relay never sends to, whatever the rules say. A datagram to the phone's own loopback
 * could land on the relay's own ports (a loop) or on a service of another app; multicast and broadcast cannot be
 * carried by a unicast relay at all.
 */
object UdpGuard {
    enum class Verdict { OK, STALE_FAKE_IP, RESERVED, LOCAL }

    /**
     * [guardFakeIps]: hev's mapped-DNS ranges are refused as well (an address from them that arrives as an IP means
     * hev no longer knows its name; see [FrontGuard]).
     */
    fun check(a: ByteArray, guardFakeIps: Boolean, refuseLoopback: Boolean = true): Verdict {
        if (a.size == 4) {
            if (guardFakeIps) {
                when (FrontGuard.check(a)) {
                    FrontGuard.Verdict.STALE_FAKE_IP -> return Verdict.STALE_FAKE_IP
                    FrontGuard.Verdict.RESERVED -> return Verdict.RESERVED
                    FrontGuard.Verdict.OK -> Unit
                }
            }
            val b0 = a[0].toInt() and 0xff
            if (b0 == 0 || b0 >= 224) return Verdict.LOCAL                       // 0.0.0.0/8, multicast 224/4, reserved 240/4, broadcast
            if (refuseLoopback && b0 == 127) return Verdict.LOCAL
            return Verdict.OK
        }
        if (a.size != 16) return Verdict.LOCAL
        // IPv4-mapped (::ffff:a.b.c.d): judge the IPv4 part.
        val mapped = (0 until 10).all { a[it].toInt() == 0 } && (a[10].toInt() and 0xff) == 0xff && (a[11].toInt() and 0xff) == 0xff
        if (mapped) return check(a.copyOfRange(12, 16), guardFakeIps, refuseLoopback)
        val allZeroButLast = (0 until 15).all { a[it].toInt() == 0 }
        val last = a[15].toInt() and 0xff
        if (allZeroButLast && last == 0) return Verdict.LOCAL                       // ::
        if (refuseLoopback && allZeroButLast && last == 1) return Verdict.LOCAL     // ::1
        if ((a[0].toInt() and 0xff) == 0xff) return Verdict.LOCAL                   // ff00::/8 multicast
        return Verdict.OK
    }
}
