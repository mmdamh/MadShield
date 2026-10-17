package com.aethershield.app.core

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom

/**
 * Resolver speed test ("DNS scanner"): sends a real A query for a well-known
 * name straight to a resolver and times the answer. Only the user's explicit
 * tap triggers it, and it only talks to the resolvers listed on screen.
 *
 * This app's own traffic is excluded from the VPN, so the probe measures the
 * path from the phone itself, NOT through the tunnel. A resolver that is slow
 * or filtered here can still be fine for the tunnel (the engine and the VPN's
 * DNS go through it) -- the result is a hint, not a verdict, and the UI says so.
 *
 * Responses are only trusted if the transaction id matches and the QR bit is
 * set, mirroring the anti-spoofing checks the core itself does for its lookups.
 */
object DnsProbe {

    private val random = SecureRandom()

    fun buildQuery(name: String, id: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(id shr 8); out.write(id and 0xff)
        out.write(0x01); out.write(0x00)          // flags: recursion desired
        out.write(0); out.write(1)                 // QDCOUNT = 1
        out.write(byteArrayOf(0, 0, 0, 0, 0, 0))   // AN/NS/AR = 0
        for (label in name.trim('.').split('.')) {
            require(label.length in 1..63) { "bad DNS label" }
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0)
        out.write(0); out.write(1)                 // QTYPE A
        out.write(0); out.write(1)                 // QCLASS IN
        return out.toByteArray()
    }

    /** True for a well-formed answer to query [id]: same id, QR set, RCODE 0, at least one answer. */
    fun isUsableAnswer(resp: ByteArray, length: Int, id: Int): Boolean {
        if (length < 12) return false
        val rid = ((resp[0].toInt() and 0xff) shl 8) or (resp[1].toInt() and 0xff)
        if (rid != id) return false
        val qr = (resp[2].toInt() and 0x80) != 0
        val rcode = resp[3].toInt() and 0x0f
        val answers = ((resp[6].toInt() and 0xff) shl 8) or (resp[7].toInt() and 0xff)
        return qr && rcode == 0 && answers > 0
    }

    /**
     * Median round-trip in ms over [samples] queries, or null if the resolver
     * did not answer correctly in time. Blocking: call from a background thread.
     */
    fun measure(
        entry: DnsEntry,
        timeoutMs: Int = 2_000,
        samples: Int = 3,
        name: String = "cloudflare.com"
    ): Long? {
        val times = ArrayList<Long>(samples)
        val target = try {
            InetSocketAddress(InetAddress.getByName(entry.ip), entry.port ?: 53) // literal IP: no lookup happens
        } catch (_: IOException) {
            return null
        }
        repeat(samples) {
            try {
                DatagramSocket().use { s ->
                    s.soTimeout = timeoutMs
                    val id = random.nextInt(0x10000)
                    val q = buildQuery(name, id)
                    val start = System.nanoTime()
                    s.send(DatagramPacket(q, q.size, target))
                    val buf = ByteArray(1500)
                    val p = DatagramPacket(buf, buf.size)
                    val deadline = System.currentTimeMillis() + timeoutMs
                    while (true) {
                        s.soTimeout = (deadline - System.currentTimeMillis()).toInt().coerceAtLeast(1)
                        s.receive(p) // throws SocketTimeoutException at the deadline
                        if (p.socketAddress == target && isUsableAnswer(buf, p.length, id)) {
                            times += (System.nanoTime() - start) / 1_000_000
                            break
                        }
                    }
                }
            } catch (_: IOException) {
                // timeout / unreachable / no IPv6: this sample simply fails
            }
        }
        if (times.isEmpty()) return null
        times.sort()
        return times[times.size / 2]
    }
}
