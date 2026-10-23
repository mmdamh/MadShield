package com.aethershield.app.core

import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Small, blocking network probes used to decide whether the engine is really
 * serving. Call them from a background dispatcher.
 *
 * Why a SOCKS5 greeting and not just "can I open the TCP port": a leftover
 * process (or any other app) can hold the port and accept connections while
 * carrying no traffic. AetherGUI documents exactly that as the cause of its
 * "needs several Connect attempts" / "airplane-mode toggle" reports, so the
 * check here must see a real SOCKS5 answer ("05 00" = no authentication).
 */
object SocksProbe {

    /** Defaults are the short startup limits; the health loops pass [PowerPolicy.HEALTH_CONNECT_TIMEOUT_MS]/[PowerPolicy.HEALTH_READ_TIMEOUT_MS]. */
    fun handshakeOk(host: String, port: Int, connectTimeoutMs: Int = 250, readTimeoutMs: Int = 400): Boolean =
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), connectTimeoutMs)
                s.soTimeout = readTimeoutMs
                s.getOutputStream().apply { write(byteArrayOf(5, 1, 0)); flush() }
                val reply = ByteArray(2)
                var got = 0
                val input = s.getInputStream()
                while (got < 2) {
                    val n = input.read(reply, got, 2 - got)
                    if (n < 0) return false
                    got += n
                }
                reply[0].toInt() == 5 && reply[1].toInt() == 0
            }
        } catch (_: IOException) {
            false
        }

    /**
     * Opens a TCP connection to [targetHost]:[targetPort] THROUGH the local SOCKS5 proxy (a real CONNECT) and
     * reports whether the proxy says it worked. A literal IPv4 target tests the tunnel path alone; a hostname
     * also makes the engine resolve the name, which is how a DNS fault is told apart from a TCP fault.
     * Heavy compared with [handshakeOk]: run it only when the user asks for a test.
     */
    fun connectThrough(host: String, port: Int, targetHost: String, targetPort: Int, timeoutMs: Int = 6_000): Boolean =
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), timeoutMs)
                s.soTimeout = timeoutMs
                val out = s.getOutputStream()
                val input = s.getInputStream()
                out.write(byteArrayOf(5, 1, 0)); out.flush()
                val hello = ByteArray(2)
                if (!readFully(input, hello) || hello[0].toInt() != 5 || hello[1].toInt() != 0) return false

                val req = java.io.ByteArrayOutputStream()
                req.write(byteArrayOf(5, 1, 0))
                val v4 = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""").matchEntire(targetHost)
                if (v4 != null && v4.groupValues.drop(1).all { it.toInt() in 0..255 }) {
                    req.write(1)
                    v4.groupValues.drop(1).forEach { req.write(it.toInt()) }
                } else {
                    val name = targetHost.toByteArray(Charsets.US_ASCII)
                    require(name.size in 1..255) { "bad host name" }
                    req.write(3); req.write(name.size); req.write(name)
                }
                req.write(targetPort shr 8); req.write(targetPort and 0xff)
                out.write(req.toByteArray()); out.flush()

                val reply = ByteArray(2)
                readFully(input, reply) && reply[0].toInt() == 5 && reply[1].toInt() == 0
            }
        } catch (_: IOException) {
            false
        }

    private fun readFully(input: java.io.InputStream, buf: ByteArray): Boolean {
        var got = 0
        while (got < buf.size) {
            val n = input.read(buf, got, buf.size - got)
            if (n < 0) return false
            got += n
        }
        return true
    }

    /** A plain TCP connect from this app, which Android keeps OUTSIDE the tunnel. Shows whether the network itself works. */
    fun directConnect(targetHost: String, targetPort: Int, timeoutMs: Int = 4_000): Boolean =
        try {
            Socket().use { it.connect(InetSocketAddress(targetHost, targetPort), timeoutMs); true }
        } catch (_: IOException) {
            false
        }

    enum class Wait { READY, TIMEOUT, ENGINE_DIED, CANCELLED }

    /**
     * Polls until the SOCKS5 listener answers, [timeoutMs] passes, or the
     * engine process dies. Dying early is reported at once so the caller can
     * show the real reason instead of waiting out the whole timeout.
     */
    fun awaitReady(
        host: String,
        port: Int,
        timeoutMs: Long,
        engineAlive: () -> Boolean,
        cancelled: () -> Boolean = { false },
        pollMs: Long = 150
    ): Wait {
        val startedAt = System.currentTimeMillis()
        val deadline = startedAt + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cancelled()) return Wait.CANCELLED
            if (!engineAlive()) return Wait.ENGINE_DIED
            if (handshakeOk(host, port)) return Wait.READY
            try {
                Thread.sleep(PowerPolicy.readyPollMs(System.currentTimeMillis() - startedAt, pollMs))
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return Wait.CANCELLED
            }
        }
        return Wait.TIMEOUT
    }

    /** True once nothing is listening on 127.0.0.1:[port] any more (the old core really let go). */
    fun awaitPortFree(port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        do {
            try {
                ServerSocket().use { s ->
                    s.reuseAddress = true
                    s.bind(InetSocketAddress("127.0.0.1", port))
                }
                return true
            } catch (_: IOException) {
                try {
                    Thread.sleep(100)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
            }
        } while (System.currentTimeMillis() < deadline)
        return false
    }
}
