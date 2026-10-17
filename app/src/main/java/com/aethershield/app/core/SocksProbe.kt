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
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cancelled()) return Wait.CANCELLED
            if (!engineAlive()) return Wait.ENGINE_DIED
            if (handshakeOk(host, port)) return Wait.READY
            try {
                Thread.sleep(pollMs)
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
