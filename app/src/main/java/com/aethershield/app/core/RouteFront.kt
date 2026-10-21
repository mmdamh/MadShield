package com.aethershield.app.core

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Minimal SOCKS5 front that applies the routing rules when a Psiphon/Tor chain is on.
 *
 *   hev-socks5-tunnel -> RouteFront (public SOCKS port)
 *        PROXY  -> chain (Psiphon/Tor) on [upstreamPort]
 *        DIRECT -> straight to the target from this app (the app is excluded from the VPN, exactly like the
 *                  core's own "direct" action, so there is no loop)
 *        BLOCK  -> refused with SOCKS reply 0x02
 *
 * Without this, the chain owns the public port and the core's routing never sees app traffic (the 1.2.0 bug).
 *
 * Safety properties:
 *  - fail closed: a connection that cannot be classified or reached is refused, never silently sent direct;
 *  - only CONNECT is served (the chains carry TCP only; hev answers DNS itself through mapdns);
 *  - one thread per active connection, no polling, no timers: nothing runs while the tunnel is idle;
 *  - logging is batched: a single summary line when the front stops.
 */
class RouteFront(
    private val listenPort: Int,
    private val upstreamPort: Int,
    private val matcher: RouteMatcher,
    private val log: (String) -> Unit
) {
    private companion object {
        const val HANDSHAKE_MS = 10_000
        const val CONNECT_MS = 15_000
        const val LINGER_AFTER_HALF_CLOSE_MS = 30_000L
    }

    @Volatile private var server: ServerSocket? = null
    private val live: MutableSet<Socket> = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())
    private val pool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "route-front").apply { isDaemon = true }
    }
    private val nProxy = AtomicLong()
    private val nDirect = AtomicLong()
    private val nBlock = AtomicLong()
    private val nFailed = AtomicLong()

    /** Binds the public port. Throws IOException if it cannot (the caller must treat that as a failed start). */
    fun start() {
        val s = ServerSocket()
        s.reuseAddress = true
        s.bind(InetSocketAddress(TunnelConfig.SOCKS_HOST, listenPort), 128)
        server = s
        pool.execute {
            while (!s.isClosed) {
                val c = try { s.accept() } catch (_: IOException) { break }
                try { pool.execute { handle(c) } } catch (_: Exception) { closeQuietly(c) }
            }
        }
        log("[route] front on $listenPort -> chain on $upstreamPort (${matcher.blockCount} block, ${matcher.directCount} direct rules)")
    }

    fun stop() {
        val s = server ?: return
        server = null
        closeQuietly(s)
        live.toList().forEach { closeQuietly(it) }
        live.clear()
        pool.shutdownNow()
        log("[route] front stopped: ${nProxy.get()} via chain, ${nDirect.get()} direct, ${nBlock.get()} blocked, ${nFailed.get()} failed")
    }

    private fun handle(client: Socket) {
        live.add(client)
        var remote: Socket? = null
        try {
            client.tcpNoDelay = true
            client.soTimeout = HANDSHAKE_MS
            val cin = client.getInputStream()
            val cout = client.getOutputStream()

            // greeting: only "no authentication" is offered (the listener is loopback-only)
            val head = ByteArray(2)
            readFully(cin, head)
            if (head[0].toInt() != 5) return
            val methods = ByteArray(head[1].toInt() and 0xff)
            readFully(cin, methods)
            if (!methods.contains(0.toByte())) { cout.write(byteArrayOf(5, -1)); cout.flush(); return }
            cout.write(byteArrayOf(5, 0)); cout.flush()

            // request
            val rq = ByteArray(4)
            readFully(cin, rq)
            if (rq[0].toInt() != 5) return
            val cmd = rq[1].toInt() and 0xff
            val atyp = rq[3].toInt() and 0xff
            val raw = ByteArrayOutputStream()
            raw.write(rq)
            var domain: String? = null
            val addr: ByteArray
            when (atyp) {
                1 -> addr = ByteArray(4).also { readFully(cin, it); raw.write(it) }
                4 -> addr = ByteArray(16).also { readFully(cin, it); raw.write(it) }
                3 -> {
                    val len = cin.read()
                    if (len <= 0) { reply(cout, 0x08); return }
                    raw.write(len)
                    addr = ByteArray(len).also { readFully(cin, it); raw.write(it) }
                    domain = String(addr, Charsets.ISO_8859_1)
                }
                else -> { reply(cout, 0x08); return }
            }
            val pb = ByteArray(2)
            readFully(cin, pb)
            raw.write(pb)
            val port = ((pb[0].toInt() and 0xff) shl 8) or (pb[1].toInt() and 0xff)

            if (cmd != 1) { reply(cout, 0x07); return }

            val action = if (domain != null) matcher.decideDomain(domain, port) else matcher.decideIp(addr, port)
            when (action) {
                RouteAction.BLOCK -> {
                    nBlock.incrementAndGet()
                    reply(cout, 0x02)
                    return
                }
                RouteAction.DIRECT -> {
                    val target = try {
                        if (domain != null) InetSocketAddress(domain, port)
                        else InetSocketAddress(InetAddress.getByAddress(addr), port)
                    } catch (_: Exception) { null }
                    if (target == null || target.isUnresolved) { nFailed.incrementAndGet(); reply(cout, 0x04); return }
                    val r = Socket()
                    remote = r
                    live.add(r)
                    try {
                        r.connect(target, CONNECT_MS)
                    } catch (e: ConnectException) {
                        nFailed.incrementAndGet(); reply(cout, 0x05); return
                    } catch (_: IOException) {
                        nFailed.incrementAndGet(); reply(cout, 0x04); return
                    }
                    nDirect.incrementAndGet()
                    reply(cout, 0x00)
                }
                RouteAction.PROXY -> {
                    val r = Socket()
                    remote = r
                    live.add(r)
                    try {
                        r.connect(InetSocketAddress(TunnelConfig.SOCKS_HOST, upstreamPort), CONNECT_MS)
                        r.soTimeout = HANDSHAKE_MS
                        val rout = r.getOutputStream()
                        val rin = r.getInputStream()
                        rout.write(byteArrayOf(5, 1, 0)); rout.flush()
                        val hello = ByteArray(2)
                        readFully(rin, hello)
                        if (hello[0].toInt() != 5 || hello[1].toInt() != 0) { nFailed.incrementAndGet(); reply(cout, 0x01); return }
                        rout.write(raw.toByteArray()); rout.flush()
                    } catch (_: IOException) {
                        nFailed.incrementAndGet(); reply(cout, 0x01); return
                    }
                    nProxy.incrementAndGet()
                    // the chain's own reply to the request travels back to the client through the pipe below
                }
            }
            client.soTimeout = 0
            remote!!.soTimeout = 0
            pipe(client, remote!!)
        } catch (_: IOException) {
            // client vanished or sent garbage: nothing to report per connection
        } finally {
            closeQuietly(client)
            remote?.let { closeQuietly(it) }
            live.remove(client)
            remote?.let { live.remove(it) }
        }
    }

    private fun pipe(a: Socket, b: Socket) {
        val back = pool.submit { copy(b, a) }
        copy(a, b)
        try { back.get(LINGER_AFTER_HALF_CLOSE_MS, TimeUnit.MILLISECONDS) } catch (_: Exception) { back.cancel(true) }
    }

    private fun copy(src: Socket, dst: Socket) {
        val buf = ByteArray(16 * 1024)
        try {
            val input = src.getInputStream()
            val output = dst.getOutputStream()
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (_: IOException) {
        } finally {
            try { dst.shutdownOutput() } catch (_: IOException) {}
        }
    }

    private fun reply(out: OutputStream, code: Int) {
        try {
            out.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
            out.flush()
        } catch (_: IOException) {}
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var got = 0
        while (got < buf.size) {
            val n = input.read(buf, got, buf.size - got)
            if (n < 0) throw IOException("eof")
            got += n
        }
    }

    private fun closeQuietly(c: java.io.Closeable) { try { c.close() } catch (_: IOException) {} }
}
