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
 * SOCKS5 front inside the app. It owns the public SOCKS port and sits between hev-socks5-tunnel and the
 * upstream (the core, or the Psiphon/Tor chain). It exists for two reasons:
 *
 *  1. ROUTING RULES WITH A CHAIN (update10). With a chain on, the chain owns the public port and the core's
 *     own routing never sees app traffic. The front applies block/direct before anything is forwarded.
 *  2. LOCAL DoH (update11). When [Options.resolver] is set, every PROXY connection to a NAME is resolved
 *     by the app through DoH and forwarded to the upstream as a CONNECT to the IP. The core / the chain's
 *     exit never resolve a name themselves. There is NO fallback to ordinary DNS: if DoH cannot answer, the
 *     connection is refused with a SOCKS error.
 *
 *        hev -> RouteFront (public port)
 *             BLOCK  -> refused, SOCKS reply 0x02
 *             DIRECT -> straight from this app (the app is excluded from the VPN, so there is no loop).
 *                       Names use the system DNS (the connection leaves the tunnel anyway, and domestic
 *                       sites need a domestic answer) unless [Options.directResolver] is set.
 *             PROXY  -> upstream on [upstreamPort]; names via DoH when [Options.resolver] is set
 *             UDP ASSOCIATE -> carried by [UdpRelay] (rules per datagram) when [Options.udpCapable] and UDP is on
 *                       (see [setUdpEnabled]); refused (0x07) when UDP is off or the chain carries TCP only
 *
 * Safety properties:
 *  - fail closed: a connection that cannot be classified or reached is refused, never silently sent direct;
 *  - with local DoH, a fake address that arrives as an IP (hev forgot its name) is refused, never forwarded;
 *  - one thread per active connection, no polling, no timers: nothing runs while the tunnel is idle;
 *  - logging is batched: a single summary line when the front stops; domain names are never logged.
 */
class RouteFront(
    private val listenPort: Int,
    private val upstreamPort: Int,
    private val matcher: RouteMatcher,
    private val options: Options = Options(),
    private val log: (String) -> Unit
) {
    /**
     * @property resolver DoH for PROXY names (through the upstream); null = names are forwarded unresolved (update10).
     * @property directResolver DoH for DIRECT names, from the phone's own network; null = system DNS.
     * @property udpCapable the upstream can carry UDP (no chain, or sing-box): a [UdpRelay] exists. False = every
     *   UDP ASSOCIATE is refused (Psiphon/Tor).
     * @property udpOn UDP is switched on at start; [setUdpEnabled] changes it while running.
     * @property udpTuning timeouts of the relay (tests shorten them).
     * @property guardFakeIps refuse IP destinations in hev's fake-IP network and DNS range (see [FrontGuard]).
     * @property allowOnion pass *.onion names to the upstream unresolved (Tor chain only); otherwise refused.
     */
    class Options(
        val resolver: FrontResolver? = null,
        val directResolver: FrontResolver? = null,
        val udpCapable: Boolean = false,
        val udpOn: Boolean = true,
        val udpTuning: UdpRelay.Tuning = UdpRelay.Tuning(),
        val guardFakeIps: Boolean = false,
        val allowOnion: Boolean = false
    )

    private companion object {
        const val HANDSHAKE_MS = 10_000
        const val CONNECT_MS = 15_000
        const val MULTI_TRY_CONNECT_MS = 8_000
        const val MAX_ADDRESSES_TRIED = 3
        const val LINGER_AFTER_HALF_CLOSE_MS = 30_000L
        const val CMD_CONNECT = 1
        const val CMD_UDP_ASSOCIATE = 3
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
    private val nUdp = AtomicLong()
    private val nUdpRefused = AtomicLong()
    @Volatile private var udpOn: Boolean = options.udpOn
    private val relay: UdpRelay? = if (options.udpCapable) {
        UdpRelay(upstreamPort, matcher, options.resolver, options.directResolver, options.guardFakeIps, log, options.udpTuning)
    } else null
    private val nRefusedFake = AtomicLong()
    private val nRefusedOther = AtomicLong()
    private val nResolveFailed = AtomicLong()

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
        log(
            "[route] front on $listenPort -> upstream on $upstreamPort (${matcher.blockCount} block, ${matcher.directCount} direct rules; " +
                "doh=${if (options.resolver != null) "on" else "off"}, doh-direct=${if (options.directResolver != null) "on" else "off"}, " +
                "udp=${udpLabel()})"
        )
    }

    private fun udpLabel(): String = when {
        relay == null -> "refused (this chain carries TCP only)"
        udpOn -> "relay, rules per datagram"
        else -> "off"
    }

    /** UDP is currently carried (switched on AND the upstream can carry it). */
    val udpActive: Boolean get() = relay != null && udpOn

    /**
     * UDP Support switched while the tunnel runs. Off: every association ends now (its sockets and the relay thread
     * are freed) and new ASSOCIATEs are refused. On: new ones are accepted again. TCP is not touched.
     */
    fun setUdpEnabled(on: Boolean) {
        if (udpOn == on) return
        udpOn = on
        if (!on) relay?.closeAll()
        log("[udp] ${if (on) "switched on" else "switched off: associations closed"}")
    }

    fun udpStats(): UdpStats = (relay?.stats() ?: UdpStats()).copy(refusedAssociations = nUdpRefused.get())

    /** Screen off and quiet: drop idle DoH connections. Cheap, starts nothing. */
    fun onIdle() {
        options.resolver?.closeIdle()
        options.directResolver?.closeIdle()
    }

    fun stop() {
        val s = server ?: return
        server = null
        closeQuietly(s)
        relay?.stop()
        live.toList().forEach { closeQuietly(it) }
        live.clear()
        pool.shutdownNow()
        log("[route] front stopped: ${nProxy.get()} via upstream, ${nDirect.get()} direct, ${nBlock.get()} blocked, ${nFailed.get()} failed" +
            if (relay != null) {
                val u = relay.stats()
                ", ${nUdp.get()} udp associations (${u.toUpstream} datagrams out, ${u.fromUpstream} in via upstream, " +
                    "${u.toDirect}/${u.fromDirect} direct, ${u.droppedTotal} dropped)"
            } else ", ${nUdpRefused.get()} udp refused")
        if (options.resolver != null || options.guardFakeIps) {
            log("[route] ${options.resolver?.summary() ?: "doh off"}; ${nResolveFailed.get()} refused after a failed lookup, " +
                "${nRefusedFake.get()} stale fake addresses refused, ${nRefusedOther.get()} reserved addresses refused")
        }
        // Answers learned through this tunnel may not hold for the next one, and the DoH connection must not outlive it.
        options.resolver?.clear()
        options.directResolver?.clear()
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

            when (cmd) {
                CMD_CONNECT -> {}
                CMD_UDP_ASSOCIATE -> {
                    serveUdpAssociate(client, cin, cout)
                    return
                }
                else -> { reply(cout, 0x07); return }
            }

            // ---- CONNECT. Destinations that must never be forwarded (only meaningful with mapped DNS).
            if (domain == null && options.guardFakeIps) {
                val v = FrontGuard.check(addr)
                if (v != FrontGuard.Verdict.OK) {
                    if (v == FrontGuard.Verdict.STALE_FAKE_IP) nRefusedFake.incrementAndGet() else nRefusedOther.incrementAndGet()
                    reply(cout, FrontGuard.replyCode(v))
                    return
                }
            }

            val onion = domain != null && options.resolver != null && domain.lowercase().endsWith(".onion")
            var action = if (domain != null) matcher.decideDomain(domain, port) else matcher.decideIp(addr, port)
            if (onion && action == RouteAction.DIRECT) action = RouteAction.PROXY // a .onion name has no clear-net address

            when (action) {
                RouteAction.BLOCK -> {
                    nBlock.incrementAndGet()
                    reply(cout, 0x02)
                    return
                }
                RouteAction.DIRECT -> {
                    remote = connectDirect(cout, domain, addr, port) ?: return
                    nDirect.incrementAndGet()
                    reply(cout, 0x00)
                }
                RouteAction.PROXY -> {
                    val resolver = options.resolver
                    if (domain != null && resolver != null && !onion) {
                        remote = connectResolved(cout, resolver, domain, port) ?: return
                    } else if (onion && !options.allowOnion) {
                        nFailed.incrementAndGet()
                        reply(cout, 0x04) // .onion needs Tor; never leak the name anywhere else
                        return
                    } else {
                        // IP destination, or a name the upstream resolves itself (update10 behaviour, .onion on Tor)
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
                    }
                    nProxy.incrementAndGet()
                    // with the legacy path the upstream's own reply travels back through the pipe below
                }
            }
            val upstream = remote ?: return
            client.soTimeout = 0
            upstream.soTimeout = 0
            pipe(client, upstream)
        } catch (_: IOException) {
            // client vanished or sent garbage: nothing to report per connection
        } finally {
            closeQuietly(client)
            remote?.let { closeQuietly(it) }
            live.remove(client)
            remote?.let { live.remove(it) }
        }
    }

    // ------------------------------------------------------------------ DIRECT

    /** @return the connected socket, or null after the client got its error reply. */
    private fun connectDirect(cout: OutputStream, domain: String?, addr: ByteArray, port: Int): Socket? {
        val targets: List<InetSocketAddress> = try {
            when {
                domain == null -> listOf(InetSocketAddress(InetAddress.getByAddress(addr), port))
                options.directResolver != null -> options.directResolver
                    .resolve(domain).take(MAX_ADDRESSES_TRIED).map { InetSocketAddress(it, port) }
                else -> listOf(InetSocketAddress(domain, port)) // system DNS, as in update10
            }
        } catch (_: ResolveFailure) {
            nResolveFailed.incrementAndGet(); nFailed.incrementAndGet(); reply(cout, 0x04); return null
        } catch (_: Exception) {
            nFailed.incrementAndGet(); reply(cout, 0x04); return null
        }
        if (targets.isEmpty() || targets.any { it.isUnresolved }) { nFailed.incrementAndGet(); reply(cout, 0x04); return null }

        var code = 0x04
        for (t in targets) {
            val r = Socket()
            live.add(r)
            try {
                r.connect(t, if (targets.size > 1) MULTI_TRY_CONNECT_MS else CONNECT_MS)
                return r
            } catch (_: ConnectException) {
                code = 0x05
            } catch (_: IOException) {
                code = 0x04
            }
            closeQuietly(r); live.remove(r)
        }
        nFailed.incrementAndGet(); reply(cout, code)
        return null
    }

    // ---------------------------------------------------- PROXY with local DoH

    /**
     * Resolves [domain] through DoH, then asks the upstream to CONNECT to the address (first of up to
     * three that connects). On success the upstream's reply has been forwarded to the client.
     */
    private fun connectResolved(cout: OutputStream, resolver: FrontResolver, domain: String, port: Int): Socket? {
        val addrs = try {
            resolver.resolve(domain).take(MAX_ADDRESSES_TRIED)
        } catch (_: ResolveFailure) {
            nResolveFailed.incrementAndGet(); nFailed.incrementAndGet(); reply(cout, 0x04); return null
        } catch (_: Exception) {
            nResolveFailed.incrementAndGet(); nFailed.incrementAndGet(); reply(cout, 0x04); return null
        }
        var lastCode = 0x04
        for (a in addrs) {
            val ip = a.address
            val req = ByteArray(4 + ip.size + 2)
            req[0] = 5; req[1] = 1; req[2] = 0; req[3] = if (ip.size == 4) 1 else 4
            System.arraycopy(ip, 0, req, 4, ip.size)
            req[4 + ip.size] = (port shr 8).toByte()
            req[5 + ip.size] = (port and 0xff).toByte()
            val r = Socket()
            live.add(r)
            try {
                val rep = upstreamExchange(r, req, if (addrs.size > 1) MULTI_TRY_CONNECT_MS else CONNECT_MS)
                if (rep[1].toInt() == 0) {
                    cout.write(rep); cout.flush()
                    return r
                }
                lastCode = rep[1].toInt() and 0xff
            } catch (_: IOException) {
                lastCode = 0x01
            }
            closeQuietly(r); live.remove(r)
        }
        nFailed.incrementAndGet()
        reply(cout, lastCode)
        return null
    }

    // ------------------------------------------------------------------- UDP

    /**
     * UDP ASSOCIATE. The client (hev) gets the address of a loopback UDP socket owned by [UdpRelay]; every datagram
     * it sends there is checked against the rules. The association lives as long as this control connection: the
     * client closing it, the relay ending the association (idle, UDP switched off) or the front stopping all end it.
     * Nothing is relayed when UDP is off or the chain cannot carry it: the client gets "command not supported".
     */
    private fun serveUdpAssociate(client: Socket, cin: InputStream, cout: OutputStream) {
        val r = relay
        if (r == null || !udpOn) { nUdpRefused.incrementAndGet(); reply(cout, 0x07); return }
        val a = r.open(client)
        if (a == null) { nFailed.incrementAndGet(); reply(cout, 0x01); return }
        nUdp.incrementAndGet()
        try {
            val rep = byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, (a.port shr 8).toByte(), (a.port and 0xff).toByte())
            cout.write(rep); cout.flush()
            client.soTimeout = 0
            val sink = ByteArray(16)
            while (cin.read(sink) >= 0) { /* a control connection carries nothing after the reply */ }
        } catch (_: IOException) {
        } finally {
            a.close()
        }
    }

    // ----------------------------------------------------------------- helpers

    /**
     * Connects [r] to the upstream, does the SOCKS5 greeting, sends [request] and reads the COMPLETE reply
     * (the length depends on its address type). Leaves [r] with no read timeout set by the caller to decide.
     */
    private fun upstreamExchange(r: Socket, request: ByteArray, connectMs: Int): ByteArray {
        r.connect(InetSocketAddress(TunnelConfig.SOCKS_HOST, upstreamPort), connectMs)
        r.tcpNoDelay = true
        r.soTimeout = connectMs
        val rout = r.getOutputStream()
        val rin = r.getInputStream()
        rout.write(byteArrayOf(5, 1, 0)); rout.flush()
        val hello = ByteArray(2)
        readFully(rin, hello)
        if (hello[0].toInt() != 5 || hello[1].toInt() != 0) throw IOException("upstream refused the greeting")
        rout.write(request); rout.flush()
        return readReply(rin)
    }

    private fun readReply(rin: InputStream): ByteArray {
        val head = ByteArray(4)
        readFully(rin, head)
        if (head[0].toInt() != 5) throw IOException("not a socks5 reply")
        val rest = when (head[3].toInt() and 0xff) {
            1 -> 4 + 2
            4 -> 16 + 2
            3 -> {
                val len = rin.read()
                if (len < 0) throw IOException("eof")
                val tail = ByteArray(len + 2)
                readFully(rin, tail)
                return head + byteArrayOf(len.toByte()) + tail
            }
            else -> throw IOException("bad reply address type")
        }
        val tail = ByteArray(rest)
        readFully(rin, tail)
        return head + tail
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
