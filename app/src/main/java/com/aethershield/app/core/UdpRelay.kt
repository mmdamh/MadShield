package com.aethershield.app.core

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PortUnreachableException
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/** What the Diagnostics page shows about UDP. A snapshot of plain numbers; nothing in it names a host. */
data class UdpStats(
    val active: Int = 0,
    val opened: Long = 0,
    /** ASSOCIATE requests answered with "not supported": UDP switched off, or the chain (Psiphon/Tor) cannot carry it. */
    val refusedAssociations: Long = 0,
    val toUpstream: Long = 0,
    val fromUpstream: Long = 0,
    val toDirect: Long = 0,
    val fromDirect: Long = 0,
    val droppedBlocked: Long = 0,
    val droppedGuard: Long = 0,
    val droppedBadPacket: Long = 0,
    val droppedNoUpstream: Long = 0,
    val droppedResolve: Long = 0,
    val droppedFull: Long = 0
) {
    val droppedTotal: Long
        get() = droppedBlocked + droppedGuard + droppedBadPacket + droppedNoUpstream + droppedResolve + droppedFull
}

/**
 * UDP for [RouteFront]: SOCKS5 UDP ASSOCIATE with a routing decision for EVERY datagram.
 *
 * Why it exists. hev-socks5-tunnel sends each UDP flow of the phone as a SOCKS5 UDP ASSOCIATE to the public port.
 * Before, the front either refused it (chain on: nothing could use UDP) or handed it to the upstream untouched
 * (no chain): the front's own rules never saw a datagram. With a sing-box chain nobody else could enforce them:
 * the core only sees the TCP stream to your server, and sing-box here has no routing rules at all.
 *
 * How it works (one association = one hev UDP flow):
 *  - the client side is ONE loopback UDP socket per association; its port is what the ASSOCIATE reply announces;
 *  - every datagram is parsed (SOCKS5 UDP header), checked by [UdpGuard] and decided by the SAME [RouteMatcher] the
 *    TCP path uses (hev puts the NAME of a mapped-DNS address into the header, so domain rules work):
 *      BLOCK  -> dropped. Nothing is opened for it.
 *      DIRECT -> sent from this app's own socket, which is outside the VPN (the app excludes itself from it).
 *      PROXY  -> sent to the upstream (sing-box, or the core) through a UDP ASSOCIATE that is opened by the FIRST
 *                datagram that needs it. If the upstream is not there the datagram is DROPPED. It is never sent
 *                direct instead: a proxy that fails must not turn into a leak.
 *  - names: with local DoH on, a PROXY/DIRECT name is resolved by the app (the answer is cached for the life of the
 *    association) and the upstream gets an IP; without DoH the name goes to the upstream as it is.
 *
 * Cost model: ONE selector thread serves every datagram of every association (no thread, socket or timer per
 * datagram); reads are event driven and the only timer is the idle sweep, which exists only while an association
 * does. When the last association closes the thread ends. Blocking work (the upstream handshake, a name lookup) runs
 * on a small cached pool whose threads die after a minute of nothing; one of them stays parked on the control
 * connection of each association that has an upstream (zero CPU, it only wakes when that connection ends).
 * The two 64 KB buffers belong to the relay object, not to an association.
 */
class UdpRelay(
    private val upstreamPort: Int,
    private val matcher: RouteMatcher,
    private val resolver: FrontResolver?,
    private val directResolver: FrontResolver?,
    private val guardFakeIps: Boolean,
    private val log: (String) -> Unit,
    private val tuning: Tuning = Tuning()
) {
    /** [refuseLoopback] is only switched off by the tests, which can only reach 127.0.0.1. */
    class Tuning(
        val idleMs: Long = 120_000L,
        val upstreamRetryMs: Long = 3_000L,
        val upstreamConnectMs: Int = 10_000,
        val refuseLoopback: Boolean = true
    )

    private companion object {
        const val BUF = 65_600
        /** Room in front of a payload read from a direct/upstream socket for the header written before it. */
        const val HEAD_ROOM = UdpPacket.MAX_WRITE_HEADER
        const val MAX_PENDING = 16
        const val MAX_DIRECTS = 8
        const val NAME_TTL_NS = 30_000_000_000L
        const val D_PROXY = 0
        const val D_DIRECT = 1
        const val D_BLOCK = 2
        const val D_GUARD = 3
        const val UP_NONE = 0
        const val UP_CONNECTING = 1
        const val UP_READY = 2
    }

    // ------------------------------------------------------------------ association

    internal class Resolved(val addr: InetAddress, val expiresNs: Long)

    internal class Direct(val addr: InetAddress, val port: Int, val ch: DatagramChannel) {
        var key: SelectionKey? = null
        val addrBytes: ByteArray = addr.address
    }

    private class UpRef(val a: Assoc)
    private class DirectRef(val a: Assoc, val d: Direct)

    /** One hev UDP flow. Everything but [close] and [port] is touched only by the relay thread. */
    inner class Assoc internal constructor(internal val control: Socket, internal val ch: DatagramChannel) {
        val port: Int = ch.socket().localPort
        @Volatile internal var closed = false
        internal var key: SelectionKey? = null
        internal var client: InetSocketAddress? = null
        internal var lastAt = System.nanoTime()

        internal var upState = UP_NONE
        internal var upCtrl: Socket? = null
        internal var upCh: DatagramChannel? = null
        internal var upKey: SelectionKey? = null
        internal var retryAt = 0L
        internal val pending = ArrayDeque<ByteArray>()

        internal val directs = ArrayList<Direct>(2)

        internal val names = HashMap<String, Resolved>(4)
        internal var resolving: String? = null
        internal val resolveQueue = ArrayDeque<ByteArray>()

        // Decision cache: a hev flow has one destination, so the matcher runs once, not once per packet.
        internal var ckAtyp = 0
        internal var ckAddr: ByteArray? = null
        internal var ckPort = -1
        internal var ckDecision = D_PROXY

        /** Ends this association from any thread (idempotent). */
        fun close() { post { closeAssoc(this) } }
    }

    // ------------------------------------------------------------------ state

    private val lock = Any()
    private var running = false       // guarded by lock
    private var stopped = false       // guarded by lock
    private var live = 0              // guarded by lock: opened and not yet closed
    @Volatile private var selector: Selector? = null
    private val tasks = ConcurrentLinkedQueue<Runnable>()
    private val workers: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "udp-relay-io").apply { isDaemon = true }
    }

    // Only the relay thread touches these.
    private val assocs = ArrayList<Assoc>()
    private val buf = ByteArray(BUF)
    private val bb = ByteBuffer.wrap(buf)
    private val obuf = ByteArray(BUF)
    private val obb = ByteBuffer.wrap(obuf)
    private val hdr = UdpPacket.Header()
    private val hdr2 = UdpPacket.Header()
    private var lastFailLogNs = 0L

    // Counters: written by the relay thread only, read from anywhere.
    private val nOpened = AtomicLong()
    @Volatile private var nToUp = 0L
    @Volatile private var nFromUp = 0L
    @Volatile private var nToDirect = 0L
    @Volatile private var nFromDirect = 0L
    @Volatile private var nBlocked = 0L
    @Volatile private var nGuard = 0L
    @Volatile private var nBad = 0L
    @Volatile private var nNoUp = 0L
    @Volatile private var nResolve = 0L
    @Volatile private var nFull = 0L

    /** True while the relay thread exists (tests check that it ends with the last association). */
    val threadRunning: Boolean get() = synchronized(lock) { running }

    fun stats(): UdpStats = UdpStats(
        active = synchronized(lock) { live },
        opened = nOpened.get(),
        toUpstream = nToUp, fromUpstream = nFromUp, toDirect = nToDirect, fromDirect = nFromDirect,
        droppedBlocked = nBlocked, droppedGuard = nGuard, droppedBadPacket = nBad,
        droppedNoUpstream = nNoUp, droppedResolve = nResolve, droppedFull = nFull
    )

    // ------------------------------------------------------------------ public API

    /**
     * Opens one association for the SOCKS5 control connection [control]. The relay closes [control] when it ends the
     * association (idle, UDP switched off, front stopping), which is how the thread that waits on it wakes up.
     * @return null when no socket or thread could be made (the caller answers the client with a SOCKS error)
     */
    fun open(control: Socket): Assoc? {
        val ch: DatagramChannel
        try {
            ch = DatagramChannel.open()
            try {
                ch.configureBlocking(false)
                ch.socket().bind(InetSocketAddress(InetAddress.getByName(TunnelConfig.SOCKS_HOST), 0))
                runCatching { ch.socket().receiveBufferSize = 262_144 }
                runCatching { ch.socket().sendBufferSize = 262_144 }
            } catch (e: IOException) {
                runCatching { ch.close() }
                return null
            }
        } catch (e: IOException) {
            return null
        }
        val a = Assoc(control, ch)
        synchronized(lock) {
            if (stopped) { runCatching { ch.close() }; return null }
            if (!running) {
                try {
                    val sel = Selector.open()
                    selector = sel
                    Thread({ loop(sel) }, "udp-relay").apply { isDaemon = true }.start()
                    running = true
                } catch (e: IOException) {
                    selector = null
                    runCatching { ch.close() }
                    return null
                }
            }
            live++
        }
        nOpened.incrementAndGet()
        post {
            if (a.closed) return@post
            assocs.add(a)
            a.lastAt = System.nanoTime()
            a.key = ch.register(selector, SelectionKey.OP_READ, a)
        }
        return a
    }

    /** Ends every association (UDP switched off while connected). New ones may be opened afterwards. */
    fun closeAll() {
        if (!threadRunning) return // nothing is open, and nothing may be left in the queue for a later thread
        post { for (a in ArrayList(assocs)) closeAssoc(a) }
    }

    /** The front is stopping: no new associations, the existing ones end. */
    fun stop() {
        synchronized(lock) { stopped = true }
        closeAll()
        workers.shutdown()
    }

    // ------------------------------------------------------------------ the thread

    private fun post(r: Runnable) {
        tasks.add(r)
        selector?.wakeup()
    }

    private fun loop(sel: Selector) {
        var sweepAt = System.nanoTime() + tuning.idleMs * 1_000_000L
        var cleanExit = false
        try {
            while (true) {
                while (true) {
                    val task = tasks.poll() ?: break
                    try { task.run() } catch (_: RuntimeException) { /* one bad task must not end the relay for everyone */ }
                }
                synchronized(lock) {
                    if (live == 0 && tasks.isEmpty()) { running = false; selector = null; cleanExit = true; return }
                }
                val now = System.nanoTime()
                val wait = if (assocs.isEmpty()) 0L else maxOf(1L, (sweepAt - now) / 1_000_000L)
                sel.select(wait)
                val it = sel.selectedKeys().iterator()
                while (it.hasNext()) {
                    val k = it.next(); it.remove()
                    if (!k.isValid) continue
                    try {
                        when (val att = k.attachment()) {
                            is Assoc -> onClient(att)
                            is UpRef -> onUpstream(att.a)
                            is DirectRef -> onDirect(att.a, att.d)
                        }
                    } catch (e: PortUnreachableException) {
                        // an ICMP "port unreachable" for an earlier datagram: that one is lost, the flow goes on
                    } catch (e: Exception) { // IOException, or a bug in one association: end that association only
                        val a = when (val att = k.attachment()) { is Assoc -> att; is UpRef -> att.a; is DirectRef -> att.a; else -> null }
                        if (a != null) closeAssoc(a)
                    }
                }
                val t = System.nanoTime()
                if (t >= sweepAt) sweepAt = sweep(t)
            }
        } catch (t: Throwable) {
            log("[udp] relay stopped on an unexpected error: ${t::class.java.simpleName}")
        } finally {
            // After a clean exit a NEW thread may already own the shared state (open() starts one as soon as
            // `running` is false), so only an abnormal end cleans it up.
            if (!cleanExit) {
                for (a in ArrayList(assocs)) runCatching { closeAssoc(a) }
                synchronized(lock) { running = false; selector = null; live = 0 }
            }
            runCatching { sel.close() }
        }
    }

    /** Closes associations idle for [Tuning.idleMs]; returns when to look again. */
    private fun sweep(now: Long): Long {
        val idleNs = tuning.idleMs * 1_000_000L
        var oldest = now
        for (a in ArrayList(assocs)) {
            if (now - a.lastAt >= idleNs) closeAssoc(a) else if (a.lastAt < oldest) oldest = a.lastAt
        }
        return oldest + idleNs
    }

    private fun closeAssoc(a: Assoc) {
        if (a.closed) return
        a.closed = true
        assocs.remove(a)
        a.key?.cancel()
        runCatching { a.ch.close() }
        teardownUpstream(a)
        for (d in a.directs) { d.key?.cancel(); runCatching { d.ch.close() } }
        a.directs.clear()
        a.pending.clear(); a.resolveQueue.clear()
        runCatching { a.control.close() } // wakes the thread that waits on the control connection
        synchronized(lock) { if (live > 0) live-- }
    }

    // ------------------------------------------------------------------ client -> out

    private fun onClient(a: Assoc) {
        bb.clear()
        val src = a.ch.receive(bb) as? InetSocketAddress ?: return
        // Only this phone's loopback may use the relay, and only the port that sent the first datagram. (The channel is
        // not connect()ed: connecting would discard a burst that is already queued when the first datagram is read.)
        val first = a.client
        if (first == null) {
            if (!src.address.isLoopbackAddress) { nGuard++; return }
            a.client = src
        } else if (src.port != first.port || src.address != first.address) { nGuard++; return }
        a.lastAt = System.nanoTime()
        handle(a, bb.position())
    }

    /** [len] bytes of a client datagram are in [buf]. */
    private fun handle(a: Assoc, len: Int) {
        val h = hdr
        if (UdpPacket.parse(buf, len, h) != UdpPacket.Result.OK) { nBad++; return }
        when (decide(a, h)) {
            D_BLOCK -> nBlocked++
            D_GUARD -> nGuard++
            D_DIRECT -> toDirect(a, h, len)
            else -> toProxy(a, h, len)
        }
    }

    private fun decide(a: Assoc, h: UdpPacket.Header): Int {
        val key = a.ckAddr
        if (key != null && a.ckPort == h.port && a.ckAtyp == h.atyp && key.size == h.addrLen) {
            var same = true
            for (i in 0 until h.addrLen) if (key[i] != buf[h.addrOff + i]) { same = false; break }
            if (same) return a.ckDecision
        }
        val d = if (h.atyp == UdpPacket.ATYP_NAME) {
            actionCode(matcher.decideDomain(UdpPacket.nameOf(buf, h), h.port))
        } else {
            val ip = UdpPacket.addrBytes(buf, h)
            if (UdpGuard.check(ip, guardFakeIps, tuning.refuseLoopback) != UdpGuard.Verdict.OK) D_GUARD
            else actionCode(matcher.decideIp(ip, h.port))
        }
        a.ckAddr = buf.copyOfRange(h.addrOff, h.addrOff + h.addrLen)
        a.ckAtyp = h.atyp; a.ckPort = h.port; a.ckDecision = d
        return d
    }

    private fun actionCode(x: RouteAction): Int = when (x) {
        RouteAction.BLOCK -> D_BLOCK
        RouteAction.DIRECT -> D_DIRECT
        RouteAction.PROXY -> D_PROXY
    }

    // ---- DIRECT

    private fun toDirect(a: Assoc, h: UdpPacket.Header, len: Int) {
        val ip: InetAddress = if (h.atyp == UdpPacket.ATYP_NAME) {
            val name = UdpPacket.nameOf(buf, h)
            cached(a, name) ?: run { queueResolve(a, name, true, len); return }
        } else {
            try { InetAddress.getByAddress(UdpPacket.addrBytes(buf, h)) } catch (_: Exception) { nBad++; return }
        }
        if (UdpGuard.check(ip.address, guardFakeIps, tuning.refuseLoopback) != UdpGuard.Verdict.OK) { nGuard++; return }
        val d = directFor(a, ip, h.port) ?: return
        bb.clear(); bb.limit(len); bb.position(h.dataOff)
        try {
            if (d.ch.write(bb) == 0) nFull++ else nToDirect++
        } catch (_: IOException) { nNoUp++ }
    }

    private fun directFor(a: Assoc, ip: InetAddress, port: Int): Direct? {
        for (d in a.directs) if (d.port == port && d.addr == ip) return d
        if (a.directs.size >= MAX_DIRECTS) { nFull++; return null }
        val sel = selector ?: return null
        var ch: DatagramChannel? = null
        return try {
            ch = DatagramChannel.open()
            ch.configureBlocking(false)
            ch.connect(InetSocketAddress(ip, port))
            val d = Direct(ip, port, ch)
            d.key = ch.register(sel, SelectionKey.OP_READ, DirectRef(a, d))
            a.directs.add(d)
            d
        } catch (_: IOException) {
            runCatching { ch?.close() }
            nNoUp++
            null
        }
    }

    private fun onDirect(a: Assoc, d: Direct) {
        bb.clear(); bb.position(HEAD_ROOM)
        val n = d.ch.read(bb)
        if (n <= 0) return
        val client = a.client ?: return
        a.lastAt = System.nanoTime()
        val hs = UdpPacket.ipHeaderSize(d.addrBytes.size)
        UdpPacket.writeIpHeader(buf, HEAD_ROOM - hs, d.addrBytes, d.port)
        bb.limit(HEAD_ROOM + n); bb.position(HEAD_ROOM - hs)
        if (a.ch.send(bb, client) == 0) nFull++ else nFromDirect++
    }

    // ---- PROXY

    private fun toProxy(a: Assoc, h: UdpPacket.Header, len: Int) {
        var data = buf
        var dataLen = len
        if (h.atyp == UdpPacket.ATYP_NAME && resolver != null) {
            // Local DoH: the upstream gets an IP, so the chain's exit never resolves a name itself.
            val name = UdpPacket.nameOf(buf, h)
            val ip = cached(a, name) ?: run { queueResolve(a, name, false, len); return }
            if (UdpGuard.check(ip.address, guardFakeIps, tuning.refuseLoopback) != UdpGuard.Verdict.OK) { nGuard++; return }
            val addr = ip.address
            val hs = UdpPacket.writeIpHeader(obuf, 0, addr, h.port)
            val plen = len - h.dataOff
            System.arraycopy(buf, h.dataOff, obuf, hs, plen)
            data = obuf
            dataLen = hs + plen
        }
        when (a.upState) {
            UP_READY -> sendUp(a, data, dataLen)
            UP_CONNECTING -> if (a.pending.size < MAX_PENDING) a.pending.add(data.copyOf(dataLen)) else nFull++
            else -> {
                if (System.nanoTime() < a.retryAt) { nNoUp++; return }
                a.upState = UP_CONNECTING
                a.pending.add(data.copyOf(dataLen))
                workers.execute { connectUpstream(a) }
            }
        }
    }

    private fun sendUp(a: Assoc, data: ByteArray, len: Int) {
        val ch = a.upCh ?: run { nNoUp++; return }
        val w = when { data === buf -> bb; data === obuf -> obb; else -> ByteBuffer.wrap(data, 0, len) } // else: a queued copy
        w.clear(); w.limit(len); w.position(0)
        try {
            if (ch.write(w) == 0) nFull++ else nToUp++
        } catch (_: IOException) { nNoUp++ }
    }

    /** Runs on a worker: opens the upstream UDP ASSOCIATE, then watches its control connection until it ends. */
    private fun connectUpstream(a: Assoc) {
        val s = Socket()
        var ch: DatagramChannel? = null
        try {
            s.connect(InetSocketAddress(TunnelConfig.SOCKS_HOST, upstreamPort), tuning.upstreamConnectMs)
            s.tcpNoDelay = true
            s.soTimeout = tuning.upstreamConnectMs
            val out = s.getOutputStream(); val inp = s.getInputStream()
            out.write(byteArrayOf(5, 1, 0)); out.flush()
            val hello = ByteArray(2); readFully(inp, hello)
            if (hello[0].toInt() != 5 || hello[1].toInt() != 0) throw IOException("upstream refused the greeting")
            out.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); out.flush()
            val rep = readReply(inp)
            if (rep[1].toInt() != 0) throw IOException("upstream answered UDP ASSOCIATE with code ${rep[1].toInt() and 0xff}")
            val bnd = when (rep[3].toInt() and 0xff) {
                1, 4 -> {
                    val size = if ((rep[3].toInt() and 0xff) == 1) 4 else 16
                    val ip = InetAddress.getByAddress(rep.copyOfRange(4, 4 + size))
                    val port = ((rep[4 + size].toInt() and 0xff) shl 8) or (rep[5 + size].toInt() and 0xff)
                    // an unspecified address means "the host you reached me on"
                    InetSocketAddress(if (ip.isAnyLocalAddress) InetAddress.getByName(TunnelConfig.SOCKS_HOST) else ip, port)
                }
                else -> throw IOException("upstream gave a name as its UDP address")
            }
            ch = DatagramChannel.open()
            ch.configureBlocking(false)
            ch.connect(bnd)
            s.soTimeout = 0
        } catch (e: IOException) {
            runCatching { s.close() }
            runCatching { ch?.close() }
            val msg = e.message ?: e::class.java.simpleName
            post { upstreamFailed(a, msg) }
            return
        }
        val dch = ch
        post { upstreamReady(a, s, dch) }
        // Hold the control connection: when it ends, the association on the upstream's side is gone too.
        try {
            val sink = ByteArray(16)
            val inp = s.getInputStream()
            while (inp.read(sink) >= 0) { /* nothing is expected */ }
        } catch (_: IOException) { }
        post { upstreamLost(a, s) }
    }

    private fun upstreamReady(a: Assoc, s: Socket, ch: DatagramChannel) {
        val sel = selector
        if (a.closed || sel == null) { runCatching { ch.close() }; runCatching { s.close() }; return }
        try {
            a.upKey = ch.register(sel, SelectionKey.OP_READ, UpRef(a))
        } catch (e: IOException) {
            runCatching { ch.close() }; runCatching { s.close() }
            upstreamFailed(a, "could not watch the upstream socket")
            return
        }
        a.upCtrl = s; a.upCh = ch; a.upState = UP_READY
        val queued = ArrayList(a.pending); a.pending.clear()
        for (d in queued) sendUp(a, d, d.size)
    }

    private fun upstreamFailed(a: Assoc, msg: String) {
        a.upState = UP_NONE
        a.retryAt = System.nanoTime() + tuning.upstreamRetryMs * 1_000_000L
        nNoUp += a.pending.size
        a.pending.clear()
        val now = System.nanoTime()
        if (now - lastFailLogNs > 30_000_000_000L || lastFailLogNs == 0L) {
            lastFailLogNs = now
            log("[udp] the upstream did not open a UDP association ($msg); datagrams that need it are dropped, never sent direct")
        }
    }

    private fun upstreamLost(a: Assoc, s: Socket) {
        if (a.upCtrl !== s) return
        teardownUpstream(a)
        a.upState = UP_NONE
        a.retryAt = System.nanoTime() + 1_000_000_000L
    }

    private fun teardownUpstream(a: Assoc) {
        a.upKey?.cancel(); a.upKey = null
        a.upCh?.let { runCatching { it.close() } }; a.upCh = null
        a.upCtrl?.let { runCatching { it.close() } }; a.upCtrl = null
        if (a.upState == UP_READY) a.upState = UP_NONE
        a.pending.clear()
    }

    private fun onUpstream(a: Assoc) {
        val ch = a.upCh ?: return
        bb.clear()
        val n = ch.read(bb)
        if (n <= 0) return
        // What comes back must be a well-formed SOCKS5 UDP datagram; anything else is not forwarded to the app.
        if (UdpPacket.parse(buf, n, hdr2) != UdpPacket.Result.OK) { nBad++; return }
        val client = a.client ?: return
        a.lastAt = System.nanoTime()
        bb.limit(n); bb.position(0)
        if (a.ch.send(bb, client) == 0) nFull++ else nFromUp++
    }

    // ------------------------------------------------------------------ names

    private fun cached(a: Assoc, name: String): InetAddress? {
        val r = a.names[name] ?: return null
        if (System.nanoTime() >= r.expiresNs) { a.names.remove(name); return null }
        return r.addr
    }

    /** The datagram in [buf] needs [name] resolved first: keep a copy, look it up on a worker, replay it afterwards. */
    private fun queueResolve(a: Assoc, name: String, direct: Boolean, len: Int) {
        val cur = a.resolving
        if (cur == null) {
            a.resolving = name
            a.resolveQueue.add(buf.copyOf(len))
            workers.execute {
                val ip: InetAddress? = try { lookup(name, direct) } catch (_: Exception) { null }
                post { resolved(a, name, ip) }
            }
        } else if (cur == name && a.resolveQueue.size < MAX_PENDING) {
            a.resolveQueue.add(buf.copyOf(len))
        } else {
            nFull++
        }
    }

    private fun lookup(name: String, direct: Boolean): InetAddress {
        val list: List<InetAddress> = if (direct) {
            directResolver?.resolve(name) ?: InetAddress.getAllByName(name).toList() // system DNS, like the TCP DIRECT path
        } else {
            (resolver ?: throw IOException("no resolver")).resolve(name)
        }
        return list.firstOrNull { it.address.size == 4 } ?: list.first()
    }

    private fun resolved(a: Assoc, name: String, ip: InetAddress?) {
        a.resolving = null
        val q = ArrayList(a.resolveQueue); a.resolveQueue.clear()
        if (a.closed) return
        if (ip == null) { nResolve += q.size; return }
        if (a.names.size >= 4) a.names.clear()
        a.names[name] = Resolved(ip, System.nanoTime() + NAME_TTL_NS)
        for (d in q) {
            System.arraycopy(d, 0, buf, 0, d.size)
            handle(a, d.size)
        }
    }

    // ------------------------------------------------------------------ wire helpers

    private fun readFully(input: java.io.InputStream, b: ByteArray) {
        var got = 0
        while (got < b.size) {
            val n = input.read(b, got, b.size - got)
            if (n < 0) throw IOException("eof")
            got += n
        }
    }

    /** One complete SOCKS5 reply (its length depends on the address type). */
    private fun readReply(input: java.io.InputStream): ByteArray {
        val head = ByteArray(4)
        readFully(input, head)
        if (head[0].toInt() != 5) throw IOException("not a socks5 reply")
        val rest = when (head[3].toInt() and 0xff) {
            1 -> 6
            4 -> 18
            3 -> {
                val len = input.read()
                if (len < 0) throw IOException("eof")
                val tail = ByteArray(len + 2)
                readFully(input, tail)
                return head + byteArrayOf(len.toByte()) + tail
            }
            else -> throw IOException("bad reply address type")
        }
        val tail = ByteArray(rest)
        readFully(input, tail)
        return head + tail
    }
}
