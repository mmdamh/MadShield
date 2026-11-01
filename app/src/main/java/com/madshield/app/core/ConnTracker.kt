package com.madshield.app.core

import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** Bytes (and refused requests) the routing front has carried, by route. A snapshot of plain numbers. */
data class RouteTotals(
    val vpnUp: Long = 0,
    val vpnDown: Long = 0,
    val directUp: Long = 0,
    val directDown: Long = 0,
    val blocked: Long = 0
)

/** One row of the "Connections" page. Built on demand; nothing is kept per row after the page closes. */
data class ConnView(
    val id: Long,
    /** The name the app asked for, or the IP address when the app only gave an address. */
    val name: String,
    val hasName: Boolean,
    val port: Int,
    /** [RouteAction.PROXY] (through the VPN) or [RouteAction.DIRECT]; for refused requests [RouteAction.BLOCK]. */
    val route: RouteAction,
    val ageMs: Long,
    val upBytes: Long,
    val downBytes: Long,
    /** How many identical refused requests this row stands for (always 1 for a live connection). */
    val repeat: Int = 1
)

data class ConnSnapshot(
    val active: List<ConnView>,
    val blocked: List<ConnView>,
    val vpnCount: Int,
    val directCount: Int,
    val blockedTotal: Long
)

/**
 * One connection the front is carrying. Created by [ConnTracker.open]; the front adds the bytes it copies and
 * calls [ConnTracker.close] when the connection ends. [close] force-closes it (the page's "close" button).
 */
class TrackedConn internal constructor(
    val id: Long,
    val name: String,
    val hasName: Boolean,
    val port: Int,
    val route: RouteAction,
    val openedAtMs: Long,
    private val upTotal: AtomicLong,
    private val downTotal: AtomicLong,
    private val closer: () -> Unit
) {
    private val up = AtomicLong()
    private val down = AtomicLong()

    fun addUp(n: Int) { up.addAndGet(n.toLong()); upTotal.addAndGet(n.toLong()) }
    fun addDown(n: Int) { down.addAndGet(n.toLong()); downTotal.addAndGet(n.toLong()) }
    internal fun upBytes(): Long = up.get()
    internal fun downBytes(): Long = down.get()

    /** Closes both sockets of the connection. The thread that carries it ends and unregisters it itself. */
    fun close() {
        try { closer() } catch (_: Exception) { /* already closed */ }
    }
}

/**
 * Live bookkeeping for [RouteFront]: which connections are open right now, how many bytes each moved, how many
 * requests were refused, and per-route byte totals (the numbers behind the "Usage" page).
 *
 * Cost model: opening and closing a connection is one map put/remove; every copied chunk (16 KB at most) is two
 * atomic adds. There is NO timer and nothing is built until the Connections page asks for [snapshot]. The page
 * is the only reader, and only while it is on screen.
 *
 * Privacy: names live in memory only, for as long as the connection (or, for refused requests, the last
 * [MAX_BLOCKED] distinct ones) is remembered, and the tracker dies with the front, i.e. on disconnect.
 */
class ConnTracker(private val clock: () -> Long = { System.nanoTime() / 1_000_000L }) {
    companion object {
        /** More simultaneous connections than this are still carried and counted, just not listed. */
        const val MAX_ACTIVE = 2000
        const val MAX_BLOCKED = 40
    }

    private class Refused(val id: Long, val name: String, val hasName: Boolean, val port: Int, var atMs: Long, var count: Int)

    private val seq = AtomicLong()
    private val active = ConcurrentHashMap<Long, TrackedConn>()
    private val refused = ArrayDeque<Refused>()

    private val vpnUp = AtomicLong()
    private val vpnDown = AtomicLong()
    private val directUp = AtomicLong()
    private val directDown = AtomicLong()
    private val blockedTotal = AtomicLong()

    /** Registers a connection that is carried ([route] must not be BLOCK). [closer] closes its sockets. */
    fun open(name: String, hasName: Boolean, port: Int, route: RouteAction, closer: () -> Unit): TrackedConn {
        val direct = route == RouteAction.DIRECT
        val c = TrackedConn(
            id = seq.incrementAndGet(), name = name, hasName = hasName, port = port, route = route,
            openedAtMs = clock(),
            upTotal = if (direct) directUp else vpnUp,
            downTotal = if (direct) directDown else vpnDown,
            closer = closer
        )
        if (active.size < MAX_ACTIVE) active[c.id] = c
        return c
    }

    fun close(c: TrackedConn) { active.remove(c.id) }

    /** A request the rules refused. Identical consecutive ones fold into one row with a count. */
    fun blocked(name: String, hasName: Boolean, port: Int) {
        blockedTotal.incrementAndGet()
        val now = clock()
        synchronized(refused) {
            val last = refused.peekFirst()
            if (last != null && last.port == port && last.name == name) {
                last.count++
                last.atMs = now
                return
            }
            if (refused.size >= MAX_BLOCKED) refused.removeLast()
            refused.addFirst(Refused(seq.incrementAndGet(), name, hasName, port, now, 1))
        }
    }

    fun totals(): RouteTotals = RouteTotals(
        vpnUp.get(), vpnDown.get(), directUp.get(), directDown.get(), blockedTotal.get()
    )

    /** Newest connection first. */
    fun snapshot(): ConnSnapshot {
        val now = clock()
        val live = active.values.sortedByDescending { it.id }.map {
            ConnView(it.id, it.name, it.hasName, it.port, it.route, now - it.openedAtMs, it.upBytes(), it.downBytes())
        }
        val gone = synchronized(refused) {
            refused.map { ConnView(it.id, it.name, it.hasName, it.port, RouteAction.BLOCK, now - it.atMs, 0, 0, it.count) }
        }
        return ConnSnapshot(
            active = live,
            blocked = gone,
            vpnCount = live.count { it.route == RouteAction.PROXY },
            directCount = live.count { it.route == RouteAction.DIRECT },
            blockedTotal = blockedTotal.get()
        )
    }

    /** @return true when the connection existed. */
    fun closeConn(id: Long): Boolean {
        val c = active[id] ?: return false
        c.close()
        return true
    }

    /** @return how many connections were told to close. */
    fun closeAll(): Int {
        val all = ArrayList(active.values)
        all.forEach { it.close() }
        return all.size
    }
}
