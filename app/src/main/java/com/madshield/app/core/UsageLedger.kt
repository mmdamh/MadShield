package com.madshield.app.core

import java.io.File
import java.io.IOException
import java.util.TreeMap

/** Which network carried the bytes. Anything that is not cellular (Wi-Fi, Ethernet, USB tethering) counts as [WIFI]. */
enum class Transport { WIFI, MOBILE }

/**
 * One day of data usage, all in bytes. "Up" is what the phone sent, "down" what it received, measured at the tunnel
 * (what the apps used). The route split is what the routing front carried: through the VPN, direct, and how many
 * requests the block rules refused. Only totals: no site, app or DNS name is ever part of this.
 */
data class DayUsage(
    val day: String,
    val wifiUp: Long = 0,
    val wifiDown: Long = 0,
    val mobileUp: Long = 0,
    val mobileDown: Long = 0,
    val vpnUp: Long = 0,
    val vpnDown: Long = 0,
    val directUp: Long = 0,
    val directDown: Long = 0,
    val blocked: Long = 0
) {
    val up: Long get() = wifiUp + mobileUp
    val down: Long get() = wifiDown + mobileDown
    val wifi: Long get() = wifiUp + wifiDown
    val mobile: Long get() = mobileUp + mobileDown
    val total: Long get() = up + down
    val vpn: Long get() = vpnUp + vpnDown
    val direct: Long get() = directUp + directDown

    internal fun plus(o: DayUsage) = DayUsage(
        day, wifiUp + o.wifiUp, wifiDown + o.wifiDown, mobileUp + o.mobileUp, mobileDown + o.mobileDown,
        vpnUp + o.vpnUp, vpnDown + o.vpnDown, directUp + o.directUp, directDown + o.directDown, blocked + o.blocked
    )

    internal fun isEmpty(): Boolean =
        wifiUp == 0L && wifiDown == 0L && mobileUp == 0L && mobileDown == 0L &&
            vpnUp == 0L && vpnDown == 0L && directUp == 0L && directDown == 0L && blocked == 0L
}

/**
 * Daily totals, kept for [KEEP_DAYS] days. Plain text, one line per day, so the whole file is a few KB:
 *
 *     v1
 *     2026-10-31,wifiUp,wifiDown,mobileUp,mobileDown,vpnUp,vpnDown,directUp,directDown,blocked
 *
 * Reading is forgiving (a damaged line is skipped, the rest is kept). No Android types: tested off-device.
 */
class UsageLedger(initial: Collection<DayUsage> = emptyList()) {
    companion object {
        const val KEEP_DAYS = 90
        private const val HEADER = "v1"
        private val DAY = Regex("""\d{4}-\d{2}-\d{2}""")

        fun parse(text: String?): UsageLedger {
            val out = ArrayList<DayUsage>()
            if (text != null) {
                for (line in text.lineSequence()) {
                    val f = line.trim().split(',')
                    if (f.size != 10 || !DAY.matches(f[0])) continue
                    val n = LongArray(9)
                    var ok = true
                    for (i in 0 until 9) {
                        val v = f[i + 1].toLongOrNull()
                        if (v == null || v < 0) { ok = false; break }
                        n[i] = v
                    }
                    if (ok) out.add(DayUsage(f[0], n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8]))
                }
            }
            return UsageLedger(out)
        }
    }

    private val days = TreeMap<String, DayUsage>()

    init {
        for (d in initial) days[d.day] = days[d.day]?.plus(d) ?: d
        prune()
    }

    /** Adds [delta] to its day. Nothing is stored for an all-zero delta. */
    @Synchronized
    fun add(delta: DayUsage) {
        if (delta.isEmpty()) return
        days[delta.day] = days[delta.day]?.plus(delta) ?: delta
        prune()
    }

    @Synchronized
    fun get(day: String): DayUsage = days[day] ?: DayUsage(day)

    /** Oldest first. */
    @Synchronized
    fun all(): List<DayUsage> = days.values.toList()

    @Synchronized
    fun clear() { days.clear() }

    private fun prune() {
        while (days.size > KEEP_DAYS) days.remove(days.firstKey())
    }

    @Synchronized
    fun serialize(): String {
        val sb = StringBuilder(HEADER).append('\n')
        for (d in days.values) {
            sb.append(d.day).append(',').append(d.wifiUp).append(',').append(d.wifiDown).append(',')
                .append(d.mobileUp).append(',').append(d.mobileDown).append(',')
                .append(d.vpnUp).append(',').append(d.vpnDown).append(',')
                .append(d.directUp).append(',').append(d.directDown).append(',').append(d.blocked).append('\n')
        }
        return sb.toString()
    }
}

/** How much a counter grew since [prev]. A smaller value means the counter restarted (new tunnel): then it counts from zero. */
fun counterDelta(prev: Long, now: Long): Long = if (now >= prev) now - prev else now

/**
 * Turns the tunnel's byte counters into daily totals. Fed ONLY from events (screen on/off, network change,
 * disconnect, the existing once-per-30-seconds counter read while the screen is on): it owns no timer.
 *
 * The first sample of a connection only sets the baseline, because an interface counter can hold everything
 * since boot. Traffic is credited to the network that was in use at the PREVIOUS sample, so the bytes before a
 * Wi-Fi/mobile switch land on the old network (the caller samples as the switch is announced).
 *
 * The file is written when something changed and either [force] is set (screen off, disconnect) or
 * [PERSIST_EVERY_MS] passed since the last write: a few small writes an hour, never one per sample.
 */
class UsageRecorder(
    private val ledger: UsageLedger,
    private val persist: (String) -> Unit
) {
    companion object {
        const val PERSIST_EVERY_MS = 5 * 60_000L
    }

    private var prevUp: Long? = null
    private var prevDown: Long? = null
    private var prevRoute: RouteTotals? = null
    private var prevTransport: Transport? = null
    private var lastPersistMs = Long.MIN_VALUE / 2
    private var dirty = false

    /**
     * @param day local date, "yyyy-MM-dd"
     * @param tunUp tunnel bytes sent so far, or null when the engine cannot count (then the route totals stand in)
     * @param route the front's totals, or null when no front runs
     */
    @Synchronized
    fun sample(day: String, nowMs: Long, tunUp: Long?, tunDown: Long?, route: RouteTotals?, transport: Transport, force: Boolean) {
        val credit = prevTransport ?: transport
        var dUp = 0L
        var dDown = 0L
        var dRoute = RouteTotals()

        if (route != null) {
            val p = prevRoute
            if (p != null) {
                dRoute = RouteTotals(
                    counterDelta(p.vpnUp, route.vpnUp), counterDelta(p.vpnDown, route.vpnDown),
                    counterDelta(p.directUp, route.directUp), counterDelta(p.directDown, route.directDown),
                    counterDelta(p.blocked, route.blocked)
                )
            }
            prevRoute = route
        } else {
            prevRoute = null
        }

        if (tunUp != null && tunDown != null) {
            val pu = prevUp
            val pd = prevDown
            if (pu != null && pd != null) { dUp = counterDelta(pu, tunUp); dDown = counterDelta(pd, tunDown) }
            prevUp = tunUp; prevDown = tunDown
        } else {
            // No tunnel counters (an engine that cannot count): what the front carried is the best figure there is.
            dUp = dRoute.vpnUp + dRoute.directUp
            dDown = dRoute.vpnDown + dRoute.directDown
            prevUp = null; prevDown = null
        }
        prevTransport = transport

        val delta = if (credit == Transport.MOBILE) {
            DayUsage(day, mobileUp = dUp, mobileDown = dDown)
        } else {
            DayUsage(day, wifiUp = dUp, wifiDown = dDown)
        }.copy(
            vpnUp = dRoute.vpnUp, vpnDown = dRoute.vpnDown,
            directUp = dRoute.directUp, directDown = dRoute.directDown, blocked = dRoute.blocked
        )
        if (!delta.isEmpty()) {
            ledger.add(delta)
            dirty = true
        }
        if (dirty && (force || nowMs - lastPersistMs >= PERSIST_EVERY_MS)) {
            persist(ledger.serialize())
            lastPersistMs = nowMs
            dirty = false
        }
    }

    /** A new connection starts from fresh counters: forget the old baseline (the next sample sets a new one). */
    @Synchronized
    fun newConnection() {
        prevUp = null; prevDown = null; prevRoute = null; prevTransport = null
    }
}

/** Where the ledger lives. Plain files, atomic replace. */
object UsageFile {
    const val NAME = "usage.txt"

    fun read(dir: File): UsageLedger =
        UsageLedger.parse(try { File(dir, NAME).takeIf { it.isFile }?.readText() } catch (_: IOException) { null })

    fun write(dir: File, text: String) {
        val tmp = File(dir, "$NAME.tmp")
        val dest = File(dir, NAME)
        try {
            tmp.writeText(text)
            if (!tmp.renameTo(dest)) { tmp.copyTo(dest, overwrite = true); tmp.delete() }
        } catch (_: IOException) {
            // A full disk must never take the VPN down; the totals simply stay in memory until the next write.
        }
    }

    fun delete(dir: File) {
        File(dir, NAME).delete()
        File(dir, "$NAME.tmp").delete()
    }
}
