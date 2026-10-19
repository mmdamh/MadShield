import com.aethershield.app.core.*

var fails = 0
fun check(name: String, ok: Boolean) { if (!ok) { fails++; println("FAIL: $name") } else println("ok:   $name") }

fun main() {
    // ---- Diagnostics bug 1: broken pipe is not a TCP failure
    val pipe = LogSignals.scan(List(5) { "write: broken pipe" })
    check("broken pipe not counted as tcp", pipe.tcp == 0)
    check("connection refused still counts", LogSignals.scan(listOf("connection refused")).tcp == 1)

    // ---- bug 2: a lone TLS BAD_DECRYPT line is not a handshake failure
    val dec = LogSignals.scan(listOf("tls: alert BAD_DECRYPT"))
    check("lone TLS alert not handshake", dec.handshake == 0)
    check("real handshake failure counts", LogSignals.scan(listOf("handshake failed: timeout")).handshake == 1)
    val connected = DiagInput(StateKind.CONNECTED, true, true, signals = LogSignals(handshake = 1))
    check("1 handshake line while connected: no finding", Diagnosis.diagnose(connected).none { it.kind == DiagKind.HANDSHAKE_FAILING })
    val c3 = Diagnosis.diagnose(connected.copy(signals = LogSignals(handshake = 3)))
    check("3 handshake lines while connected: medium", c3.any { it.kind == DiagKind.HANDSHAKE_FAILING && it.confidence == Confidence.MEDIUM })
    val err1 = Diagnosis.diagnose(connected.copy(state = StateKind.ERROR, signals = LogSignals(handshake = 1)))
    check("1 handshake line while in error: low", err1.any { it.kind == DiagKind.HANDSHAKE_FAILING && it.confidence == Confidence.LOW })

    // ---- bug 3: lines from before the recovery are history
    val log = listOf("[vpn] health check failed", "dns lookup failed", "connection reset", "handshake failed",
        "[vpn] tunnel bridge running (mtu=1500)", "[vpn] tunnel counters: 1 / 2 B / 3 / 4 B")
    check("old lines before recovery ignored", LogSignals.scanRecent(log) == LogSignals())
    check("plain scan still sees them", LogSignals.scan(log).dns == 1)
    val log2 = log + listOf("dns lookup failed")
    check("lines after recovery count", LogSignals.scanRecent(log2).dns == 1)
    check("no marker: all lines", LogSignals.scanRecent(listOf("dns failed")).dns == 1)
    check("proxy marker", LogSignals.scanRecent(listOf("dns failed", "[proxy] engine up")).dns == 0)

    // ---- IdleTracker
    val t = IdleTracker()
    var now = 1_000_000L
    fun tick(screen: Boolean, bytes: Long?, dt: Long = 30_000): Boolean { now += dt; return t.onTick(now, screen, bytes) }
    check("screen on: never idle", !tick(true, null))
    var b = 0L
    tick(false, b)                         // first sample: starts the clock
    var idle = false
    repeat(3) { b += 100; idle = tick(false, b) }   // 90 s quiet
    check("90 s quiet: not idle yet", !idle)
    b += 100; idle = tick(false, b)        // 120 s
    check("120 s quiet: idle", idle)
    b += 50_000; idle = tick(false, b, 60_000)      // 50 KB in a minute > busy
    check("traffic ends idle at once", !idle)
    repeat(4) { b += 100; idle = tick(false, b, 60_000) }
    check("quiet again for 2+ min: idle again", idle)
    b += 20_000; idle = tick(false, b, 60_000)      // 20 KB/min: between quiet and busy, hysteresis
    check("hysteresis: moderate traffic keeps idle", idle)
    idle = tick(true, null); check("screen on ends idle", !idle)
    check("light chatter counts as quiet", run {
        val u = IdleTracker(); var n = 0L; var by = 0L; var r = false
        u.onTick(n, false, by)
        repeat(5) { n += 30_000; by += 200; r = u.onTick(n, false, by) }
        r })
    check("unknown traffic (proxy mode): screen decides", run {
        val u = IdleTracker(); var n = 5_000L; var r = false
        repeat(6) { n += 30_000; r = u.onTick(n, false, null) }
        r })
    check("counter reset counts as activity", run {
        val u = IdleTracker(); var n = 5_000L; var by = 1_000_000L; var r = false
        u.onTick(n, false, by)
        repeat(5) { n += 30_000; by += 10; r = u.onTick(n, false, by) }
        n += 30_000; r = u.onTick(n, false, 5L)
        !r })
    t.wake(); check("wake() clears idle", !t.idle)

    // ---- PowerPolicy cadence
    check("cadence screen on", PowerPolicy.cadence(true).healthMs == 5_000L && PowerPolicy.cadence(true).sampleCpu)
    check("cadence screen off", PowerPolicy.cadence(false).healthMs == 30_000L && !PowerPolicy.cadence(false).sampleCpu)
    check("cadence idle", PowerPolicy.cadence(false, true).healthMs == 60_000L && PowerPolicy.cadence(false, true).logCountersEveryTicks == 0)
    check("idle never applies with screen on", PowerPolicy.cadence(true, true).healthMs == 5_000L)

    // ---- NotificationText
    check("rate B", NotificationText.rate(512) == "512 B/s")
    check("rate KB", NotificationText.rate(12 * 1024L) == "12 KB/s")
    check("rate MB", NotificationText.rate((1.2 * 1048576).toLong()) == "1.2 MB/s")
    check("speed line", NotificationText.speedLine(1024, 2 * 1048576L).contains("↑ 1 KB/s") && NotificationText.speedLine(1024, 2 * 1048576L).contains("↓ 2.0 MB/s"))
    check("bps maths", NotificationText.bps(0, 10_000, 2_000) == 5_000L)
    check("bps backwards counter", NotificationText.bps(100, 50, 1_000) == 0L)
    check("bps zero time", NotificationText.bps(0, 50, 0) == 0L)

    println(if (fails == 0) "ALL PASSED" else "$fails FAILED")
    if (fails > 0) kotlin.system.exitProcess(1)
}
