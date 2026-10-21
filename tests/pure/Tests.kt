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

    // ---- 1.2.1: in-app routing engine (same grammar and precedence as routing.rs)
    fun rm(block: String, direct: String) = RouteMatcher.parse("[block]\n$block\n[direct]\n$direct\n")
    fun ip(s: String) = s.split('.').map { it.toInt().toByte() }.toByteArray()
    val e = rm("", "")
    check("empty rules: proxy", e.isEmpty && e.decideDomain("example.com", 443) == RouteAction.PROXY)
    val d = rm("ads.example", "")
    check("bare domain matches itself", d.decideDomain("ads.example", 443) == RouteAction.BLOCK)
    check("bare domain matches subdomain", d.decideDomain("t.ads.example", 443) == RouteAction.BLOCK)
    check("notads.example is not a subdomain", d.decideDomain("notads.example", 443) == RouteAction.PROXY)
    check("ads.example.org is not a match", d.decideDomain("ads.example.org", 443) == RouteAction.PROXY)
    check("case-insensitive", d.decideDomain("ADS.Example", 443) == RouteAction.BLOCK)
    val f = rm("full:example.com", "")
    check("full matches exact only", f.decideDomain("example.com", 1) == RouteAction.BLOCK && f.decideDomain("www.example.com", 1) == RouteAction.PROXY)
    check("keyword", rm("keyword:doubleclick", "").decideDomain("stats.doubleclick.net", 443) == RouteAction.BLOCK)
    val rg = rm("regexp:^ad[0-9]+\\.", "")
    check("regexp", rg.decideDomain("ad42.example.com", 443) == RouteAction.BLOCK && rg.decideDomain("ads.example.com", 443) == RouteAction.PROXY)
    val c = rm("", "10.0.0.0/8")
    check("cidr inside", c.decideIp(ip("10.1.2.3"), 22) == RouteAction.DIRECT)
    check("cidr outside", c.decideIp(ip("11.1.2.3"), 22) == RouteAction.PROXY)
    val one = rm("1.2.3.4", "")
    check("bare address is a /32", one.decideIp(ip("1.2.3.4"), 80) == RouteAction.BLOCK && one.decideIp(ip("1.2.3.5"), 80) == RouteAction.PROXY)
    val pr = rm("port:25", "port:3000-3010")
    check("port rules", pr.decideDomain("m.example", 25) == RouteAction.BLOCK && pr.decideDomain("d.example", 3005) == RouteAction.DIRECT && pr.decideDomain("d.example", 3011) == RouteAction.PROXY)
    val pv = rm("", "private")
    check("private v4", listOf("10.1.1.1", "192.168.1.5", "172.16.9.9", "127.0.0.1", "100.96.0.2").all { pv.decideIp(ip(it), 80) == RouteAction.DIRECT })
    check("public is not private", pv.decideIp(ip("8.8.8.8"), 80) == RouteAction.PROXY)
    check("localhost is private", pv.decideDomain("localhost", 80) == RouteAction.DIRECT)
    check("block wins over direct", rm("example.com", "example.com").decideDomain("example.com", 443) == RouteAction.BLOCK)
    val w = rm("*.example.com", "")
    check("leading wildcard tolerated", w.decideDomain("a.example.com", 1) == RouteAction.BLOCK && w.decideDomain("example.com", 1) == RouteAction.BLOCK)
    val lst = rm("a.example, b.example\n# note\nc.example", "")
    check("lists accept commas, newlines, comments", listOf("a.example", "b.example", "c.example").all { lst.decideDomain(it, 1) == RouteAction.BLOCK } && lst.decideDomain("note", 1) == RouteAction.PROXY)
    val unk = RouteMatcher.parse("[proxy]\nexample.com\n[block]\nads.example\n")
    check("unknown section ignored", unk.decideDomain("example.com", 1) == RouteAction.PROXY && unk.decideDomain("ads.example", 1) == RouteAction.BLOCK)
    val bad = rm("regexp:[unclosed, port:abc, ip:not-an-ip, geoip:cn, :", "")
    check("malformed entries dropped without crashing", bad.decideDomain("example.com", 443) == RouteAction.PROXY)
    val v6r = rm("", "2001:db8::/32")
    val inside = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[2] = 0x0d; it[3] = 0xb8.toByte(); it[15] = 1 }
    val outside = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[2] = 0x0d; it[3] = 0xb9.toByte() }
    check("bare ipv6 cidr is dropped, exactly like routing.rs (kind '2001' is unknown)", v6r.decideIp(inside, 80) == RouteAction.PROXY)
    check("ipv6 explicit cidr", rm("", "cidr:2001:db8::/32").decideIp(inside, 80) == RouteAction.DIRECT)

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

    // ---- RuleParser: hosts, AdGuard/ABP, domain lists, engine syntax
    fun rules(vararg lines: String): List<String> { val o = ArrayList<String>(); lines.forEach { l -> RuleParser.parse(l) { o.add(it) } }; return o }
    check("hosts line", rules("0.0.0.0 ads.example.com") == listOf("ads.example.com"))
    check("hosts 127.0.0.1 + comment", rules("127.0.0.1 Track.Example.COM # note") == listOf("track.example.com"))
    check("hosts several names", rules("0.0.0.0 a.com b.net") == listOf("a.com", "b.net"))
    check("hosts localhost skipped", rules("127.0.0.1 localhost", "::1 ip6-localhost", "0.0.0.0 0.0.0.0").isEmpty())
    check("hosts with other ip is not a block", rules("192.168.1.5 nas.home").isEmpty())
    check("abp domain rule", rules("||ads.example.com^") == listOf("ads.example.com"))
    check("abp important", rules("||ads.example.com^\$important") == listOf("ads.example.com"))
    check("abp third-party accepted", rules("||ads.example.com^\$third-party") == listOf("ads.example.com"))
    check("abp popup + third-party accepted", rules("||pop.example.net^\$popup,third-party") == listOf("pop.example.net"))
    check("abp document accepted", rules("||bad.example.org^\$document") == listOf("bad.example.org"))
    check("abp script option skipped", rules("||cdn.example.com^\$script").isEmpty())
    check("abp domain= option skipped", rules("||ads.example.com^\$domain=site.com").isEmpty())
    check("abp mixed with narrow option skipped", rules("||ads.example.com^\$third-party,image").isEmpty())
    check("abp path skipped", rules("||example.com/ads/banner").isEmpty())
    check("abp exception skipped", rules("@@||example.com^").isEmpty())
    check("cosmetic filter skipped", rules("example.com##.ad-banner", "##.ad").isEmpty())
    check("comments and headers skipped", rules("# c", "! c", "[Adblock Plus 2.0]", "", "   ").isEmpty())
    check("plain domain + wildcard", rules("Example.org", "*.cdn.example.org.") == listOf("example.org", "cdn.example.org"))
    check("single label rejected", rules("intranet").isEmpty())
    check("junk rejected", rules("exa mple", "http://example.com/x", "-bad.com", "a..com").isEmpty())
    check("idn to punycode", rules("bücher.de") == listOf("xn--bcher-kva.de"))
    check("engine syntax passes through", rules("full:Bank.Example.IR", "keyword:Sheba", "10.0.0.0/8", "private", "port:443", "regexp:^a.*#b") ==
        listOf("full:bank.example.ir", "keyword:sheba", "10.0.0.0/8", "private", "port:443", "regexp:^a.*#b"))
    check("collapse drops covered subdomains", RuleParser.collapse(listOf("a.b.com", "b.com", "x.y.com", "full:a.b.com")) == listOf("b.com", "x.y.com", "full:a.b.com"))
    check("collapse keeps unrelated suffix", RuleParser.collapse(listOf("notb.com", "b.com")) == listOf("notb.com", "b.com"))
    check("manual keeps unknown lines", RuleParser.normalizeManual("0.0.0.0 ads.com\nintranet\n# c\nads.com") == listOf("ads.com", "intranet"))

    // ---- GeoDat: v2ray geoip.dat / geosite.dat (protobuf), Iran entries only
    fun bytesOf(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    // GeoIP "IR" with 10.0.0.0/8 and an IPv6 2001:db8::/32; GeoIP "US" with 1.2.3.0/24 (must be ignored)
    val v6 = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[2] = 0x0d; it[3] = 0xb8.toByte() }
    val cidr4 = bytesOf(0x0A, 4, 10, 0, 0, 0, 0x10, 8)
    val cidr6 = bytesOf(0x0A, 16) + v6 + bytesOf(0x10, 32)
    val irIp = bytesOf(0x0A, 2, 'I'.code, 'R'.code, 0x12, cidr4.size) + cidr4 + bytesOf(0x12, cidr6.size) + cidr6
    val usIp = bytesOf(0x0A, 2, 'U'.code, 'S'.code, 0x12, 8) + bytesOf(0x0A, 4, 1, 2, 3, 0, 0x10, 24)
    val geoip = bytesOf(0x0A, irIp.size) + irIp + bytesOf(0x0A, usIp.size) + usIp
    check("geoip: only IR entries, v4 and v6", GeoDat.extract(geoip, GeoDat.IRAN_CODES) == listOf("10.0.0.0/8", "2001:db8:0:0:0:0:0:0/32"))
    // GeoSite "IR": domain example.ir (type 2), full:pay.example.ir (3), keyword shop (0, field 1 omitted), regexp (1)
    fun dom(type: Int, v: String): ByteArray {
        val bytes = v.toByteArray()
        val body = (if (type != 0) bytesOf(0x08, type) else ByteArray(0)) + bytesOf(0x12, bytes.size) + bytes
        return bytesOf(0x12, body.size) + body
    }
    val irSite = bytesOf(0x0A, 2, 'I'.code, 'R'.code) + dom(2, "Example.ir") + dom(3, "pay.example.ir") + dom(0, "shop") + dom(1, "^a.*\\.ir\$") + dom(2, "ir")
    val geosite = bytesOf(0x0A, irSite.size) + irSite
    check("geosite: domain, full, keyword, regexp, single-label TLD",
        GeoDat.extract(geosite, GeoDat.IRAN_CODES) == listOf("example.ir", "full:pay.example.ir", "keyword:shop", "regexp:^a.*\\.ir\$", "ir"))
    check("geo: other code finds nothing", GeoDat.extract(geosite, setOf("CN")).isEmpty())
    check("geo: lowercase code matches", GeoDat.extract(geoip, setOf("ir")).size == 2)
    check("geo: truncated file throws", try { GeoDat.extract(geoip.copyOf(geoip.size - 3), GeoDat.IRAN_CODES); false } catch (e: java.io.IOException) { true })
    check("geo file detection", GeoDat.isGeoFile("https://x.org/release/geoip.dat?raw=1") && !GeoDat.isGeoFile("https://x.org/hosts"))

    // ---- RuleDedupe
    val dd = RuleDedupe(10)
    check("dedupe: new then duplicate", dd.add("a.com") && !dd.add("a.com") && dd.add("b.com"))
    check("dedupe: stops when half full", run { val t = RuleDedupe(4); var ok = 0; for (i in 0 until 20) if (t.add("r$i")) ok++; ok == 8 })

    // ---- ReconnectPolicy: slow retries for a blocked chain; flapping no longer resets the counter
    check("normal first retry 1 s", ReconnectPolicy.delayMs(1, true) == 1_000L)
    check("chain failure first retry 20 s", ReconnectPolicy.delayMs(1, true, 0.0, true) == 20_000L)
    check("chain failure third retry 3 min", ReconnectPolicy.delayMs(3, true, 0.0, true) == 180_000L)
    check("chain failure then waiting phase", ReconnectPolicy.delayMs(4, false, 0.0, true) == ReconnectPolicy.WAIT_SCREEN_OFF_MS)
    check("stable window is 10 min", ReconnectPolicy.STABLE_AFTER_MS == 600_000L)

    println(if (fails == 0) "ALL PASSED" else "$fails FAILED")
    if (fails > 0) kotlin.system.exitProcess(1)
}
