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

    dohTests()
    linkProfileTests()
    speedMeterTests()

    println(if (fails == 0) "ALL PASSED" else "$fails FAILED")
    if (fails > 0) kotlin.system.exitProcess(1)
}


// =====================================================================================================
// update11: local DoH (DnsMessage, DnsCache, Singleflight, DohSpec, FrontPlan/FrontGuard, FrontResolver,
// RouteFront end to end over loopback sockets)
// =====================================================================================================

private fun w16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())
private fun w32(v: Long) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())
private fun wname(n: String): ByteArray {
    val o = java.io.ByteArrayOutputStream()
    if (n.isNotEmpty()) for (l in n.split('.')) { o.write(l.length); o.write(l.toByteArray()) }
    o.write(0)
    return o.toByteArray()
}
/** A resource record whose owner name is written as a pointer to [ownerOff] (12 = the question name). */
private fun rr(ownerOff: Int, type: Int, ttl: Long, rdata: ByteArray) =
    w16(0xC000 or ownerOff) + w16(type) + w16(1) + w32(ttl) + w16(rdata.size) + rdata
private fun rrNamed(owner: String, type: Int, ttl: Long, rdata: ByteArray) =
    wname(owner) + w16(type) + w16(1) + w32(ttl) + w16(rdata.size) + rdata
private fun mkResp(qname: String, qtype: Int, rcode: Int = 0, answers: List<ByteArray> = emptyList(),
                   authority: List<ByteArray> = emptyList(), flags: Int = 0x8180 or rcode): ByteArray {
    val o = java.io.ByteArrayOutputStream()
    o.write(w16(0)); o.write(w16(flags)); o.write(w16(1)); o.write(w16(answers.size)); o.write(w16(authority.size)); o.write(w16(0))
    o.write(wname(qname)); o.write(w16(qtype)); o.write(w16(1))
    answers.forEach { o.write(it) }
    authority.forEach { o.write(it) }
    return o.toByteArray()
}
private fun soa(minimum: Long) = wname("ns.example.com") + wname("host.example.com") + w32(1) + w32(2) + w32(3) + w32(4) + w32(minimum)
private fun a4(vararg b: Int) = ByteArray(4) { b[it].toByte() }

/** Counts queries, can be slow or fail, answers from a lambda. */
private class FakeTransport(val answer: (ByteArray) -> ByteArray) : DnsTransport {
    val calls = java.util.concurrent.atomic.AtomicInteger()
    @Volatile var delayMs = 0L
    @Volatile var fail = false
    @Volatile var idleClosed = 0
    @Volatile var closed = 0
    override fun exchange(query: ByteArray): ByteArray {
        calls.incrementAndGet()
        if (delayMs > 0) Thread.sleep(delayMs)
        if (fail) throw java.io.IOException("down")
        return answer(query)
    }
    override fun closeIdle() { idleClosed++ }
    override fun close() { closed++ }
}
private fun qnameOf(q: ByteArray): String = DnsMessage.readName(q, 12)!!.first
private fun qtypeOf(q: ByteArray): Int { val e = DnsMessage.readName(q, 12)!!.second; return ((q[e].toInt() and 0xff) shl 8) or (q[e + 1].toInt() and 0xff) }

fun dohTests() {
    // ---------------------------------------------------------------- DnsMessage: query
    val q = DnsMessage.buildQuery("Example.COM.", DnsMessage.TYPE_A)!!
    check("query: id 0, RD, one question, no other sections (no EDNS)",
        q.take(12).toByteArray().contentEquals(byteArrayOf(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)))
    check("query: labels + type A + class IN, name lower-cased",
        q.drop(12).toByteArray().contentEquals(wname("example.com") + w16(1) + w16(1)))
    check("query: AAAA type", DnsMessage.buildQuery("a.b", 28)!!.takeLast(4).toByteArray().contentEquals(w16(28) + w16(1)))
    check("query: empty / empty label / leading dot rejected",
        DnsMessage.buildQuery("", 1) == null && DnsMessage.buildQuery("a..b", 1) == null && DnsMessage.buildQuery(".a", 1) == null)
    check("query: 63-byte label ok, 64 rejected",
        DnsMessage.buildQuery("a".repeat(63) + ".com", 1) != null && DnsMessage.buildQuery("a".repeat(64) + ".com", 1) == null)
    val n253 = (List(3) { "a".repeat(63) } + "b".repeat(61)).joinToString(".")
    check("query: length limit", n253.length == 253 && DnsMessage.buildQuery(n253, 1) != null && DnsMessage.buildQuery(n253 + "x", 1) == null)
    check("query: IDN (non-ASCII) and spaces rejected", DnsMessage.buildQuery("b\u00fccher.de", 1) == null && DnsMessage.buildQuery("a b.com", 1) == null)
    check("query: punycode, underscore and digits accepted", DnsMessage.buildQuery("xn--bcher-kva.de", 1) != null && DnsMessage.buildQuery("_dmarc.example.com", 1) != null)

    // ---------------------------------------------------------------- DnsMessage: response
    val ok = DnsMessage.parseResponse(mkResp("example.com", 1, answers = listOf(rr(12, 1, 300, a4(93, 184, 216, 34)), rr(12, 1, 60, a4(1, 2, 3, 4)))))!!
    check("response: two A records via compression pointer",
        ok.rcode == 0 && ok.answers.size == 2 && ok.answers[0].name == "example.com" && ok.answers[0].address!!.contentEquals(a4(93, 184, 216, 34)) && ok.answers[1].ttl == 60L)
    check("response: question parsed", ok.question.name == "example.com" && ok.question.type == 1 && ok.question.clazz == 1)
    val v6 = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[15] = 1 }
    check("response: AAAA", DnsMessage.parseResponse(mkResp("a.b", 28, answers = listOf(rr(12, 28, 10, v6))))!!.answers[0].address!!.contentEquals(v6))
    // www.example.com CNAME example.com (target compressed to offset 16 = "example.com" inside the question)
    val cn = DnsMessage.parseResponse(mkResp("www.example.com", 1, answers = listOf(
        rr(12, 5, 100, byteArrayOf(0xC0.toByte(), 16)), rrNamed("example.com", 1, 50, a4(5, 6, 7, 8)))))!!
    check("response: CNAME target read through a pointer", cn.answers[0].target == "example.com" && cn.answers[1].name == "example.com")
    val nx = DnsMessage.parseResponse(mkResp("nope.example.com", 1, rcode = 3, authority = listOf(rrNamed("example.com", 6, 900, soa(60)))))!!
    check("response: NXDOMAIN, negative TTL = min(SOA ttl, minimum)", nx.rcode == 3 && nx.negativeTtl == 60L)
    check("response: negative TTL takes the SOA ttl when it is smaller",
        DnsMessage.parseResponse(mkResp("n.example.com", 1, rcode = 3, authority = listOf(rrNamed("example.com", 6, 20, soa(600)))))!!.negativeTtl == 20L)
    check("response: no SOA means no negative TTL", DnsMessage.parseResponse(mkResp("n.example.com", 1, rcode = 3))!!.negativeTtl == null)
    check("response: TTL above 2^31 is read unsigned", DnsMessage.parseResponse(mkResp("a.b", 1, answers = listOf(rr(12, 1, 0xFFFFFFFFL, a4(1, 1, 1, 1)))))!!.answers[0].ttl == 0xFFFFFFFFL)
    check("response: truncated flag", DnsMessage.parseResponse(mkResp("a.b", 1, flags = 0x8380))!!.truncated)

    // hostile input: never an exception, always null
    val good = mkResp("example.com", 1, answers = listOf(rr(12, 1, 300, a4(1, 2, 3, 4))))
    check("hostile: every truncation of a good answer is null or parses, never throws", (0 until good.size).all { n ->
        try { DnsMessage.parseResponse(good.copyOf(n)); true } catch (e: Throwable) { false } })
    check("hostile: cut inside the answer is null", DnsMessage.parseResponse(good.copyOf(good.size - 1)) == null)
    check("hostile: query bit (not a response)", DnsMessage.parseResponse(mkResp("a.b", 1, flags = 0x0100)) == null)
    check("hostile: non-QUERY opcode", DnsMessage.parseResponse(mkResp("a.b", 1, flags = 0x8980)) == null)
    check("hostile: empty and 11-byte input", DnsMessage.parseResponse(ByteArray(0)) == null && DnsMessage.parseResponse(ByteArray(11)) == null)
    val noQ = good.copyOf().also { it[5] = 0 }
    check("hostile: zero questions", DnsMessage.parseResponse(noQ) == null)
    val loop = good.copyOf().also { it[12] = 0xC0.toByte(); it[13] = 12 } // question name points at itself
    check("hostile: pointer loop", DnsMessage.parseResponse(loop) == null)
    // a chain of pointers longer than 128 hops
    run {
        val hdr = byteArrayOf(0, 0, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 0, 0, 0, 0, 0)
        val body = java.io.ByteArrayOutputStream()
        // question name at 12 is a pointer to 14, which points to 16, ... 200 hops, finally a root label
        val hops = 200
        for (i in 0 until hops) { val target = 12 + 2 * (i + 1); body.write(0xC0 or (target shr 8)); body.write(target and 0xff) }
        body.write(0)
        val msg = hdr + body.toByteArray() + w16(1) + w16(1)
        check("hostile: 200 pointer hops rejected", DnsMessage.parseResponse(msg) == null)
        val few = java.io.ByteArrayOutputStream()
        for (i in 0 until 100) { val target = 12 + 2 * (i + 1); few.write(0xC0 or (target shr 8)); few.write(target and 0xff) }
        few.write(1); few.write('a'.code); few.write(0)
        check("hostile: 100 pointer hops still fine", DnsMessage.parseResponse(hdr + few.toByteArray() + w16(1) + w16(1))?.question?.name == "a")
    }
    check("hostile: reserved label type 0x40", DnsMessage.parseResponse(good.copyOf().also { it[12] = 0x40 }) == null)
    val longName = byteArrayOf(0, 0, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 0, 0, 0, 0, 0) +
        (List(5) { byteArrayOf(63) + ByteArray(63) { 'a'.code.toByte() } }.reduce { a, b -> a + b }) + byteArrayOf(0) + w16(1) + w16(1)
    check("hostile: name over 255 bytes on the wire", DnsMessage.parseResponse(longName) == null)
    check("hostile: rdlength past the end", DnsMessage.parseResponse(good.copyOf().also { it[good.size - 5] = 0x7f }) == null)
    check("hostile: A record with 3 bytes of data", DnsMessage.parseResponse(mkResp("a.b", 1, answers = listOf(rr(12, 1, 1, byteArrayOf(1, 2, 3))))) == null)
    check("hostile: AAAA record with 4 bytes of data", DnsMessage.parseResponse(mkResp("a.b", 28, answers = listOf(rr(12, 28, 1, a4(1, 2, 3, 4))))) == null)
    check("hostile: answer count larger than the data", DnsMessage.parseResponse(good.copyOf().also { it[7] = 9 }) == null)
    check("hostile: random garbage never throws", run {
        val rnd = java.util.Random(7); var allOk = true
        repeat(3000) { val b = ByteArray(rnd.nextInt(80)); rnd.nextBytes(b); try { DnsMessage.parseResponse(b) } catch (e: Throwable) { allOk = false } }
        allOk })
    check("hostile: mutated good answers never throw", run {
        val rnd = java.util.Random(11); var allOk = true
        repeat(3000) { val b = good.copyOf(); b[rnd.nextInt(b.size)] = rnd.nextInt(256).toByte(); try { DnsMessage.parseResponse(b) } catch (e: Throwable) { allOk = false } }
        allOk })

    check("ip literal: v4", DnsMessage.parseIpLiteral("1.2.3.4")!!.contentEquals(a4(1, 2, 3, 4)))
    check("ip literal: v6 forms", DnsMessage.parseIpLiteral("2606:4700:4700::1111")!!.let { it.size == 16 && it[0] == 0x26.toByte() && it[15] == 0x11.toByte() } &&
        DnsMessage.parseIpLiteral("[::1]")!!.let { it.size == 16 && it[15] == 1.toByte() && it.take(15).all { b -> b == 0.toByte() } })
    check("ip literal: names and junk are not literals", listOf("example.com", "1.2.3", "256.1.1.1", "01.2.3.4", "").all { DnsMessage.parseIpLiteral(it) == null })

    // ---------------------------------------------------------------- DnsCache
    val c = DnsCache(3)
    fun key(n: String) = DnsCache.Key(n, 1)
    val one = Resolved(listOf(a4(1, 1, 1, 1)), false)
    c.put(key("a"), one, 100, 0); c.put(key("b"), one, 100, 0); c.put(key("c"), one, 100, 0)
    check("cache: hit before expiry, miss after", c.get(key("a"), 99_999) != null && c.get(key("b"), 100_000) == null)
    val lru = DnsCache(3)
    lru.put(key("a"), one, 100, 0); lru.put(key("b"), one, 100, 0); lru.put(key("c"), one, 100, 0)
    lru.get(key("a"), 1)                     // touch a: b is now the least recently used
    lru.put(key("d"), one, 100, 0)
    check("cache: LRU evicts the least recently used", lru.get(key("b"), 1) == null && lru.get(key("a"), 1) != null && lru.get(key("c"), 1) != null && lru.get(key("d"), 1) != null && lru.size == 3)
    check("cache: TTL clamps", DnsCache.positiveTtl(listOf(1L)) == 10L && DnsCache.positiveTtl(listOf(86_400L)) == 3600L &&
        DnsCache.positiveTtl(listOf(300L, 60L, 900L)) == 60L && DnsCache.positiveTtl(emptyList()) == 10L)
    check("cache: negative TTL clamps", DnsCache.negativeTtl(1L) == 5L && DnsCache.negativeTtl(9999L) == 300L && DnsCache.negativeTtl(60L) == 60L && DnsCache.negativeTtl(null) == 5L)
    val s = DnsCache(10)
    s.put(key("x"), one, 10, 0)
    check("stale: not before expiry needed, available just after", s.getStale(key("x"), 5_000) != null && s.getStale(key("x"), 12_000) != null)
    check("stale: 10 minutes after expiry is the limit", s.getStale(key("x"), 10_000 + 600_000) != null && s.getStale(key("x"), 10_000 + 600_001) == null)
    check("stale: an entry past the limit is dropped", s.get(key("x"), 1) == null)
    s.put(key("n"), Resolved(emptyList(), true), 10, 0)
    check("stale: negative answers are never served stale", s.getStale(key("n"), 12_000) == null)
    check("cache: clear", run { s.put(key("y"), one, 100, 0); s.clear(); s.size == 0 })

    // ---------------------------------------------------------------- Singleflight
    run {
        val sf = Singleflight<String, Int>()
        val runs = java.util.concurrent.atomic.AtomicInteger()
        val start = java.util.concurrent.CountDownLatch(1)
        val results = java.util.concurrent.ConcurrentLinkedQueue<Int>()
        val ts = List(8) { Thread { start.await(); results.add(sf.execute("k") { runs.incrementAndGet(); Thread.sleep(150); 42 }) } }
        ts.forEach { it.start() }; start.countDown(); ts.forEach { it.join() }
        check("singleflight: 8 concurrent callers, one execution", runs.get() == 1 && results.size == 8 && results.all { it == 42 })
        check("singleflight: entry removed afterwards", sf.pending == 0)
        check("singleflight: next call runs again", sf.execute("k") { runs.incrementAndGet(); 7 } == 7 && runs.get() == 2)
        val fails = java.util.concurrent.atomic.AtomicInteger()
        val go = java.util.concurrent.CountDownLatch(1)
        val ts2 = List(4) { Thread { go.await(); try { sf.execute("e") { Thread.sleep(100); throw java.io.IOException("boom") } } catch (e: java.io.IOException) { fails.incrementAndGet() } } }
        ts2.forEach { it.start() }; go.countDown(); ts2.forEach { it.join() }
        check("singleflight: a failure reaches every waiter and leaves nothing behind", fails.get() == 4 && sf.pending == 0)
        check("singleflight: after a failure the next caller retries", sf.execute("e") { 5 } == 5)
        val par = java.util.concurrent.atomic.AtomicInteger()
        val ts3 = List(3) { i -> Thread { sf.execute("p$i") { par.incrementAndGet(); Thread.sleep(50); i } } }
        ts3.forEach { it.start() }; ts3.forEach { it.join() }
        check("singleflight: different keys do not share work", par.get() == 3)
    }

    // ---------------------------------------------------------------- DohSpec
    fun spec(s: String) = DohSpec.parse(s).spec
    val cf = spec("https://cloudflare-dns.com/dns-query@address=1.1.1.1")!!
    check("doh spec: host, default port, path, address", cf.host == "cloudflare-dns.com" && cf.port == 443 && cf.path == "/dns-query" && cf.address == "1.1.1.1" && cf.sni == null)
    check("doh spec: path defaults to /dns-query", spec("https://dns.google@address=8.8.8.8")!!.path == "/dns-query")
    check("doh spec: custom port and path", spec("https://doh.example.net:8443/p/x@address=9.9.9.9")!!.let { it.port == 8443 && it.path == "/p/x" })
    check("doh spec: literal IPv4 host needs no @address", spec("https://1.1.1.1/dns-query")!!.let { it.address == "1.1.1.1" && it.host == "1.1.1.1" })
    check("doh spec: literal IPv6 host", spec("https://[2606:4700:4700::1111]/dns-query")!!.let { it.address == "2606:4700:4700::1111" && it.host == "2606:4700:4700::1111" })
    check("doh spec: name with IPv6 address", spec("https://dns.example@address=[2001:db8::1]")!!.address == "2001:db8::1")
    check("doh spec: sni option", spec("https://dns.example/dns-query@address=1.2.3.4@sni=front.example")!!.let { it.sni == "front.example" && it.tlsName == "front.example" })
    check("doh spec: options in either order", spec("https://dns.example@sni=a.example@address=1.2.3.4")!!.let { it.sni == "a.example" && it.address == "1.2.3.4" })
    check("doh spec: host is lower-cased", spec("https://DNS.Example@address=1.2.3.4")!!.host == "dns.example")
    DohSpec.parse("https://dns.example/dns-query").let {
        check("doh spec: a NAME without an IP is refused with the pinning message", it.spec == null && it.error == DohSpec.NEED_ADDRESS)
    }
    check("doh spec: http:// refused", spec("http://1.1.1.1/dns-query") == null)
    check("doh spec: udp:// and bare IP refused", spec("udp://1.1.1.1") == null && spec("1.1.1.1") == null)
    check("doh spec: user info refused", spec("https://user:pw@dns.example@address=1.2.3.4") == null && spec("https://user@dns.example/dns-query") == null)
    check("doh spec: bad address / option / port",
        spec("https://dns.example@address=not-an-ip") == null && spec("https://dns.example@address=dns2.example") == null &&
            spec("https://dns.example@foo=bar") == null && spec("https://dns.example@address") == null &&
            spec("https://dns.example:0@address=1.2.3.4") == null && spec("https://dns.example:99999@address=1.2.3.4") == null &&
            spec("https://dns.example:abc@address=1.2.3.4") == null)
    check("doh spec: duplicate options refused", spec("https://d.example@address=1.1.1.1@address=2.2.2.2") == null && spec("https://d.example@address=1.1.1.1@sni=a.b@sni=c.d") == null)
    check("doh spec: bad host names", listOf("https://-bad.example@address=1.1.1.1", "https://a..b@address=1.1.1.1", "https://b\u00fccher.de@address=1.1.1.1",
        "https://${"a".repeat(64)}.com@address=1.1.1.1", "https://@address=1.1.1.1", "https://").all { spec(it) == null })
    check("doh spec: query string / fragment / spaces refused", spec("https://d.example/dns-query?x=1@address=1.1.1.1") == null && spec("https://d.example/a b@address=1.1.1.1") == null)
    check("doh spec: canonical round-trips", listOf(
        "https://cloudflare-dns.com/dns-query@address=1.1.1.1", "https://1.1.1.1", "https://[2606:4700:4700::1111]",
        "https://dns.example:8443/p@address=9.9.9.9@sni=x.example", "https://dns.example/dns-query@address=[2001:db8::1]"
    ).all { raw -> val a = spec(raw)!!; spec(a.canonical) == a })
    check("doh spec: addressBytes", cf.addressBytes().contentEquals(a4(1, 1, 1, 1)))
    val lst = DohSpec.parseList("https://dns.google@address=8.8.8.8\nhttps://dns.google@address=8.8.8.8, https://cloudflare-dns.com@address=1.1.1.1 https://dns.quad9.net@address=9.9.9.9;https://x.example@address=2.2.2.2")
    check("doh list: order kept, duplicate dropped, at most 3", lst.valid.map { it.host } == listOf("dns.google", "cloudflare-dns.com", "dns.quad9.net") && lst.errors.size == 1)
    check("doh list: errors name the token", DohSpec.parseList("https://nope.example\nhttps://1.1.1.1").let { it.valid.size == 1 && it.errors.single().first == "https://nope.example" })
    check("doh presets all parse", DohPresets.ALL.all { spec(it.second) != null })

    // ---------------------------------------------------------------- FrontPlan / FrontGuard
    run {
        val none = PrivacyChain.NONE; val psi = PrivacyChain.PSIPHON; val tor = PrivacyChain.TOR
        val p1 = FrontPlan.of(none, false, false, 1819)
        check("plan: no chain, no DoH: update10 (core on the public port, no front)",
            !p1.frontOn && p1.corePort == 1819 && p1.chainPort == null && p1.upstreamPort == 1819 && !p1.udpRelay && p1.coreGetsRoutes && !p1.localDoh)
        val p1b = FrontPlan.of(none, false, true, 1819)
        check("plan: no chain, rules but no DoH: still no front (the core applies them)", !p1b.frontOn && p1b.corePort == 1819 && p1b.coreGetsRoutes)
        val p2 = FrontPlan.of(psi, false, true, 1819)
        check("plan: chain + rules, no DoH: update10 front", p2.frontOn && p2.corePort == 1823 && p2.chainPort == 1824 && p2.upstreamPort == 1824 && !p2.udpRelay && !p2.coreGetsRoutes && !p2.localDoh)
        val p3 = FrontPlan.of(tor, false, false, 1819)
        check("plan: chain, no rules, no DoH: update10 (chain on the public port)", !p3.frontOn && p3.corePort == 1823 && p3.chainPort == 1819 && p3.upstreamPort == 1819 && p3.coreGetsRoutes)
        val p4 = FrontPlan.of(none, true, false, 1819)
        check("plan: DoH without a chain: front on, core on 1823, UDP goes through the relay, core keeps the rules",
            p4.frontOn && p4.corePort == 1823 && p4.chainPort == null && p4.upstreamPort == 1823 && p4.udpRelay && p4.coreGetsRoutes && p4.localDoh)
        val p5 = FrontPlan.of(psi, true, false, 1819)
        check("plan: DoH with Psiphon (no rules): front on, chain on 1824, no UDP, no routes for the core",
            p5.frontOn && p5.corePort == 1823 && p5.chainPort == 1824 && p5.upstreamPort == 1824 && !p5.udpRelay && !p5.coreGetsRoutes && p5.localDoh)
        check("plan: DoH with Tor behaves like Psiphon", FrontPlan.of(tor, true, true, 1900).let { it.upstreamPort == 1824 && it.corePort == 1823 && it.frontOn })
        check("plan: the front never shares a port with the core or the chain", listOf(none, psi, tor).all { ch ->
            listOf(false, true).all { d -> listOf(false, true).all { r ->
                val p = FrontPlan.of(ch, d, r, 1819)
                val ports = listOfNotNull(p.corePort, p.chainPort)
                ports.distinct().size == ports.size && (!p.frontOn || 1819 !in ports) } } })
    }
    fun ipb(s: String) = s.split('.').map { it.toInt().toByte() }.toByteArray()
    check("guard: fake network 100.64.0.0/10", listOf("100.64.0.1", "100.100.5.5", "100.127.255.255").all { FrontGuard.check(ipb(it)) == FrontGuard.Verdict.STALE_FAKE_IP } &&
        listOf("100.63.255.255", "100.128.0.0", "99.64.0.1", "101.64.0.1").all { FrontGuard.check(ipb(it)) == FrontGuard.Verdict.OK })
    check("guard: 198.18.0.0/15 reserved", listOf("198.18.0.2", "198.19.255.255").all { FrontGuard.check(ipb(it)) == FrontGuard.Verdict.RESERVED } &&
        listOf("198.17.255.255", "198.20.0.0", "198.1.0.2").all { FrontGuard.check(ipb(it)) == FrontGuard.Verdict.OK })
    check("guard: ordinary and IPv6 addresses pass, reply codes", FrontGuard.check(ipb("8.8.8.8")) == FrontGuard.Verdict.OK && FrontGuard.check(ByteArray(16)) == FrontGuard.Verdict.OK &&
        FrontGuard.replyCode(FrontGuard.Verdict.STALE_FAKE_IP) == 4 && FrontGuard.replyCode(FrontGuard.Verdict.RESERVED) == 5)

    // ---------------------------------------------------------------- EngineConfig / EngineEnvironment
    run {
        val base = EngineConfig()
        check("config: DoH is off by default", !base.dohEnabled && !base.dohActive)
        check("config: switch on but no resolver is still off", !base.copy(dohOn = true).dohEnabled)
        check("config: a resolver without the switch is still off", !base.copy(dohResolvers = listOf("https://1.1.1.1")).dohEnabled)
        val on = base.copy(dohOn = true, dohResolvers = listOf("https://1.1.1.1"), protocol = Protocol.WIREGUARD)
        check("config: enabled", on.dohEnabled && on.dohActive)
        check("config: Psiphon keeps DoH", on.copy(privacyChain = PrivacyChain.PSIPHON).dohActive)
        check("config: Tor keeps DoH by default", on.copy(privacyChain = PrivacyChain.TOR).dohActive)
        check("config: Tor with the Tor switch off drops DoH", !on.copy(privacyChain = PrivacyChain.TOR, dohViaTor = false).dohActive)
        check("config: the Tor switch does not touch Psiphon or no chain", on.copy(privacyChain = PrivacyChain.PSIPHON, dohViaTor = false).dohActive && on.copy(dohViaTor = false).dohActive)
        check("config: SMART ignores the chain, so the Tor switch is moot", on.copy(protocol = Protocol.SMART, privacyChain = PrivacyChain.TOR, dohViaTor = false).dohActive)
        fun env(c: EngineConfig, rules: Boolean = false): Map<String, String> =
            EngineEnvironment.build(c, "/x/aether.toml", "/tmp", if (FrontPlan.of(c.effectiveChain, c.dohActive, rules, c.socksPort).coreGetsRoutes) "/x/routes" else null,
                emptyMap(), "/n/libpsiphon.so", "/d", FrontPlan.of(c.effectiveChain, c.dohActive, rules, c.socksPort))
        val e0 = env(base.copy(protocol = Protocol.WIREGUARD))
        check("env: update10 without chain and DoH: core on the public port", e0["AETHER_SOCKS"] == "127.0.0.1:1819" && "AETHER_PSIPHON" !in e0 && e0["AETHER_ROUTES_FILE"] == "/x/routes")
        val e1 = env(on)
        check("env: DoH without chain: core on 1823, routes kept for the core", e1["AETHER_SOCKS"] == "127.0.0.1:1823" && e1["AETHER_ROUTES_FILE"] == "/x/routes")
        val e2 = env(on.copy(privacyChain = PrivacyChain.PSIPHON))
        check("env: DoH + Psiphon: core 1823, Psiphon 1824, no routes file for the core", e2["AETHER_SOCKS"] == "127.0.0.1:1823" && e2["AETHER_PSIPHON_BIND"] == "127.0.0.1:1824" && "AETHER_ROUTES_FILE" !in e2)
        val e3 = env(on.copy(privacyChain = PrivacyChain.TOR))
        check("env: DoH + Tor: Tor on 1824", e3["AETHER_TOR_BIND"] == "127.0.0.1:1824" && e3["AETHER_SOCKS"] == "127.0.0.1:1823")
        val e4 = env(base.copy(protocol = Protocol.WIREGUARD, privacyChain = PrivacyChain.PSIPHON), rules = true)
        check("env: update10 chain + rules is unchanged (front, 1824, no routes)", e4["AETHER_PSIPHON_BIND"] == "127.0.0.1:1824" && "AETHER_ROUTES_FILE" !in e4 && e4["AETHER_SOCKS"] == "127.0.0.1:1823")
        val e5 = env(base.copy(protocol = Protocol.WIREGUARD, privacyChain = PrivacyChain.PSIPHON), rules = false)
        check("env: update10 chain, no rules is unchanged (Psiphon on the public port)", e5["AETHER_PSIPHON_BIND"] == "127.0.0.1:1819" && e5["AETHER_SOCKS"] == "127.0.0.1:1823")
        check("env: the core is never told about DoH (AETHER_DNS untouched)", listOf(e0, e1, e2, e3).all { it.keys.none { k -> k.contains("DOH") } } && "AETHER_DNS" !in e1)
    }

    // ---------------------------------------------------------------- FallbackTransport
    run {
        val bad = FakeTransport { error("unused") }.also { it.fail = true }
        val good2 = FakeTransport { mkResp(qnameOf(it), qtypeOf(it), answers = listOf(rr(12, 1, 60, a4(9, 9, 9, 9)))) }
        val fb = FallbackTransport(listOf(bad, good2))
        val r = fb.exchange(DnsMessage.buildQuery("x.example", 1)!!)
        check("fallback: next DoH resolver answers when the first failed", bad.calls.get() == 1 && good2.calls.get() == 1 && DnsMessage.parseResponse(r) != null)
        val nxT = FakeTransport { mkResp(qnameOf(it), qtypeOf(it), rcode = 3) }
        val second = FakeTransport { mkResp(qnameOf(it), qtypeOf(it)) }
        FallbackTransport(listOf(nxT, second)).exchange(DnsMessage.buildQuery("x.example", 1)!!)
        check("fallback: an NXDOMAIN answer is an answer, the second resolver is not asked", second.calls.get() == 0)
        val b1 = FakeTransport { error("x") }.also { it.fail = true }; val b2 = FakeTransport { error("x") }.also { it.fail = true }
        check("fallback: all failing is a failure (never plain DNS)", try { FallbackTransport(listOf(b1, b2)).exchange(ByteArray(12)); false } catch (e: java.io.IOException) { b1.calls.get() == 1 && b2.calls.get() == 1 })
        FallbackTransport(listOf(b1, b2)).also { it.closeIdle(); it.close() }
        check("fallback: closeIdle/close reach every transport", b1.idleClosed == 1 && b2.idleClosed == 1 && b1.closed == 1 && b2.closed == 1)
    }

    // ---------------------------------------------------------------- FrontResolver
    fun answerA(ip: IntArray, ttl: Long = 300) = FakeTransport { q -> mkResp(qnameOf(q), qtypeOf(q), answers = if (qtypeOf(q) == 1) listOf(rr(12, 1, ttl, a4(ip[0], ip[1], ip[2], ip[3]))) else emptyList()) }
    run {
        val t = answerA(intArrayOf(93, 184, 216, 34))
        val r = FrontResolver(t)
        val a = r.resolve("Example.com")
        check("resolver: resolves a name", a.size == 1 && a[0].address.contentEquals(a4(93, 184, 216, 34)))
        r.resolve("example.com"); r.resolve("EXAMPLE.COM.")
        check("resolver: repeat requests are served from the cache", t.calls.get() == 1 && r.cacheHits == 2L && r.queries == 1L)
        check("resolver: IP literals never touch DNS", r.resolve("8.8.8.8")[0].address.contentEquals(a4(8, 8, 8, 8)) && r.resolve("[2001:db8::1]")[0].address.size == 16 && t.calls.get() == 1)
        check("resolver: unsendable name is a failure, not a lookup", try { r.resolve("bad name"); false } catch (e: ResolveFailure) { t.calls.get() == 1 })
        r.closeIdle(); check("resolver: closeIdle reaches the transport", t.idleClosed == 1)
        r.clear(); r.resolve("example.com")
        check("resolver: clear() empties the cache and closes the transport", t.calls.get() == 2 && t.closed == 1)
    }
    run {
        val t = answerA(intArrayOf(1, 2, 3, 4)).also { it.delayMs = 200 }
        val r = FrontResolver(t)
        val go = java.util.concurrent.CountDownLatch(1)
        val ok = java.util.concurrent.atomic.AtomicInteger()
        val ts = List(8) { Thread { go.await(); if (r.resolve("busy.example").size == 1) ok.incrementAndGet() } }
        ts.forEach { it.start() }; go.countDown(); ts.forEach { it.join() }
        check("resolver: 8 simultaneous lookups of one name cost one request", t.calls.get() == 1 && ok.get() == 8)
    }
    run {
        val t = FakeTransport { q -> mkResp(qnameOf(q), qtypeOf(q), rcode = 3, authority = listOf(rrNamed("example.com", 6, 300, soa(120)))) }
        val r = FrontResolver(t)
        val f1 = try { r.resolve("nope.example.com"); null } catch (e: ResolveFailure) { e }
        val f2 = try { r.resolve("nope.example.com"); null } catch (e: ResolveFailure) { e }
        check("resolver: NXDOMAIN is a failure flagged nxdomain and is cached", f1?.nxdomain == true && f2?.nxdomain == true && t.calls.get() == 1 && r.nxdomains == 2L)
    }
    run {
        val t = FakeTransport { q -> mkResp(qnameOf(q), qtypeOf(q)) } // NOERROR, no records: NODATA
        check("resolver: NODATA with ipMode v4 never asks AAAA", run { try { FrontResolver(t, "v4").resolve("a.example"); false } catch (e: ResolveFailure) { !e.nxdomain && t.calls.get() == 1 } })
        val t2 = FakeTransport { q -> if (qtypeOf(q) == 28) mkResp(qnameOf(q), 28, answers = listOf(rr(12, 28, 60, v6))) else mkResp(qnameOf(q), 1) }
        check("resolver: ipMode both falls back to AAAA when there is no A", FrontResolver(t2, "both").resolve("a.example")[0].address.size == 16 && t2.calls.get() == 2)
        val t3 = FakeTransport { q -> if (qtypeOf(q) == 28) mkResp(qnameOf(q), 28, answers = listOf(rr(12, 28, 60, v6))) else mkResp(qnameOf(q), 1, answers = listOf(rr(12, 1, 60, a4(1, 1, 1, 1)))) }
        check("resolver: ipMode v6 asks AAAA first", FrontResolver(t3, "v6").resolve("a.example")[0].address.size == 16 && t3.calls.get() == 1)
        check("resolver: ipMode v4 asks only A", FrontResolver(t3, "v4").resolve("a.example")[0].address.size == 4)
    }
    run {
        // an answer that has an unrelated A record next to the CNAME chain: only the chain counts
        val t = FakeTransport { q -> mkResp(qnameOf(q), 1, answers = listOf(
            rr(12, 5, 100, byteArrayOf(0xC0.toByte(), 16)),                  // www.example.com -> example.com
            rrNamed("evil.example", 1, 100, a4(6, 6, 6, 6)),                  // not part of the chain
            rrNamed("example.com", 1, 100, a4(5, 6, 7, 8)))) }
        val a = FrontResolver(t).resolve("www.example.com")
        check("resolver: follows CNAMEs, ignores records for other names", a.size == 1 && a[0].address.contentEquals(a4(5, 6, 7, 8)))
        val t2 = FakeTransport { q -> mkResp(qnameOf(q), 1, answers = listOf(rrNamed("other.example", 1, 100, a4(6, 6, 6, 6)))) }
        check("resolver: only unrelated records means no address", try { FrontResolver(t2).resolve("www.example.com"); false } catch (e: ResolveFailure) { true })
    }
    run {
        val t = FakeTransport { q -> mkResp(qnameOf(q), 1, answers = listOf(rr(12, 1, 300, a4(1, 1, 1, 1)), rr(12, 1, 300, a4(1, 1, 1, 1)), rr(12, 1, 300, a4(2, 2, 2, 2)))) }
        check("resolver: duplicate addresses are removed", FrontResolver(t).resolve("d.example").size == 2)
    }
    run {
        // failures are failures: no plain-DNS fallback exists to be called
        val t = answerA(intArrayOf(1, 2, 3, 4)).also { it.fail = true }
        val r = FrontResolver(t)
        check("resolver: DoH down is a ResolveFailure", try { r.resolve("a.example"); false } catch (e: ResolveFailure) { !e.nxdomain && r.failures == 1L })
        t.fail = false
        check("resolver: a failed lookup is not cached, the next one works", r.resolve("a.example").size == 1)
        val servfail = FakeTransport { q -> mkResp(qnameOf(q), qtypeOf(q), rcode = 2) }
        check("resolver: SERVFAIL is a failure and is not cached", run { val rr2 = FrontResolver(servfail); repeat(2) { try { rr2.resolve("s.example") } catch (_: ResolveFailure) {} }; servfail.calls.get() == 2 })
        val trunc = FakeTransport { q -> mkResp(qnameOf(q), qtypeOf(q), flags = 0x8380) }
        check("resolver: truncated answer is a failure", try { FrontResolver(trunc).resolve("t.example"); false } catch (e: ResolveFailure) { true })
        val wrongQ = FakeTransport { mkResp("other.example", 1, answers = listOf(rr(12, 1, 60, a4(6, 6, 6, 6)))) }
        check("resolver: an answer for another question is refused", try { FrontResolver(wrongQ).resolve("a.example"); false } catch (e: ResolveFailure) { true })
        val junk = FakeTransport { byteArrayOf(1, 2, 3) }
        check("resolver: garbage is a failure", try { FrontResolver(junk).resolve("a.example"); false } catch (e: ResolveFailure) { true })
    }
    run {
        var now = 1_000_000L
        val t = answerA(intArrayOf(7, 7, 7, 7), ttl = 30)
        val r = FrontResolver(t, serveStale = true, clock = { now })
        r.resolve("stale.example")
        now += 31_000; t.fail = true
        check("stale: expired entry is served when DoH is down", r.resolve("stale.example")[0].address.contentEquals(a4(7, 7, 7, 7)) && r.staleServed == 1L)
        now += 10 * 60 * 1000L
        check("stale: not after 10 minutes", try { r.resolve("stale.example"); false } catch (e: ResolveFailure) { true })
        var now2 = 1_000_000L
        val t2 = answerA(intArrayOf(7, 7, 7, 7), ttl = 30)
        val r2 = FrontResolver(t2, serveStale = false, clock = { now2 })
        r2.resolve("s.example"); now2 += 31_000; t2.fail = true
        check("stale: off by default means a failure", try { r2.resolve("s.example"); false } catch (e: ResolveFailure) { true })
        val t3 = answerA(intArrayOf(7, 7, 7, 7), ttl = 30)
        var now3 = 0L
        val r3 = FrontResolver(t3, serveStale = true, clock = { now3 })
        r3.resolve("f.example"); now3 += 31_000
        check("stale: a fresh answer is preferred when DoH works", run { r3.resolve("f.example"); t3.calls.get() == 2 && r3.staleServed == 0L })
    }
    check("resolver: summary never contains a name", run {
        val t = answerA(intArrayOf(1, 1, 1, 1)); val r = FrontResolver(t); r.resolve("secret-name.example")
        !r.summary().contains("secret") })

    routeFrontTests()
    udpRelayTests()
}


// ---------------------------------------------------------------------------------------------------
// RouteFront end to end: a real front on a loopback port, a fake SOCKS5 upstream, a fake DoH transport.
// ---------------------------------------------------------------------------------------------------

/**
 * [udp]: a real UDP relay behind ASSOCIATE. It echoes every datagram back with the same SOCKS5 header and the payload
 * prefixed "R:", and records the destination of each ("host:port"). [failUdp]: ASSOCIATE is answered with an error.
 */
private class FakeUpstream(val rejectIps: Set<String> = emptySet(), val udp: Boolean = false, val failUdp: Boolean = false) {
    val server = java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort
    val requests = java.util.concurrent.ConcurrentLinkedQueue<String>()
    val udpSeen = java.util.concurrent.ConcurrentLinkedQueue<String>()
    val udpSock: java.net.DatagramSocket? = if (udp) java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1")) else null
    val udpBnd = byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0x15, 0xB3.toByte()).also {
        udpSock?.let { u -> it[8] = (u.localPort shr 8).toByte(); it[9] = u.localPort.toByte() } // 127.0.0.1:5555 unless real
    }
    val controlClosed = java.util.concurrent.CountDownLatch(1)
    init {
        udpSock?.let { u ->
            Thread {
                val b = ByteArray(65535)
                while (!u.isClosed) {
                    val pk = java.net.DatagramPacket(b, b.size)
                    try { u.receive(pk) } catch (_: Exception) { break }
                    val n = pk.length
                    val hs = when (b[3].toInt()) { 1 -> 10; 4 -> 22; else -> 7 + (b[4].toInt() and 0xff) }
                    val host = when (b[3].toInt()) { 1 -> (4..7).joinToString(".") { (b[it].toInt() and 0xff).toString() }; 3 -> String(b, 5, b[4].toInt() and 0xff); else -> "v6" }
                    val prt = ((b[hs - 2].toInt() and 0xff) shl 8) or (b[hs - 1].toInt() and 0xff)
                    udpSeen.add("$host:$prt")
                    val out = b.copyOfRange(0, hs) + "R:".toByteArray() + b.copyOfRange(hs, n)
                    try { u.send(java.net.DatagramPacket(out, out.size, pk.socketAddress)) } catch (_: Exception) { }
                }
            }.apply { isDaemon = true }.start()
        }
        Thread {
            while (!server.isClosed) {
                val c = try { server.accept() } catch (_: Exception) { break }
                Thread { serve(c) }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true }.start()
    }
    private fun rd(i: java.io.InputStream, n: Int): ByteArray { val b = ByteArray(n); var g = 0; while (g < n) { val r = i.read(b, g, n - g); if (r < 0) throw java.io.IOException("eof"); g += r }; return b }
    private fun serve(c: java.net.Socket) {
        try {
            val i = c.getInputStream(); val o = c.getOutputStream()
            rd(i, 3); o.write(byteArrayOf(5, 0)); o.flush()
            val h = rd(i, 4)
            val target = when (h[3].toInt()) {
                1 -> rd(i, 4).joinToString(".") { (it.toInt() and 0xff).toString() }
                4 -> "v6"
                else -> { val l = rd(i, 1)[0].toInt() and 0xff; String(rd(i, l)) }
            }
            val pb = rd(i, 2); val prt = ((pb[0].toInt() and 0xff) shl 8) or (pb[1].toInt() and 0xff)
            if (h[1].toInt() == 3) {
                requests.add("UDP")
                if (failUdp) { o.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0)); o.flush(); return }
                o.write(udpBnd); o.flush()
                try { while (i.read() >= 0) { } } catch (_: Exception) { }
                controlClosed.countDown()
                return
            }
            requests.add("CONNECT $target:$prt")
            if (target in rejectIps) { o.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0)); o.flush(); return }
            o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); o.flush()
            val buf = ByteArray(1024)
            while (true) { val n = i.read(buf); if (n < 0) break; o.write(buf, 0, n); o.flush() }
        } catch (_: Exception) { } finally { try { c.close() } catch (_: Exception) { } }
    }
    fun close() { try { server.close() } catch (_: Exception) { }; udpSock?.close() }
}

/** Plain TCP echo server: the target of DIRECT connections. */
private class EchoServer {
    val server = java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort
    val accepted = java.util.concurrent.atomic.AtomicInteger()
    init {
        Thread {
            while (!server.isClosed) {
                val c = try { server.accept() } catch (_: Exception) { break }
                accepted.incrementAndGet()
                Thread {
                    try { val i = c.getInputStream(); val o = c.getOutputStream(); val b = ByteArray(1024)
                        while (true) { val n = i.read(b); if (n < 0) break; o.write(b, 0, n); o.flush() } } catch (_: Exception) { } finally { try { c.close() } catch (_: Exception) { } }
                }.apply { isDaemon = true }.start()
            }
        }.apply { isDaemon = true }.start()
    }
    fun close() { try { server.close() } catch (_: Exception) { } }
}

private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

/** Speaks SOCKS5 to the front. Returns the reply code and the open socket. */
private fun socks(frontPort: Int, request: ByteArray): Pair<Int, java.net.Socket> {
    val s = java.net.Socket("127.0.0.1", frontPort); s.soTimeout = 5000
    val o = s.getOutputStream(); val i = s.getInputStream()
    o.write(byteArrayOf(5, 1, 0)); o.flush()
    val g = ByteArray(2); var n = 0; while (n < 2) n += i.read(g, n, 2 - n)
    o.write(request); o.flush()
    val head = ByteArray(4); n = 0; while (n < 4) n += i.read(head, n, 4 - n)
    val rest = when (head[3].toInt()) { 1 -> 6; 4 -> 18; else -> 0 }
    val tail = ByteArray(rest); n = 0; while (n < rest) n += i.read(tail, n, rest - n)
    lastReply = head + tail
    return head[1].toInt() to s
}
private var lastReply: ByteArray = ByteArray(0)
private fun reqName(name: String, port: Int) = byteArrayOf(5, 1, 0, 3, name.length.toByte()) + name.toByteArray() + w16(port)
private fun reqIp(ip: String, port: Int) = byteArrayOf(5, 1, 0, 1) + ip.split('.').map { it.toInt().toByte() }.toByteArray() + w16(port)

private fun echoOk(s: java.net.Socket): Boolean = try {
    s.getOutputStream().write("hello".toByteArray()); s.getOutputStream().flush()
    val b = ByteArray(5); var n = 0; while (n < 5) { val r = s.getInputStream().read(b, n, 5 - n); if (r < 0) break; n += r }
    String(b, 0, n) == "hello"
} catch (_: Exception) { false }

fun routeFrontTests() {
    val rules = RouteMatcher.parse("[block]\nblocked.example\n[direct]\nlocalhost\ndirect.example\n127.0.0.1\n")
    fun front(up: FakeUpstream, resolver: FrontResolver?, opts: RouteFront.Options? = null, matcher: RouteMatcher = rules, logs: MutableList<String> = ArrayList()): Pair<RouteFront, Int> {
        val port = freePort()
        val f = RouteFront(port, up.port, matcher, opts ?: RouteFront.Options(resolver = resolver, guardFakeIps = resolver != null)) { synchronized(logs) { logs.add(it) } }
        f.start()
        return f to port
    }
    fun transportFor(vararg ips: String, calls: MutableList<String>? = null) = FakeTransport { q ->
        calls?.add(qnameOf(q))
        val parts = ips.map { it.split('.').map { x -> x.toInt() }.toIntArray() }
        mkResp(qnameOf(q), qtypeOf(q), answers = if (qtypeOf(q) == 1) parts.map { rr(12, 1, 120, a4(it[0], it[1], it[2], it[3])) } else emptyList())
    }

    // --- PROXY name -> DoH -> CONNECT with the IP, data flows
    run {
        val up = FakeUpstream(); val t = transportFor("93.184.216.34"); val logs = ArrayList<String>()
        val (f, port) = front(up, FrontResolver(t), logs = logs)
        val (code, sock) = socks(port, reqName("example.com", 443))
        check("front: PROXY name is resolved by DoH and forwarded as an IP CONNECT", code == 0 && up.requests.toList() == listOf("CONNECT 93.184.216.34:443"))
        check("front: data flows both ways through the upstream", echoOk(sock))
        sock.close()
        val (code2, s2) = socks(port, reqName("example.com", 443)); s2.close()
        check("front: second connection to the same name uses the cache", code2 == 0 && t.calls.get() == 1)
        f.onIdle(); check("front: onIdle() closes idle DoH connections", t.idleClosed == 1)
        f.stop()
        check("front: stop() closes the DoH transport and logs one summary", t.closed == 1 && logs.any { it.startsWith("[route] front stopped") } && logs.any { it.contains("doh:") })
        check("front: no domain name ever reaches the log", logs.none { it.contains("example") })
        up.close()
    }
    // --- NXDOMAIN, DoH down: refused, upstream never contacted
    run {
        val up = FakeUpstream(); val nxT = FakeTransport { q -> mkResp(qnameOf(q), qtypeOf(q), rcode = 3) }
        val (f, port) = front(up, FrontResolver(nxT))
        val (code, s) = socks(port, reqName("nothing.example", 443)); s.close()
        check("front: NXDOMAIN becomes SOCKS 0x04 and nothing is forwarded", code == 4 && up.requests.isEmpty())
        f.stop(); up.close()
        val up2 = FakeUpstream(); val down = FakeTransport { error("x") }.also { it.fail = true }
        val (f2, port2) = front(up2, FrontResolver(down))
        val (code2, s2) = socks(port2, reqName("a.example", 443)); s2.close()
        check("front: DoH unreachable is SOCKS 0x04 with NO fallback to the upstream resolving the name", code2 == 4 && up2.requests.isEmpty() && down.calls.get() >= 1)
        f2.stop(); up2.close()
    }
    // --- stale fake IPs and the DNS range
    run {
        val up = FakeUpstream(); val (f, port) = front(up, FrontResolver(transportFor("1.1.1.1")))
        val (c1, s1) = socks(port, reqIp("100.64.9.9", 443)); s1.close()
        val (c2, s2) = socks(port, reqIp("198.18.0.2", 853)); s2.close()
        val (c3, s3) = socks(port, reqIp("198.19.1.1", 53)); s3.close()
        check("front: a stale fake IP is refused (0x04), DoT to the DNS address at once (0x05)", c1 == 4 && c2 == 5 && c3 == 5 && up.requests.isEmpty())
        val (c4, s4) = socks(port, reqIp("8.8.8.8", 53)); s4.close()
        check("front: an ordinary IP goes to the upstream", c4 == 0 && up.requests.toList() == listOf("CONNECT 8.8.8.8:53"))
        f.stop(); up.close()
        val up2 = FakeUpstream(); val (f2, port2) = front(up2, null, RouteFront.Options()) // update10 behaviour
        val (c5, s5) = socks(port2, reqIp("100.64.9.9", 443)); s5.close()
        check("front: without DoH there is no fake-IP guard (update10 behaviour)", c5 == 0 && up2.requests.toList() == listOf("CONNECT 100.64.9.9:443"))
        f2.stop(); up2.close()
    }
    // --- rules
    run {
        val up = FakeUpstream(); val calls = ArrayList<String>(); val t = transportFor("1.1.1.1", calls = calls)
        val (f, port) = front(up, FrontResolver(t))
        val (cb, sb) = socks(port, reqName("blocked.example", 443)); sb.close()
        check("front: BLOCK rule refuses with 0x02 and never resolves the name", cb == 2 && calls.isEmpty() && up.requests.isEmpty())
        f.stop(); up.close()
    }
    run {
        val up = FakeUpstream(); val echo = EchoServer(); val calls = ArrayList<String>()
        val t = transportFor("127.0.0.1", calls = calls)
        val (f, port) = front(up, FrontResolver(t))
        val (c1, s1) = socks(port, reqName("localhost", echo.port))
        check("front: DIRECT name uses the system resolver and connects from the app", c1 == 0 && echoOk(s1) && up.requests.isEmpty() && calls.isEmpty())
        s1.close()
        val (c2, s2) = socks(port, reqIp("127.0.0.1", echo.port))
        check("front: DIRECT IP connects from the app", c2 == 0 && echoOk(s2) && up.requests.isEmpty()); s2.close()
        f.stop()
        // DoH for direct names
        val dcalls = ArrayList<String>()
        val dt = transportFor("127.0.0.1", calls = dcalls)
        val (f2, port2) = front(up, null, RouteFront.Options(resolver = FrontResolver(transportFor("1.1.1.1")), directResolver = FrontResolver(dt), guardFakeIps = true))
        val (c3, s3) = socks(port2, reqName("direct.example", echo.port))
        check("front: DoH-for-Direct resolves the DIRECT name by DoH and connects from the app", c3 == 0 && echoOk(s3) && dcalls == listOf("direct.example") && up.requests.isEmpty()); s3.close()
        f2.stop()
        val nxD = FakeTransport { q -> mkResp(qnameOf(q), qtypeOf(q), rcode = 3) }
        val (f3, port3) = front(up, null, RouteFront.Options(resolver = FrontResolver(transportFor("1.1.1.1")), directResolver = FrontResolver(nxD)))
        val (c4, s4) = socks(port3, reqName("direct.example", echo.port)); s4.close()
        check("front: DoH-for-Direct failure is a refusal, never the system resolver", c4 == 4)
        f3.stop(); echo.close(); up.close()
    }
    // --- address fallback
    run {
        val up = FakeUpstream(rejectIps = setOf("1.1.1.1")); val (f, port) = front(up, FrontResolver(transportFor("1.1.1.1", "2.2.2.2")))
        val (code, s) = socks(port, reqName("multi.example", 80))
        check("front: the next address is tried when the first is refused (order kept)", code == 0 && up.requests.toList() == listOf("CONNECT 1.1.1.1:80", "CONNECT 2.2.2.2:80") && echoOk(s))
        s.close(); f.stop(); up.close()
        val up2 = FakeUpstream(rejectIps = setOf("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"))
        val (f2, port2) = front(up2, FrontResolver(transportFor("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")))
        val (code2, s2) = socks(port2, reqName("multi.example", 80)); s2.close()
        check("front: at most three addresses are tried, then the upstream's error is reported", code2 == 5 && up2.requests.size == 3)
        f2.stop(); up2.close()
    }
    // --- UDP ASSOCIATE: refusals (the carried case is in udpRelayTests)
    run {
        val up2 = FakeUpstream(); val (f2, port2) = front(up2, FrontResolver(transportFor("1.1.1.1")))
        val (code2, s2) = socks(port2, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); s2.close()
        check("front: UDP ASSOCIATE on a chain that cannot carry UDP (udpCapable=false) is refused with 0x07", code2 == 7 && up2.requests.isEmpty())
        f2.stop(); up2.close()
        val up3 = FakeUpstream(); val (f3, port3) = front(up3, null, RouteFront.Options())
        val (code3, s3) = socks(port3, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); s3.close()
        check("front: update10 behaviour for UDP is unchanged (0x07)", code3 == 7)
        f3.stop(); up3.close()
        val up4 = FakeUpstream(); val (f4, port4) = front(up4, null, RouteFront.Options(udpCapable = true))
        val (code4, s4) = socks(port4, byteArrayOf(5, 4, 0, 1, 0, 0, 0, 0, 0, 0)); s4.close()
        check("front: an unknown command is 0x07", code4 == 7 && up4.requests.isEmpty())
        f4.stop(); up4.close()
    }
    // --- .onion and the legacy path
    run {
        val up = FakeUpstream(); val calls = ArrayList<String>()
        val (f, port) = front(up, FrontResolver(transportFor("1.1.1.1", calls = calls)))
        val (c1, s1) = socks(port, reqName("abcdefghijklmnop.onion", 80)); s1.close()
        check("front: .onion without Tor is refused and the name goes nowhere", c1 == 4 && up.requests.isEmpty() && calls.isEmpty())
        f.stop()
        val (f2, port2) = front(up, null, RouteFront.Options(resolver = FrontResolver(transportFor("1.1.1.1", calls = calls)), guardFakeIps = true, allowOnion = true))
        val (c2, s2) = socks(port2, reqName("abcdefghijklmnop.onion", 80)); s2.close()
        check("front: .onion with Tor is forwarded as a name, not resolved", c2 == 0 && up.requests.toList() == listOf("CONNECT abcdefghijklmnop.onion:80") && calls.isEmpty())
        f2.stop(); up.close()
        val up2 = FakeUpstream(); val (f3, port3) = front(up2, null, RouteFront.Options())
        val (c3, s3) = socks(port3, reqName("legacy.example", 443)); s3.close()
        check("front: without DoH a name is forwarded unresolved, exactly as in update10", c3 == 0 && up2.requests.toList() == listOf("CONNECT legacy.example:443"))
        f3.stop(); up2.close()
    }
    // --- robustness
    run {
        val up = FakeUpstream(); val (f, port) = front(up, FrontResolver(transportFor("1.1.1.1")))
        val bad = java.net.Socket("127.0.0.1", port); bad.getOutputStream().write(byteArrayOf(4, 1, 0)); bad.close()
        val (ok, s) = socks(port, reqName("fine.example", 443)); s.close()
        check("front: garbage from a client does not disturb the next one", ok == 0)
        f.stop(); up.close()
    }

    // ---- 1.3.1: no network pauses the engine; the probe EOF line is folded
    run {
        val t = OnlineTracker<String>()
        check("online at the start", t.online)
        check("first network is new", t.available("wifi"))
        check("same network again is not new", !t.available("wifi"))
        check("losing the current network goes offline", t.lost("wifi") && !t.online)
        check("a network coming back is new again", t.available("wifi") && t.online)
        // handover: the new network is announced first, then the old one is lost
        check("mobile takes over", t.available("mobile"))
        check("old network lost after takeover: still online", !t.lost("wifi") && t.online)
        check("losing the last one goes offline", t.lost("mobile") && !t.online)
        // other order: old lost first, then the new one appears
        check("online again after the gap", t.available("wifi") && t.online)
        check("a stranger network lost is ignored", !t.lost("other") && t.online)
        check("grace period is 5 s", PowerPolicy.OFFLINE_GRACE_MS == 5_000L)
    }
    run {
        val eof = "[2026-10-22T08:31:40.850Z WARN  aether::psiphon] [-] psiphon: SOCKS proxy accept error: socks5ReadCommand: EOF"
        val eof2 = eof.replace("08:31:40.850", "08:31:45.863")
        val real = "[2026-10-22T08:35:11.000Z WARN  aether::psiphon] [-] psiphon: operate tunnel error for abc: timed out"
        check("probe line recognised", LogNoiseFolder.isOwnProbeNoise(eof))
        check("other psiphon lines are not noise", !LogNoiseFolder.isNoise(real))
        check("a line that merely says EOF elsewhere is not noise", !LogNoiseFolder.isOwnProbeNoise("[x] read: EOF"))
        val f = LogNoiseFolder()
        check("first noise line is kept", f.feed(eof) == listOf(eof))
        check("later noise is swallowed", f.feed(eof2).isEmpty() && f.feed(eof2).isEmpty())
        check("a real line after only 2 folded ones prints no summary", f.feed(real) == listOf(real))
        val g = LogNoiseFolder(); g.feed(eof)
        repeat(LogNoiseFolder.MIN_SUMMARY) { g.feed(eof2) }
        val out = g.feed(real)
        check("a real line flushes a summary first once enough were folded", out.size == 2 && out[0].contains("folded ${LogNoiseFolder.MIN_SUMMARY} more") && out[1] == real)
        check("no summary when nothing is left folded", g.feed(real) == listOf(real))
        val h = LogNoiseFolder(); h.feed(eof)
        var summaries = 0; var kept = 0
        repeat(LogNoiseFolder.SUMMARY_EVERY * 3) { for (l in h.feed(eof2)) { if (l.contains("folded")) summaries++ else kept++ } }
        check("a long run of noise leaves 1 summary per ${LogNoiseFolder.SUMMARY_EVERY} lines and no raw line", summaries == 3 && kept == 0)
        // Diagnostics never counted this line, so folding it changes nothing there
        val sig = LogSignals.scan(listOf(eof, eof2))
        check("probe line is not a diagnostics signal", sig.dns == 0 && sig.tcp == 0 && sig.handshake == 0 && sig.timeouts == 0)
    }

    // ---- 1.3.2: Psiphon retry noise folded; a stalled WireGuard tunnel is detected from the core's log
    run {
        val refused = "[2026-10-22T09:41:26.052Z WARN  aether::psiphon] [-] psiphon: meek round trip failed: psiphon.DialTCP#81: psiphon.proxiedTcpDial#170: socks connect tcp [redacted]->[redacted]: psiphon.proxiedTcpDial.func1#126: psiphon.tcpDial#304: dial tcp [redacted]: connect: connection refused"
        val deadline = "[2026-10-22T09:41:47.391Z WARN  aether::psiphon] [-] psiphon: meek round trip failed: context deadline exceeded"
        val relay = "[2026-10-22T09:41:32.988Z WARN  aether::psiphon] [-] psiphon: psiphon.(*MeekConn).relay.func1#1310: psiphon.(*MeekConn).relay#1438: dial tcp [redacted]: connect: connection refused"
        val tlsFail = "[2026-10-22T09:41:50.000Z WARN  aether::psiphon] [-] psiphon: meek round trip failed: tls: handshake failure"
        val serverList = "[2026-10-22T09:42:58.675Z WARN  aether::psiphon] [-] psiphon: failed to fetch common remote server list: connection refused"
        val wgLine = "[2026-10-22T09:41:08.463Z WARN  aether] [-] last known-good endpoint 188.114.*.*:955 no longer responds (io: Network is unreachable (os error 101)); rescanning"
        check("refused meek line is retry noise", LogNoiseFolder.isChainRetryNoise(refused))
        check("deadline meek line is retry noise", LogNoiseFolder.isChainRetryNoise(deadline))
        check("meek relay line is retry noise", LogNoiseFolder.isChainRetryNoise(relay))
        check("a meek failure with another reason is kept", !LogNoiseFolder.isNoise(tlsFail))
        check("the server-list failure is kept", !LogNoiseFolder.isNoise(serverList))
        check("core WireGuard lines are never noise", !LogNoiseFolder.isNoise(wgLine))
        val f = LogNoiseFolder()
        check("first retry line is kept", f.feed(refused) == listOf(refused))
        repeat(LogNoiseFolder.SUMMARY_EVERY - 1) { check("retry line swallowed", f.feed(deadline).isEmpty()) }
        val sum = f.feed(refused)
        check("one summary per ${LogNoiseFolder.SUMMARY_EVERY} retry lines", sum.size == 1 && sum[0].contains("folded ${LogNoiseFolder.SUMMARY_EVERY} more Psiphon retry"))
        // both kinds at once (what the real log looked like): each is counted on its own
        val eof = "[2026-10-22T09:41:31.000Z WARN  aether::psiphon] [-] psiphon: SOCKS proxy accept error: socks5ReadCommand: EOF"
        val g = LogNoiseFolder()
        g.feed(eof); g.feed(refused)
        repeat(12) { g.feed(eof); g.feed(refused) }
        val o = g.feed(wgLine)
        check("a real line flushes both summaries, then itself", o.size == 3 && o[2] == wgLine && o[0].contains("SOCKS proxy accept error") && o[1].contains("Psiphon retry"))
        check("exit-reason tail skips both kinds", LogNoiseFolder.isNoise(eof) && LogNoiseFolder.isNoise(refused))
    }
    run {
        val up = "[2026-10-22T09:40:42.989Z INFO  aether] [+] wireguard tunnel validated (end-to-end data confirmed); exposing socks5"
        val dead = "[2026-10-22T09:41:06.450Z WARN  aether::wireguard] [wg] no valid data from peer 188.114.*.*:955 in 12.4s; tunnel considered dead"
        val failed = "[2026-10-22T09:41:15.199Z WARN  aether] [-] no usable WireGuard endpoint found: prober: no clean endpoint found; rescanning shortly"
        val profileFail = "[2026-10-22T09:41:10.396Z WARN  aether] [-] profile 'balanced' found no data-plane endpoint: prober: no clean endpoint found; trying next profile"
        check("only the two lines that matter are relevant", TunnelStallTracker.isRelevant(up) && TunnelStallTracker.isRelevant(failed) &&
            !TunnelStallTracker.isRelevant(dead) && !TunnelStallTracker.isRelevant(profileFail))
        val t = TunnelStallTracker()
        check("a new engine is not stalled", !t.stalled && t.failedScans == 0)
        t.feed(up)
        check("a working tunnel is not stalled", !t.stalled)
        t.feed(failed)
        check("one failed scan is a bad moment, not a stall", !t.stalled && t.failedScans == 1)
        t.feed(failed)
        check("${TunnelStallTracker.STALL_AFTER_SCANS} failed scans in a row is a stall", t.stalled)
        t.feed(failed)
        check("it stays stalled while scans keep failing", t.stalled && t.failedScans == 3)
        t.feed(up)
        check("a validated tunnel ends the stall at once", !t.stalled && t.failedScans == 0)
        t.feed(failed); t.feed(up); t.feed(failed)
        check("failures separated by a working tunnel do not add up", !t.stalled)
        check("a restarted engine starts clean", !TunnelStallTracker().stalled)
        // the offline tracker: the system's direct look outranks a callback that never came
        val o = OnlineTracker<String>()
        o.available("wifi"); o.lost("wifi")
        check("callback said offline", !o.online)
        o.markOnline()
        check("markOnline puts it back", o.online)
        check("poll safety net is slower than the grace period", PowerPolicy.OFFLINE_POLL_MS > PowerPolicy.OFFLINE_GRACE_MS)
        check("offline poll: 30 s screen on, 120 s screen off", PowerPolicy.offlinePollMs(true) == 30_000L && PowerPolicy.offlinePollMs(false) == 120_000L)
        check("screen-off poll is never faster than screen-on", PowerPolicy.OFFLINE_POLL_SCREEN_OFF_MS >= PowerPolicy.OFFLINE_POLL_MS)
        // notification: sing-box style zero line while there is no traffic
        check("zero speed line", NotificationText.speedLine(0L, 0L).contains("↑ 0 B/s") && NotificationText.speedLine(0L, 0L).contains("↓ 0 B/s"))
        check("bps never negative after a bridge restart", NotificationText.bps(5_000L, 100L, 2_000L) == 0L)
    }

    // ------------------------------------------------------------------ update15
    run {
        // stall tracker: MASQUE scan failures count, every transport's "tunnel validated" resets
        val masqueFail = "[2026-10-23T09:00:00.000Z WARN  aether] [-] no usable MASQUE gateway found: scan: nothing reachable; rescanning shortly"
        val masqueUp = "[2026-10-23T09:00:10.000Z INFO  aether::quic] [+] masque tunnel validated (end-to-end data confirmed); exposing socks5"
        val h2Up = "[2026-10-23T09:00:10.000Z INFO  aether::masque_h2] [h2] tunnel validated (end-to-end data confirmed); exposing socks5"
        val goolUp = "[2026-10-23T09:00:10.000Z INFO  aether] [+] [inner] wireguard tunnel validated (end-to-end data confirmed)"
        check("update15: MASQUE failure and every validated line are relevant",
            TunnelStallTracker.isRelevant(masqueFail) && TunnelStallTracker.isRelevant(masqueUp) &&
                TunnelStallTracker.isRelevant(h2Up) && TunnelStallTracker.isRelevant(goolUp))
        check("update15: unrelated line is not relevant", !TunnelStallTracker.isRelevant("[x] socks5 server listening on 127.0.0.1:1823"))
        val t = TunnelStallTracker()
        t.feed(masqueFail)
        check("update15: one MASQUE miss is not a stall", !t.stalled && t.failedScans == 1)
        t.feed(masqueFail)
        check("update15: two MASQUE misses in a row are a stall", t.stalled)
        t.feed(h2Up)
        check("update15: an h2 validated line resets the count", !t.stalled && t.failedScans == 0)
        t.feed(masqueFail); t.feed(masqueUp); t.feed(masqueFail)
        check("update15: a validated line in between keeps it below the limit", !t.stalled)

        // power policy
        check("update15: health probe limits are above the old 250/400 ms",
            PowerPolicy.HEALTH_CONNECT_TIMEOUT_MS > 250 && PowerPolicy.HEALTH_READ_TIMEOUT_MS > 400)
        check("update15: ready poll is fast first, then slower",
            PowerPolicy.readyPollMs(0) == 150L && PowerPolicy.readyPollMs(9_999) == 150L &&
                PowerPolicy.readyPollMs(10_000) == 500L && PowerPolicy.readyPollMs(59_999) == 500L &&
                PowerPolicy.readyPollMs(60_000) == 1_000L && PowerPolicy.readyPollMs(300_000) == 1_000L)
        check("update15: ready poll never goes below a caller's own base", PowerPolicy.readyPollMs(0, 2_000L) == 2_000L && PowerPolicy.readyPollMs(70_000, 2_000L) == 2_000L)

        // battery saver profile
        check("update15: saver values are consistent (stale >= 3 probe intervals)", BatterySaver.isConsistent())
        check("update15: inconsistent pair is detected", !BatterySaver.isConsistent(healthSecs = 10, staleSecs = 20))
        val sv = BatterySaver.env()
        check("update15: saver env has exactly the four variables",
            sv.keys == setOf("AETHER_WG_HEALTH_SECS", "AETHER_WG_STALE_SECS", "AETHER_WG_KEEPALIVE", "AETHER_MASQUE_H2_KEEPALIVE_SECS"))
        check("update15: saver env values", sv["AETHER_WG_HEALTH_SECS"] == "10" && sv["AETHER_WG_STALE_SECS"] == "30" &&
            sv["AETHER_WG_KEEPALIVE"] == "25" && sv["AETHER_MASQUE_H2_KEEPALIVE_SECS"] == "30")
        check("update15: WireGuard keepalive stays under common 30 s NAT timeouts", BatterySaver.WG_KEEPALIVE_SECS <= 25)

        fun envOf(c: EngineConfig): Map<String, String> {
            val plan = FrontPlan.of(c.effectiveChain, c.dohActive, false, c.socksPort)
            return EngineEnvironment.build(c, "/x/aether.toml", "/tmp", null, emptyMap(), "/n/libpsiphon.so", "/d", plan)
        }
        val cfg = EngineConfig(protocol = Protocol.WIREGUARD)
        check("update15: powerSaver is on by default", cfg.powerSaver)
        val eOn = envOf(cfg)
        check("update15: engine env carries the saver variables when on",
            eOn["AETHER_WG_STALE_SECS"] == "30" && eOn["AETHER_WG_KEEPALIVE"] == "25" && eOn["AETHER_WG_HEALTH_SECS"] == "10")
        val eOff = envOf(cfg.copy(powerSaver = false))
        check("update15: engine env is exactly the old one when off",
            eOff.keys.none { it in BatterySaver.env().keys })
        check("update15: log level stays info (the stall tracker needs the validated line)", eOn["AETHER_LOG_LEVEL"] == "info" && eOff["AETHER_LOG_LEVEL"] == "info")
        check("update15: a secret still wins over everything", EngineEnvironment.build(cfg, "/c", "/t", null,
            mapOf("AETHER_ACCESS_CLIENT_SECRET" to "s"), null, null, FrontPlan.of(cfg.effectiveChain, false, false, cfg.socksPort))["AETHER_ACCESS_CLIENT_SECRET"] == "s")

        // ECH failure detection: the word, not a substring
        check("update15: real ECH errors match",
            EchFallback.isEchFailure("ECH is on but there is no ECH key to offer") && EchFallback.isEchFailure("failed to fetch ech key") &&
                EchFallback.isEchFailure("[ECH] lookup failed"))
        check("update15: words that only contain 'ech' do not match",
            !EchFallback.isEchFailure("technical problem") && !EchFallback.isEchFailure("detected a fault") &&
                !EchFallback.isEchFailure("the check failed") && !EchFallback.isEchFailure(null) && !EchFallback.isEchFailure(""))
    }

    // ------------------------------------------------------------------ update16: custom chain (sing-box)
    run {
        // the links here are made up; they only have the SHAPE of real ones
        val uuid = "11111111-2222-3333-4444-555555555555"
        fun ok(l: String): LinkParse.Ok = (ProxyLink.parse(l) as? LinkParse.Ok) ?: error("expected Ok for $l")
        fun err(l: String): LinkError? = (ProxyLink.parse(l) as? LinkParse.Err)?.error
        fun b64url(s: String) = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())
        fun b64(s: String) = java.util.Base64.getEncoder().encodeToString(s.toByteArray())
        @Suppress("UNCHECKED_CAST") fun m(o: Any?) = o as Map<String, Any?>

        // MiniJson
        check("json: write keeps order and escapes", MiniJson.write(linkedMapOf("a" to 1, "b" to "x\"y\n", "c" to listOf(true, null))) ==
            "{\n  \"a\": 1,\n  \"b\": \"x\\\"y\\n\",\n  \"c\": [\n    true,\n    null\n  ]\n}")
        check("json: parse object", MiniJson.parseObject("{\"a\": 1, \"b\": [1,2,{\"c\":\"\\u0041\"}], \"d\": null, \"e\": -2.5}") ==
            mapOf("a" to 1L, "b" to listOf(1L, 2L, mapOf("c" to "A")), "d" to null, "e" to -2.5))
        check("json: garbage and trailing text are refused", MiniJson.parse("{\"a\":1} x") == null && MiniJson.parse("{\"a\":") == null && MiniJson.parseObject("[1]") == null)
        check("json: empty containers", MiniJson.write(emptyMap<String, Any?>()) == "{}" && MiniJson.write(emptyList<Any?>()) == "[]")

        // VLESS over WebSocket + TLS (the kind of link a CDN-fronted server gives)
        val v1 = ok("vless://$uuid@203.0.113.7:443?path=%2Fabc-def&security=tls&encryption=none&pbk=enabled&insecure=0&host=cdn.example.workers.dev&fp=chrome&type=ws&allowInsecure=0&sni=cdn.example.workers.dev#203.0.113.7-test%20%F0%9F%8E%88")
        check("vless ws: basics", v1.protocol == "vless" && v1.server == "203.0.113.7" && v1.port == 443 && v1.outbound["uuid"] == uuid && v1.outbound["type"] == "vless")
        check("vless ws: name is percent-decoded UTF-8", v1.name == "203.0.113.7-test \uD83C\uDF88")
        check("vless ws: tls with sni and utls", m(v1.outbound["tls"])["server_name"] == "cdn.example.workers.dev" &&
            m(m(v1.outbound["tls"])["utls"])["fingerprint"] == "chrome" && m(v1.outbound["tls"])["insecure"] == null)
        check("vless ws: transport has path and Host header", m(v1.outbound["transport"])["type"] == "ws" && m(v1.outbound["transport"])["path"] == "/abc-def" &&
            m(m(v1.outbound["transport"])["headers"])["Host"] == listOf("cdn.example.workers.dev"))
        check("vless ws: the summary never contains the id", !v1.summary.contains(uuid) && v1.summary.contains("203.0.113.7:443") && v1.summary.contains("WebSocket"))
        check("vless: 'pbk' is ignored when the security is not reality", m(v1.outbound["tls"])["reality"] == null)

        // XHTTP is refused with its own reason, not dropped
        check("vless xhttp is refused", err("vless://$uuid@vpn.example.com:443?type=xhttp&security=tls&sni=s.example.com&path=%2Fx&mode=auto") == LinkError.XHTTP)
        check("splithttp is refused too", err("vless://$uuid@vpn.example.com:443?type=splithttp&security=tls") == LinkError.XHTTP)

        // reality and grpc
        val v2 = ok("vless://$uuid@vpn.example.com:8443?security=reality&sni=www.example.org&fp=firefox&pbk=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA&sid=ab12&type=tcp&flow=xtls-rprx-vision&encryption=none#r")
        check("vless reality: flow, reality block, utls", v2.outbound["flow"] == "xtls-rprx-vision" && m(m(v2.outbound["tls"])["reality"])["public_key"] == "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA" &&
            m(m(v2.outbound["tls"])["reality"])["short_id"] == "ab12" && m(m(v2.outbound["tls"])["utls"])["fingerprint"] == "firefox" && v2.outbound["transport"] == null)
        check("vless reality with a malformed public key is refused", err("vless://$uuid@h.example.com:443?security=reality&sni=a.example.org&pbk=PUBKEY123") == LinkError.SECURITY)
        check("vless reality without a public key is refused", err("vless://$uuid@h.example.com:443?security=reality&sni=a.example.org") == LinkError.SECURITY)
        val v3 = ok("vless://$uuid@g.example.com:443?security=tls&type=grpc&serviceName=svc&alpn=h2,http%2F1.1&allowInsecure=1")
        check("vless grpc: service name, alpn, insecure on request", m(v3.outbound["transport"])["service_name"] == "svc" &&
            m(v3.outbound["tls"])["alpn"] == listOf("h2", "http/1.1") && m(v3.outbound["tls"])["insecure"] == true && m(v3.outbound["tls"])["server_name"] == "g.example.com")
        check("vless: unknown fingerprint is dropped, randomizedalpn is mapped", ok("vless://$uuid@h.example.com:443?security=tls&fp=nonsense").outbound.let { m(it["tls"])["utls"] == null } &&
            m(m(ok("vless://$uuid@h.example.com:443?security=tls&fp=randomizedalpn").outbound["tls"])["utls"])["fingerprint"] == "randomized")
        check("vless: IP server without sni gets no server_name", m(ok("vless://$uuid@203.0.113.9:443?security=tls").outbound["tls"])["server_name"] == null)
        check("vless: no security means no tls block", ok("vless://$uuid@203.0.113.9:80?type=ws&path=%2F").outbound["tls"] == null)
        check("vless: ipv6 server", ok("vless://$uuid@[2001:db8::1]:443?security=tls&sni=a.example.com").let { it.server == "2001:db8::1" && it.summary.contains("[2001:db8::1]:443") })
        check("vless: ws early data is split out", m(ok("vless://$uuid@h.example.com:443?type=ws&path=%2Fp%3Fed%3D2048").outbound["transport"]).let {
            it["path"] == "/p" && it["max_early_data"] == 2048 && it["early_data_header_name"] == "Sec-WebSocket-Protocol" })
        check("vless: http/h2 transport takes host list", m(ok("vless://$uuid@h.example.com:443?security=tls&type=h2&host=a.example.com,b.example.com&path=%2Fh").outbound["transport"]).let {
            it["type"] == "http" && it["host"] == listOf("a.example.com", "b.example.com") && it["path"] == "/h" })
        check("vless: httpupgrade", m(ok("vless://$uuid@h.example.com:80?type=httpupgrade&host=a.example.com&path=%2Fu").outbound["transport"]).let { it["type"] == "httpupgrade" && it["host"] == "a.example.com" })
        check("vless: bad ids, ports, encryption", err("vless://not-a-uuid@h.example.com:443") == LinkError.CREDENTIAL && err("vless://@h.example.com:443") == LinkError.CREDENTIAL &&
            err("vless://$uuid@h.example.com") == LinkError.PORT && err("vless://$uuid@h.example.com:99999") == LinkError.PORT &&
            err("vless://$uuid@h.example.com:443?encryption=mlkem768x25519plus") == LinkError.ENCRYPTION)
        check("vless: unsupported transports and security are refused", err("vless://$uuid@h.example.com:443?type=kcp") == LinkError.TRANSPORT &&
            err("vless://$uuid@h.example.com:443?type=tcp&headerType=http") == LinkError.TRANSPORT && err("vless://$uuid@h.example.com:443?security=xtls") == LinkError.SECURITY)

        // Shadowsocks: SIP002 (base64 userinfo), plain userinfo, legacy whole-base64
        val s1 = ok("ss://" + b64url("aes-256-gcm:test-password-123") + "@ss.example.com:990#de-test")
        check("ss sip002", s1.outbound == linkedMapOf<String, Any?>("type" to "shadowsocks", "server" to "ss.example.com", "server_port" to 990,
            "method" to "aes-256-gcm", "password" to "test-password-123") && s1.name == "de-test" && !s1.summary.contains("test-password"))
        val s2 = ok("ss://chacha20-ietf-poly1305:p%40ss%3Aword@203.0.113.5:8388")
        check("ss plain userinfo with percent-encoding", s2.outbound["password"] == "p@ss:word" && s2.outbound["method"] == "chacha20-ietf-poly1305")
        val s3 = ok("ss://" + b64("aes-128-gcm:pw@ss.example.com:443") + "#legacy")
        check("ss legacy base64 form", s3.server == "ss.example.com" && s3.port == 443 && s3.outbound["password"] == "pw" && s3.name == "legacy")
        check("ss padded and URL-safe base64 both work", ok("ss://" + b64("aes-256-gcm:abc") + "@h.example.com:1").outbound["password"] == "abc")
        check("ss alias chacha20-poly1305", ok("ss://chacha20-poly1305:pw@h.example.com:1").outbound["method"] == "chacha20-ietf-poly1305")
        check("ss 2022 method", ok("ss://2022-blake3-aes-256-gcm:KEYKEYKEY@h.example.com:1").outbound["method"] == "2022-blake3-aes-256-gcm")
        check("ss: plugins and bad methods are refused", err("ss://" + b64url("aes-256-gcm:x") + "@h.example.com:1?plugin=obfs-local%3Bobfs%3Dtls") == LinkError.PLUGIN &&
            err("ss://" + b64url("foo-cipher:x") + "@h.example.com:1") == LinkError.METHOD && err("ss://" + b64url("aes-256-gcm:x") + "@h.example.com") == LinkError.PORT &&
            err("ss://!!!notbase64!!!@h.example.com:1") == LinkError.MALFORMED)

        // Trojan
        val t1 = ok("trojan://p%40ss@t.example.com:443?sni=front.example.com&type=ws&host=front.example.com&path=%2Fws&fp=chrome#t")
        check("trojan: password decoded, tls by default, ws", t1.outbound["password"] == "p@ss" && m(t1.outbound["tls"])["server_name"] == "front.example.com" &&
            m(t1.outbound["transport"])["type"] == "ws")
        check("trojan: security=none really means none", ok("trojan://pw@t.example.com:80?security=none").outbound["tls"] == null)
        check("trojan: password is required", err("trojan://@t.example.com:443") == LinkError.CREDENTIAL)

        // VMess: v2rayN base64 JSON and the URI form
        val vm = b64("""{"v":"2","ps":"vm test","add":"vm.example.com","port":"443","id":"$uuid","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/vm","tls":"tls","sni":"vm.example.com","alpn":"h2","fp":"chrome"}""")
        val vm1 = ok("vmess://$vm")
        check("vmess json: server, tls, ws", vm1.server == "vm.example.com" && vm1.port == 443 && vm1.name == "vm test" && vm1.outbound["security"] == "auto" &&
            m(vm1.outbound["tls"])["alpn"] == listOf("h2") && m(vm1.outbound["transport"])["path"] == "/vm" && vm1.outbound["alter_id"] == null)
        check("vmess json: port as a number and alterId", ok("vmess://" + b64("""{"add":"a.example.com","port":8080,"id":"$uuid","aid":4,"net":"tcp"}""")).let { it.port == 8080 && it.outbound["alter_id"] == 4 && it.outbound["tls"] == null })
        check("vmess json: grpc takes the path as service name", m(ok("vmess://" + b64("""{"add":"a.example.com","port":"443","id":"$uuid","net":"grpc","path":"svc","tls":"tls"}""")).outbound["transport"])["service_name"] == "svc")
        check("vmess: not base64 json is refused", err("vmess://%%%") == LinkError.MALFORMED && err("vmess://" + b64("{\"add\":\"x\"}")) != null)
        val vm2 = ok("vmess://$uuid@vm.example.com:443?security=tls&type=ws&path=%2Fv&encryption=aes-128-gcm")
        check("vmess uri form", vm2.outbound["security"] == "aes-128-gcm" && m(vm2.outbound["transport"])["path"] == "/v")

        // generic refusals
        check("empty / no scheme / unsupported scheme", err("  ") == LinkError.EMPTY && err("just text") == LinkError.SCHEME && err("hysteria2://x@h.example.com:443") == LinkError.SCHEME &&
            err("https://example.com") == LinkError.SCHEME)
        check("surrounding whitespace is ignored", ProxyLink.parse("  ss://" + b64url("aes-256-gcm:x") + "@h.example.com:1 \n") is LinkParse.Ok)
        check("every link error has a message", LinkError.values().all { LinkMessages.english(LinkParse.Err(it, "x")).isNotBlank() })
        check("base64 helper: both alphabets, with and without padding", Base64Lite.decode("aGk=")!!.toString(Charsets.UTF_8) == "hi" && Base64Lite.decode("aGk")!!.toString(Charsets.UTF_8) == "hi" &&
            Base64Lite.decode("_-8")!!.size == 2 && Base64Lite.decode("a") == null && Base64Lite.decode("a$") == null)

        // the configuration
        val cfg = MiniJson.parseObject(SingBoxConfig.build(v1, corePort = 1823, listenPort = 1824))!!
        val outs = cfg["outbounds"] as List<*>
        check("config: inbound is a local SOCKS on the chain port", (cfg["inbounds"] as List<*>).let { m(it[0]).let { i -> i["type"] == "socks" && i["listen"] == "127.0.0.1" && i["listen_port"] == 1824L } })
        check("config: proxy outbound goes through warp, warp is the core's SOCKS", m(outs[0])["tag"] == "proxy" && m(outs[0])["detour"] == "warp" &&
            m(outs[1]).let { it["tag"] == "warp" && it["type"] == "socks" && it["server"] == "127.0.0.1" && it["server_port"] == 1823L && it["version"] == "5" })
        check("config: everything leaves through the proxy, roots are built in", m(cfg["route"])["final"] == "proxy" && m(cfg["certificate"])["store"] == "mozilla")
        check("config: no dns, tun, rules, file output", cfg["dns"] == null && cfg["experimental"] == null && m(cfg["log"])["output"] == null && cfg["inbounds"].toString().contains("tun").not())
        check("config: bad ports are refused", runCatching { SingBoxConfig.build(v1, 0, 1824) }.isFailure && runCatching { SingBoxConfig.build(v1, 1823, 70000) }.isFailure)

        // golden files: what the builder writes is exactly what CI hands to the real `sing-box check`
        val root = System.getenv("MADSHIELD_ROOT") ?: "."
        val goldenDir = java.io.File(root, "tests/pure/golden")
        val goldens = linkedMapOf(
            "vless-ws-tls.json" to v1, "vless-reality.json" to v2, "vless-grpc.json" to v3, "ss.json" to s1,
            "trojan-ws.json" to t1, "vmess-ws.json" to vm1
        )
        for ((name, link) in goldens) {
            val text = SingBoxConfig.build(link, corePort = 1823, listenPort = 1824)
            val f = java.io.File(goldenDir, name)
            if (System.getenv("UPDATE_GOLDEN") == "1") { goldenDir.mkdirs(); f.writeText(text) }
            check("golden: $name matches the builder", f.isFile && f.readText() == text)
        }

        // topology and policy
        for (chain in listOf(PrivacyChain.PSIPHON, PrivacyChain.TOR, PrivacyChain.SINGBOX)) {
            val a = FrontPlan.of(chain, false, false, 1819)
            val b = FrontPlan.of(chain, true, false, 1819)
            check("plan $chain: no front -> chain on the public port, core underneath", !a.frontOn && a.chainPort == 1819 && a.corePort == Chain.UNDERLAY_PORT && a.upstreamPort == 1819)
            check("plan $chain: with front -> chain on 1824, UDP via the relay only for sing-box (Psiphon/Tor refuse it)",
                b.frontOn && b.chainPort == Chain.CHAIN_PORT && b.upstreamPort == Chain.CHAIN_PORT && b.udpRelay == (chain == PrivacyChain.SINGBOX) && !b.coreGetsRoutes)
        }
        val sbCfg = EngineConfig(protocol = Protocol.WIREGUARD, privacyChain = PrivacyChain.SINGBOX)
        val sbPlan = FrontPlan.of(sbCfg.effectiveChain, false, false, sbCfg.socksPort)
        val sbEnv = EngineEnvironment.build(sbCfg, "/c", "/t", null, emptyMap(), null, null, sbPlan)
        check("env: the custom chain gives the core no chain variables, and the core sits on the underlay port",
            sbEnv.keys.none { it.startsWith("AETHER_PSIPHON") || it.startsWith("AETHER_TOR") || it == "GOMAXPROCS" } && sbEnv["AETHER_SOCKS"] == "127.0.0.1:${Chain.UNDERLAY_PORT}")
        check("custom chain is not offered with SMART", sbCfg.copy(protocol = Protocol.SMART).effectiveChain == PrivacyChain.NONE)
        check("policy: sing-box failures count as chain failures", ConnectPolicy.isChainFailure("the custom chain (sing-box) did not carry traffic in 45s") &&
            ConnectPolicy.isChainFailure("The custom chain (sing-box) stopped (exit code 1)") && !ConnectPolicy.isChainFailure("no answer from the engine after 90s") &&
            !ConnectPolicy.shouldTryHardened(sbCfg, "the custom chain (sing-box) did not carry traffic in 45s"))
        check("policy: allowance for the custom chain", ConnectPolicy.chainAllowanceMs(sbCfg) == ConnectPolicy.SINGBOX_ALLOWANCE_MS &&
            ConnectPolicy.firstPassTimeoutMs(sbCfg) == ConnectPolicy.SIMPLE_PASS_MS + ConnectPolicy.SINGBOX_ALLOWANCE_MS)
        check("stored chain names still load, unknown ones fall back to none", PrivacyChain.fromStored("SINGBOX") == PrivacyChain.SINGBOX && PrivacyChain.fromStored("PSIPHON") == PrivacyChain.PSIPHON && PrivacyChain.fromStored("bogus") == PrivacyChain.NONE)

        // the end-to-end probe, against a fake SOCKS5 server
        fun fakeSocks(connectReply: Int, http: String?): Pair<java.net.ServerSocket, Thread> {
            val ss = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
            val th = Thread {
                try {
                    ss.accept().use { c ->
                        val i = c.getInputStream(); val o = c.getOutputStream()
                        val g = ByteArray(3); i.readNBytes(g, 0, 3)
                        o.write(byteArrayOf(5, 0)); o.flush()
                        val r = ByteArray(10); i.readNBytes(r, 0, 10)
                        o.write(byteArrayOf(5, connectReply.toByte(), 0, 1, 0, 0, 0, 0, 0, 0)); o.flush()
                        if (connectReply == 0 && http != null) {
                            val buf = StringBuilder()
                            while (!buf.endsWith("\r\n\r\n")) { val b = i.read(); if (b < 0) break; buf.append(b.toChar()) }
                            o.write(http.toByteArray()); o.flush()
                        }
                    }
                } catch (_: Exception) {}
            }.also { it.isDaemon = true; it.start() }
            return ss to th
        }
        val (okSrv, _) = fakeSocks(0, "HTTP/1.1 301 Moved\r\n\r\n")
        check("e2e probe: an HTTP answer through SOCKS is success", SocksProbe.httpAnswersThrough("127.0.0.1", okSrv.localPort, "1.1.1.1", 80, 3_000))
        okSrv.close()
        val (badSrv, _) = fakeSocks(5, null)
        check("e2e probe: a refused CONNECT is failure", !SocksProbe.httpAnswersThrough("127.0.0.1", badSrv.localPort, "1.1.1.1", 80, 3_000))
        badSrv.close()
        val (junkSrv, _) = fakeSocks(0, "not http at all")
        check("e2e probe: bytes that are not HTTP are failure", !SocksProbe.httpAnswersThrough("127.0.0.1", junkSrv.localPort, "1.1.1.1", 80, 3_000))
        junkSrv.close()
        check("e2e probe: only literal IPv4 targets, and a closed port is failure",
            !SocksProbe.httpAnswersThrough("127.0.0.1", 1, "1.1.1.1", 80, 500) && !SocksProbe.httpAnswersThrough("127.0.0.1", 1, "example.com", 80, 500))
    }
}


// =====================================================================================================
// update17: several saved links for the custom chain (LinkProfiles)
// =====================================================================================================
fun linkProfileTests() {
    val uuid = "11111111-2222-3333-4444-555555555555"
    fun b64url(s: String) = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())
    val vless = "vless://$uuid@vpn.example.com:443?type=ws&security=tls&sni=vpn.example.com&path=%2Fw#My%20Berlin"
    val vlessNoName = "vless://$uuid@nn.example.com:443?type=ws&security=tls&sni=nn.example.com&path=%2Fw"
    val ss = "ss://" + b64url("aes-256-gcm:secret") + "@frankfurt.example.com:990#de-1"
    var n = 0
    val ids = { "id${++n}" }
    val empty = LinkProfileBook()

    val a1 = LinkProfiles.add(empty, vless, "", ids) as LinkAdd.Added
    check("links: first profile is added and becomes active", a1.book.profiles.size == 1 && a1.book.activeId == a1.profile.id)
    check("links: name comes from the link's #name, URL-decoded", a1.profile.name == "My Berlin")
    val a2 = LinkProfiles.add(a1.book, ss, "  Frankfurt\n ", ids) as LinkAdd.Added
    check("links: a second profile does NOT take over the active one", a2.book.profiles.size == 2 && a2.book.activeId == a1.profile.id)
    check("links: an own name is trimmed and flattened", a2.profile.name == "Frankfurt")
    val a3 = LinkProfiles.add(a2.book, vlessNoName, "", ids) as LinkAdd.Added
    check("links: no #name -> PROTOCOL · host, no credential in it", a3.profile.name == "VLESS · nn.example.com" && !a3.profile.name.contains(uuid))
    check("links: the same link twice is a duplicate, nothing added", LinkProfiles.add(a3.book, "  $vless \n", "x", ids).let { it is LinkAdd.Duplicate && it.existing.id == a1.profile.id })
    check("links: bad links are refused with the parser's reason", (LinkProfiles.add(a3.book, "vless://nope", "", ids) as? LinkAdd.Invalid)?.error?.error == LinkError.CREDENTIAL &&
        LinkProfiles.add(a3.book, "  ", "", ids) is LinkAdd.Invalid && LinkProfiles.add(a3.book, "https://example.com", "", ids) is LinkAdd.Invalid)
    check("links: a long name is cut at MAX_NAME", LinkProfiles.cleanName("x".repeat(100)).length == LinkProfiles.MAX_NAME)

    val act = LinkProfiles.activate(a3.book, a2.profile.id)
    check("links: activate switches the active profile", act.activeId == a2.profile.id && act.active?.link == ss)
    check("links: activating an unknown id changes nothing", LinkProfiles.activate(act, "zzz") == act)
    val ren = LinkProfiles.rename(act, a2.profile.id, "  Work  ")
    check("links: rename works and keeps the link and the active choice", ren.profiles.first { it.id == a2.profile.id }.let { it.name == "Work" && it.link == ss } && ren.activeId == act.activeId)
    check("links: a blank rename is ignored", LinkProfiles.rename(ren, a2.profile.id, "   ") == ren)
    val rmOther = LinkProfiles.remove(act, a1.profile.id)
    check("links: removing a non-active profile keeps the active one", rmOther.profiles.size == 2 && rmOther.activeId == a2.profile.id)
    val rmActive = LinkProfiles.remove(act, a2.profile.id)
    check("links: removing the ACTIVE profile leaves none active (no silent switch)", rmActive.profiles.size == 2 && rmActive.activeId == null && rmActive.active == null)
    check("links: removing the last one gives an empty book", LinkProfiles.remove(LinkProfiles.remove(LinkProfiles.remove(a3.book, "id1"), "id2"), "id3") == empty)

    var full = empty
    for (i in 1..LinkProfiles.MAX_PROFILES) {
        full = (LinkProfiles.add(full, "trojan://pw$i@h$i.example.com:443", "", ids) as LinkAdd.Added).book
    }
    check("links: the list is capped", full.profiles.size == LinkProfiles.MAX_PROFILES && LinkProfiles.add(full, "trojan://other@x.example.com:443", "", ids) is LinkAdd.Full)
    var fixedId = 0
    val clash = LinkProfiles.add(a1.book, ss, "", { if (fixedId++ < 1) a1.profile.id else "fresh" }) as LinkAdd.Added
    check("links: an id that already exists is never reused", clash.profile.id == "fresh")

    val text = LinkProfiles.encode(act)
    val back = LinkProfiles.decode(text)
    check("links: encode/decode round trip keeps everything, including odd characters", back == act &&
        LinkProfiles.decode(LinkProfiles.encode(LinkProfiles.rename(act, a1.profile.id, "a \"q\" \\ ü ✓"))).profiles[0].name == "a \"q\" \\ ü ✓")
    check("links: decode survives junk", LinkProfiles.decode(null) == empty && LinkProfiles.decode("") == empty && LinkProfiles.decode("not json") == empty &&
        LinkProfiles.decode("{\"items\": 5}") == empty && LinkProfiles.decode("[]") == empty)
    val half = LinkProfiles.decode("{\"active\":\"ghost\",\"items\":[{\"id\":\"a\",\"link\":\"$ss\"},{\"id\":\"\",\"link\":\"x\"},{\"name\":\"no id\",\"link\":\"y\"},{\"id\":\"a\",\"link\":\"$vless\"}]}")
    check("links: decode drops broken/duplicate items and an active id that does not exist", half.profiles.size == 1 && half.profiles[0].name == "Link" && half.activeId == null)

    val mig = LinkProfiles.migrate(empty, "  $vless ")
    check("links: update16's single link becomes one active profile", mig.profiles.size == 1 && mig.activeId == LinkProfiles.LEGACY_ID && mig.active?.link == vless && mig.active?.name == "My Berlin")
    check("links: migration never touches a non-empty book or an empty link", LinkProfiles.migrate(act, vless) == act && LinkProfiles.migrate(empty, "  ") == empty && LinkProfiles.migrate(empty, null) == empty)
    check("links: migrating an unparseable old link still keeps it", LinkProfiles.migrate(empty, "garbage").profiles.single().name == "Link")
    check("links: the stored text never leaks into the summary shown in the UI", (ProxyLink.parse(vless) as LinkParse.Ok).summary.let { !it.contains(uuid) })

    // ------------------------------------------------------------------ update19: MASQUE SNI and TLS look
    run {
        check("sni: a plain domain is accepted", MasqueSni.normalize("example.com") == "example.com")
        check("sni: case and one trailing dot are cleaned", MasqueSni.normalize("  WWW.Example.COM. ") == "www.example.com")
        check("sni: the core's default and the WARP client name are valid", MasqueSni.isValid(MasqueSni.DEFAULT) && MasqueSni.isValid(MasqueSni.WARP_CLIENT))
        check("sni: empty, null and blank give nothing", MasqueSni.normalize(null) == null && MasqueSni.normalize("") == null && MasqueSni.normalize("   ") == null)
        check("sni: IPv4 and IPv6 are refused (the core stops on them)",
            MasqueSni.normalize("1.1.1.1") == null && MasqueSni.normalize("104.16.0.1") == null && MasqueSni.normalize("1.2.3") == null &&
                MasqueSni.normalize("2606:4700::1111") == null && MasqueSni.normalize("[::1]") == null)
        check("sni: a single label, double dot and leading dot are refused",
            MasqueSni.normalize("localhost") == null && MasqueSni.normalize("a..com") == null && MasqueSni.normalize(".example.com") == null && MasqueSni.normalize("example.com..") == null)
        check("sni: spaces, schemes, paths, ports, underscores and non-ASCII are refused",
            MasqueSni.normalize("exa mple.com") == null && MasqueSni.normalize("https://example.com") == null &&
                MasqueSni.normalize("example.com/x") == null && MasqueSni.normalize("example.com:443") == null &&
                MasqueSni.normalize("my_host.example.com") == null && MasqueSni.normalize("exämple.com") == null)
        check("sni: hyphens only inside a label", MasqueSni.isValid("a-b.example.com") && !MasqueSni.isValid("-a.example.com") && !MasqueSni.isValid("a-.example.com"))
        check("sni: punycode names are fine", MasqueSni.isValid("xn--mnchen-3ya.de"))
        check("sni: label and total length limits", MasqueSni.isValid("a".repeat(63) + ".com") && !MasqueSni.isValid("a".repeat(64) + ".com") &&
            !MasqueSni.isValid(("a".repeat(60) + ".").repeat(5) + "com"))
        check("sni: kinds", MasqueSni.kindOf(null) == MasqueSni.Kind.DEFAULT && MasqueSni.kindOf("") == MasqueSni.Kind.DEFAULT &&
            MasqueSni.kindOf("WWW.cloudflare.com") == MasqueSni.Kind.DEFAULT && MasqueSni.kindOf(MasqueSni.WARP_CLIENT) == MasqueSni.Kind.WARP_CLIENT &&
            MasqueSni.kindOf("example.org") == MasqueSni.Kind.CUSTOM && MasqueSni.kindOf("1.1.1.1") == MasqueSni.Kind.DEFAULT)
        check("sni: env value only when it differs from the core default",
            MasqueSni.envValue("") == null && MasqueSni.envValue("www.cloudflare.com") == null && MasqueSni.envValue("junk") == null &&
                MasqueSni.envValue("Example.org") == "example.org")
        check("sni: only MASQUE-capable protocols use it",
            MasqueSni.appliesTo(Protocol.SMART) && MasqueSni.appliesTo(Protocol.MASQUE_H2) && MasqueSni.appliesTo(Protocol.MASQUE_H3) &&
                MasqueSni.appliesTo(Protocol.GOOL) && !MasqueSni.appliesTo(Protocol.WIREGUARD) && !MasqueSni.appliesTo(Protocol.GOOL_CLASSIC))

        check("tls: default preset sets nothing", TlsPreset.DEFAULT.env().isEmpty())
        check("tls: Chrome+ is exactly the four extras",
            TlsPreset.CHROME_PLUS.env() == mapOf(
                "AETHER_ENABLE_GREASE_SIGALGS" to "1", "AETHER_TLS_CERT_COMPRESSION" to "brotli",
                "AETHER_TLS_ALPS" to "new", "AETHER_ENABLE_ECH_GREASE" to "1"))
        val ff = TlsPreset.FIREFOX.env()
        val ffGroups = ff["AETHER_TLS_GROUPS"]!!.split(':')
        val ffShares = ff["AETHER_TLS_KEY_SHARES"]!!.split(':')
        check("tls: Firefox key shares are groups, in the groups' order, each once (the core refuses anything else)",
            ffShares.all { it in ffGroups } && ffShares == ffGroups.filter { it in ffShares } && ffShares.toSet().size == ffShares.size)
        check("tls: Firefox TLS 1.3 suites are the three standard ones, each once",
            ff["AETHER_TLS13_CIPHERS"]!!.split(':').sorted() == listOf("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"))
        check("tls: Firefox signature algorithms are each named once and contain no spaces",
            ff["AETHER_TLS_SIGALGS"]!!.split(':').let { it.toSet().size == it.size && it.none { n -> n.isBlank() || n.contains(' ') } })
        check("tls: Firefox compression is zlib, brotli, zstd", ff["AETHER_TLS_CERT_COMPRESSION"] == "zlib:brotli:zstd")
        check("tls: no preset value has a space or a newline",
            TlsPreset.entries.all { p -> p.env().values.all { v -> v.none { c -> c == ' ' || c == '\n' } } })
        check("tls: stored names round-trip, junk falls back to the default",
            TlsPreset.entries.all { TlsPreset.fromStored(it.name) == it } && TlsPreset.fromStored(null) == TlsPreset.DEFAULT && TlsPreset.fromStored("NOPE") == TlsPreset.DEFAULT)

        fun env19(c: EngineConfig): Map<String, String> {
            val plan = FrontPlan.of(c.effectiveChain, c.dohActive, false, c.socksPort)
            return EngineEnvironment.build(c, "/x/aether.toml", "/tmp", null, emptyMap(), "/n/libpsiphon.so", "/d", plan)
        }
        val newVars = TlsPreset.ALL_VARIABLES.toSet()
        for (proto in Protocol.entries) {
            check("update19: defaults add NO new variable for $proto", env19(EngineConfig(protocol = proto)).keys.none { it in newVars })
        }
        check("update19: SNI reaches the core for MASQUE h2, h3, Gool and Smart",
            listOf(Protocol.MASQUE_H2, Protocol.MASQUE_H3, Protocol.GOOL, Protocol.SMART).all {
                env19(EngineConfig(protocol = it, masqueSni = MasqueSni.WARP_CLIENT))["AETHER_MASQUE_SNI"] == MasqueSni.WARP_CLIENT
            })
        check("update19: SNI is not sent for WireGuard or classic Gool",
            env19(EngineConfig(protocol = Protocol.WIREGUARD, masqueSni = MasqueSni.WARP_CLIENT)).containsKey("AETHER_MASQUE_SNI").not() &&
                env19(EngineConfig(protocol = Protocol.GOOL_CLASSIC, masqueSni = MasqueSni.WARP_CLIENT)).containsKey("AETHER_MASQUE_SNI").not())
        check("update19: the core's own default name is never sent",
            env19(EngineConfig(protocol = Protocol.MASQUE_H2, masqueSni = "www.cloudflare.com")).containsKey("AETHER_MASQUE_SNI").not())
        check("update19: an invalid stored name is dropped, never passed to the core",
            listOf("1.1.1.1", "not a domain", "https://x.com", "a_b.com").all {
                env19(EngineConfig(protocol = Protocol.MASQUE_H2, masqueSni = it)).containsKey("AETHER_MASQUE_SNI").not()
            })
        for (preset in listOf(TlsPreset.CHROME_PLUS, TlsPreset.FIREFOX)) {
            for (proto in Protocol.entries) {
                val e = env19(EngineConfig(protocol = proto, tlsPreset = preset))
                check("update19: preset $preset reaches the core for $proto (the WARP API calls use it too)", preset.env().all { (k, v) -> e[k] == v })
            }
        }
        check("update19: a preset never changes the carrier, port or protocol variables",
            env19(EngineConfig(protocol = Protocol.MASQUE_H2)).filterKeys { it !in newVars } ==
                env19(EngineConfig(protocol = Protocol.MASQUE_H2, tlsPreset = TlsPreset.FIREFOX, masqueSni = "example.org")).filterKeys { it !in newVars })
        check("update19: the fallback passes keep the user's SNI and preset",
            EngineConfig(masqueSni = "example.org", tlsPreset = TlsPreset.CHROME_PLUS).hardened().let { it.masqueSni == "example.org" && it.tlsPreset == TlsPreset.CHROME_PLUS })

        // CI must name every variable, so that a renamed upstream option fails the build instead of doing nothing
        val ci = java.io.File(System.getenv("MADSHIELD_ROOT") ?: ".", ".github/workflows/build.yml")
        if (ci.isFile) {
            val text = ci.readText()
            check("update19: build.yml checks every variable of the presets and the SNI", TlsPreset.ALL_VARIABLES.all { text.contains(it) })
        }

        val insecure = ProxyLink.parse("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=ws&path=%2Fa&allowInsecure=1")
        val secure = ProxyLink.parse("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=ws&path=%2Fa")
        check("update19: a link with allowInsecure is recognised (and still parses)", insecure is LinkParse.Ok && ProxyLink.isInsecure(insecure))
        check("update19: a normal link is not flagged", secure is LinkParse.Ok && !ProxyLink.isInsecure(secure))
    }
}


// ====================================================================== UDP relay (update20)

private fun udpHdrName(name: String, port: Int) = byteArrayOf(0, 0, 0, 3, name.length.toByte()) + name.toByteArray() + w16(port)
private fun udpHdrIp(ip: String, port: Int) = byteArrayOf(0, 0, 0, 1) + ip.split('.').map { it.toInt().toByte() }.toByteArray() + w16(port)

/** One SOCKS5 UDP ASSOCIATE through [frontPort]: the reply code, the control socket and a datagram socket aimed at the BND port. */
private class UdpFlow(frontPort: Int) {
    val code: Int
    val ctrl: java.net.Socket
    val sock = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
    init {
        val (c, s) = socks(frontPort, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        code = c; ctrl = s
        if (c == 0) {
            val port = ((lastReply[8].toInt() and 0xff) shl 8) or (lastReply[9].toInt() and 0xff)
            sock.connect(java.net.InetAddress.getByName("127.0.0.1"), port)
            sock.soTimeout = 1500
        }
    }
    fun send(header: ByteArray, payload: String) { val b = header + payload.toByteArray(); sock.send(java.net.DatagramPacket(b, b.size)) }
    /** The datagram that comes back, or null after [ms] of silence. */
    fun recv(ms: Int = 1500): ByteArray? = try {
        sock.soTimeout = ms
        val pk = java.net.DatagramPacket(ByteArray(2048), 2048); sock.receive(pk); pk.data.copyOf(pk.length)
    } catch (_: java.net.SocketTimeoutException) { null } catch (_: java.io.IOException) { null }
    fun ctrlClosedWithin(ms: Int): Boolean = try { ctrl.soTimeout = ms; ctrl.getInputStream().read() < 0 } catch (_: java.net.SocketTimeoutException) { false } catch (_: java.io.IOException) { true }
    fun close() { try { ctrl.close() } catch (_: Exception) { }; sock.close() }
}

private fun relayThreads(): Int = Thread.getAllStackTraces().keys.count { it.name == "udp-relay" && it.isAlive }
private fun waitFor(ms: Long, cond: () -> Boolean): Boolean { val end = System.currentTimeMillis() + ms; while (System.currentTimeMillis() < end) { if (cond()) return true; Thread.sleep(20) }; return cond() }

/** A UDP echo server standing in for a DIRECT destination; counts what reaches it. */
private class UdpDirectServer {
    val sock = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = sock.localPort
    val got = java.util.concurrent.atomic.AtomicInteger()
    init {
        Thread {
            val b = ByteArray(2048)
            while (!sock.isClosed) {
                val pk = java.net.DatagramPacket(b, b.size)
                try { sock.receive(pk) } catch (_: Exception) { break }
                got.incrementAndGet()
                val out = "D:".toByteArray() + b.copyOf(pk.length)
                try { sock.send(java.net.DatagramPacket(out, out.size, pk.socketAddress)) } catch (_: Exception) { }
            }
        }.apply { isDaemon = true }.start()
    }
    fun close() = sock.close()
}

fun udpRelayTests() {
    val rules = RouteMatcher.parse("[block]\nblocked.example\n198.51.100.7\n[direct]\ndirect.example\n127.0.0.1\n")
    val tun = UdpRelay.Tuning(idleMs = 120_000L, upstreamRetryMs = 200L, refuseLoopback = false)
    fun mk(up: FakeUpstream, opts: RouteFront.Options, matcher: RouteMatcher = rules, logs: MutableList<String> = ArrayList()): Pair<RouteFront, Int> {
        val port = freePort()
        val f = RouteFront(port, up.port, matcher, opts) { synchronized(logs) { logs.add(it) } }
        f.start(); return f to port
    }
    fun transportFor(ip: String, calls: MutableList<String>? = null) = FakeTransport { q ->
        calls?.add(qnameOf(q))
        val it = ip.split('.').map { x -> x.toInt() }
        mkResp(qnameOf(q), qtypeOf(q), answers = if (qtypeOf(q) == 1) listOf(rr(12, 1, 120, a4(it[0], it[1], it[2], it[3]))) else emptyList())
    }
    fun body(r: ByteArray?, hs: Int = 10): String = if (r == null) "" else String(r, hs, r.size - hs)

    // --- PROXY to an IP: carried through the upstream, in both directions; one upstream association for many datagrams
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        val fl = UdpFlow(port)
        check("udp: ASSOCIATE answered with a loopback relay address", fl.code == 0 && lastReply[3].toInt() == 1 && lastReply[4].toInt() == 127)
        check("udp: nothing is opened upstream before the first datagram", up.requests.isEmpty())
        fl.send(udpHdrIp("93.184.216.34", 443), "one"); val r1 = fl.recv()
        fl.send(udpHdrIp("93.184.216.34", 443), "two"); val r2 = fl.recv()
        check("udp: PROXY datagram reaches the upstream and the answer comes back with its header",
            body(r1) == "R:one" && body(r2) == "R:two" && r1!!.copyOf(10).contentEquals(udpHdrIp("93.184.216.34", 443)))
        check("udp: one upstream association serves every datagram of the flow", up.requests.toList() == listOf("UDP") && up.udpSeen.toList() == listOf("93.184.216.34:443", "93.184.216.34:443"))
        waitFor(1000) { f.udpStats().fromUpstream == 2L } // the counter moves just after the client got the datagram
        val st = f.udpStats()
        check("udp: stats count the datagrams and the association", st.active == 1 && st.opened == 1L && st.toUpstream == 2L && st.fromUpstream == 2L && st.droppedTotal == 0L)
        fl.close()
        check("udp: closing the control connection ends the association upstream too", up.controlClosed.await(3, java.util.concurrent.TimeUnit.SECONDS))
        check("udp: with no association left the relay thread ends", waitFor(3000) { relayThreads() == 0 && f.udpStats().active == 0 })
        f.stop(); up.close()
    }
    // --- BLOCK by name and by IP: dropped, nothing opened, nothing sent anywhere
    run {
        val up = FakeUpstream(udp = true); val dir = UdpDirectServer()
        val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        val fl = UdpFlow(port)
        fl.send(udpHdrName("blocked.example", 443), "x"); fl.send(udpHdrIp("198.51.100.7", 443), "y")
        check("udp: a BLOCK rule (name and IP) drops the datagram: no answer", fl.recv(600) == null)
        check("udp: ... and nothing is opened or sent upstream or direct", up.requests.isEmpty() && up.udpSeen.isEmpty() && dir.got.get() == 0)
        check("udp: ... and the drop is counted as a rule block", waitFor(1000) { f.udpStats().droppedBlocked == 2L }.also { if (!it) println("   stats: ${f.udpStats()}") })
        fl.close(); f.stop(); up.close(); dir.close()
    }
    // --- DIRECT: from the app's own socket; the upstream is never contacted
    run {
        val up = FakeUpstream(udp = true); val dir = UdpDirectServer()
        val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        val fl = UdpFlow(port)
        fl.send(udpHdrIp("127.0.0.1", dir.port), "hi"); val r = fl.recv()
        check("udp: a DIRECT rule sends the datagram straight out and returns the answer with the right header",
            body(r) == "D:hi" && r!!.copyOf(10).contentEquals(udpHdrIp("127.0.0.1", dir.port)))
        check("udp: ... without touching the upstream", up.requests.isEmpty() && up.udpSeen.isEmpty())
        val st = f.udpStats()
        check("udp: direct counters", st.toDirect == 1L && st.fromDirect == 1L && st.toUpstream == 0L)
        fl.close(); f.stop(); up.close(); dir.close()
    }
    // --- names: without DoH the NAME goes upstream unresolved
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        val fl = UdpFlow(port)
        fl.send(udpHdrName("example.com", 443), "q"); val r = fl.recv()
        check("udp: a PROXY name without DoH is forwarded as a name", r != null && up.udpSeen.toList() == listOf("example.com:443") && body(r, r.size - 3) == "R:q")
        fl.close(); f.stop(); up.close()
    }
    // --- names with DoH: PROXY names are resolved by the app (cached), DIRECT names by the direct resolver
    run {
        val up = FakeUpstream(udp = true); val dir = UdpDirectServer(); val calls = ArrayList<String>(); val dcalls = ArrayList<String>()
        val opts = RouteFront.Options(
            resolver = FrontResolver(transportFor("93.184.216.34", calls)), directResolver = FrontResolver(transportFor("127.0.0.1", dcalls)),
            udpCapable = true, udpTuning = tun, guardFakeIps = true
        )
        val (f, port) = mk(up, opts)
        val fl = UdpFlow(port)
        fl.send(udpHdrName("example.com", 443), "a"); val r1 = fl.recv(); fl.send(udpHdrName("example.com", 443), "b"); val r2 = fl.recv()
        check("udp: with DoH a PROXY name reaches the upstream as an IP", r1 != null && r2 != null && up.udpSeen.toList() == listOf("93.184.216.34:443", "93.184.216.34:443"))
        check("udp: ... resolved once for the whole flow", calls.count { it == "example.com" } == 1)
        fl.send(udpHdrName("direct.example", dir.port), "d"); val r3 = fl.recv()
        check("udp: with DoH-for-direct a DIRECT name is resolved by the direct resolver and sent from the app", r3 != null && body(r3, r3.size - 3) == "D:d" && dir.got.get() == 1 && dcalls.contains("direct.example"))
        check("udp: ... the reply carries an IP header", r3 != null && r3[3].toInt() == 1)
        fl.close(); f.stop(); up.close(); dir.close()
    }
    // --- guard: stale fake IPs, malformed and fragmented packets
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun, guardFakeIps = true))
        val fl = UdpFlow(port)
        fl.send(udpHdrIp("100.64.0.9", 443), "stale")                         // hev forgot its name
        fl.send(udpHdrIp("224.0.0.251", 5353), "mdns")                         // multicast
        fl.send(byteArrayOf(0, 0, 1, 1, 1, 2, 3, 4, 0, 80), "frag")            // FRAG != 0
        fl.send(byteArrayOf(0, 0, 0, 9, 1, 2), "junk")                         // bad ATYP
        check("udp: stale fake IP, multicast, fragments and junk are dropped, nothing is sent", fl.recv(600) == null && up.requests.isEmpty())
        waitFor(1000) { f.udpStats().droppedTotal == 4L }
        val st = f.udpStats()
        check("udp: each drop is counted under its reason", st.droppedGuard == 2L && st.droppedBadPacket == 2L)
        fl.close(); f.stop(); up.close()
    }
    // --- a proxy that fails must NOT become a leak: no fallback to DIRECT
    run {
        val dir = UdpDirectServer(); val logs = ArrayList<String>()
        val up = FakeUpstream(udp = true, failUdp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun), logs = logs)
        val fl = UdpFlow(port)
        fl.send(udpHdrIp("93.184.216.34", 443), "a")
        check("udp: upstream refuses ASSOCIATE -> the datagram is dropped, no answer", fl.recv(800) == null)
        check("udp: ... and it is NOT sent direct instead", dir.got.get() == 0 && up.udpSeen.isEmpty())
        check("udp: ... the drop is counted and logged once without any destination",
            waitFor(1000) { f.udpStats().droppedNoUpstream >= 1L } && synchronized(logs) { logs.count { it.contains("never sent direct") } == 1 && logs.none { it.contains("93.184") } })
        fl.close(); f.stop(); up.close()
        // upstream gone altogether
        val up2 = FakeUpstream(udp = true); val (f2, port2) = mk(up2, RouteFront.Options(udpCapable = true, udpTuning = tun))
        up2.close()
        val fl2 = UdpFlow(port2)
        fl2.send(udpHdrIp("93.184.216.34", 443), "b")
        check("udp: upstream down -> dropped, not direct", fl2.recv(800) == null && waitFor(1000) { f2.udpStats().droppedNoUpstream >= 1L } && dir.got.get() == 0)
        fl2.close(); f2.stop(); dir.close()
    }
    // --- UDP switched OFF while connected: associations end at once, new ones are refused, TCP is untouched; ON again works
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        val fl = UdpFlow(port)
        fl.send(udpHdrIp("93.184.216.34", 443), "a"); fl.recv()
        check("udp live: before switching off there is one association and one relay thread", f.udpStats().active == 1 && relayThreads() == 1 && f.udpActive)
        f.setUdpEnabled(false)
        check("udp live: switching off closes the control connection", fl.ctrlClosedWithin(2000))
        check("udp live: ... frees the association and ends the relay thread", waitFor(3000) { f.udpStats().active == 0 && relayThreads() == 0 })
        check("udp live: ... and the upstream's side is closed too", up.controlClosed.await(3, java.util.concurrent.TimeUnit.SECONDS))
        val before = up.udpSeen.size
        try { fl.send(udpHdrIp("93.184.216.34", 443), "late") } catch (_: Exception) { }
        check("udp live: datagrams sent after switching off get no answer and reach no one", fl.recv(500) == null && up.udpSeen.size == before)
        val (code, s2) = socks(port, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); s2.close()
        check("udp live: a new ASSOCIATE is refused with 0x07 and counted", code == 7 && f.udpStats().refusedAssociations == 1L && !f.udpActive)
        val (tc, ts) = socks(port, reqIp("93.184.216.34", 443))
        check("udp live: TCP through the same front still works while UDP is off", tc == 0 && echoOk(ts)); ts.close()
        f.setUdpEnabled(true)
        val fl2 = UdpFlow(port)
        fl2.send(udpHdrIp("93.184.216.34", 443), "back"); val r = fl2.recv()
        check("udp live: switching on again accepts and carries UDP", fl2.code == 0 && body(r) == "R:back")
        fl2.close(); fl.close(); f.stop(); up.close()
    }
    // --- started with UDP OFF: refused, no UDP socket or thread exists, TCP works
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpOn = false, udpTuning = tun))
        val (code, s) = socks(port, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); s.close()
        check("udp off: ASSOCIATE is refused (0x07) and the upstream is never contacted", code == 7 && up.requests.isEmpty() && f.udpStats().refusedAssociations == 1L)
        check("udp off: no relay thread and no association exist", relayThreads() == 0 && f.udpStats().active == 0 && f.udpStats().opened == 0L)
        val (tc, ts) = socks(port, reqIp("93.184.216.34", 443))
        check("udp off: TCP works normally", tc == 0 && echoOk(ts)); ts.close()
        f.stop(); up.close()
    }
    // --- idle: the association ends by itself, the thread with it
    run {
        val up = FakeUpstream(udp = true)
        val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = UdpRelay.Tuning(idleMs = 400L, refuseLoopback = false)))
        val fl = UdpFlow(port)
        fl.send(udpHdrIp("93.184.216.34", 443), "a"); fl.recv()
        check("udp idle: an idle association is closed after the idle timeout", fl.ctrlClosedWithin(4000))
        check("udp idle: ... its sockets and the relay thread are gone", waitFor(3000) { relayThreads() == 0 && f.udpStats().active == 0 })
        fl.close(); f.stop(); up.close()
    }
    // --- many flows: still ONE relay thread; stop() ends everything
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        val flows = (1..20).map { UdpFlow(port) }
        flows.forEachIndexed { i, fl -> fl.send(udpHdrIp("93.184.216.34", 443), "m$i") }
        val answered = flows.count { it.recv() != null }
        check("udp: 20 flows are all answered", answered == 20)
        check("udp: ... by ONE relay thread", relayThreads() == 1 && f.udpStats().active == 20)
        f.stop()
        check("udp: stop() ends every association and the relay thread", waitFor(3000) { relayThreads() == 0 } && flows.all { it.ctrlClosedWithin(1000) })
        flows.forEach { it.close() }; up.close()
    }
    // --- the relay only listens to one client port
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        val fl = UdpFlow(port)
        fl.send(udpHdrIp("93.184.216.34", 443), "a"); fl.recv()
        val other = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
        val b = udpHdrIp("93.184.216.34", 443) + "intruder".toByteArray()
        other.send(java.net.DatagramPacket(b, b.size, fl.sock.remoteSocketAddress)); other.close()
        Thread.sleep(300)
        check("udp: a datagram from another local port is not relayed", up.udpSeen.size == 1)
        fl.close(); f.stop(); up.close()
    }

    // --- churn: associations opened and closed in a tight loop (the relay thread starts and ends again and again)
    run {
        val up = FakeUpstream(udp = true); val (f, port) = mk(up, RouteFront.Options(udpCapable = true, udpTuning = tun))
        var allOpened = true
        for (i in 1..150) {
            val fl = UdpFlow(port)
            if (fl.code != 0) allOpened = false
            if (i % 3 == 0) fl.send(udpHdrIp("93.184.216.34", 443), "c$i")
            fl.close()
        }
        check("udp churn: 150 open/close cycles all succeed", allOpened)
        check("udp churn: everything is released afterwards", waitFor(5000) { f.udpStats().active == 0 && relayThreads() == 0 })
        val fl = UdpFlow(port)
        fl.send(udpHdrIp("93.184.216.34", 443), "after"); val r = fl.recv()
        check("udp churn: the relay still works after the churn", fl.code == 0 && body(r) == "R:after")
        fl.close(); f.stop(); up.close()
    }

    // --- pure: status text, plan
    run {
        val none = PrivacyChain.NONE; val sb = PrivacyChain.SINGBOX; val psi = PrivacyChain.PSIPHON
        check("status: front carrying UDP is RELAY", UdpStatus.of(true, sb, true, true, true) == UdpState.RELAY)
        check("status: setting off with a front is OFF", UdpStatus.of(false, none, true, false, false) == UdpState.OFF)
        check("status: no front, setting on, started on -> straight to the upstream", UdpStatus.of(true, none, false, false, true) == UdpState.UPSTREAM_DIRECT)
        check("status: no front, setting turned off -> applies at the next connect", UdpStatus.of(false, none, false, false, true) == UdpState.PENDING_OFF)
        check("status: no front, setting turned on after starting off -> PENDING_ON", UdpStatus.of(true, none, false, false, false) == UdpState.PENDING_ON)
        check("status: Psiphon/Tor refuse UDP", UdpStatus.of(true, psi, true, false, true) == UdpState.CHAIN_REFUSES && UdpStatus.of(true, PrivacyChain.TOR, false, false, true) == UdpState.CHAIN_REFUSES)
        val off = FrontPlan.of(none, false, false, 1819, udpEnabled = false)
        check("plan: UDP off without anything else still starts the front (only it can refuse ASSOCIATE) and forces hev's DNS",
            off.frontOn && !off.udpRelay && off.mappedDns && off.corePort == Chain.UNDERLAY_PORT && off.coreGetsRoutes)
        check("plan: UDP on, no DoH, no chain: no front, plain DNS as before", FrontPlan.of(none, false, false, 1819).let { !it.frontOn && !it.mappedDns })
        check("plan: sing-box with rules: relay on; UDP off turns it off", FrontPlan.of(sb, false, true, 1819).udpRelay && !FrontPlan.of(sb, false, true, 1819, udpEnabled = false).udpRelay)
        check("plan: sing-box without rules and DoH: no front, hev -> sing-box directly", FrontPlan.of(sb, false, false, 1819).let { !it.frontOn && !it.udpRelay })
        val cfgOff = EngineConfig(udpEnabled = false); val cfgOn = EngineConfig()
        check("config: UDP on by default, mapped DNS only when needed", cfgOn.udpEnabled && !cfgOn.mappedDnsActive && cfgOff.mappedDnsActive)
        check("config: mappedDnsActive agrees with the plan", listOf(none, sb, psi, PrivacyChain.TOR).all { ch -> listOf(false, true).all { d -> listOf(false, true).all { u ->
            val c = EngineConfig(protocol = Protocol.WIREGUARD, privacyChain = ch, dohOn = d, dohResolvers = if (d) listOf("https://1.1.1.1/dns-query") else emptyList(), udpEnabled = u)
            c.mappedDnsActive == FrontPlan.of(c.effectiveChain, c.dohActive, false, c.socksPort, u).mappedDns } } })
    }
}


// =====================================================================================================
// update21: speed meter check (SpeedMeterCheck)
// =====================================================================================================

private fun speedMeterTests() {
    val P = SpeedMeterCheck.Kind.PHYSICAL; val T = SpeedMeterCheck.Kind.TUNNEL; val L = SpeedMeterCheck.Kind.LOOPBACK
    fun r(n: String, k: SpeedMeterCheck.Kind, rx: Long, tx: Long) = SpeedMeterCheck.Reading(n, k, rx, tx)
    val mb = 1_000_000L
    val before = listOf(r("lo", L, 5 * mb, 5 * mb), r("tun0", T, 7 * mb, 1 * mb), r("wlan0", P, 100 * mb, 10 * mb))
    // 10 s: the link moved 100 MB down / 10 MB up; the tunnel the same; three loopback hops carried 300 MB down / 30 MB up
    val after = listOf(r("lo", L, 305 * mb, 35 * mb), r("tun0", T, 107 * mb, 11 * mb), r("wlan0", P, 200 * mb, 20 * mb))
    val res = SpeedMeterCheck.compute(before, after, longArrayOf(0, 0), longArrayOf(500 * mb, 50 * mb), 10_000)!!
    check("meter: link rate is bytes per second", res.down.physical == 10 * mb && res.up.physical == 1 * mb)
    check("meter: tunnel and loopback rates", res.down.tunnel == 10 * mb && res.down.loopback == 30 * mb)
    check("meter: tunnel + link is 2x", res.down.tunnelPlusLink == 2.0)
    check("meter: with loopback is 5x", res.down.withLoopback == 5.0)
    check("meter: phone total counter 5x", res.down.systemTotal == 5.0 && res.up.systemTotal == 5.0)
    check("meter: enough traffic", res.enough && res.seconds == 10.0)

    // no speed test running: nothing to compare against
    val quiet = SpeedMeterCheck.compute(before, before, longArrayOf(1, 1), longArrayOf(1, 1), 10_000)!!
    check("meter: no traffic is not enough and has no factors", !quiet.enough && quiet.down.tunnelPlusLink == null && quiet.down.systemTotal == null)

    // an interface that exists only in one snapshot is ignored; a counter that went back is no traffic
    val switched = SpeedMeterCheck.compute(
        before, listOf(r("lo", L, 1 * mb, 1 * mb), r("rmnet_data0", P, 900 * mb, 900 * mb)), null, null, 10_000
    )!!
    check("meter: new interface ignored, reset counter is zero", switched.down.physical == 0L && switched.down.loopback == 0L)

    // unsupported system counters (the API returns -1) or none at all: no total, the rest still works
    val noSys = SpeedMeterCheck.compute(before, after, longArrayOf(-1, -1), longArrayOf(-1, -1), 10_000)!!
    check("meter: unsupported total counter is null", noSys.down.system == null && noSys.down.systemTotal == null && noSys.down.tunnelPlusLink == 2.0)
    check("meter: non-positive window gives nothing", SpeedMeterCheck.compute(before, after, null, null, 0) == null)

    // the raw rows and the reasons a result can be empty
    check("meter: raw rows list every interface with its rates", res.rows.size == 3 && res.rows.first { it.name == "wlan0" }.let { it.downBps == 10 * mb && it.upBps == 1 * mb })
    check("meter: link seen", res.linkSeen && !res.countersHidden)
    check("meter: switched network means no link seen", !switched.linkSeen)
    // the phone-wide counter moved 50 MB in 10 s but no interface counter changed: per-interface counters are hidden
    val hidden = SpeedMeterCheck.compute(before, before, longArrayOf(0, 0), longArrayOf(500 * mb, 0), 10_000)!!
    check("meter: moving total with a still link means hidden counters", hidden.linkSeen && !hidden.enough && hidden.countersHidden)
    check("meter: an idle phone is not hidden counters", !quiet.countersHidden)
    // download test: down is the real direction; upload test: up is
    check("meter: a download test is dominated by down", res.dominantIsDown)
    val uploadTest = SpeedMeterCheck.compute(
        listOf(r("wlan0", P, 0, 0)), listOf(r("wlan0", P, 10 * mb, 100 * mb)), null, null, 10_000
    )!!
    check("meter: an upload test is dominated by up", !uploadTest.dominantIsDown)
    // ---- update24: experimental tunnel engine (hev / sing-box TUN)
    check("engine id: round trip", TunEngineId.entries.all { TunEngineId.fromStored(it.stored) == it })
    check("engine id: unknown or missing is hev", TunEngineId.fromStored("x") == TunEngineId.HEV && TunEngineId.fromStored(null) == TunEngineId.HEV)
    check("counters: total bytes", TunCounters(1, 100, 2, 300).totalBytes == 400L && TunCounters(null, 5, null, 7).totalBytes == 12L)
    check("counters: unsupported (-1) is null, not zeros", countersOrNull(-1, 5) == null && countersOrNull(5, -1) == null)
    check("counters: valid pair has no packets", countersOrNull(5, 7).let { it != null && it.txBytes == 5L && it.rxBytes == 7L && it.txPackets == null && it.rxPackets == null })
    check("select engine: hev is always used", listOf(false, true).all { selectTunEngine(TunEngineId.HEV, it) == EngineSelection.Use(TunEngineId.HEV) })
    check("select engine: sing-box TUN used when present", selectTunEngine(TunEngineId.SINGBOX_TUN, true) == EngineSelection.Use(TunEngineId.SINGBOX_TUN))
    check("select engine: missing sing-box TUN is reported, never replaced by hev",
        selectTunEngine(TunEngineId.SINGBOX_TUN, false).let { it is EngineSelection.Unavailable && it.reason.isNotBlank() })

    // idle mode with unknown counters
    run {
        val quietNull = IdleTracker()
        var idleNow = false
        for (t in listOf(1_000L, 61_000L, 131_000L, 191_000L)) idleNow = quietNull.onTick(t, false, null)
        check("idle: today unknown counters with the screen off end in idle mode", idleNow)
        val unknown = IdleTracker()
        var idleUnknown = false
        for (t in listOf(1_000L, 61_000L, 131_000L, 191_000L)) { unknown.onTick(t, false, null); idleUnknown = unknown.onUnknownCounters() }
        check("idle: onUnknownCounters never drifts into idle", !idleUnknown && !unknown.idle)
    }

    // fd handoff socket path
    check("tun fd socket: path is dir + name", TunFdChannel.socketPath("/data/user/0/com.aethershield.app/cache/singtun") == "/data/user/0/com.aethershield.app/cache/singtun/tunfd.sock")
    check("tun fd socket: a trailing slash is not doubled", TunFdChannel.socketPath("/a/b/") == "/a/b/tunfd.sock")
    check("tun fd socket: a path over the unix limit is refused", runCatching { TunFdChannel.socketPath("/" + "d".repeat(120)) }.isFailure)

    // sing-box TUN config
    run {
        val plain = SingBoxTunConfig.render(1400, 1819, false)
        val mapped = SingBoxTunConfig.render(1360, 10808, true)
        check("singtun config: no stack key (deprecated in 1.15)", !plain.contains("\"stack\"") && !mapped.contains("\"stack\""))
        check("singtun config: addresses equal the VpnService ones", plain.contains("10.10.14.1/30") && plain.contains("fc00::10:10:14:1/126"))
        check("singtun config: mtu and port follow the input", plain.contains("\"mtu\": 1400") && plain.contains("\"server_port\": 1819") && mapped.contains("\"mtu\": 1360") && mapped.contains("\"server_port\": 10808"))
        check("singtun config: auto_route is off and the log level is warn", plain.contains("\"auto_route\": false") && plain.contains("\"level\": \"warn\""))
        check("singtun config: fakeip and DNS hijack only with mapped DNS",
            !plain.contains("fakeip") && !plain.contains("hijack-dns") && mapped.contains("100.64.0.0/10") && mapped.contains("hijack-dns") && mapped.contains("198.18.0.2/32"))
        check("singtun config: bad input is refused", runCatching { SingBoxTunConfig.render(1400, 0, false) }.isFailure && runCatching { SingBoxTunConfig.render(100, 1819, false) }.isFailure)
        val root = System.getenv("MADSHIELD_ROOT") ?: "."
        val dir = java.io.File(root, "tests/pure/golden-singtun")
        for ((name, text) in linkedMapOf("singtun-plain.json" to plain, "singtun-mapdns.json" to mapped)) {
            val f = java.io.File(dir, name)
            if (System.getenv("UPDATE_GOLDEN") == "1") { dir.mkdirs(); f.writeText(text) }
            check("golden: $name matches the builder", f.isFile && f.readText() == text)
        }
    }
}
