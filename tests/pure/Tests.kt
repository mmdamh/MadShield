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
            !p1.frontOn && p1.corePort == 1819 && p1.chainPort == null && p1.upstreamPort == 1819 && !p1.udpPassThrough && p1.coreGetsRoutes && !p1.localDoh)
        val p1b = FrontPlan.of(none, false, true, 1819)
        check("plan: no chain, rules but no DoH: still no front (the core applies them)", !p1b.frontOn && p1b.corePort == 1819 && p1b.coreGetsRoutes)
        val p2 = FrontPlan.of(psi, false, true, 1819)
        check("plan: chain + rules, no DoH: update10 front", p2.frontOn && p2.corePort == 1823 && p2.chainPort == 1824 && p2.upstreamPort == 1824 && !p2.udpPassThrough && !p2.coreGetsRoutes && !p2.localDoh)
        val p3 = FrontPlan.of(tor, false, false, 1819)
        check("plan: chain, no rules, no DoH: update10 (chain on the public port)", !p3.frontOn && p3.corePort == 1823 && p3.chainPort == 1819 && p3.upstreamPort == 1819 && p3.coreGetsRoutes)
        val p4 = FrontPlan.of(none, true, false, 1819)
        check("plan: DoH without a chain: front on, core on 1823, UDP passes through, core keeps the rules",
            p4.frontOn && p4.corePort == 1823 && p4.chainPort == null && p4.upstreamPort == 1823 && p4.udpPassThrough && p4.coreGetsRoutes && p4.localDoh)
        val p5 = FrontPlan.of(psi, true, false, 1819)
        check("plan: DoH with Psiphon (no rules): front on, chain on 1824, no UDP, no routes for the core",
            p5.frontOn && p5.corePort == 1823 && p5.chainPort == 1824 && p5.upstreamPort == 1824 && !p5.udpPassThrough && !p5.coreGetsRoutes && p5.localDoh)
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
}


// ---------------------------------------------------------------------------------------------------
// RouteFront end to end: a real front on a loopback port, a fake SOCKS5 upstream, a fake DoH transport.
// ---------------------------------------------------------------------------------------------------

private class FakeUpstream(val rejectIps: Set<String> = emptySet()) {
    val server = java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort
    val requests = java.util.concurrent.ConcurrentLinkedQueue<String>()
    val udpBnd = byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0x15, 0xB3.toByte()) // 127.0.0.1:5555
    val controlClosed = java.util.concurrent.CountDownLatch(1)
    init {
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
                requests.add("UDP"); o.write(udpBnd); o.flush()
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
    fun close() { try { server.close() } catch (_: Exception) { } }
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
    // --- UDP
    run {
        val up = FakeUpstream(); val (f, port) = front(up, FrontResolver(transportFor("1.1.1.1")), RouteFront.Options(resolver = FrontResolver(transportFor("1.1.1.1")), udpPassThrough = true, guardFakeIps = true))
        val (code, s) = socks(port, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        check("front: UDP ASSOCIATE is relayed and the upstream's reply (its relay address) comes back byte for byte", code == 0 && lastReply.contentEquals(up.udpBnd) && up.requests.toList() == listOf("UDP"))
        s.close()
        check("front: closing the control connection ends the association upstream", up.controlClosed.await(3, java.util.concurrent.TimeUnit.SECONDS))
        f.stop(); up.close()
        val up2 = FakeUpstream(); val (f2, port2) = front(up2, FrontResolver(transportFor("1.1.1.1")))
        val (code2, s2) = socks(port2, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); s2.close()
        check("front: UDP ASSOCIATE with a chain (no pass-through) is refused with 0x07", code2 == 7 && up2.requests.isEmpty())
        f2.stop(); up2.close()
        val up3 = FakeUpstream(); val (f3, port3) = front(up3, null, RouteFront.Options())
        val (code3, s3) = socks(port3, byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)); s3.close()
        check("front: update10 behaviour for UDP is unchanged (0x07)", code3 == 7)
        f3.stop(); up3.close()
        val up4 = FakeUpstream(); val (f4, port4) = front(up4, null, RouteFront.Options(udpPassThrough = true))
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
        val real = "[2026-10-22T08:35:11.000Z WARN  aether::psiphon] [-] psiphon: meek round trip failed: connection refused"
        check("probe line recognised", LogNoiseFolder.isOwnProbeNoise(eof))
        check("other psiphon lines are not noise", !LogNoiseFolder.isOwnProbeNoise(real))
        check("a line that merely says EOF elsewhere is not noise", !LogNoiseFolder.isOwnProbeNoise("[x] read: EOF"))
        val f = LogNoiseFolder()
        check("first noise line is kept", f.feed(eof) == listOf(eof))
        check("later noise is swallowed", f.feed(eof2).isEmpty() && f.feed(eof2).isEmpty())
        val out = f.feed(real)
        check("a real line flushes a summary first, then itself", out.size == 2 && out[0].contains("folded 2 more") && out[1] == real)
        check("no summary when nothing was folded", f.feed(real) == listOf(real))
        val g = LogNoiseFolder(); g.feed(eof)
        var summaries = 0; var kept = 0
        repeat(LogNoiseFolder.SUMMARY_EVERY * 3) { for (l in g.feed(eof2)) { if (l.contains("folded")) summaries++ else kept++ } }
        check("a long run of noise leaves 1 summary per ${LogNoiseFolder.SUMMARY_EVERY} lines and no raw line", summaries == 3 && kept == 0)
        // Diagnostics never counted this line, so folding it changes nothing there
        val sig = LogSignals.scan(listOf(eof, eof2))
        check("probe line is not a diagnostics signal", sig.dns == 0 && sig.tcp == 0 && sig.handshake == 0 && sig.timeouts == 0)
    }
}
