package com.madshield.app.core

import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong

/**
 * One way to send a DNS message and get the answer back (DoH in the app, a fake in the tests).
 * Blocking; every failure (timeout, bad status, closed connection) is an [IOException].
 */
interface DnsTransport {
    @Throws(IOException::class)
    fun exchange(query: ByteArray): ByteArray

    /** Drop idle connections (screen off and quiet). Must be cheap and must not start any timer. */
    fun closeIdle() {}

    /** Drop everything (tunnel went down or the front stops). */
    fun close() {}
}

/**
 * Tries each transport in order and moves to the next one only when the previous FAILED (an NXDOMAIN is an
 * answer, not a failure). This is the only fallback there is: never to plain DNS, never to the chain's exit.
 */
class FallbackTransport(private val chain: List<DnsTransport>) : DnsTransport {
    init { require(chain.isNotEmpty()) { "at least one DoH resolver" } }

    override fun exchange(query: ByteArray): ByteArray {
        var last: IOException? = null
        for (t in chain) {
            try { return t.exchange(query) } catch (e: IOException) { last = e }
        }
        throw last ?: IOException("no DoH resolver answered")
    }

    override fun closeIdle() = chain.forEach { it.closeIdle() }
    override fun close() = chain.forEach { it.close() }
}

/** Why a name could not be resolved. [nxdomain] = the resolver answered "no such name". */
class ResolveFailure(message: String, val nxdomain: Boolean = false) : IOException(message)

/**
 * Turns a host name into addresses through [transport], with a cache and one network request per name at a
 * time. NEVER touches the system resolver: if the DoH resolvers cannot answer the lookup fails (optionally
 * after serving a recently expired cache entry), which RouteFront reports as a SOCKS error.
 *
 * Counters are plain numbers read once, when the front stops. Names are never logged.
 *
 * [ipMode] follows the engine setting: "v4" asks for A only, "v6" asks AAAA first then A, "both" asks A and
 * falls back to AAAA when the name has no A record.
 */
class FrontResolver(
    private val transport: DnsTransport,
    private val ipMode: String = "v4",
    private val serveStale: Boolean = false,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val cache: DnsCache = DnsCache()
) {
    private val flight = Singleflight<DnsCache.Key, Resolved>()

    private val nQueries = AtomicLong()
    private val nCacheHits = AtomicLong()
    private val nFailures = AtomicLong()
    private val nStale = AtomicLong()
    private val nNx = AtomicLong()
    val queries: Long get() = nQueries.get()
    val cacheHits: Long get() = nCacheHits.get()
    val failures: Long get() = nFailures.get()
    val staleServed: Long get() = nStale.get()
    val nxdomains: Long get() = nNx.get()

    /**
     * @return one or more addresses (the order the resolver gave)
     * @throws ResolveFailure when the name does not exist or the resolvers cannot be reached
     */
    fun resolve(name: String): List<InetAddress> {
        DnsMessage.parseIpLiteral(name)?.let { return listOf(InetAddress.getByAddress(it)) }
        val n = DnsMessage.normalize(name) ?: throw ResolveFailure("not a resolvable name")

        val order = when (ipMode) {
            "v6" -> listOf(DnsMessage.TYPE_AAAA, DnsMessage.TYPE_A)
            "both" -> listOf(DnsMessage.TYPE_A, DnsMessage.TYPE_AAAA)
            else -> listOf(DnsMessage.TYPE_A)
        }
        var lastNx = false
        for (type in order) {
            val r = lookup(n, type)
            if (r.addresses.isNotEmpty()) return r.addresses.map { InetAddress.getByAddress(it) }
            lastNx = r.nxdomain
            if (r.nxdomain) break // no such name: asking for another record type cannot help
        }
        if (lastNx) nNx.incrementAndGet()
        throw ResolveFailure(if (lastNx) "no such name" else "no address record", nxdomain = lastNx)
    }

    private fun lookup(name: String, type: Int): Resolved {
        val key = DnsCache.Key(name, type)
        cache.get(key, clock())?.let { nCacheHits.incrementAndGet(); return it }
        return try {
            flight.execute(key) {
                // another caller may have filled the cache while this one was waiting to lead
                cache.get(key, clock())?.let { nCacheHits.incrementAndGet(); return@execute it }
                fetch(name, type, key)
            }
        } catch (e: ResolveFailure) {
            throw e
        } catch (e: Exception) {
            nFailures.incrementAndGet()
            if (serveStale) {
                cache.getStale(key, clock())?.let { nStale.incrementAndGet(); return it }
            }
            throw ResolveFailure(e.message ?: "DoH lookup failed")
        }
    }

    private fun fetch(name: String, type: Int, key: DnsCache.Key): Resolved {
        val query = DnsMessage.buildQuery(name, type) ?: throw ResolveFailure("not a resolvable name")
        nQueries.incrementAndGet()
        val raw = transport.exchange(query)
        val resp = DnsMessage.parseResponse(raw) ?: throw IOException("unreadable DNS answer")
        if (resp.truncated) throw IOException("truncated DNS answer")
        if (resp.question.type != type || resp.question.name != name) throw IOException("answer is for another question")

        val now = clock()
        when (resp.rcode) {
            DnsMessage.RCODE_NOERROR -> Unit
            DnsMessage.RCODE_NXDOMAIN -> {
                val r = Resolved(emptyList(), nxdomain = true)
                cache.put(key, r, DnsCache.negativeTtl(resp.negativeTtl), now)
                return r
            }
            else -> throw IOException("resolver answered rcode ${resp.rcode}") // SERVFAIL, REFUSED: a failure, not an answer
        }

        // Follow the CNAME chain from the question name; ignore records that belong to some other name.
        val owners = HashSet<String>().apply { add(name) }
        var grew = true
        var rounds = 0
        while (grew && rounds++ < 16) {
            grew = false
            for (rec in resp.answers) {
                if (rec.type == DnsMessage.TYPE_CNAME && rec.name in owners && rec.target != null && owners.add(rec.target)) grew = true
            }
        }
        val addrs = ArrayList<ByteArray>()
        val ttls = ArrayList<Long>()
        for (rec in resp.answers) {
            val a = rec.address ?: continue
            if (rec.type != type || rec.name !in owners) continue
            if (addrs.none { it.contentEquals(a) }) addrs.add(a)
            ttls.add(rec.ttl)
        }
        if (addrs.isEmpty()) {
            val r = Resolved(emptyList(), nxdomain = false)
            cache.put(key, r, DnsCache.negativeTtl(resp.negativeTtl), now)
            return r
        }
        val r = Resolved(addrs, nxdomain = false)
        cache.put(key, r, DnsCache.positiveTtl(ttls), now)
        return r
    }

    fun closeIdle() = transport.closeIdle()

    /** Forget everything (tunnel went down: answers learned through it may not be valid for the next one). */
    fun clear() { cache.clear(); transport.close() }

    fun summary(): String =
        "doh: $queries queries, $cacheHits cache hits, $nxdomains no-such-name, $failures failed, $staleServed served stale"
}
