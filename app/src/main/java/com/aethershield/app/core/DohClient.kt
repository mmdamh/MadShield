package com.aethershield.app.core

import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import okhttp3.Protocol as HttpProtocol

/**
 * DoH (RFC 8484, POST) to ONE resolver, as a [DnsTransport].
 *
 * How the connection is made (and why it cannot leak):
 *  - the resolver's IP comes from the [DohSpec] (`@address=`), so the app never needs ordinary DNS to reach it;
 *  - the TCP connection goes through the upstream SOCKS port ([socksPort]: the core, or Psiphon/Tor), straight
 *    to that IP. It does NOT go through RouteFront (no loop) and carries an IP, not a name, so the upstream
 *    never resolves anything for it. With [socksPort] = null the connection is made directly from the phone
 *    (this app is excluded from the VPN): only used for "DoH for Direct" names;
 *  - TLS runs on top, with the certificate checked against the resolver's host name (or `@sni=` name);
 *  - redirects are never followed.
 *
 * Battery: no pings, no keep-alive timers of our own. HTTP/2 lets one connection serve every query; the
 * connection pool keeps at most one idle connection for 60 s, and [closeIdle] drops it earlier when the
 * screen is off and the tunnel is quiet. After any failure the pool is emptied, so a broken connection is
 * never reused.
 *
 * NOT compiled or run in the build environment where this was written (OkHttp is not available there).
 */
class DohClient(private val spec: DohSpec, private val socksPort: Int?) : DnsTransport {

    private companion object {
        val DNS_MESSAGE = "application/dns-message".toMediaType()
        const val MAX_BODY = 65_535L
    }

    private val lock = Any()
    private var client: OkHttpClient? = null

    private fun obtain(): OkHttpClient = synchronized(lock) {
        client ?: build().also { client = it }
    }

    private fun build(): OkHttpClient {
        val bytes = spec.addressBytes()
        val name = spec.tlsName
        val dns = Dns { hostname ->
            // Exactly one answer: the pinned address. Any other name (a redirect, a bug) is refused.
            if (!hostname.equals(name, ignoreCase = true)) throw UnknownHostException("not the pinned DoH host")
            listOf(InetAddress.getByAddress(name, bytes))
        }
        return OkHttpClient.Builder()
            .proxy(Proxy.NO_PROXY)               // the SocketFactory below does the proxying; never the system proxy
            .socketFactory(UpstreamSocketFactory(socksPort))
            .dns(dns)
            .protocols(listOf(HttpProtocol.HTTP_2, HttpProtocol.HTTP_1_1))
            .connectionPool(ConnectionPool(1, 60, TimeUnit.SECONDS))
            .retryOnConnectionFailure(false)
            .cache(null)
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .callTimeout(10, TimeUnit.SECONDS)
            .build()
    }

    override fun exchange(query: ByteArray): ByteArray {
        try {
            val url = HttpUrl.Builder()
                .scheme("https")
                .host(spec.tlsName)
                .port(spec.port)
                .encodedPath(spec.path)
                .build()
            val rb = Request.Builder()
                .url(url)
                .header("Accept", "application/dns-message")
                .post(query.toRequestBody(DNS_MESSAGE))
            // With @sni= the certificate/SNI name differs from the HTTP host: keep the HTTP host as written.
            if (spec.sni != null && spec.sni != spec.host) {
                val h = if (spec.host.contains(':')) "[${spec.host}]" else spec.host
                rb.header("Host", if (spec.port == 443) h else "$h:${spec.port}")
            }
            return obtain().newCall(rb.build()).execute().use { resp ->
                if (!resp.isSuccessful) throw IOException("DoH resolver answered HTTP ${resp.code}")
                val body = resp.body ?: throw IOException("DoH answer has no body")
                val src = body.source()
                src.request(MAX_BODY + 1)
                if (src.buffer.size > MAX_BODY) throw IOException("DoH answer too large")
                src.readByteArray()
            }
        } catch (e: IOException) {
            reset()
            throw e
        } catch (e: RuntimeException) {
            reset()
            throw IOException("DoH request failed: ${e.javaClass.simpleName}")
        }
    }

    /** Throws the pool (and the client) away: used after any failure, so nothing broken is kept. */
    private fun reset() {
        val old = synchronized(lock) { client.also { client = null } } ?: return
        runCatching { old.connectionPool.evictAll() }
        runCatching { old.dispatcher.executorService.shutdown() }
    }

    override fun closeIdle() {
        val c = synchronized(lock) { client } ?: return
        runCatching { c.connectionPool.evictAll() } // closes idle connections only; a call in flight keeps its own
    }

    override fun close() = reset()
}

/**
 * Creates unconnected sockets; OkHttp connects them itself. With a port, every socket speaks SOCKS5 to
 * 127.0.0.1:port (OkHttp hands it an already resolved address, so the proxy receives an IP, never a name).
 */
private class UpstreamSocketFactory(private val port: Int?) : SocketFactory() {
    override fun createSocket(): Socket =
        if (port == null) Socket()
        else Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))

    // OkHttp only ever calls createSocket(); the connecting variants are deliberately unsupported.
    override fun createSocket(host: String?, p: Int): Socket = throw UnsupportedOperationException()
    override fun createSocket(host: String?, p: Int, localHost: InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()
    override fun createSocket(host: InetAddress?, p: Int): Socket = throw UnsupportedOperationException()
    override fun createSocket(address: InetAddress?, p: Int, localAddress: InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()
}

/** Builds the transport for [specs] (tried in order). [socksPort] null = direct from the phone. */
object DohTransports {
    fun create(specs: List<DohSpec>, socksPort: Int?): DnsTransport =
        FallbackTransport(specs.map { DohClient(it, socksPort) })
}
