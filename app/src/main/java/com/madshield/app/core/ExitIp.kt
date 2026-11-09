package com.madshield.app.core

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * What the outside world sees of this connection (update41): the address a site gets from us and its country.
 * [country] is a two-letter code or null when the answer was missing or "unknown"; [colo] is the three-letter code
 * of the Cloudflare data center that answered.
 */
data class ExitInfo(val ip: String, val country: String?, val colo: String?) {
    val isV6: Boolean get() = ip.contains(':')
}

/** Reads the plain `key=value` answer of Cloudflare's trace page. Pure text code, so it is tested without a phone. */
object ExitTrace {

    fun parse(text: String): ExitInfo? {
        val kv = HashMap<String, String>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            val key = line.substring(0, eq)
            // HTTP header lines ("Alt-Svc: h3=...") have a space or capitals in front of the '=': not ours.
            if (!key.all { it in 'a'..'z' || it in '0'..'9' || it == '_' }) continue
            kv.putIfAbsent(key, line.substring(eq + 1).trim())
        }
        val ip = kv["ip"]?.takeIf { isAddress(it) } ?: return null
        val colo = kv["colo"]?.takeIf { it.length in 2..4 && it.all { c -> c in 'A'..'Z' } }
        return ExitInfo(ip, country(kv["loc"]), colo)
    }

    /** "DE" -> "DE"; "XX" (unknown), "T1" (Tor), blanks and anything else -> null. */
    fun country(loc: String?): String? {
        val c = loc?.trim()?.uppercase() ?: return null
        if (c.length != 2 || c == "XX" || !c.all { it in 'A'..'Z' }) return null
        return c
    }

    fun isAddress(s: String): Boolean = isV4(s) || isV6(s)

    private fun isV4(s: String): Boolean {
        val parts = s.split('.')
        return parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } && p.toInt() in 0..255 }
    }

    private fun isV6(s: String): Boolean =
        s.length in 2..45 && s.contains(':') && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
}

/**
 * Asks Cloudflare's trace page for the address and country we exit from, THROUGH the app's own SOCKS5 port, so the
 * answer is the tunnel's exit and the phone's real address is never involved. The server is named by a literal
 * address (no name lookup, so no DNS request leaves anywhere) and its certificate is checked against that address.
 * One short HTTPS request; the callers run it once per connection and when the user asks again, never on a timer.
 * Blocking: call from a background thread.
 */
object ExitIpProbe {
    private const val HOST_V4 = "1.1.1.1"
    private const val HOST_V6 = "2606:4700:4700::1111"
    private const val MAX_BYTES = 8 * 1024

    /**
     * [ipv6] false: the IPv4 path (the answer may still be an IPv6 address if the exit only has one);
     * true: the IPv6 path, which answers only when the tunnel really carries IPv6 (the answer is then an IPv6 address).
     * Null = no answer (not carried, refused, timed out, bad certificate).
     */
    fun fetch(socksPort: Int, auth: SocksAuth?, ipv6: Boolean, timeoutMs: Int = 8_000): ExitInfo? {
        val host = if (ipv6) HOST_V6 else HOST_V4
        val info = try {
            Socket().use { raw ->
                raw.connect(InetSocketAddress(TunnelConfig.SOCKS_HOST, socksPort), timeoutMs)
                raw.soTimeout = timeoutMs
                val out = raw.getOutputStream()
                val input = raw.getInputStream()
                Socks5Handshake.greet(input, out, auth)
                out.write(Socks5Handshake.connectRequest(InetSocketAddress(InetAddress.getByName(host), 443)))
                out.flush()
                if (Socks5Handshake.readReplyCode(input) != 0) return null

                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val tls = factory.createSocket(raw, host, 443, false) as SSLSocket
                tls.soTimeout = timeoutMs
                tls.startHandshake()
                if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, tls.session)) return null

                val hostHeader = if (ipv6) "[$host]" else host
                tls.outputStream.apply {
                    write("GET /cdn-cgi/trace HTTP/1.1\r\nHost: $hostHeader\r\nAccept: text/plain\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    flush()
                }
                val body = ByteArrayOutputStream()
                val buf = ByteArray(1024)
                try {
                    while (body.size() < MAX_BYTES) {
                        val n = tls.inputStream.read(buf)
                        if (n < 0) break
                        body.write(buf, 0, n)
                    }
                } catch (_: IOException) {
                    // A late reset after the answer is not a failure: parse whatever arrived.
                }
                ExitTrace.parse(String(body.toByteArray(), Charsets.UTF_8))
            }
        } catch (_: IOException) {
            null
        }
        return if (ipv6 && info?.isV6 != true) null else info
    }
}
