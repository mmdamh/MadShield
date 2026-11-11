package com.madshield.desktop

import com.madshield.app.core.ExitInfo
import com.madshield.app.core.ExitTrace
import com.madshield.app.core.Socks5Handshake
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The exit-address lookup for the desktop: Cloudflare's trace page, asked THROUGH the routing front, so the answer is
 * the tunnel's exit. Same idea as the shared ExitIpProbe, with one difference that matters on a JVM: the shared probe
 * checks the certificate name with HttpsURLConnection.getDefaultHostnameVerifier(), which on Android really checks but
 * on a desktop JDK is a stub that ALWAYS answers "no" (verified: the JDK's default verifier returns false for any input).
 * So the shared probe can never succeed here, whatever the tunnel does. This one asks the TLS stack itself to check the
 * name (endpoint identification "HTTPS", which also covers IP-address certificates), and says at which step it stopped.
 */
object DesktopExitProbe {
    private const val HOST = "1.1.1.1"
    private const val MAX_BYTES = 8 * 1024

    /** [stage]: where it ended ("ok", "connect", "socks", "tls", "http", "parse"); [detail] is a short reason. */
    class Result(val info: ExitInfo?, val stage: String, val detail: String) {
        override fun toString() = if (info != null) "ok $info" else "no answer at step '$stage': $detail"
    }

    fun run(socksPort: Int, timeoutMs: Int = 10_000): Result {
        var stage = "connect"
        return try {
            Socket().use { raw ->
                raw.connect(InetSocketAddress("127.0.0.1", socksPort), timeoutMs)
                raw.soTimeout = timeoutMs
                val out = raw.getOutputStream()
                val input = raw.getInputStream()
                stage = "socks"
                Socks5Handshake.greet(input, out, null)
                out.write(Socks5Handshake.connectRequest(InetSocketAddress(InetAddress.getByName(HOST), 443)))
                out.flush()
                val code = Socks5Handshake.readReplyCode(input)
                if (code != 0) return Result(null, stage, "the front refused the connection (reply code $code)")

                stage = "tls"
                val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, HOST, 443, false) as SSLSocket
                tls.soTimeout = timeoutMs
                val params: SSLParameters = tls.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                tls.sslParameters = params
                tls.startHandshake()

                stage = "http"
                tls.outputStream.apply {
                    write("GET /cdn-cgi/trace HTTP/1.1\r\nHost: $HOST\r\nAccept: text/plain\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
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
                    // a late reset after the answer is not a failure: parse what arrived
                }
                stage = "parse"
                val info = ExitTrace.parse(String(body.toByteArray(), Charsets.UTF_8))
                if (info != null) Result(info, "ok", "") else Result(null, stage, "the answer had no address (" + body.size() + " bytes)")
            }
        } catch (e: Exception) {
            Result(null, stage, e.javaClass.simpleName + ": " + (e.message ?: "").take(160))
        }
    }
}
