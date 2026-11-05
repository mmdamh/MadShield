package com.madshield.app.core

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress

/**
 * Login of an upstream SOCKS5 listener (RFC 1929 username/password). Only the Foxy engine has one: its core
 * listens on loopback, where every app on the phone could otherwise use the account's data. The password is never
 * printed ([toString] hides both values).
 */
class SocksAuth(val user: String, val password: String) {
    init {
        require(user.toByteArray(Charsets.UTF_8).size in 1..255) { "bad SOCKS user" }
        require(password.toByteArray(Charsets.UTF_8).size in 1..255) { "bad SOCKS password" }
    }

    override fun toString(): String = "SocksAuth(***)"
}

/**
 * The login for the engine's upstream port, set by [EngineProcessManager] while a Foxy core runs. Everything that
 * dials that port ([RouteFront], the DoH client, the health probe) asks [forPort]; other ports never get a login, so
 * the default engines behave exactly as before.
 */
object UpstreamLogin {
    @Volatile private var port = 0
    @Volatile private var auth: SocksAuth? = null

    fun set(port: Int, auth: SocksAuth) {
        this.auth = auth
        this.port = port
    }

    fun clear() {
        auth = null
        port = 0
    }

    fun forPort(p: Int): SocksAuth? {
        val a = auth
        return if (a != null && p == port) a else null
    }
}

/** The client side of the SOCKS5 greeting, with or without a login. Pure stream code, so it is tested without a phone. */
object Socks5Handshake {
    /**
     * Sends the method selection and, when [auth] is given, the username/password sub-negotiation. On return the
     * connection is ready for a SOCKS5 request. Throws [IOException] with the reason otherwise.
     */
    fun greet(input: InputStream, output: OutputStream, auth: SocksAuth?) {
        if (auth == null) {
            output.write(byteArrayOf(5, 1, 0)); output.flush()
            val hello = readN(input, 2)
            if (hello[0].toInt() != 5 || hello[1].toInt() != 0) throw IOException("upstream refused the greeting")
            return
        }
        output.write(byteArrayOf(5, 1, 2)); output.flush() // offer only "username/password"
        val hello = readN(input, 2)
        if (hello[0].toInt() != 5 || hello[1].toInt() != 2) throw IOException("upstream does not take a login")
        val u = auth.user.toByteArray(Charsets.UTF_8)
        val p = auth.password.toByteArray(Charsets.UTF_8)
        val msg = ByteArray(3 + u.size + p.size)
        msg[0] = 1
        msg[1] = u.size.toByte()
        System.arraycopy(u, 0, msg, 2, u.size)
        msg[2 + u.size] = p.size.toByte()
        System.arraycopy(p, 0, msg, 3 + u.size, p.size)
        output.write(msg); output.flush()
        val reply = readN(input, 2)
        if (reply[0].toInt() != 1 || reply[1].toInt() != 0) throw IOException("upstream refused the login")
    }

    /** SOCKS5 CONNECT request bytes for [target] (a resolved address, or a name when it has none). */
    fun connectRequest(target: InetSocketAddress): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(5, 1, 0))
        val addr = target.address
        when {
            addr is Inet4Address -> { out.write(1); out.write(addr.address) }
            addr is Inet6Address -> { out.write(4); out.write(addr.address) }
            else -> {
                val name = target.hostString.toByteArray(Charsets.US_ASCII)
                require(name.size in 1..255) { "bad host name" }
                out.write(3); out.write(name.size); out.write(name)
            }
        }
        out.write(target.port shr 8); out.write(target.port and 0xff)
        return out.toByteArray()
    }

    /** Reads one complete reply to a request and returns its code (0 = success). */
    fun readReplyCode(input: InputStream): Int {
        val head = readN(input, 4)
        if (head[0].toInt() != 5) throw IOException("not a socks5 reply")
        val skip = when (head[3].toInt() and 0xff) {
            1 -> 4 + 2
            4 -> 16 + 2
            3 -> { val l = input.read(); if (l < 0) throw IOException("eof"); l + 2 }
            else -> throw IOException("bad reply address type")
        }
        readN(input, skip)
        return head[1].toInt() and 0xff
    }

    private fun readN(input: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = input.read(buf, got, n - got)
            if (r < 0) throw IOException("upstream closed the connection")
            got += r
        }
        return buf
    }
}

/**
 * A socket that reaches its destination through the loopback SOCKS5 listener on [proxyPort] using [auth]. It replaces
 * java.net.Proxy(SOCKS) for the DoH client: that class cannot carry a login without a process-wide Authenticator.
 */
class LoginSocksSocket(private val proxyPort: Int, private val auth: SocksAuth) : Socket() {
    override fun connect(endpoint: SocketAddress, timeout: Int) {
        val target = endpoint as? InetSocketAddress ?: throw IllegalArgumentException("unsupported address")
        val limit = if (timeout > 0) timeout else 10_000
        super.connect(InetSocketAddress(TunnelConfig.SOCKS_HOST, proxyPort), limit)
        val before = soTimeout
        try {
            soTimeout = limit
            val out = getOutputStream()
            val inp = getInputStream()
            Socks5Handshake.greet(inp, out, auth)
            out.write(Socks5Handshake.connectRequest(target)); out.flush()
            val code = Socks5Handshake.readReplyCode(inp)
            if (code != 0) throw IOException("SOCKS5 request refused (code $code)")
            soTimeout = before
        } catch (e: IOException) {
            runCatching { close() }
            throw e
        }
    }
}
