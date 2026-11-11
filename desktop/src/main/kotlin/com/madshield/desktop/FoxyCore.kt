package com.madshield.desktop

import com.madshield.app.core.FxClient
import com.madshield.app.core.FxCredentials
import com.madshield.app.core.FxEnvironment
import com.madshield.app.core.FxStatus
import com.madshield.app.core.FxVpn
import com.madshield.app.core.SocksAuth
import com.madshield.app.util.RingLogBuffer
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.SecureRandom

/** Where a running Foxy core can be reached. The login of its SOCKS port never leaves this process. */
class FxEp(val apiPort: Int, val socksPort: Int, val auth: SocksAuth, val dataDir: File) {
    fun client(): FxClient = FxClient(apiPort, File(dataDir, FxVpn.TOKEN_FILE))
}

/**
 * The Foxy core (madshield-fx.exe) as a child process. One owner at a time: a connection uses it with its own ports, or the
 * Foxy page uses it (sign-in, account, location) while no Foxy connection runs. Its standard input stays open: when this
 * app ends the pipe closes and the core ends with it.
 */
object FoxyCore {
    const val PAGE_PORT = 1825
    private val proc = ManagedProcess("fxvpn")
    @Volatile var endpoint: FxEp? = null
        private set

    val alive: Boolean get() = proc.alive
    fun lastLines(): List<String> = proc.lastLines()

    @Synchronized
    fun start(socksPort: Int): FxEp {
        stop()
        val dataDir = DataDir.sub("fxvpn")
        val apiPort = freePort(socksPort)
        val creds = FxCredentials.generate(SecureRandom())
        val env = FxEnvironment.build(socksPort, apiPort, creds, FxVpn.DEFAULT_DNS, DataDir.sub("tmp").absolutePath)
        // The non-secret part only: the login is never written anywhere.
        RingLogBuffer.append("[fxvpn] starting socks=127.0.0.1:$socksPort api=127.0.0.1:$apiPort")
        proc.start(Kit.fx, listOf("-data-dir", dataDir.absolutePath), env, dataDir, stdin = null)
        return FxEp(apiPort, socksPort, creds.toAuth(), dataDir).also { endpoint = it }
    }

    /** The core for the Foxy page, started on demand and left alone when a connection already runs one. */
    @Synchronized
    fun ensure(): FxEp {
        val ep = endpoint
        if (ep != null && proc.alive) return ep
        return start(PAGE_PORT)
    }

    /** Polls the API until it answers (the core needs a moment to bind and write its token). Throws IOException on timeout. */
    fun awaitApi(ep: FxEp, timeoutMs: Long): FxStatus {
        val deadline = System.currentTimeMillis() + timeoutMs
        var last: Exception? = null
        while (System.currentTimeMillis() < deadline) {
            if (!proc.alive) throw IOException("the Foxy core stopped: " + (proc.lastLines().lastOrNull() ?: "no output"))
            try { return ep.client().status() } catch (e: IOException) { last = e }
            try { Thread.sleep(250) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
        }
        throw IOException("the Foxy core did not answer" + (last?.message?.let { ": $it" } ?: ""))
    }

    @Synchronized
    fun stop() {
        endpoint = null
        proc.stop()
    }

    /** Removes everything the core stored: the account's credentials, its tokens and the server list. */
    fun wipe() {
        stop()
        runCatching { File(DataDir.root, "fxvpn").deleteRecursively() }
    }

    private fun freePort(except: Int): Int {
        repeat(8) {
            val p = try { ServerSocket().use { s -> s.reuseAddress = true; s.bind(InetSocketAddress("127.0.0.1", 0)); s.localPort } } catch (_: IOException) { 0 }
            if (p in 1024..65535 && p != except) return p
        }
        throw IOException("no free loopback port")
    }
}
