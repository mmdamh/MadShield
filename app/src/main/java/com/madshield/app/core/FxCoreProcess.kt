package com.madshield.app.core

import android.content.Context
import android.os.Build
import com.madshield.app.util.LogRedactor
import com.madshield.app.util.RingLogBuffer
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.SecureRandom

/** Where a running Foxy core can be reached (see [FxVpn]). The login never leaves the app's process. */
class FxEndpoint(val apiPort: Int, val socksPort: Int, val auth: SocksAuth, val dataDir: File) {
    fun client(): FxClient = FxClient(apiPort, File(dataDir, FxVpn.TOKEN_FILE))
}

/**
 * One run of the Foxy core as a child process: starts it, pumps its output into the in-memory log (never a file),
 * and stops it. Two owners use it and never at the same time: [EngineProcessManager] for a connection, and [FxSession]
 * for the Foxy page (sign-in and account) while no connection runs. [FxRuntime.endpoint] says which one is live.
 *
 * The core is started with its standard input OPEN (our end of the pipe): when this app dies the pipe closes and the
 * core ends by itself, so no engine is ever left running without its app.
 */
class FxCoreProcess(private val context: Context) {

    @Volatile private var process: Process? = null
    @Volatile private var dying: Process? = null
    @Volatile var endpoint: FxEndpoint? = null
        private set
    @Volatile var lastExit: EngineExit? = null
        private set
    private var pump: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tail = ArrayDeque<String>()

    val isAlive: Boolean get() = process?.isAlive == true

    /** Starts the core with its SOCKS5 listener on [socksPort]. Blocking, short; throws [EnginePreflightException] before anything runs. */
    fun start(socksPort: Int, dns: List<String>): FxEndpoint {
        // Read before anything starts: the phone's own DNS (the core cannot find it on Android).
        val systemDns = PhoneDns.servers(context)
        stop()
        waitForPrevious()
        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val bin = File(nativeDir, FxVpn.BIN)
        preflight(bin)
        checkIntegrity(nativeDir)

        // Leftovers of an earlier run of this app (it was killed) are removed first: the data folder allows one core.
        val reaped = CoreProcessGuard.reapOrphans(
            expectedExecutables = setOf(bin.absolutePath), selfPid = android.os.Process.myPid(),
            appUid = android.os.Process.myUid(), kill = { android.os.Process.killProcess(it) }, log = { RingLogBuffer.append(it) }
        )
        if (!SocksProbe.awaitPortFree(socksPort, if (reaped > 0) 3_000 else 1_000)) {
            throw IllegalStateException("Port $socksPort is still in use by another process.")
        }
        val dataDir = FxRuntime.dataDir(context).also { it.mkdirs() }
        val apiPort = FxRuntime.freePort(except = socksPort)
        val creds = FxCredentials.generate(SecureRandom())
        val helloSplit = FxTricks.helloSplit(context)
        val sessions = FxTricks.sessions(context)
        val transport = FxTricks.transport(context)
        val relay = FxTricks.relay(context)
        val env = FxEnvironment.build(socksPort, apiPort, creds, dns, context.cacheDir.absolutePath, systemDns, helloSplit, sessions, transport, relay)

        val pb = ProcessBuilder(bin.absolutePath, "-data-dir", dataDir.absolutePath)
            .directory(dataDir)
            .redirectErrorStream(true)
        pb.environment().apply {
            keys.removeAll { EngineEnvironment.isInherited(it) }
            putAll(env)
        }
        // The non-secret part only: the login is never written anywhere.
        RingLogBuffer.append(
            "[fxvpn] starting ${bin.name} socks=127.0.0.1:$socksPort api=127.0.0.1:$apiPort dns=${env["MFX_DNS"] ?: "core default"} " +
                "system-dns=${env["MFX_SYSTEM_DNS"]?.split(',')?.size ?: 0} hello-split=${helloSplit.stored} sessions=$sessions transport=${transport.stored}" +
                (relay?.let { " guardian-relay=${FxRelay.hostOf(it)}" } ?: "") // the host only: the path may hold the relay's secret
        )
        synchronized(tail) { tail.clear() }
        lastExit = null
        val p = pb.start() // stdin stays open on purpose, see the class comment
        process = p
        val ep = FxEndpoint(apiPort, socksPort, creds.toAuth(), dataDir)
        endpoint = ep
        pump = scope.launch {
            try {
                BufferedReader(InputStreamReader(p.inputStream)).use { reader ->
                    while (isActive) {
                        val line = reader.readLine() ?: break
                        RingLogBuffer.append("[fxvpn] $line") // memory only; the log redactor masks addresses and tokens
                        synchronized(tail) {
                            if (tail.size >= 20) tail.removeFirst()
                            tail.addLast(line)
                        }
                    }
                }
            } catch (_: IOException) {
                // pipe closed on stop()
            }
            val code = try { p.waitFor() } catch (_: InterruptedException) { -1 }
            if (process === p) {
                val lines = synchronized(tail) { tail.toList() }
                lastExit = EngineExit(code, lines)
                RingLogBuffer.append("[fxvpn] exited unexpectedly with code $code")
                DiagnosticsHub.recordExit("Foxy core exited unexpectedly with code $code", lines)
            }
        }
        return ep
    }

    /** Never blocks the caller (it may be the main thread): SIGTERM now, escalation and port release in the background. */
    fun stop() {
        pump?.cancel(); pump = null
        endpoint = null
        val p = process ?: return
        process = null
        RingLogBuffer.append("[fxvpn] stopping")
        dying = p
        p.destroy() // the core shuts down on SIGTERM
        scope.launch { CoreProcessGuard.stop(p, 750) }
    }

    /** One line saying why the core is not running (null when unknown). Call from a background thread. */
    fun failureReason(): String? {
        if (lastExit == null && process?.isAlive == false) {
            val deadline = System.currentTimeMillis() + 1_500
            while (lastExit == null && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(25) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        }
        val exit = lastExit ?: return null
        val joined = exit.lastLines.joinToString("\n")
        return when {
            joined.contains("CANNOT LINK EXECUTABLE") ->
                "Android could not load the Foxy core: " + (exit.lastLines.firstOrNull { it.contains("CANNOT LINK") } ?: "link error")
            joined.contains("address already in use", ignoreCase = true) -> "the Foxy port is used by another program"
            else -> "The Foxy core stopped (exit code ${exit.code})" +
                (exit.lastLines.lastOrNull()?.takeIf { it.isNotBlank() }?.let { ": ${LogRedactor.redact(it).take(160)}" } ?: "")
        }
    }

    private fun waitForPrevious() {
        val prev = dying ?: return
        if (prev.isAlive && !CoreProcessGuard.stop(prev, 1_000)) {
            throw IllegalStateException("The previous Foxy core has not shut down yet. Try again in a moment.")
        }
        dying = null
    }

    private fun preflight(bin: File) {
        if (!bin.isFile) {
            throw EnginePreflightException(
                "This build has no Foxy engine (libfxvpn.so missing). Rebuild with the updated CI workflow, or use the WARP engine."
            )
        }
        val info = try { ElfInspector.inspect(bin) } catch (e: IOException) {
            throw EnginePreflightException("The Foxy core is not a valid executable (${e.message}).")
        }
        if (info.machineName !in Build.SUPPORTED_ABIS) {
            throw EnginePreflightException("The Foxy core was built for ${info.machineName}, but this device runs ${Build.SUPPORTED_ABIS.joinToString()}.")
        }
    }

    /** Same promise as the other native files: what runs is what CI built (hash stamped into the APK). Debug builds have none. */
    private fun checkIntegrity(nativeDir: File) {
        val expected = runCatching {
            context.assets.open("native_hashes.properties").bufferedReader().use { NativeHashes.parse(it.readText()) }
        }.map { NativeHashes.forDevice(it, Build.SUPPORTED_ABIS.toList()) }.getOrDefault(emptyMap())
        val mine = expected.filterKeys { it == FxVpn.BIN }
        val result = BinaryIntegrity.verifyDir(nativeDir, mine)
        if (!result.ok) {
            throw EnginePreflightException("The Foxy core does not match what the build produced. Reinstall the app from your own build.")
        }
    }
}

/** The DNS servers of the phone's real network (not the VPN's), for the core's system lookups. */
object PhoneDns {
    @Suppress("DEPRECATION")
    fun servers(context: Context): List<String> = try {
        val cm = context.getSystemService(android.net.ConnectivityManager::class.java)
        val found = ArrayList<String>()
        if (cm != null) {
            // Our own VPN network is skipped: its DNS is the tunnel's, which the core (outside the tunnel) cannot reach.
            val nets = cm.allNetworks.filter { n ->
                val c = cm.getNetworkCapabilities(n)
                c != null && c.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
            }
            val active = cm.activeNetwork
            for (n in nets.sortedByDescending { it == active }) {
                cm.getLinkProperties(n)?.dnsServers?.forEach { found.add(it.hostAddress ?: "") }
            }
        }
        FxVpn.cleanSystemDns(found)
    } catch (_: Exception) {
        emptyList()
    }
}

/** Process-wide facts about the Foxy engine. */
object FxRuntime {
    /** The core that is running right now (set by whoever started it), or null. */
    @Volatile var endpoint: FxEndpoint? = null

    fun dataDir(context: Context): File = File(context.filesDir, FxVpn.DATA_DIR)

    /** The APK carries the core (CI builds it as an optional file). */
    fun isInBuild(context: Context): Boolean = File(context.applicationInfo.nativeLibraryDir, FxVpn.BIN).isFile

    /** An address the core can bind: asks the system for a free loopback port. */
    fun freePort(except: Int): Int {
        repeat(8) {
            val p = try { ServerSocket().use { s -> s.reuseAddress = true; s.bind(InetSocketAddress("127.0.0.1", 0)); s.localPort } } catch (_: IOException) { 0 }
            if (p in 1024..65535 && p != except) return p
        }
        throw IOException("no free loopback port")
    }

    /** Removes everything the core stored: the account's credentials, its tokens and the server list. */
    fun wipe(context: Context) {
        runCatching { dataDir(context).deleteRecursively() }
    }
}

/**
 * The core for the Foxy PAGE (sign-in, account, quota, location) while no connection uses it. A connection that
 * runs the Firefox engine owns its own core and the page simply talks to that one ([FxRuntime.endpoint]); starting a
 * connection stops this one first ([stopForConnection]) because the connection needs its own login and ports.
 */
object FxSession {
    private val lock = Any()
    private var own: FxCoreProcess? = null

    /** The live core: the connection's, or one started here. Blocking (waits for the API): call from a background thread. */
    fun ensure(context: Context): FxEndpoint {
        synchronized(lock) {
            FxRuntime.endpoint?.let { ep -> if (own == null || own?.isAlive == true) return ep }
            own?.stop(); own = null
            val proc = FxCoreProcess(context.applicationContext)
            val ep = proc.start(Chain.UNDERLAY_PORT, FxVpn.DEFAULT_DNS)
            own = proc
            FxRuntime.endpoint = ep
            return ep
        }
    }

    /** Polls the API until it answers (the core needs a moment to bind and write its token). Throws IOException on timeout. */
    fun awaitApi(ep: FxEndpoint, timeoutMs: Long): FxStatus {
        val deadline = System.currentTimeMillis() + timeoutMs
        var last: Exception? = null
        while (System.currentTimeMillis() < deadline) {
            try { return ep.client().status() } catch (e: IOException) { last = e }
            try { Thread.sleep(250) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
        }
        throw IOException("the Foxy core did not answer" + (last?.message?.let { ": $it" } ?: ""))
    }

    /** The page was closed: the core it started stops (nothing keeps running for an account page). */
    fun release() {
        synchronized(lock) {
            val o = own ?: return
            own = null
            if (FxRuntime.endpoint === o.endpoint) FxRuntime.endpoint = null
            o.stop()
        }
    }

    /** A connection is about to start its own core: ours goes first. */
    fun stopForConnection() = release()

    val ownsCore: Boolean get() = synchronized(lock) { own != null }
}

/** The choice of [FxHelloSplit], kept in a small private preferences file: the Foxy page and every connection read it. */
object FxTricks {
    private const val FILE = "fx_tricks"
    private const val KEY = "hello_split"

    fun helloSplit(context: Context): FxHelloSplit = try {
        FxHelloSplit.fromStored(context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString(KEY, null))
    } catch (_: Exception) { FxHelloSplit.DEFAULT }

    fun sessions(context: Context): Int = try {
        FxSessions.clean(context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).getInt("sessions", FxSessions.DEFAULT))
    } catch (_: Exception) { FxSessions.DEFAULT }

    fun setSessions(context: Context, n: Int) {
        try { context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putInt("sessions", FxSessions.clean(n)).apply() }
        catch (_: Exception) { /* not saved: the default applies */ }
    }

    fun transport(context: Context): FxTransport = try {
        FxTransport.fromStored(context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString("transport", null))
    } catch (_: Exception) { FxTransport.DEFAULT }

    fun setTransport(context: Context, v: FxTransport) {
        try { context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putString("transport", v.stored).apply() }
        catch (_: Exception) { /* not saved: the default applies */ }
    }

    /** The user's own Guardian relay address (see [FxRelay]); null when none or unusable. */
    fun relay(context: Context): String? = try {
        FxRelay.clean(context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString("relay", null))
    } catch (_: Exception) { null }

    /** Saves the address as given when usable, and forgets it when empty. @return false when it was not usable (nothing saved). */
    fun setRelay(context: Context, raw: String): Boolean {
        val v = raw.trim()
        val clean = FxRelay.clean(v)
        if (v.isNotEmpty() && clean == null) return false
        try {
            val e = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
            if (clean == null) e.remove("relay") else e.putString("relay", clean)
            e.apply()
        } catch (_: Exception) { return false }
        return true
    }

    fun setHelloSplit(context: Context, v: FxHelloSplit) {
        try { context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putString(KEY, v.stored).apply() }
        catch (_: Exception) { /* not saved: the default applies */ }
    }
}
