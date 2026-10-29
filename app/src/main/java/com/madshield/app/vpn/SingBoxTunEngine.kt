package com.madshield.app.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.os.Build
import android.os.ParcelFileDescriptor
import com.madshield.app.core.*
import com.madshield.app.util.RingLogBuffer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader

/**
 * EXPERIMENTAL tunnel engine (update24): a separate sing-box process (libsingtun.so, sing-box 1.15 with sing-tun's own
 * TCP/IP stack) reads the TUN device and forwards to the same SOCKS port hev uses. The config is [SingBoxTunConfig]; the
 * TUN fd comes from the app over a unix socket ([TunFdServer]); the app (VpnService) keeps owning the device, so the Kill
 * Switch and per-app split are exactly as with hev. A process that dies leaves the TUN in place, and the health loop
 * re-attaches it like it does for hev.
 *
 * Counters are the byte counters of the VPN interface (TrafficStats); there are no packet counts.
 */
class SingBoxTunEngine(private val context: Context) : TunEngine {
    companion object {
        private const val HANDOFF_TIMEOUT_MS = 8_000L
        /** After the fd is handed over the process must stay alive this long: start-up errors end the process at once. */
        private const val STAY_ALIVE_MS = 1_500L
        private const val STOP_GRACE_MS = 1_500L
        private const val TAIL_LINES = 20

        /** The binary is optional in the build (the CI job may have failed): see [selectTunEngine]. */
        fun isInBuild(context: Context): Boolean =
            File(context.applicationInfo.nativeLibraryDir, EngineEnv.SINGTUN_BIN).isFile
    }

    override val id = TunEngineId.SINGBOX_TUN

    @Volatile private var process: Process? = null
    @Volatile private var vpnInterface: String? = null
    private val tail = ArrayDeque<String>()

    override fun isRunning(): Boolean = process?.isAlive == true

    override fun stop() {
        val p = process ?: return
        process = null
        CoreProcessGuard.stop(p, STOP_GRACE_MS)
    }

    @Suppress("DEPRECATION")
    override fun counters(): TunCounters? {
        // Same lookup and the same Android floor as SpeedMeterProbe: the interface of the network with the VPN transport.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        val name = vpnInterface ?: run {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
            var found: String? = null
            for (n in cm.allNetworks) {
                if (cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true) continue
                found = cm.getLinkProperties(n)?.interfaceName ?: continue
                break
            }
            found?.also { vpnInterface = it }
        } ?: return null
        return countersOrNull(TrafficStats.getTxBytes(name), TrafficStats.getRxBytes(name))
    }

    override suspend fun start(tunFd: ParcelFileDescriptor, config: EngineConfig): StartResult = withContext(Dispatchers.IO) {
        stop() // never two processes
        vpnInterface = null // the TUN interface is new for every connect
        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val bin = File(nativeDir, EngineEnv.SINGTUN_BIN)
        preflight(bin)?.let { return@withContext StartResult.Failed(it) }

        val dir = File(context.cacheDir, "singtun").also { it.mkdirs() }
        // A leftover process (the app was killed earlier) would still hold the old device: clear it, only this binary.
        CoreProcessGuard.reapOrphans(
            expectedExecutables = setOf(bin.absolutePath),
            selfPid = android.os.Process.myPid(),
            appUid = android.os.Process.myUid(),
            kill = { android.os.Process.killProcess(it) },
            log = { RingLogBuffer.append(it) }
        )

        val socketPath = try {
            TunFdChannel.socketPath(dir.absolutePath)
        } catch (e: IllegalArgumentException) {
            return@withContext StartResult.Failed("sing-box TUN engine: ${e.message}")
        }
        val json = SingBoxTunConfig.render(config.effectiveMtu, config.socksPort, config.mappedDnsActive)
        val server = TunFdServer(socketPath)
        try {
            server.open()
            val pb = ProcessBuilder(bin.absolutePath, "run", "-c", "stdin", "-D", dir.absolutePath, "--disable-color")
                .directory(dir)
                .redirectErrorStream(true)
            pb.environment().apply {
                keys.removeAll { EngineEnvironment.isInherited(it) }
                put("TMPDIR", context.cacheDir.absolutePath)
                put("GOMAXPROCS", Chain.GO_MAX_PROCS)   // same caps as Psiphon and the chain: a burst must not spread over every big core
                put("GOMEMLIMIT", Chain.GO_MEMORY_LIMIT)
                put(TunFdChannel.ENV_VAR, socketPath)
            }
            synchronized(tail) { tail.clear() }
            RingLogBuffer.append("[singtun] starting (mtu=${config.effectiveMtu}, socks=${config.socksPort}, dns=${if (config.mappedDnsActive) "fakeip" else "plain"})")
            val p = pb.start()
            process = p
            try {
                p.outputStream.use { it.write(json.toByteArray(Charsets.UTF_8)) } // closing it = EOF, which ends the config read
            } catch (e: IOException) {
                stop()
                throw e
            }
            startPump(p)

            if (!server.serve(tunFd.fileDescriptor, HANDOFF_TIMEOUT_MS)) {
                val why = lastLines()
                stop()
                RingLogBuffer.append("[singtun] the engine did not take the TUN device")
                return@withContext StartResult.Failed("the sing-box TUN engine did not take the TUN device" + why)
            }
            val until = System.currentTimeMillis() + STAY_ALIVE_MS
            while (System.currentTimeMillis() < until && p.isAlive) delay(100)
            if (!p.isAlive) {
                val why = lastLines()
                process = null
                RingLogBuffer.append("[singtun] stopped right after start")
                return@withContext StartResult.Failed("the sing-box TUN engine stopped right after starting" + why)
            }
            RingLogBuffer.append("[singtun] running")
            StartResult.Ok
        } catch (c: CancellationException) {
            stop()
            throw c
        } catch (t: Throwable) {
            stop()
            RingLogBuffer.append("[singtun] start failed: ${t.message}")
            StartResult.Failed(t.message ?: "sing-box TUN engine start failed")
        } finally {
            server.close()
        }
    }

    /** null = fine, otherwise the reason. Same checks the other engines get (a real executable for this CPU). */
    private fun preflight(bin: File): String? {
        if (!bin.isFile) return "This build has no sing-box TUN engine (libsingtun.so missing)."
        val info = try {
            ElfInspector.inspect(bin)
        } catch (e: IOException) {
            return "The sing-box TUN engine is not a valid executable (${e.message})."
        }
        if (info.machineName !in Build.SUPPORTED_ABIS) {
            return "The sing-box TUN engine was built for ${info.machineName}, but this device runs ${Build.SUPPORTED_ABIS.joinToString()}."
        }
        return null
    }

    private fun startPump(p: Process) {
        Thread {
            try {
                BufferedReader(InputStreamReader(p.inputStream)).use { reader ->
                    while (true) {
                        val line = reader.readLine() ?: break
                        RingLogBuffer.append("[singtun] $line")
                        synchronized(tail) {
                            if (tail.size >= TAIL_LINES) tail.removeFirst()
                            tail.addLast(line)
                        }
                    }
                }
            } catch (_: IOException) {
            }
            val code = try { p.waitFor() } catch (_: InterruptedException) { -1 }
            if (process === p) {
                RingLogBuffer.append("[singtun] exited unexpectedly with code $code")
                DiagnosticsHub.recordExit("sing-box TUN engine exited unexpectedly with code $code", synchronized(tail) { tail.toList() })
            }
        }.also { it.isDaemon = true; it.name = "singtun-log" }.start()
    }

    /** The last log lines for an error message: ": line1 | line2", or "" when the process said nothing. */
    private fun lastLines(): String {
        val lines = synchronized(tail) { tail.takeLast(3) }
        return if (lines.isEmpty()) "" else ": " + lines.joinToString(" | ")
    }
}
