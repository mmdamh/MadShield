package com.aethershield.app.vpn

import android.content.Context
import android.os.ParcelFileDescriptor
import com.aethershield.app.core.*
import com.aethershield.app.util.RingLogBuffer
import kotlinx.coroutines.delay
import java.io.File

/**
 * hev-socks5-tunnel through our JNI bridge ([TProxyService]), inside the app process. This is the code that used to live
 * in AetherVpnService (writeHevConfig, stopBridge, bridgeTunToEngine, awaitBridgeStopped), moved here unchanged so that
 * the default engine behaves exactly as before. The strings in [StartResult.Failed] are the ones the service used to put
 * into the Error state itself.
 */
class HevEngine(private val context: Context) : TunEngine {
    companion object {
        private const val BRIDGE_STOP_TIMEOUT_MS = 4_000L
    }

    override val id = TunEngineId.HEV

    /**
     * hev config: tunnel.ipv4/ipv6 MUST equal the VpnService addAddress values
     * (both come from TunnelConfig). The SOCKS port is the one the
     * engine is actually bound to (config.socksPort), not a constant.
     */
    private fun writeHevConfig(config: EngineConfig): File {
        val file = File(context.cacheDir, "hev.yaml")
        // Same keys and values as ZedSecure's field-tested hev config (hev's own defaults for
        // everything else; no stack-size or timeout overrides that could starve a session).
        val mapdns = if (!config.mappedDnsActive) "" else """

            mapdns:
              address: ${Chain.MAPDNS_ADDRESS}
              port: 53
              network: 100.64.0.0
              netmask: 255.192.0.0
              cache-size: 10000"""
        val yaml = """
            tunnel:
              mtu: ${config.effectiveMtu}
              ipv4: ${TunnelConfig.TUN_IPV4}
              ipv6: '${TunnelConfig.TUN_IPV6}'
            socks5:
              port: ${config.socksPort}
              address: ${TunnelConfig.SOCKS_HOST}
              udp: 'udp'
            misc:
              tcp-buffer-size: 131072
              udp-recv-buffer-size: 262144
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
              log-level: warn
        """.trimIndent() + mapdns.trimIndent().let { if (it.isEmpty()) "" else "\n\n$it" }
        file.writeText(yaml)
        return file
    }

    /**
     * Asks hev to stop, but only when it is running. hev REMEMBERS a stop request that arrives while it is
     * not running and then ends the NEXT start immediately: that was the "tunnel bridge stopped right after
     * start" on the first connect of a session (seen after every earlier disconnect or failed connect), which
     * only worked on Retry. The native thread flag is exact, so this never races a start.
     */
    override fun stop() {
        if (runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)) {
            runCatching { TProxyService.TProxyStopService() }
        }
    }

    /** Throws when the native bridge cannot be loaded (callers wrap it, exactly as they wrapped TProxyIsRunning before). */
    override fun isRunning(): Boolean = TProxyService.TProxyIsRunning()

    override fun counters(): TunCounters? {
        if (!TProxyService.available) return null
        val s = runCatching { TProxyService.TProxyGetStats() }.getOrNull()?.takeIf { it.size >= 4 } ?: return null
        return TunCounters(s[0], s[1], s[2], s[3])
    }

    override suspend fun start(tunFd: ParcelFileDescriptor, config: EngineConfig): StartResult {
        val cfgFile = writeHevConfig(config)
        return try {
            // A previous hev thread that is still shutting down would make the start a
            // silent no-op (tunnel published, nothing carried): wait for it first.
            if (!awaitBridgeStopped()) {
                RingLogBuffer.append("[vpn] previous tunnel bridge has not shut down yet")
                return StartResult.Failed("previous tunnel bridge still shutting down")
            }
            // Two tries: if the first one ends at once (a stop request left over from an earlier session
            // is consumed by it), the second one starts cleanly.
            var up = false
            for (attempt in 1..2) {
                val started = TProxyService.TProxyStartService(cfgFile.absolutePath, tunFd.fd)
                if (!started) {
                    RingLogBuffer.append("[vpn] hev refused to start (config/fd rejected)")
                    return StartResult.Failed("tunnel start refused")
                }
                // The native start only schedules a thread. If that thread exits at once the tunnel
                // would be reported "connected" while carrying nothing ("connected, no internet").
                delay(700)
                up = runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
                if (up) break
                RingLogBuffer.append("[vpn] tunnel bridge ended right after start (attempt $attempt/2)")
                if (!awaitBridgeStopped()) break
            }
            if (!up) {
                RingLogBuffer.append("[vpn] tunnel bridge stopped right after start (config: ${cfgFile.readText().replace('\n', ' ')})")
                return StartResult.Failed("the tunnel bridge stopped right after starting")
            }
            RingLogBuffer.append("[vpn] tunnel bridge running (mtu=${config.effectiveMtu}, socks=${config.socksPort})")
            StartResult.Ok
        } catch (t: Throwable) {
            RingLogBuffer.append("[vpn] hev start failed: ${t.message}")
            StartResult.Failed(t.message ?: "tunnel start failed")
        }
    }

    private suspend fun awaitBridgeStopped(): Boolean {
        val deadline = System.currentTimeMillis() + BRIDGE_STOP_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val running = runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
            if (!running) return true
            delay(100)
        }
        return false
    }
}
