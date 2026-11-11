package com.madshield.desktop

import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowState
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import com.madshield.app.core.EngineKind
import com.madshield.app.core.PrivacyChain
import com.madshield.app.util.RingLogBuffer
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if ("--selftest" in args) exitProcess(SelfTest.run(args))

    // The tunnel adapter and its routes need administrator rights: ask once, through UAC, and start again elevated.
    if (!Elevation.isAdmin() && "--no-elevate" !in args) {
        if (Elevation.relaunch(args)) return
    }
    val settings = SettingsStore.load()
    val conn = Connection()
    Runtime.getRuntime().addShutdownHook(Thread { conn.shutdownBlocking(); FoxyCore.stop() })
    if (settings.connectOnStart) conn.connect(settings)

    application {
        val state: WindowState = rememberWindowState(width = 980.dp, height = 680.dp)
        Window(
            onCloseRequest = {
                conn.shutdownBlocking()
                FoxyCore.stop()
                exitApplication()
            },
            title = "MadShield",
            state = state
        ) {
            App(conn, settings)
        }
    }
}

/**
 * `--selftest`: the real connection code without a window, for CI on an administrator Windows runner. It connects with
 * Aether (HTTP/2) through the TUN and the routing front, checks the exit, disconnects and checks the network came back.
 * Exit code 0 = everything held. Never run it on a PC you are working on without knowing it takes the network for a minute.
 */
object SelfTest {
    private var failed = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        println("[" + (if (ok) "PASS" else "FAIL") + "] $name" + (if (detail.isNotEmpty()) ": $detail" else ""))
        if (!ok) failed++
    }

    private fun waitFor(timeoutMs: Long, cond: () -> Boolean): Boolean {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) { if (cond()) return true; Thread.sleep(500) }
        return cond()
    }

    private fun httpGet(url: String, timeoutMs: Int = 15_000): String? = try {
        val c = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        c.connectTimeout = timeoutMs; c.readTimeout = timeoutMs
        c.inputStream.bufferedReader().use { it.readText() }
    } catch (_: Exception) { null }

    fun run(args: Array<String>): Int {
        println("kit: ${Kit.dir}")
        check("administrator", Elevation.isAdmin())
        check("kit complete", Kit.missing(Kit.singBox, Kit.aether, Kit.fx, Kit.psiphon) == null, Kit.missing(Kit.singBox, Kit.aether, Kit.fx, Kit.psiphon) ?: "")
        if (failed > 0) return 1

        val direct0 = httpGet("https://www.cloudflare.com/cdn-cgi/trace") ?: ""
        check("before: not through WARP", !Regex("(?m)^warp=(on|plus)").containsMatchIn(direct0), direct0.lineSequence().firstOrNull { it.startsWith("ip=") } ?: "no answer")

        val conn = Connection()
        val settings = DesktopSettings(engine = EngineKind.WARP, chain = PrivacyChain.NONE)
        conn.connect(settings)
        val up = waitFor(240_000) { conn.state.value is ConnState.Connected || conn.state.value is ConnState.Failed }
        val st = conn.state.value
        check("connects", up && st is ConnState.Connected, st.toString())
        if (st is ConnState.Connected) {
            check("exit address known", st.exit != null, st.exit?.toString() ?: "")
            // a program that does not know the tunnel: its traffic goes through WARP
            val viaTun = httpGet("https://www.cloudflare.com/cdn-cgi/trace") ?: ""
            check("system traffic goes through WARP", Regex("(?m)^warp=(on|plus)").containsMatchIn(viaTun), viaTun.lineSequence().firstOrNull { it.startsWith("ip=") } ?: "no answer")
            val page = httpGet("https://example.com/") ?: ""
            check("a page loads", page.contains("Example Domain"))
            val totals = conn.routeFront()?.routeTotals()
            check("the front counts the traffic", totals != null && totals.vpnDown > 0, totals.toString())
            Thread.sleep(8_000)
            check("still connected after 8 s", conn.state.value is ConnState.Connected, conn.state.value.toString())
        }
        println("---- log tail")
        RingLogBuffer.tail(60).forEach { println(it) }

        conn.disconnect()
        val down = waitFor(30_000) { conn.state.value is ConnState.Idle }
        check("disconnects", down, conn.state.value.toString())
        Thread.sleep(3_000)
        val after = httpGet("https://www.cloudflare.com/cdn-cgi/trace") ?: ""
        check("after: network is back and direct", after.contains("ip=") && !Regex("(?m)^warp=(on|plus)").containsMatchIn(after))
        val left = ProcessHandle.allProcesses().anyMatch { h -> h.info().command().map { it.lowercase().startsWith(Kit.dir.absolutePath.lowercase()) }.orElse(false) }
        check("no engine program left running", !left)
        println(if (failed == 0) "SELFTEST PASSED" else "SELFTEST FAILED ($failed)")
        return if (failed == 0) 0 else 1
    }
}
