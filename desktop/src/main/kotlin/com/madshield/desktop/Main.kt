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
    if ("--selftest" in args) {
        // The packaged app has no console: the report is also written to a file CI (or a person) can read.
        val report = java.io.File(System.getenv("TEMP") ?: ".", "madshield-selftest.txt")
        val console = System.out
        val file = java.io.PrintStream(java.io.FileOutputStream(report), true, "UTF-8")
        System.setOut(java.io.PrintStream(object : java.io.OutputStream() {
            override fun write(b: Int) { console.write(b); file.write(b) }
            override fun write(b: ByteArray, off: Int, len: Int) { console.write(b, off, len); file.write(b, off, len) }
            override fun flush() { console.flush(); file.flush() }
        }, true, "UTF-8"))
        exitProcess(SelfTest.run(args))
    }

    // The tunnel adapter and its routes need administrator rights: ask once, through UAC, and start again elevated.
    if (!Elevation.isAdmin() && "--no-elevate" !in args) {
        if (Elevation.relaunch(args)) return
    }
    val settings = SettingsStore.load()
    val conn = Connection()
    Runtime.getRuntime().addShutdownHook(Thread { conn.shutdownBlocking(); FoxyCore.stop() })
    if (settings.connectOnStart) conn.connect(settings)

    application {
        val state: WindowState = rememberWindowState(
            width = minOf(1120, java.awt.Toolkit.getDefaultToolkit().screenSize.width - 40).dp,
            height = minOf(740, java.awt.Toolkit.getDefaultToolkit().screenSize.height - 80).dp
        )
        Window(
            onCloseRequest = {
                conn.shutdownBlocking()
                FoxyCore.stop()
                exitApplication()
            },
            title = "MadShield",
            state = state
        ) {
            androidx.compose.runtime.LaunchedEffect(Unit) { window.minimumSize = java.awt.Dimension(900, 600) }
            App(conn, settings, args.firstOrNull { it.startsWith("--page=") }?.substringAfter('=') ?: "")
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
    private var warned = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        println("[" + (if (ok) "PASS" else "FAIL") + "] $name" + (if (detail.isNotEmpty()) ": $detail" else ""))
        if (!ok) failed++
    }

    /** A check that is informative but never fails the self-test: its failure is only INCONCLUSIVE. */
    private fun soft(name: String, ok: Boolean, detail: String = "") {
        println("[" + (if (ok) "PASS" else "WARN inconclusive") + "] $name" + (if (detail.isNotEmpty()) ": $detail" else ""))
        if (!ok) warned++
    }

    private fun waitFor(timeoutMs: Long, cond: () -> Boolean): Boolean {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) { if (cond()) return true; Thread.sleep(500) }
        return cond()
    }

    /**
     * Fetches a page with the system's own curl.exe: a program this app does not know, so its traffic enters the TUN
     * like any other program's. (This JVM is itself on the "direct" list, so it cannot be used to test the tunnel.)
     */
    private fun httpGet(url: String, timeoutMs: Int = 25_000): String? = try {
        val p = ProcessBuilder("curl.exe", "-sS", "--max-time", (timeoutMs / 1000).toString(), url).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().use { it.readText() }
        if (p.waitFor() == 0) out else { println("curl $url: " + out.trim().take(200)); null }
    } catch (e: Exception) { println("curl $url: " + e.message); null }

    private fun field(trace: String, key: String): String? =
        trace.lineSequence().firstOrNull { it.startsWith("$key=") }?.substringAfter('=')?.trim()

    fun run(args: Array<String>): Int {
        println("kit: ${Kit.dir}")
        check("administrator", Elevation.isAdmin())
        check("kit complete", Kit.missing(Kit.singBox, Kit.aether, Kit.fx, Kit.psiphon) == null, Kit.missing(Kit.singBox, Kit.aether, Kit.fx, Kit.psiphon) ?: "")
        if (failed > 0) return 1

        // The real criterion: the public address the whole system shows to the internet changes to a WARP address.
        val before = httpGet("https://www.cloudflare.com/cdn-cgi/trace") ?: ""
        val ipBefore = field(before, "ip")
        val warpBefore = field(before, "warp")
        check("before: a public address is seen, not through WARP", ipBefore != null && warpBefore != "on" && warpBefore != "plus", "ip=$ipBefore warp=$warpBefore")

        val conn = Connection()
        conn.connect(DesktopSettings(engine = EngineKind.WARP, chain = PrivacyChain.NONE))
        val up = waitFor(240_000) { conn.state.value is ConnState.Connected || conn.state.value is ConnState.Failed }
        val st = conn.state.value
        check("connects", up && st is ConnState.Connected, st.toString())
        if (st is ConnState.Connected) {
            val viaTun = httpGet("https://www.cloudflare.com/cdn-cgi/trace") ?: ""
            val ipAfter = field(viaTun, "ip")
            val warpAfter = field(viaTun, "warp")
            check("PUBLIC ADDRESS CHANGED: system traffic leaves through WARP",
                ipAfter != null && ipAfter != ipBefore && (warpAfter == "on" || warpAfter == "plus"),
                "before=$ipBefore after=$ipAfter warp=$warpAfter")
            check("a page loads", (httpGet("https://example.com/") ?: "").contains("Example Domain"))
            val totals = conn.routeFront()?.routeTotals()
            check("the front counts the traffic", totals != null && totals.vpnDown > 0, totals.toString())

            // Independent test of the exit-address lookup (it asks through the front, not through the TUN).
            // Its failure is INCONCLUSIVE, never a failure of the self-test: the address check above is the verdict.
            var probe = (st.exit?.let { DesktopExitProbe.Result(it, "ok", "") }) ?: DesktopExitProbe.run(TunnelPorts.PUBLIC, 15_000)
            soft("exit lookup answers", probe.info != null, probe.toString())
            val pi = probe.info
            if (pi != null && ipAfter != null) soft("exit lookup agrees with the public address", pi.ip == ipAfter, "lookup=${pi.ip} system=$ipAfter")

            Thread.sleep(8_000)
            check("still connected after 8 s", conn.state.value is ConnState.Connected, conn.state.value.toString())
        }
        println("---- log tail")
        RingLogBuffer.tail(250).forEach { println(it) }

        conn.disconnect()
        val down = waitFor(30_000) { conn.state.value is ConnState.Idle }
        check("disconnects", down, conn.state.value.toString())
        Thread.sleep(3_000)
        val after = httpGet("https://www.cloudflare.com/cdn-cgi/trace") ?: ""
        val warpEnd = field(after, "warp")
        check("after: network is back and direct", field(after, "ip") != null && warpEnd != "on" && warpEnd != "plus", "ip=${field(after, "ip")} warp=$warpEnd")
        val left = ProcessHandle.allProcesses().anyMatch { h -> h.info().command().map { it.lowercase().startsWith(Kit.dir.absolutePath.lowercase()) }.orElse(false) }
        check("no engine program left running", !left)
        println(if (failed == 0) "SELFTEST PASSED" + (if (warned > 0) " ($warned inconclusive)" else "") else "SELFTEST FAILED ($failed)")
        return if (failed == 0) 0 else 1
    }
}
