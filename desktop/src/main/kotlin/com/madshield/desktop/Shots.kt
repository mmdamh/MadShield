package com.madshield.desktop

import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import com.madshield.app.core.EngineKind
import com.madshield.app.core.PrivacyChain
import java.io.File
import org.jetbrains.skia.EncodedImageFormat

/**
 * `--shots=<folder>`: draws the real screens off-screen (no window needed) and saves them as pictures, so the design can
 * be looked at from CI. Idle pages first, then it connects for real and draws the live Home page. CI only.
 */
@OptIn(ExperimentalComposeUiApi::class)
object Shots {
    private fun save(dir: File, name: String, settings: DesktopSettings, conn: Connection, page: String, settleMs: Long = 600) {
        val scene = ImageComposeScene(1120, 740, Density(1f)) { App(conn, settings, page) }
        try {
            val end = System.currentTimeMillis() + settleMs
            while (System.currentTimeMillis() < end) { scene.render(System.nanoTime()); Thread.sleep(100) }
            val img = scene.render(System.nanoTime())
            val data = img.encodeToData(EncodedImageFormat.PNG) ?: return
            File(dir, "$name.png").writeBytes(data.bytes)
            println("[shot] $name")
        } finally { scene.close() }
    }

    fun run(dir: File): Int {
        dir.mkdirs()
        val conn = Connection()
        for (lang in listOf("en", "fa")) {
            val s = DesktopSettings(language = lang, engine = EngineKind.WARP, chain = PrivacyChain.NONE)
            for (page in listOf("home", "engine", "foxy", "rules", "conns", "logs", "settings")) save(dir, "$lang-$page", s, conn, page, if (page == "foxy") 2500 else 600)
            val chain = s.copy(chain = PrivacyChain.PSIPHON)
            save(dir, "$lang-engine-psiphon", chain, conn, "engine")
        }
        val s = DesktopSettings(language = "en", engine = EngineKind.WARP, chain = PrivacyChain.NONE)
        conn.connect(s)
        val end = System.currentTimeMillis() + 150_000
        while (System.currentTimeMillis() < end && conn.state.value !is ConnState.Connected && conn.state.value !is ConnState.Failed) Thread.sleep(500)
        println("[shots] state: " + conn.state.value)
        // some real traffic so the readout and the graph have something to show
        val gen = Thread { repeat(8) { try { ProcessBuilder("curl.exe", "-s", "-o", "NUL", "--max-time", "6", "https://speed.cloudflare.com/__down?bytes=3000000").start().waitFor() } catch (_: Exception) {} } }
        gen.isDaemon = true; gen.start()
        save(dir, "en-home-connected", s, conn, "home", 9000)
        save(dir, "fa-home-connected", s.copy(language = "fa"), conn, "home", 3000)
        save(dir, "en-conns-connected", s, conn, "conns", 1500)
        conn.disconnect()
        val down = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < down && conn.state.value !is ConnState.Idle) Thread.sleep(500)
        conn.shutdownBlocking()
        FoxyCore.stop()
        return 0
    }
}
