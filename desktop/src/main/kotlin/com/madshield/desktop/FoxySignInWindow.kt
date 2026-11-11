package com.madshield.desktop

import com.madshield.app.core.FxClient
import com.madshield.app.core.FxStep
import com.madshield.app.core.FxWebChannel
import com.madshield.app.core.MiniJson
import com.madshield.app.util.RingLogBuffer
import java.awt.BorderLayout
import java.awt.Dimension
import java.net.CookieHandler
import java.net.CookieManager
import java.net.URI
import javafx.application.Platform
import javafx.embed.swing.JFXPanel
import javafx.scene.Scene
import javafx.scene.web.WebEngine
import javafx.scene.web.WebView
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.SwingUtilities
import javax.swing.WindowConstants

/**
 * The Foxy sign-in, on Mozilla's own page, in an embedded browser (JavaFX WebView). Mozilla's bot check answers HTTP 406
 * to a program that is not a browser, so, as in the Android app, the page signs in and the app only reads its WebChannel
 * message (the account's session) and hands it to the core ([FxClient.signInBrowser]). Not tested against Mozilla's live
 * page on a real PC yet (update46). Cookies are cleared when the window closes.
 */
object FoxySignInWindow {
    private const val DESKTOP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0"

    // The page's side of the WebChannel. The host is reached through alert(): the engine's alert handler is the bridge.
    private const val HOOK_JS = """
(function () {
  if (window.__msHooked) return;
  window.__msHooked = true;
  window.addEventListener('WebChannelMessageToChrome', function (e) {
    try { alert('__ms__' + JSON.stringify({ p: (typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail)), u: window.location.href })); } catch (x) {}
  });
  window.__msReply = function (id, messageId, command, dataJson) {
    try {
      var env = { id: id, message: { messageId: messageId, command: command, data: JSON.parse(dataJson) } };
      window.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: env }));
      window.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: JSON.stringify(env) }));
    } catch (x) {}
  };
})();
"""

    private var frame: JFrame? = null
    private var cookies: CookieManager? = null

    private fun js(s: String): String = MiniJson.write(s, 0)

    fun open(client: () -> FxClient, texts: (String) -> String, onDone: () -> Unit) {
        SwingUtilities.invokeLater {
            frame?.let { it.toFront(); return@invokeLater }
            val cm = CookieManager().also { cookies = it }
            CookieHandler.setDefault(cm)
            val label = JLabel(texts("foxy.web.title"))
            val panel = JFXPanel()
            val f = JFrame(texts("foxy.web.title")).apply {
                defaultCloseOperation = WindowConstants.DISPOSE_ON_CLOSE
                layout = BorderLayout()
                add(label, BorderLayout.NORTH)
                add(panel, BorderLayout.CENTER)
                preferredSize = Dimension(560, 780)
                pack()
                setLocationRelativeTo(null)
            }
            frame = f
            var running: String? = null
            var lastSession = ""
            f.addWindowListener(object : java.awt.event.WindowAdapter() {
                override fun windowClosed(e: java.awt.event.WindowEvent?) {
                    frame = null
                    running?.let { id -> Thread { runCatching { client().signInCancel(id) } }.start() }
                    runCatching { cm.cookieStore.removeAll() }
                }
            })
            f.isVisible = true

            fun setLabel(text: String) = SwingUtilities.invokeLater { label.text = text }

            fun follow(l: FxWebChannel.Login) {
                setLabel(texts("foxy.web.working"))
                Thread {
                    try {
                        val id = client().signInBrowser(l.email, l.sessionToken).id
                        running = id
                        while (frame != null) {
                            val s = client().signInGet(id)
                            when (s.step) {
                                FxStep.DONE -> {
                                    running = null
                                    setLabel(texts("foxy.web.done"))
                                    SwingUtilities.invokeLater { frame?.dispose() }
                                    onDone()
                                    return@Thread
                                }
                                FxStep.FAILED, FxStep.CANCELLED -> {
                                    running = null
                                    setLabel(listOf(s.error, s.message).firstOrNull { it.isNotBlank() } ?: "failed")
                                    return@Thread
                                }
                                else -> {
                                    if (s.errorCode == "waiting_confirm") setLabel(texts("foxy.web.confirm"))
                                    Thread.sleep(1_000)
                                }
                            }
                        }
                    } catch (e: Exception) {
                        running = null
                        setLabel((e.message ?: e.javaClass.simpleName).take(200))
                        RingLogBuffer.append("[app] foxy sign-in: ${e.message}")
                    }
                }.apply { isDaemon = true }.start()
            }

            Platform.setImplicitExit(false)
            Platform.runLater {
                val view = WebView()
                val engine: WebEngine = view.engine
                engine.isJavaScriptEnabled = true
                engine.userAgent = DESKTOP_UA

                engine.setOnAlert { ev ->
                    val raw = ev.data ?: return@setOnAlert
                    if (!raw.startsWith("__ms__")) return@setOnAlert
                    val outer = MiniJson.parseObject(raw.removePrefix("__ms__")) ?: return@setOnAlert
                    val url = outer["u"] as? String ?: return@setOnAlert
                    val payload = outer["p"] as? String ?: return@setOnAlert
                    if (!FxWebChannel.hostAllowed(runCatching { URI(url).host }.getOrNull())) return@setOnAlert
                    val m = FxWebChannel.parse(payload) ?: return@setOnAlert
                    FxWebChannel.reply(m)?.let { (command, data) ->
                        runCatching {
                            engine.executeScript(
                                "window.__msReply && window.__msReply(${js(FxWebChannel.CHANNEL_ID)}, ${js(m.messageId)}, ${js(command)}, ${js(data)});"
                            )
                        }
                    }
                    FxWebChannel.login(m)?.let { l ->
                        if (l.sessionToken != lastSession) { lastSession = l.sessionToken; follow(l) }
                    }
                }
                engine.loadWorker.stateProperty().addListener { _, _, state ->
                    if (state == javafx.concurrent.Worker.State.SUCCEEDED) runCatching { engine.executeScript(HOOK_JS) }
                }
                engine.locationProperty().addListener { _, _, loc ->
                    val u = runCatching { URI(loc) }.getOrNull()
                    if (loc != null && loc.isNotBlank() && loc != "about:blank" && !FxWebChannel.navigationAllowed(u?.scheme, u?.host)) {
                        engine.load(FxWebChannel.START_URL) // only Mozilla's own pages may be shown
                    }
                }
                panel.scene = Scene(view)
                engine.load(FxWebChannel.START_URL)
            }
        }
    }
}
