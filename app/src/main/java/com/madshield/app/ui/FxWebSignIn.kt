package com.madshield.app.ui

import android.annotation.SuppressLint
import android.net.Uri
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.madshield.app.R
import com.madshield.app.core.FxClient
import com.madshield.app.core.FxStep
import com.madshield.app.core.FxWebChannel
import com.madshield.app.core.MiniJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The page's side of the WebChannel: forwards what the page sends to the app, and lets the app answer. */
private const val HOOK_JS = """
(function () {
  if (window.__msHooked) return;
  window.__msHooked = true;
  window.addEventListener('WebChannelMessageToChrome', function (e) {
    try { ms.onMessage(typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail), window.location.href); } catch (x) {}
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

private fun js(s: String): String = MiniJson.write(s, 0) // a JSON string is a JavaScript string

/** What the bridge hands to the screen, always on the main thread. */
internal class BridgeEvents(val onLogin: (FxWebChannel.Login) -> Unit)

internal class FxBridge(private val view: WebView, private val events: BridgeEvents) {
    @JavascriptInterface
    fun onMessage(payload: String, url: String) {
        if (!FxWebChannel.hostAllowed(runCatching { Uri.parse(url).host }.getOrNull())) return
        val m = FxWebChannel.parse(payload) ?: return
        FxWebChannel.reply(m)?.let { (command, data) ->
            view.post {
                runCatching { view.evaluateJavascript("window.__msReply && window.__msReply(${js(FxWebChannel.CHANNEL_ID)}, ${js(m.messageId)}, ${js(command)}, ${js(data)});", null) }
            }
        }
        FxWebChannel.login(m)?.let { l -> view.post { events.onLogin(l) } }
    }
}

/**
 * Full-screen sign-in of the Foxy engine in a WebView on Mozilla's own page (see [FxWebChannel]). Ends by adding the account
 * to the core ([FxClient.signInBrowser], which the dialog follows); [onDone] is then called. Nothing the page shows or sends is kept: the WebView's
 * cookies and storage are cleared when this closes.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun FxWebSignInDialog(client: () -> FxClient, onDone: () -> Unit, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var webView by remember { mutableStateOf<WebView?>(null) }
    var progress by remember { mutableIntStateOf(0) }
    var login by remember { mutableStateOf<FxWebChannel.Login?>(null) }
    var running by remember { mutableStateOf<String?>(null) } // the core's sign-in being followed
    var waitingConfirm by remember { mutableStateOf(false) }
    var finishing by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var finished by remember { mutableStateOf(false) }

    // ends the core's sign-in (the page closed, or another session replaced it); it must not outlive the dialog
    fun cancelRunning() {
        val id = running ?: return
        running = null
        Thread { runCatching { client().signInCancel(id) } }.start()
    }

    // hands the page's session to the core, which does the rest (waits for the confirmation, gets the tokens, stores the account)
    // and follows it until it is done
    fun follow(l: FxWebChannel.Login) {
        if (finished) return
        cancelRunning()
        error = null
        waitingConfirm = false
        finishing = true
        scope.launch {
            var id = ""
            try {
                id = withContext(Dispatchers.IO) { client().signInBrowser(l.email, l.sessionToken).id }
                running = id
                while (!finished && running == id && login?.sessionToken == l.sessionToken) {
                    val s = withContext(Dispatchers.IO) { client().signInGet(id) }
                    waitingConfirm = s.step == FxStep.WORKING && s.message.contains("confirmed", ignoreCase = true)
                    when (s.step) {
                        FxStep.DONE -> { finished = true; running = null; onDone(); return@launch }
                        FxStep.FAILED, FxStep.CANCELLED -> {
                            running = null
                            finishing = false
                            error = listOf(s.message, s.error).filter { it.isNotBlank() }.joinToString(": ").ifEmpty { "failed" }
                            return@launch
                        }
                        else -> delay(1_000)
                    }
                }
            } catch (e: Exception) {
                if (running == id || id.isEmpty()) { running = null; finishing = false; error = e.message ?: e.javaClass.simpleName }
            }
        }
    }

    val events = remember {
        BridgeEvents(onLogin = { l -> if (login?.sessionToken != l.sessionToken) { login = l; follow(l) } })
    }

    DisposableEffect(Unit) {
        onDispose {
            cancelRunning()
            runCatching {
                CookieManager.getInstance().removeAllCookies(null)
                CookieManager.getInstance().flush()
                WebStorage.getInstance().deleteAllData()
            }
        }
    }
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnBackPress = false, dismissOnClickOutside = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            BackHandler { if (webView?.canGoBack() == true) webView?.goBack() else onClose() } // inside: the dialog has its own back handling
            Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
                Row(Modifier.fillMaxWidth().padding(start = 4.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onClose) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.fx_web_close)) }
                    Text(stringResource(R.string.fx_web_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                    IconButton(onClick = { webView?.reload() }, enabled = !finishing) {
                        Icon(Icons.Filled.Refresh, contentDescription = stringResource(R.string.fx_web_reload))
                    }
                }
                if (finishing || progress < 100) {
                    if (finishing) LinearProgressIndicator(Modifier.fillMaxWidth())
                    else LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth())
                }
                val note = when {
                    waitingConfirm -> stringResource(R.string.fx_web_confirm)
                    finishing -> stringResource(R.string.fx_web_finishing)
                    else -> stringResource(R.string.fx_web_waiting)
                }
                Text(note, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                error?.let { e ->
                    Text(stringResource(R.string.fx_web_failed, e), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                    login?.let { l ->
                        FilledTonalButton(onClick = { follow(l) }, modifier = Modifier.padding(horizontal = 16.dp)) {
                            Text(stringResource(R.string.fx_web_retry))
                        }
                    }
                }
                AndroidView(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    factory = { context ->
                        WebView(context).apply {
                            webView = this
                            settings.javaScriptEnabled = true
                            settings.userAgentString = FxWebChannel.userAgent(android.os.Build.VERSION.RELEASE) // Mozilla's page wants a Firefox
                            settings.domStorageEnabled = true
                            settings.allowFileAccess = false
                            settings.allowContentAccess = false
                            settings.setSupportMultipleWindows(false)
                            CookieManager.getInstance().setAcceptCookie(true)
                            CookieManager.getInstance().setAcceptThirdPartyCookies(this, true) // the page's own bot-check frames
                            addJavascriptInterface(FxBridge(this, events), "ms")
                            webViewClient = object : WebViewClient() {
                                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
                                    !FxWebChannel.navigationAllowed(request.url.scheme, request.url.host) // never leaves Mozilla's pages
                                override fun onPageStarted(view: WebView, url: String?, favicon: android.graphics.Bitmap?) {
                                    super.onPageStarted(view, url, favicon)
                                    runCatching { view.evaluateJavascript(HOOK_JS, null) }
                                }
                                override fun onPageFinished(view: WebView, url: String?) {
                                    super.onPageFinished(view, url)
                                    runCatching { view.evaluateJavascript(HOOK_JS, null) }
                                }
                            }
                            webChromeClient = object : WebChromeClient() {
                                override fun onProgressChanged(view: WebView?, newProgress: Int) { progress = newProgress }
                            }
                            loadUrl(FxWebChannel.START_URL)
                        }
                    },
                    onRelease = { v -> webView = null; v.stopLoading(); v.destroy() }
                )
            }
        }
    }
}
