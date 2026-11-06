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
import com.madshield.app.core.FxWebChannel
import com.madshield.app.core.MiniJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

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
internal class BridgeEvents(
    val onLogin: (FxWebChannel.Login) -> Unit,
    val onGrant: (nonce: String, status: Int, text: String) -> Unit,
    val onGrantError: (nonce: String, text: String) -> Unit
)

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

    @JavascriptInterface
    fun onGrant(nonce: String, status: Int, text: String) { view.post { events.onGrant(nonce, status, text) } }

    @JavascriptInterface
    fun onGrantError(nonce: String, text: String) { view.post { events.onGrantError(nonce, text) } }
}

/**
 * Full-screen sign-in of the Foxy engine in a WebView on Mozilla's own page (see [FxWebChannel]). Ends by adding the account
 * to the core ([FxClient.browserImport]); [onDone] is then called. Nothing the page shows or sends is kept: the WebView's
 * cookies and storage are cleared when this closes.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun FxWebSignInDialog(client: () -> FxClient, onDone: () -> Unit, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var webView by remember { mutableStateOf<WebView?>(null) }
    var progress by remember { mutableIntStateOf(0) }
    var login by remember { mutableStateOf<FxWebChannel.Login?>(null) }
    var nonce by remember { mutableStateOf("") }
    var waitingConfirm by remember { mutableStateOf(false) }
    var finishing by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var finished by remember { mutableStateOf(false) }

    fun requestGrant(l: FxWebChannel.Login) {
        if (finished) return
        scope.launch {
            val g = try { withContext(Dispatchers.IO) { client().browserGrant(l.sessionToken) } }
            catch (e: Exception) { error = e.message ?: e.javaClass.simpleName; return@launch }
            val n = UUID.randomUUID().toString()
            nonce = n
            // the browser sends it, from Mozilla's own page, so Mozilla's bot check sees a browser
            val script = "(function(){fetch(${js(g.url)},{method:'POST',headers:{'Authorization':${js(g.authorization)},'Content-Type':'application/json'},body:${js(g.body)}})" +
                ".then(function(r){return r.text().then(function(t){ms.onGrant(${js(n)},r.status,t);});})" +
                ".catch(function(e){ms.onGrantError(${js(n)},''+((e&&e.message)||e));});})();"
            webView?.evaluateJavascript(script, null) ?: run { error = "the page is gone" }
        }
    }

    fun finish(l: FxWebChannel.Login, g: FxWebChannel.Grant.Ok) {
        if (finished) return
        finished = true
        finishing = true
        scope.launch {
            try { withContext(Dispatchers.IO) { client().browserImport(l.email, g) }; onDone() }
            catch (e: Exception) { finished = false; finishing = false; error = e.message ?: e.javaClass.simpleName }
        }
    }

    fun handleGrant(n: String, status: Int, text: String) {
        val l = login
        if (n != nonce || l == null || finished) return
        when (val g = FxWebChannel.grant(status, text)) {
            is FxWebChannel.Grant.Ok -> finish(l, g)
            FxWebChannel.Grant.Unconfirmed -> {
                // the page still asks for a code or a link: ask again in a few seconds
                waitingConfirm = true
                scope.launch { delay(3_000); if (!finished && login?.sessionToken == l.sessionToken) requestGrant(l) }
            }
            is FxWebChannel.Grant.Failed -> error = "HTTP ${g.status}: ${g.text}"
        }
    }

    val events = remember {
        BridgeEvents(
            onLogin = { l ->
                if (login?.sessionToken != l.sessionToken) { login = l; error = null; waitingConfirm = false; requestGrant(l) }
            },
            onGrant = { n, status, text -> handleGrant(n, status, text) },
            onGrantError = { n, text -> if (n == nonce && !finished) error = text }
        )
    }

    DisposableEffect(Unit) {
        onDispose {
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
                    finishing -> stringResource(R.string.fx_web_finishing)
                    waitingConfirm -> stringResource(R.string.fx_web_confirm)
                    else -> stringResource(R.string.fx_web_waiting)
                }
                Text(note, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                error?.let { e ->
                    Text(stringResource(R.string.fx_web_failed, e), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                    login?.let { l ->
                        FilledTonalButton(onClick = { error = null; requestGrant(l) }, modifier = Modifier.padding(horizontal = 16.dp)) {
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
