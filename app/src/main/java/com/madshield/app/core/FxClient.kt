package com.madshield.app.core

import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL

/**
 * Blocking client of the Foxy core's dashboard API on 127.0.0.1:[apiPort]. Call it from a background thread.
 *
 * Every request carries the token the core wrote to its data folder ([tokenFile]); the core answers nothing else (it runs
 * with "local token required", see native/fxvpn/host/main.go), so another app on the phone that finds the port gets a 401.
 * The token is read on every call: the core writes a new one at each start. It never leaves this class and is not logged.
 */
class FxClient(private val apiPort: Int, private val tokenFile: File) {

    /** An answer other than success. [status] is the HTTP status, the message the core's own English text. */
    class ApiException(val status: Int, message: String) : IOException(message)

    private fun token(): String {
        val t = try { tokenFile.readText().trim() } catch (_: IOException) { "" }
        if (t.isEmpty()) throw IOException("the Foxy core is not ready (no token yet)")
        return t
    }

    private fun call(method: String, path: String, body: String? = null, timeoutMs: Int = 10_000): String {
        val conn = URL("http://127.0.0.1:$apiPort$path").openConnection(Proxy.NO_PROXY) as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 3_000
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.setRequestProperty("X-Local-Token", token())
            conn.setRequestProperty("Accept", "application/json")
            if (method != "GET") {
                // the core refuses a write that does not say it is JSON (a guard against web pages posting to it)
                conn.setRequestProperty("Content-Type", "application/json")
                if (body != null) {
                    conn.doOutput = true
                    conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.use { it.readBytes().toString(Charsets.UTF_8) } ?: ""
            if (code !in 200..299) throw ApiException(code, FxJson.errorText(text) ?: "HTTP $code")
            return text
        } finally {
            conn.disconnect()
        }
    }

    private fun json(vararg pairs: Pair<String, Any?>): String = MiniJson.write(mapOf(*pairs), 0)

    fun status(): FxStatus = FxJson.status(call("GET", "/api/status")) ?: throw IOException("unreadable status")

    fun accounts(): List<FxAccount> = FxJson.accounts(call("GET", "/api/accounts")) ?: throw IOException("unreadable accounts")

    /** The app's button: on starts the proxy (given up by the core when Mozilla is not reached within a minute). */
    fun power(on: Boolean) { call("POST", "/api/power", json("on" to on)) }

    /** Wakes the proxy (it holds no session to Mozilla until used) and tests the data path. Slow on the first call. */
    fun test(): FxTestResult = FxJson.test(call("POST", "/api/test", "{}", 40_000)) ?: throw IOException("unreadable test result")

    fun signInStart(email: String, password: String): FxSignIn =
        FxJson.signIn(call("POST", "/api/signin", json("email" to email, "password" to password))) ?: throw IOException("unreadable sign-in")

    fun signInGet(id: String): FxSignIn =
        FxJson.signIn(call("GET", "/api/signin/" + enc(id))) ?: throw IOException("unreadable sign-in")

    fun signInAnswer(id: String, value: String): FxSignIn =
        FxJson.signIn(call("POST", "/api/signin/" + enc(id), json("value" to value))) ?: throw IOException("unreadable sign-in")

    fun signInCancel(id: String) { call("DELETE", "/api/signin/" + enc(id)) }

    /**
     * Hands the session of a browser sign-in (the WebView on Mozilla's page) to the core: it asks Mozilla for the account's
     * tokens (waiting while the page still asks for a code), stores the account without a password and ends the session. It
     * runs like the password sign-in: poll [signInGet] with the id, [signInCancel] ends it.
     */
    fun signInBrowser(email: String, sessionToken: String): FxSignIn =
        FxJson.signIn(call("POST", "/api/ms/signin-browser", json("email" to email, "session_token" to sessionToken))) ?: throw IOException("unreadable sign-in")

    /** Starts (or joins) the renewal of the account's access token with a person answering Fastly's CAPTCHA (patch 0003). */
    fun reauthStart(accountId: String): FxReauth =
        FxJson.reauth(call("POST", "/api/ms/reauth", json("account_id" to accountId))) ?: throw IOException("unreadable renewal")

    fun reauthGet(): FxReauth = FxJson.reauth(call("GET", "/api/ms/reauth")) ?: throw IOException("unreadable renewal")

    /** The characters of the picture named [id]. A 409 means that picture is no longer the one waiting. */
    fun reauthAnswer(id: String, text: String) { call("POST", "/api/ms/reauth/answer", json("id" to id, "answer" to text)) }

    fun reauthCancel() { call("DELETE", "/api/ms/reauth") }

    fun removeAccount(id: String) { call("DELETE", "/api/accounts/" + enc(id)) }

    fun locations(): List<FxLocation> = FxJson.locations(call("GET", "/api/locations", timeoutMs = 25_000)) ?: throw IOException("unreadable locations")

    /** "" = the recommended location, otherwise a country code from [locations]. */
    fun setLocation(country: String) { call("POST", "/api/location", json("country" to country)) }

    private fun enc(s: String): String = java.net.URLEncoder.encode(s, "UTF-8")
}
