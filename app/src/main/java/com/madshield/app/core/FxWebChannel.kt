package com.madshield.app.core

/**
 * The browser sign-in of the Foxy engine. Mozilla's bot check (Fastly) answers HTTP 406 to the OAuth grant of a program that
 * is not a browser, so the sign-in runs in a real browser engine (an Android WebView) on Mozilla's own page, the way the
 * Firefox browser does it: the page talks to its host over a "WebChannel" and ends the sign-in with a session token. The
 * core turns that token into the grant request (it owns the signing), the WebView sends it, and the OAuth tokens it returns
 * go to the core as a new account. This file is the pure part: what the page says, what we answer, what the grant returns.
 */
object FxWebChannel {
    /** The page that starts the sign-in: Firefox's own "desktop sync" context, which ends in a WebChannel login message. */
    const val START_URL = "https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email"
    const val CHANNEL_ID = "account_updates"
    const val CMD_STATUS = "fxaccounts:fxa_status"
    const val CMD_CAN_LINK = "fxaccounts:can_link_account"
    const val CMD_LOGIN = "fxaccounts:login"

    /** One message of the page: `{"id": channel, "message": {"command", "messageId", "data"}}`. */
    class Message(val command: String, val messageId: String, val data: Map<String, Any?>)

    class Login(val email: String, val sessionToken: String, val verified: Boolean)

    fun parse(payload: String): Message? {
        if (payload.length > 200_000) return null
        val root = MiniJson.parseObject(payload) ?: return null
        @Suppress("UNCHECKED_CAST")
        val msg = root["message"] as? Map<String, Any?> ?: return null
        val command = msg["command"] as? String ?: return null
        @Suppress("UNCHECKED_CAST")
        val data = msg["data"] as? Map<String, Any?> ?: emptyMap()
        return Message(command, msg["messageId"] as? String ?: "", data)
    }

    /** Only Mozilla's account pages may talk to the bridge (and be shown): `accounts.firefox.com` and other `*.firefox.com`. */
    fun hostAllowed(host: String?): Boolean {
        val h = host?.lowercase()?.trimEnd('.') ?: return false
        return h == "firefox.com" || h.endsWith(".firefox.com")
    }

    /** Hosts the WebView may open as a page: the account pages and Mozilla's own sites (help, terms), over https only. */
    fun navigationAllowed(scheme: String?, host: String?): Boolean {
        if (scheme?.lowercase() != "https") return false
        val h = host?.lowercase()?.trimEnd('.') ?: return false
        return listOf("firefox.com", "mozilla.org", "mozilla.com").any { h == it || h.endsWith(".$it") }
    }

    /**
     * The User-Agent of Firefox for Android. Mozilla's page checks it ("Oops! It looks like you're not using Firefox"), and
     * its sign-in and API treat only a Firefox as a client of the Firefox Account flow; the WebView's own Chrome agent is not.
     */
    fun userAgent(androidRelease: String?): String {
        val v = androidRelease?.trim().orEmpty().takeIf { r -> r.isNotEmpty() && r.length <= 8 && r.all { it.isDigit() || it == '.' } } ?: "14"
        return "Mozilla/5.0 (Android $v; Mobile; rv:$FIREFOX_VERSION.0) Gecko/$FIREFOX_VERSION.0 Firefox/$FIREFOX_VERSION.0"
    }

    private const val FIREFOX_VERSION = 158

    fun isSessionToken(s: String): Boolean = s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /** The login message: the account's email and session token, and whether the session is already confirmed. */
    fun login(m: Message): Login? {
        if (m.command != CMD_LOGIN) return null
        val token = ((m.data["sessionToken"] as? String) ?: "").trim().lowercase()
        val email = ((m.data["email"] as? String) ?: "").trim()
        if (!isSessionToken(token) || !email.contains('@') || email.length > 254) return null
        val reason = (m.data["verificationReason"] as? String).orEmpty()
        val verified = (m.data["verified"] as? Boolean) ?: reason.isBlank()
        return Login(email, token, verified)
    }

    /** What the page expects back, as (command, data JSON), or null when it expects nothing. */
    fun reply(m: Message): Pair<String, String>? = when {
        m.command == CMD_STATUS -> CMD_STATUS to """{"capabilities":{},"signedInUser":null}"""
        m.command == CMD_CAN_LINK -> CMD_CAN_LINK to """{"ok":true}"""
        m.messageId.isNotEmpty() -> m.command to """{"ok":true}"""
        else -> null
    }
}
