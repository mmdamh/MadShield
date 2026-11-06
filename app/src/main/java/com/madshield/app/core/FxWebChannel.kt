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

    /** The result of the grant request the browser sent. */
    sealed class Grant {
        class Ok(val accessToken: String, val refreshToken: String, val expiresIn: Int, val scope: String) : Grant()
        /** The session is not confirmed yet (an email code or authenticator code is still to be entered): try again soon. */
        object Unconfirmed : Grant()
        class Failed(val status: Int, val text: String) : Grant()
    }

    fun grant(status: Int, text: String): Grant {
        val obj = MiniJson.parseObject(text)
        if (status in 200..299) {
            val access = (obj?.get("access_token") as? String).orEmpty()
            if (access.isNotEmpty()) {
                val expires = (obj?.get("expires_in") as? Number)?.toInt() ?: 0
                return Grant.Ok(access, (obj?.get("refresh_token") as? String).orEmpty(), expires, (obj?.get("scope") as? String).orEmpty())
            }
            return Grant.Failed(status, "the answer has no access token")
        }
        val errno = (obj?.get("errno") as? Number)?.toInt()
        val message = (obj?.get("message") as? String).orEmpty()
        if (status == 400 && (errno == 104 || message.contains("unconfirmed", ignoreCase = true))) return Grant.Unconfirmed
        return Grant.Failed(status, (message.ifEmpty { text }).take(200))
    }
}
