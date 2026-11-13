package com.madshield.app.core

import java.util.Random

/**
 * Which connection engine a connection uses (update28, EXPERIMENTAL, test branch).
 *
 *  - [WARP]: the Aether WARP core, with all its protocols and chains. The default; with it selected nothing in this file
 *    runs and behaviour is exactly that of update27.
 *  - [FIREFOX]: Mozilla's own VPN service, through the user's own Firefox Account (see [FxVpn]). A separate engine,
 *    never a link in the WARP chain: the traffic goes from the phone to Mozilla's proxy servers and nowhere else.
 */
enum class EngineKind(val stored: String) {
    WARP("warp"),
    FIREFOX("firefox");

    companion object {
        /** Unknown or missing values mean the default, so a damaged setting can never select nothing. */
        fun fromStored(s: String?): EngineKind = entries.firstOrNull { it.stored == s } ?: WARP
    }
}

/**
 * What happens to a TCP connection to a port Mozilla's proxy does not carry (only 80, 443, 8080 and 8443 pass; games,
 * mail, SSH... are refused by Mozilla itself). [BLOCK] (default) refuses it here, at once, with nothing leaving the phone;
 * [DIRECT] sends it outside the VPN, which makes a game work if its server is reachable without a VPN, and shows the
 * phone's real address to that server.
 */
enum class FxPortPolicy(val stored: String, val action: RouteAction) {
    BLOCK("block", RouteAction.BLOCK),
    DIRECT("direct", RouteAction.DIRECT);

    companion object {
        fun fromStored(s: String?): FxPortPolicy = entries.firstOrNull { it.stored == s } ?: BLOCK
    }
}

/**
 * The route a connection really takes once the ports Mozilla refuses are considered: a connection that would go through
 * the VPN to a port outside [allowed] takes [otherwise] instead; everything else (a block or direct RULE) is untouched.
 */
class PortGate(val allowed: Set<Int>, otherwise: RouteAction) {
    /** Changed while connected (Block <-> Direct): the next connection follows it, nothing is restarted. */
    @Volatile var otherwise: RouteAction = otherwise
    fun decide(action: RouteAction, port: Int): RouteAction = if (action == RouteAction.PROXY && port !in allowed) otherwise else action
}

/**
 * The Foxy engine: the Go core of the open-source client armanlife/firefox-vpn-client (GPL-3, unofficial, built by
 * CI from the commit in native/fxvpn.pin) run as a child process, started like the other native engines, through
 * native/fxvpn/host/main.go. MadShield talks to it in two ways:
 *
 *  - a SOCKS5 listener on loopback with a LOGIN made up for every start ([FxCredentials]); [RouteFront] sits in front of it
 *    (routing rules, Connections, Usage, local DoH all keep working) and the tunnel engine (hev / sing-box TUN) sends to
 *    [RouteFront];
 *  - its dashboard API on loopback, which only answers a client that sends the token the core wrote to its data folder
 *    (sign-in steps, account and quota, locations, connection test). See [FxClient].
 *
 * What this engine does NOT do, on purpose: UDP (Mozilla's proxy carries TCP, and UDP only partly) - UDP is switched off
 * for the connection, DNS goes through hev's mapped DNS and the names travel over TCP; a second account or any
 * failover between accounts (Mozilla's terms allow one account per person; this app offers one).
 */
object FxVpn {
    /** TCP ports Mozilla's proxies connect to (the core logs: "connects to ports 80, 443, 8080, and 8443 only"). */
    val ALLOWED_TCP_PORTS: Set<Int> = setOf(80, 443, 8080, 8443)

    const val BIN = "libfxvpn.so"
    const val DATA_DIR = "fxvpn"
    const val TOKEN_FILE = "local-api.token"
    const val GO_MAX_PROCS = "2"
    const val GO_MEMORY_LIMIT = "192MiB"

    /** Monthly data of one account (Mozilla's own limit; the real figure comes from the account's quota). */
    const val FREE_QUOTA_GB = 50

    /** The core ends a connect the user asked for after a minute (its own rule); this app waits a little longer. */
    const val CONNECT_ALLOWANCE_MS = 75_000L

    /** The core's first start may fetch the server list and a pass before it answers: a slow network needs time. */
    const val START_ALLOWANCE_MS = 20_000L

    /**
     * Resolvers the core uses for its own lookups (Mozilla's servers). Plain IPs and DoH URLs both work in its config. The
     * static Go binary has no system resolver on Android, so these are always given. Empty = the core's own defaults.
     */
    val DEFAULT_DNS = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query")

    /** Characters a core DNS entry may hold (a conservative whitelist: it goes through an environment variable). */
    private val DNS_ENTRY = Regex("^(https://|tls://|udp://|tcp://)?[A-Za-z0-9.:\\[\\]/_-]{1,200}$")

    /** Entries that the core's config would accept, in order, without duplicates. */
    fun cleanDns(entries: List<String>): List<String> =
        entries.map { it.trim() }.filter { it.isNotEmpty() && DNS_ENTRY.matches(it) && !it.contains(',') }.distinct()

    /**
     * The phone's own DNS servers (plain DNS, port 53) as bare IP literals, at most [MAX_SYSTEM_DNS]. The core cannot find
     * them itself on Android (no /etc/resolv.conf), so its "system fallback" would ask 127.0.0.1 and fail; MadShield
     * hands them over (MFX_SYSTEM_DNS). Loopback, wildcard and link-local entries are dropped; the order is kept.
     */
    fun cleanSystemDns(entries: List<String>): List<String> =
        entries.map { it.trim().substringBefore('%') }
            .filter { e ->
                e.isNotEmpty() && (IPV4.matches(e) || (e.contains(':') && IPV6.matches(e))) &&
                    !e.startsWith("127.") && e != "0.0.0.0" && e != "::" && e != "::1" && !e.lowercase().startsWith("fe80")
            }
            .distinct().take(MAX_SYSTEM_DNS)

    const val MAX_SYSTEM_DNS = 4
    private val IPV4 = Regex("""(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})""")
    private val IPV6 = Regex("""[0-9a-fA-F:]{2,39}""")
}

/** A made-up login for the core's SOCKS5 listener: different at every start, never stored, never logged. */
data class FxCredentials(val user: String, val password: String) {
    fun toAuth(): SocksAuth = SocksAuth(user, password)

    override fun toString(): String = "FxCredentials(***)"

    companion object {
        /** [random] must be a SecureRandom in production; tests pass a seeded one. */
        fun generate(random: Random): FxCredentials {
            fun hex(bytes: Int): String {
                val b = ByteArray(bytes)
                random.nextBytes(b)
                return b.joinToString("") { "%02x".format(it) }
            }
            return FxCredentials("mfx" + hex(3), hex(16))
        }
    }
}

/**
 * How the core sends the TLS hello of its own connections to Mozilla (sign-in, Guardian, the proxy servers). A network that
 * filters by server name often stalls the handshake ("TLS handshake timeout"); cutting the first packet gets past many such
 * filters, and the server receives the same bytes. SNI (the default) cuts it inside the name as TCP segments; FIRST_BYTE
 * after its first byte; RECORD makes two TLS records. Costs one extra packet per new connection, nothing while connected.
 */
enum class FxHelloSplit(val stored: String) {
    OFF("off"), SNI("sni"), FIRST_BYTE("first-byte"), RECORD("record");

    companion object {
        val DEFAULT = SNI
        fun fromStored(s: String?): FxHelloSplit = entries.firstOrNull { it.stored == s } ?: DEFAULT
    }
}

/** How the data reaches Mozilla's proxy: HTTP/2 over TCP (default) or HTTP/3 over QUIC (UDP). */
enum class FxTransport(val stored: String) {
    H2("h2"), H3("h3");

    companion object {
        val DEFAULT = H2
        fun fromStored(s: String?): FxTransport = entries.firstOrNull { it.stored == s } ?: DEFAULT
    }
}

/**
 * How many parallel sessions the core keeps open to Mozilla's proxy (1 to 4). Each new connection goes to the next one, so a
 * network that slows every connection down on its own gives more speed with more of them; each costs a handshake and a
 * keepalive, so one stays the default.
 */
object FxSessions {
    const val MIN = 1
    const val MAX = 4
    const val DEFAULT = 1
    fun clean(n: Int?): Int = (n ?: DEFAULT).coerceIn(MIN, MAX)
}

/**
 * The user's own Guardian relay: the https address of a Cloudflare Worker they deployed (tools/guardian-relay). Mozilla's VPN
 * service refuses some regions by the address a request comes from; through the relay the account's pass requests leave from
 * the Worker's address. The relay sees the account's access token, so there is no default and no shared one: nothing is sent
 * unless the user typed an address. The address may end in a secret path part, so it is never written to the log.
 */
object FxRelay {
    const val MAX_LENGTH = 300

    /** The address to hand to the core, or null for none/unusable (the core then talks to Mozilla directly). */
    fun clean(raw: String?): String? {
        val v = raw?.trim().orEmpty().trimEnd('/')
        if (v.isEmpty() || v.length > MAX_LENGTH) return null
        if (v.any { it.isWhitespace() || it.isISOControl() || it == '?' || it == '#' || it == '@' || it == '\\' }) return null
        if (!v.startsWith("https://", ignoreCase = true)) return null
        val rest = v.substring(8)
        val host = rest.substringBefore('/').substringBefore(':').lowercase()
        if (!host.all { it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' }) return null // a name, never an IP literal in brackets
        val labels = host.split('.')
        if (labels.size < 2 || labels.any { it.isEmpty() || it.startsWith('-') || it.endsWith('-') }) return null
        if (host.all { it in '0'..'9' || it == '.' }) return null // an IPv4 address
        return v
    }

    /** Only the host, for the log: the path may hold the secret. */
    fun hostOf(clean: String): String = clean.substring(8).substringBefore('/').substringBefore(':')
}

/** The environment of the core's process. Built here (pure) so a test sees exactly what is handed over. */
object FxEnvironment {
    fun build(
        socksPort: Int, apiPort: Int, creds: FxCredentials, dns: List<String>, tmpDir: String,
        systemDns: List<String> = emptyList(), helloSplit: FxHelloSplit = FxHelloSplit.DEFAULT,
        sessions: Int = FxSessions.DEFAULT, transport: FxTransport = FxTransport.DEFAULT, guardianRelay: String? = null
    ): Map<String, String> {
        require(socksPort in 1024..65535 && apiPort in 1024..65535 && socksPort != apiPort) { "bad ports" }
        val env = linkedMapOf(
            "MFX_SOCKS_PORT" to socksPort.toString(),
            "MFX_API_PORT" to apiPort.toString(),
            "MFX_SOCKS_USER" to creds.user,
            "MFX_SOCKS_PASS" to creds.password,
            "TMPDIR" to tmpDir,
            "HOME" to tmpDir,
            // same resource caps as the other Go engines (Psiphon, sing-box): a burst must not spread over every big core
            "GOMAXPROCS" to FxVpn.GO_MAX_PROCS,
            "GOMEMLIMIT" to FxVpn.GO_MEMORY_LIMIT
        )
        val servers = FxVpn.cleanDns(dns)
        if (servers.isNotEmpty()) env["MFX_DNS"] = servers.joinToString(",")
        val system = FxVpn.cleanSystemDns(systemDns)
        if (system.isNotEmpty()) env["MFX_SYSTEM_DNS"] = system.joinToString(",")
        env["MFX_HELLO_SPLIT"] = helloSplit.stored // always sent: the core keeps its setting in a file, so "off" must be said too
        env["MFX_UPSTREAM_CONNS"] = FxSessions.clean(sessions).toString() // also always sent, for the same reason
        env["MFX_TRANSPORT"] = transport.stored
        FxRelay.clean(guardianRelay)?.let { env["MFX_GUARDIAN_RELAY"] = it } // only the user's own address, never a default
        return env
    }

    /** The keys that must never reach the in-app log. */
    fun isSecret(key: String): Boolean = key == "MFX_SOCKS_PASS" || key == "MFX_SOCKS_USER"
}

// ---------------------------------------------------------------------------------------------------- API models

/** One Firefox Account the core knows. */
data class FxAccount(
    val id: String,
    val email: String,
    val enabled: Boolean,
    val active: Boolean,
    /** The core's word for the account's state ("ok", "needs sign-in", "quota", ...). Shown as it is, in English. */
    val status: String,
    val reasonCode: String,
    val usedPercent: Double,
    val limitBytes: Long,
    val remainingBytes: Long,
    val unlimited: Boolean,
    /** ISO time when the quota resets, "" when unknown. */
    val resetAt: String,
    val hasPassword: Boolean
) {
    val usedBytes: Long get() = if (unlimited || limitBytes <= 0) 0L else (limitBytes - remainingBytes).coerceAtLeast(0L)
}

/** The parts of the core's /api/status this app uses. */
data class FxStatus(
    /** starting / running / waiting / error / off */
    val phase: String,
    val message: String,
    /** no_accounts, no_usable_account, waiting_for_network, proxy_port_in_use, start_failed, "" */
    val code: String,
    /** The proxy exists (it listens); false while off. */
    val proxyUp: Boolean,
    /** The proxy holds no session to Mozilla yet (it wakes on the first connection or test). */
    val sleeping: Boolean,
    val wakeErrorCode: String,
    val wakeError: String,
    /** Why the last connect the app asked for was given up, "" otherwise. */
    val connectFailure: String,
    val noNetwork: Boolean,
    val selection: String,
    val selectionName: String,
    val exitCountry: String,
    val exitCity: String,
    val exitIp: String,
    val activeEmail: String,
    val downBytes: Long,
    val upBytes: Long,
    val downRate: Long,
    val upRate: Long
)

/** What the sign-in asks of the person right now. */
enum class FxStep(val wire: String, val needsInput: Boolean) {
    WORKING("working", false),
    EMAIL_CODE("need_email_code", true),
    TOTP("need_totp", true),
    UNBLOCK_CODE("need_unblock_code", true),
    CAPTCHA("need_captcha", true),
    EMAIL_LINK("need_email_link", false),
    DONE("done", false),
    FAILED("failed", false),
    CANCELLED("cancelled", false);

    val finished: Boolean get() = this == DONE || this == FAILED || this == CANCELLED

    companion object {
        fun fromWire(s: String?): FxStep = entries.firstOrNull { it.wire == s } ?: WORKING
    }
}

data class FxSignIn(
    val id: String,
    val step: FxStep,
    val message: String,
    val error: String,
    val errorCode: String,
    /** A data: URL of the CAPTCHA picture, "" when none. */
    val captcha: String,
    val accountId: String
)

/**
 * The core's renewal of an account's access token while a person answers Fastly's image CAPTCHA (patch 0003):
 * [state] is idle, running, captcha (a picture waits in [image], named [id]), done or failed.
 */
data class FxReauth(val state: String, val id: String, val image: String, val error: String, val renewed: Boolean) {
    val waitingCaptcha: Boolean get() = state == "captcha" && id.isNotEmpty() && image.isNotEmpty()
    val finished: Boolean get() = state == "done" || state == "failed"
}

/**
 * While a person answers a CAPTCHA the connection must not restart the core under them (every restart ends the renewal
 * in it). The health loop of the VPN asks [active] and waits. The hold ends by itself after [HOLD_MS], whatever happens to
 * the page that took it, so a closed page can never keep the connection from recovering.
 */
object FxReauthGate {
    const val HOLD_MS = 5 * 60_000L
    @Volatile private var until = 0L

    fun hold(nowMs: Long = System.currentTimeMillis()) { until = nowMs + HOLD_MS }
    fun release() { until = 0L }
    fun active(nowMs: Long = System.currentTimeMillis()): Boolean = nowMs < until
}

data class FxLocation(
    val code: String,
    val name: String,
    val city: String,
    val recommended: Boolean,
    val pingMs: Long
)

/**
 * The flag of a two-letter country code as the pair of regional-indicator symbols every phone draws as a flag (no image
 * files needed). "" for anything that is not two ASCII letters.
 */
fun flagEmoji(code: String): String {
    val c = code.trim().uppercase(java.util.Locale.ROOT)
    if (c.length != 2 || c.any { it !in 'A'..'Z' }) return ""
    return c.map { String(Character.toChars(0x1F1E6 + (it - 'A'))) }.joinToString("")
}

/** The locations whose name, city or code contains [query] (case-insensitive); everything for a blank query. */
fun filterLocations(all: List<FxLocation>, query: String): List<FxLocation> {
    val q = query.trim().lowercase(java.util.Locale.ROOT)
    if (q.isEmpty()) return all
    return all.filter { it.name.lowercase(java.util.Locale.ROOT).contains(q) || it.city.lowercase(java.util.Locale.ROOT).contains(q) || it.code.lowercase(java.util.Locale.ROOT) == q }
}

data class FxTestResult(val ok: Boolean, val errorCode: String, val error: String, val exitCountry: String, val exitIp: String, val totalMs: Long)

/** Reading the core's JSON. Every field is optional on purpose: a missing one means "unknown", never a crash. */
object FxJson {
    @Suppress("UNCHECKED_CAST")
    private fun obj(v: Any?): Map<String, Any?>? = v as? Map<String, Any?>

    private fun str(m: Map<String, Any?>?, k: String): String = (m?.get(k) as? String) ?: ""
    private fun bool(m: Map<String, Any?>?, k: String): Boolean = (m?.get(k) as? Boolean) ?: false
    private fun num(m: Map<String, Any?>?, k: String): Long = when (val v = m?.get(k)) {
        is Long -> v
        is Int -> v.toLong()
        is Double -> v.toLong()
        else -> 0L
    }
    private fun dbl(m: Map<String, Any?>?, k: String): Double = when (val v = m?.get(k)) {
        is Double -> v
        is Long -> v.toDouble()
        is Int -> v.toDouble()
        else -> 0.0
    }

    fun status(text: String): FxStatus? {
        val root = MiniJson.parseObject(text) ?: return null
        val state = obj(root["state"])
        val proxy = obj(root["proxy"])
        val exit = obj(root["exit"])
        val active = obj(root["active_account"])
        val traffic = obj(root["traffic"])
        return FxStatus(
            phase = str(state, "phase"),
            message = str(state, "message"),
            code = str(state, "code"),
            proxyUp = proxy != null,
            sleeping = proxy != null && proxy.containsKey("sleeping_since"),
            wakeErrorCode = str(proxy, "wake_error_code"),
            wakeError = str(proxy, "wake_error"),
            connectFailure = str(root, "connect_failure"),
            noNetwork = bool(root, "no_network"),
            selection = str(root, "selection"),
            selectionName = str(root, "selection_name"),
            exitCountry = str(exit, "country_code"),
            exitCity = str(exit, "city"),
            exitIp = str(exit, "ipv4").ifEmpty { str(exit, "ipv6") },
            activeEmail = str(active, "email"),
            downBytes = num(traffic, "down"),
            upBytes = num(traffic, "up"),
            downRate = num(traffic, "down_rate"),
            upRate = num(traffic, "up_rate")
        )
    }

    fun accounts(text: String): List<FxAccount>? {
        val root = MiniJson.parseObject(text) ?: return null
        val list = root["accounts"] as? List<*> ?: return emptyList()
        return list.mapNotNull { item ->
            val a = obj(item) ?: return@mapNotNull null
            val usage = obj(a["usage"])
            FxAccount(
                id = str(a, "id"), email = str(a, "email"), enabled = bool(a, "enabled"), active = bool(a, "active"),
                status = str(a, "status"), reasonCode = str(a, "reason_code"), usedPercent = dbl(a, "used_percent"),
                limitBytes = num(usage, "limit_bytes"), remainingBytes = num(usage, "remaining_bytes"),
                unlimited = bool(usage, "unlimited"), resetAt = str(usage, "reset_at"), hasPassword = bool(a, "has_password")
            )
        }.filter { it.id.isNotEmpty() }
    }

    fun signIn(text: String): FxSignIn? {
        val m = MiniJson.parseObject(text) ?: return null
        val id = str(m, "id")
        if (id.isEmpty()) return null
        return FxSignIn(
            id = id, step = FxStep.fromWire(str(m, "step")), message = str(m, "message"),
            error = str(m, "error"), errorCode = str(m, "error_code"), captcha = str(m, "captcha"), accountId = str(m, "account_id")
        )
    }

    fun reauth(text: String): FxReauth? {
        val m = MiniJson.parseObject(text) ?: return null
        val state = str(m, "state")
        if (state.isEmpty()) return null
        return FxReauth(state, str(m, "id"), str(m, "image"), str(m, "error"), bool(m, "renewed"))
    }

    fun locations(text: String): List<FxLocation>? {
        val root = MiniJson.parseObject(text) ?: return null
        val list = root["locations"] as? List<*> ?: return emptyList()
        return list.mapNotNull { item ->
            val l = obj(item) ?: return@mapNotNull null
            val code = str(l, "code")
            if (code.isEmpty()) null else FxLocation(code, str(l, "name").ifEmpty { code }, str(l, "city"), bool(l, "recommended"), num(l, "ping_ms"))
        }
    }

    fun test(text: String): FxTestResult? {
        val m = MiniJson.parseObject(text) ?: return null
        return FxTestResult(bool(m, "ok"), str(m, "error_code"), str(m, "error"), str(m, "exit_country"), str(m, "exit_ipv4").ifEmpty { str(m, "exit_ipv6") }, num(m, "total_ms"))
    }

    /** The core's error body is `{"error": "..."}`. */
    fun errorText(text: String): String? = MiniJson.parseObject(text)?.let { str(it, "error") }?.takeIf { it.isNotEmpty() }

    /** A data: URL ("data:image/png;base64,...") of a CAPTCHA to its bytes, or null when it is not one. */
    fun dataUrlBytes(url: String): ByteArray? {
        val comma = url.indexOf(',')
        if (!url.startsWith("data:") || comma < 0 || url.length > 600_000) return null
        return runCatching { java.util.Base64.getDecoder().decode(url.substring(comma + 1).filter { !it.isWhitespace() }) }.getOrNull()
    }
}

/** What the connect wait concludes from the core's status and its connection test. */
sealed interface FxVerdict {
    data object Ready : FxVerdict
    data class Failed(val code: String, val detail: String) : FxVerdict
}

object FxErrors {
    /** The code the sign-in / account / failure fields use, as one line for the log and the Error card (English). */
    fun english(code: String, detail: String = ""): String {
        if (isCaptcha(detail)) return CAPTCHA_TEXT
        val base = when (code) {
            "no_accounts" -> "Foxy has no account yet: open Foxy and sign in with your Firefox Account"
            "no_usable_account" -> "The Firefox Account cannot be used now (quota used up, sign-in expired, or no VPN entitlement): open Foxy to see why"
            "waiting_for_network" -> "no network"
            "no_network" -> "no network"
            "proxy_port_in_use" -> "the Foxy port is used by another program"
            "unreachable" -> "Mozilla's servers cannot be reached from this network"
            "inside_vpn" -> "the Foxy core was captured by a VPN; it must stay outside"
            "refused" -> "Mozilla's proxy refused the connection"
            "location_refused" -> "this location refused the connection: choose another one"
            "sign_in" -> "the Firefox Account must sign in again"
            "quota" -> "this month's data of the Firefox Account is used up"
            "not_entitled" -> "this Firefox Account has no access to Foxy (not available in this country, or not enabled)"
            "region" -> "Foxy is not offered in this region"
            "server" -> "Mozilla's server answered with an error"
            "no_account" -> "Foxy has no account yet: open Foxy and sign in"
            else -> "the Foxy core could not connect"
        }
        val d = detail.trim().take(160)
        return if (d.isNotEmpty() && !base.contains(d)) "$base [$d]" else base
    }

    /** Fastly's image CAPTCHA, which the core cannot answer on its own while it renews the account's sign-in in the background. */
    fun isCaptcha(text: String): Boolean = text.contains("image CAPTCHA", ignoreCase = true)

    const val CAPTCHA_TEXT = "Fastly asks for a CAPTCHA before the account's sign-in can be renewed: open Foxy and tap \"Renew sign-in\""

    /** A failure that retrying will not fix: the connect loop must not keep hammering Mozilla for these. */
    fun isLasting(code: String): Boolean = code in setOf("no_accounts", "no_usable_account", "no_account", "sign_in", "quota", "not_entitled", "region")
}

/** Decides from a status snapshot whether the engine can carry traffic, or why not. Pure. */
object FxProgress {
    /** Status alone: a hard stop (no account, a failed connect, a lasting wake failure) is a verdict; otherwise null = keep waiting. */
    fun fromStatus(s: FxStatus): FxVerdict? {
        if (s.connectFailure.isNotEmpty()) return FxVerdict.Failed(s.connectFailure, s.message)
        if (s.code == "no_accounts" || s.code == "no_usable_account" || s.code == "proxy_port_in_use" || s.code == "start_failed") {
            return FxVerdict.Failed(s.code, s.message)
        }
        if (s.wakeErrorCode.isNotEmpty() && FxErrors.isLasting(s.wakeErrorCode)) return FxVerdict.Failed(s.wakeErrorCode, s.wakeError)
        return null
    }

    /** A connection test answered: ok = ready, else its failure code. */
    fun fromTest(t: FxTestResult): FxVerdict =
        if (t.ok) FxVerdict.Ready else FxVerdict.Failed(t.errorCode.ifEmpty { "other" }, t.error)

}
