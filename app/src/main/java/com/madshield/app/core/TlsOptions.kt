package com.madshield.app.core

/**
 * update19: the two anti-DPI knobs Aether core v2.4.0 added for its TLS handshakes.
 * Pure (no Android types) so it is unit-tested. Everything here is OFF by default: with the defaults NO
 * environment variable of this file reaches the core, so the connection behaves exactly as before.
 *
 * Facts below were checked against the core's own source at the pinned commit (d58f9d5): `quic.rs` (masque_sni_of),
 * `dns.rs` (valid_domain), `tls.rs` (Fingerprint::configured and the Chrome / Firefox tests of October 2026).
 */

/**
 * The server name every MASQUE handshake puts in its ClientHello (AETHER_MASQUE_SNI). The HTTP host stays
 * `cloudflareaccess.com`; only the TLS name changes.
 *
 * The core STOPS at start when the value is not a domain name (an IP address included), so the app validates first
 * and never passes anything it is unsure about. This validator is a little stricter than the core's on purpose:
 * lower-case letters, digits and hyphens only, at least two labels, and a last label that is not all digits (so
 * "1.2.3.4" can never get through).
 */
object MasqueSni {
    /** What the core sends when the variable is not set. */
    const val DEFAULT = "www.cloudflare.com"

    /** The name the official WARP client sends (named in the core's docs). */
    const val WARP_CLIENT = "consumer-masque.cloudflareclient.com"

    private const val MAX_NAME = 253
    private const val MAX_LABEL = 63

    /** The clean, lower-case name, or null when [raw] is empty or not acceptable. One trailing dot is removed. */
    fun normalize(raw: String?): String? {
        var s = raw?.trim()?.lowercase() ?: return null
        if (s.endsWith(".")) s = s.dropLast(1)
        if (s.isEmpty() || s.length > MAX_NAME) return null
        val labels = s.split('.')
        if (labels.size < 2) return null
        for (l in labels) {
            if (l.isEmpty() || l.length > MAX_LABEL) return null
            if (l.first() == '-' || l.last() == '-') return null
            if (!l.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }) return null
        }
        if (labels.last().all { it in '0'..'9' }) return null
        return s
    }

    fun isValid(raw: String?): Boolean = normalize(raw) != null

    /** What the user's stored value means: the default, the WARP client's name, or something of their own. */
    enum class Kind { DEFAULT, WARP_CLIENT, CUSTOM }

    fun kindOf(stored: String?): Kind {
        val n = normalize(stored) ?: return Kind.DEFAULT
        return when (n) {
            DEFAULT -> Kind.DEFAULT
            WARP_CLIENT -> Kind.WARP_CLIENT
            else -> Kind.CUSTOM
        }
    }

    /** The value for AETHER_MASQUE_SNI, or null when nothing must be set (empty, invalid, or equal to the core's own default). */
    fun envValue(stored: String?): String? = normalize(stored)?.takeIf { it != DEFAULT }

    /** Protocols whose handshakes use the name: everything that can run over MASQUE. */
    fun appliesTo(protocol: Protocol): Boolean = when (protocol) {
        Protocol.SMART, Protocol.MASQUE_H3, Protocol.MASQUE_H2, Protocol.GOOL -> true
        Protocol.WIREGUARD, Protocol.GOOL_CLASSIC -> false
    }
}

/**
 * "TLS look": one choice instead of sixteen raw options. The core's default already imitates Chrome (cipher order,
 * GREASE, shuffled extensions, `h2`/`http/1.1`), so [DEFAULT] sends nothing at all.
 *
 *  CHROME_PLUS  the default plus the four extras Chrome sends and BoringSSL leaves out by default
 *               (GREASE signature algorithm, brotli certificate compression, ALPS, ECH GREASE).
 *               The first packet keeps its size.
 *  FIREFOX      Firefox's ClientHello of October 2026, with the exact values the core's own test uses to build
 *               it. It carries a post-quantum key share, so the first packet is about 1.2 KB larger.
 *
 * The presets are plain data. The names are listed in [ALL_VARIABLES] and CI checks that the core still knows each one.
 */
enum class TlsPreset {
    DEFAULT, CHROME_PLUS, FIREFOX;

    /** The variables this preset sets: nothing for [DEFAULT]. */
    fun env(): Map<String, String> = when (this) {
        DEFAULT -> emptyMap()
        CHROME_PLUS -> linkedMapOf(
            "AETHER_ENABLE_GREASE_SIGALGS" to "1",
            "AETHER_TLS_CERT_COMPRESSION" to "brotli",
            "AETHER_TLS_ALPS" to "new",
            "AETHER_ENABLE_ECH_GREASE" to "1"
        )
        FIREFOX -> linkedMapOf(
            "AETHER_TLS13_CIPHERS" to "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
            "AETHER_TLS_GROUPS" to "X25519MLKEM768:X25519:P-256:P-384:P-521",
            "AETHER_TLS_KEY_SHARES" to "X25519MLKEM768:X25519:P-256",
            "AETHER_DISABLE_GREASE" to "1",
            "AETHER_TLS_SIGALGS" to "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:" +
                "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:" +
                "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1",
            "AETHER_TLS_CERT_COMPRESSION" to "zlib:brotli:zstd",
            "AETHER_ENABLE_ECH_GREASE" to "1",
            "AETHER_DISABLE_SESSION_TICKET" to "1",
            "AETHER_DISABLE_EXTENSION_PERMUTATION" to "1"
        )
    }

    companion object {
        fun fromStored(name: String?): TlsPreset =
            name?.let { n -> entries.firstOrNull { it.name == n } } ?: DEFAULT

        /** Every variable any preset (or the SNI) can set; CI greps the core's source for each of them. */
        val ALL_VARIABLES: List<String> =
            (entries.flatMap { it.env().keys } + "AETHER_MASQUE_SNI").distinct().sorted()
    }
}
