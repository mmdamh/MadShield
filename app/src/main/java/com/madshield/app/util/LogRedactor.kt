package com.madshield.app.util

/**
 * Removes what must not leave the phone from a piece of text that is about to be copied or shared:
 * private/local IP addresses, the host part of public IPs, tokens/secrets/keys and long opaque strings.
 * Pure text processing (no Android types) so it is unit-tested off-device.
 *
 * It is best effort on free text, which is why the default diagnostics report contains no raw log lines
 * at all and only offers a redacted tail when the user switches that on.
 */
object LogRedactor {
    const val MASK = "[redacted]"
    const val PRIVATE_IP = "[private-ip]"
    const val IPV6 = "[ipv6]"

    private val ipv4 = Regex("""(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.]*\w)""")
    private val ipv6 = Regex(
        """(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}""" +
            """|(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?""" +
            """|::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?)(?![\w:])"""
    )
    private val bearer = Regex("""(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}""")
    private val keyValue = Regex(
        """(?i)\b([a-z0-9_.-]*(?:secret|token|password|passwd|private[_-]?key|api[_-]?key|authorization|credential)[a-z0-9_.-]*)""" +
            """(["']?\s*[:=]\s*|\s+)(["']?)(?:(?:bearer|basic)\s+)?[^\s"',;]+"""
    )
    private val opaque = Regex("""(?<![A-Za-z0-9+_=-])[A-Za-z0-9+_=-]{40,}(?![A-Za-z0-9+_=-])""")

    fun redact(text: String): String {
        if (text.isEmpty()) return text
        var s = text
        s = keyValue.replace(s) { "${it.groupValues[1]}${it.groupValues[2]}${it.groupValues[3]}$MASK" }
        s = bearer.replace(s) { "${it.groupValues[1]} $MASK" }
        s = ipv4.replace(s) { m ->
            val o = m.groupValues.drop(1).map { it.toInt() }
            when {
                o.any { it > 255 } -> m.value // not an address (a version string, say)
                isPrivate(o) -> PRIVATE_IP
                else -> "${o[0]}.${o[1]}.*.*"
            }
        }
        s = ipv6.replace(s, IPV6)
        s = opaque.replace(s, MASK)
        return s
    }

    fun redactLines(lines: List<String>): List<String> = lines.map(::redact)

    private fun isPrivate(o: List<Int>): Boolean {
        val a = o[0]; val b = o[1]
        return a == 0 || a == 10 || a == 127 ||
            (a == 169 && b == 254) ||
            (a == 172 && b in 16..31) ||
            (a == 192 && b == 168) ||
            (a == 100 && b in 64..127) ||   // carrier-grade NAT, also our mapped-DNS range
            (a == 198 && (b == 18 || b == 19)) || // benchmark range, our tunnel/mapdns addresses
            a >= 224
    }
}
