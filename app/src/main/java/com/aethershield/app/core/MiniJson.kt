package com.aethershield.app.core

/**
 * A tiny JSON writer and reader, written for exactly two jobs and no more:
 *  - write the sing-box configuration (maps, lists, strings, numbers, booleans) as pretty text;
 *  - read the small flat object inside a `vmess://` link.
 * Pure Kotlin (no org.json, which does not exist off-device), so both can be tested without a phone.
 * Values are: null, Boolean, Int/Long/Double, String, List<*>, Map<String, *>.
 */
object MiniJson {

    fun write(value: Any?, indent: Int = 2): String {
        val sb = StringBuilder()
        writeValue(sb, value, indent, 0)
        return sb.toString()
    }

    private fun writeValue(sb: StringBuilder, v: Any?, indent: Int, level: Int) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is Int, is Long -> sb.append(v.toString())
            is Double -> sb.append(if (v == Math.floor(v) && !v.isInfinite()) v.toLong().toString() else v.toString())
            is String -> writeString(sb, v)
            is Map<*, *> -> {
                if (v.isEmpty()) { sb.append("{}"); return }
                sb.append("{\n")
                var first = true
                for ((k, value) in v) {
                    if (!first) sb.append(",\n")
                    first = false
                    pad(sb, indent, level + 1)
                    writeString(sb, k.toString())
                    sb.append(": ")
                    writeValue(sb, value, indent, level + 1)
                }
                sb.append('\n'); pad(sb, indent, level); sb.append('}')
            }
            is List<*> -> {
                if (v.isEmpty()) { sb.append("[]"); return }
                sb.append("[\n")
                var first = true
                for (item in v) {
                    if (!first) sb.append(",\n")
                    first = false
                    pad(sb, indent, level + 1)
                    writeValue(sb, item, indent, level + 1)
                }
                sb.append('\n'); pad(sb, indent, level); sb.append(']')
            }
            else -> throw IllegalArgumentException("cannot write ${v::class.java.simpleName} as JSON")
        }
    }

    private fun pad(sb: StringBuilder, indent: Int, level: Int) {
        repeat(indent * level) { sb.append(' ') }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c.code < 0x20 -> sb.append("\\u").append(c.code.toString(16).padStart(4, '0'))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }

    /** Parses one JSON value; null when the text is not valid JSON (or has trailing text). */
    fun parse(text: String): Any? {
        return try {
            val p = Parser(text)
            p.skipWs()
            val v = p.value(0)
            p.skipWs()
            if (p.pos != text.length) null else v
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** The JSON object in [text] as a map, or null when it is not an object. */
    @Suppress("UNCHECKED_CAST")
    fun parseObject(text: String): Map<String, Any?>? = parse(text) as? Map<String, Any?>

    private class Parser(val s: String) {
        var pos = 0

        fun skipWs() { while (pos < s.length && s[pos].isWhitespace()) pos++ }

        fun value(depth: Int): Any? {
            require(depth <= 20) { "too deep" }
            skipWs()
            require(pos < s.length) { "end" }
            return when (val c = s[pos]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> if (c == '-' || c.isDigit()) num() else throw IllegalArgumentException("unexpected $c")
            }
        }

        private fun lit(word: String, v: Any?): Any? {
            require(s.startsWith(word, pos)) { "bad literal" }
            pos += word.length
            return v
        }

        private fun num(): Any {
            val start = pos
            if (s[pos] == '-') pos++
            while (pos < s.length && (s[pos].isDigit() || s[pos] in ".eE+-")) pos++
            val t = s.substring(start, pos)
            return t.toLongOrNull() ?: t.toDoubleOrNull() ?: throw IllegalArgumentException("bad number")
        }

        private fun str(): String {
            pos++ // opening quote
            val sb = StringBuilder()
            while (true) {
                require(pos < s.length) { "unterminated string" }
                val c = s[pos++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        require(pos < s.length) { "bad escape" }
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000c'); 'n' -> sb.append('\n')
                            'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'u' -> {
                                require(pos + 4 <= s.length) { "bad unicode escape" }
                                sb.append(s.substring(pos, pos + 4).toIntOrNull(16)?.toChar() ?: throw IllegalArgumentException("bad unicode escape"))
                                pos += 4
                            }
                            else -> throw IllegalArgumentException("bad escape $e")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun arr(depth: Int): List<Any?> {
            pos++
            val out = ArrayList<Any?>()
            skipWs()
            if (pos < s.length && s[pos] == ']') { pos++; return out }
            while (true) {
                out.add(value(depth + 1))
                skipWs()
                require(pos < s.length) { "unterminated array" }
                when (s[pos++]) {
                    ',' -> continue
                    ']' -> return out
                    else -> throw IllegalArgumentException("bad array")
                }
            }
        }

        private fun obj(depth: Int): Map<String, Any?> {
            pos++
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (pos < s.length && s[pos] == '}') { pos++; return out }
            while (true) {
                skipWs()
                require(pos < s.length && s[pos] == '"') { "key expected" }
                val k = str()
                skipWs()
                require(pos < s.length && s[pos++] == ':') { "colon expected" }
                out[k] = value(depth + 1)
                skipWs()
                require(pos < s.length) { "unterminated object" }
                when (s[pos++]) {
                    ',' -> continue
                    '}' -> return out
                    else -> throw IllegalArgumentException("bad object")
                }
            }
        }
    }
}
