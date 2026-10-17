package com.aethershield.app.core

import android.content.Context
import java.io.File

/**
 * Format confirmed directly against aether/src/routing.rs::split_sections():
 * a single file, "[block]" and "[direct]" section headers (case-insensitive),
 * one rule per line, "#" for comments. --route-direct/--route-block on their
 * own take the rule list as literal CLI argument text, not a file path --
 * fine for a couple of entries, a bad idea for a large domain list, which is
 * exactly the "Iranian sites" use case, so this app always goes through
 * --routes with a file instead.
 *
 * Rule syntax (also from routing.rs): a bare entry matches the domain and its
 * subdomains; other recognized prefixes are full:/exact:, keyword:,
 * regexp:/regex:, ip:/cidr: (or just a bare CIDR/address), port:N or
 * port:N-M, and the literal word "private" for loopback/LAN/CGNAT ranges.
 * Block wins over direct if the same entry matches both lists.
 *
 * Rule file lives in the app's private files dir, rewritten fresh on every
 * engine start.
 */
class RuleFileWriter(private val context: Context) {

    fun writeRoutesFile(directRules: List<String>, blockRules: List<String>): File? {
        if (directRules.isEmpty() && blockRules.isEmpty()) return null
        val f = File(context.filesDir, "routes.txt")
        buildString {
            appendLine("[block]")
            blockRules.forEach { appendLine(it.trim()) }
            appendLine()
            appendLine("[direct]")
            directRules.forEach { appendLine(it.trim()) }
        }.let { f.writeText(it) }
        return f
    }
}
