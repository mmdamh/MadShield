package com.aethershield.app.core

import android.content.Context
import java.io.BufferedWriter
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
 * The file holds the typed rules (EngineConfig.directRules / blockRules) plus every ENABLED imported list
 * (see RuleLists). Imported lists are streamed from their own files line by line, never loaded into memory.
 *
 * The engine is restarted whenever the tunnel flaps, and rewriting a 100k-line file each time is pure waste
 * (CPU and flash writes), so the file is rebuilt only when a signature of its inputs changed.
 */
class RuleFileWriter(private val context: Context) {

    fun writeRoutesFile(directRules: List<String>, blockRules: List<String>): File? {
        val lists = RuleLists.get(context)
        val sources = lists.sources.value.filter { it.enabled }
        if (directRules.isEmpty() && blockRules.isEmpty() && sources.isEmpty()) return null

        val f = File(context.filesDir, "routes.txt")
        val sigFile = File(context.filesDir, "routes.sig")
        val sig = signature(directRules, blockRules, sources)
        if (f.isFile && sigFile.isFile && runCatching { sigFile.readText() }.getOrNull() == sig) return f

        val tmp = File(context.filesDir, "routes.tmp")
        tmp.bufferedWriter().use { w ->
            writeSection(w, "[block]", blockRules, sources.filter { it.target == RuleTarget.BLOCK }, lists)
            w.newLine()
            writeSection(w, "[direct]", directRules, sources.filter { it.target == RuleTarget.DIRECT }, lists)
        }
        if (!tmp.renameTo(f)) { tmp.copyTo(f, overwrite = true); tmp.delete() }
        sigFile.writeText(sig)
        return f
    }

    private fun writeSection(w: BufferedWriter, header: String, typed: List<String>, imported: List<RuleSource>, lists: RuleLists) {
        w.write(header); w.newLine()
        for (r in typed) {
            val t = r.trim()
            if (t.isNotEmpty()) { w.write(t); w.newLine() }
        }
        for (src in imported) {
            val file = lists.fileOf(src)
            if (!file.isFile) continue
            file.bufferedReader().use { r ->
                while (true) {
                    val line = r.readLine() ?: break
                    if (line.isNotEmpty()) { w.write(line); w.newLine() }
                }
            }
        }
    }

    private fun signature(direct: List<String>, block: List<String>, sources: List<RuleSource>): String =
        buildString {
            append("v2|").append(direct.size).append(':').append(direct.hashCode())
            append('|').append(block.size).append(':').append(block.hashCode())
            sources.sortedBy { it.id }.forEach {
                append('|').append(it.id).append(':').append(it.target.name).append(':').append(it.count).append(':').append(it.updatedAt)
            }
        }
}
