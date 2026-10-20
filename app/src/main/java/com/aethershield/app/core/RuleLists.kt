package com.aethershield.app.core

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.aethershield.app.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.UUID

enum class RuleTarget { DIRECT, BLOCK }

/** One imported list (a file or a link). Its normalised rules live in rules/<id>.txt, one per line. */
data class RuleSource(
    val id: String,
    val name: String,
    val url: String?,
    val target: RuleTarget,
    val count: Int,
    val updatedAt: Long,
    val enabled: Boolean = true,
    /** Rules left out because the size limit was reached. */
    val dropped: Int = 0
)

data class RuleStatus(val busy: Boolean = false, val message: String? = null, val error: Boolean = false)

/**
 * Big lists (ad-block hosts files have 100k+ lines) do NOT belong in DataStore or in a text field: every
 * settings change would rewrite and re-read them, and the UI would freeze. They are imported once, cleaned
 * up by [RuleParser] and kept as plain files. [RuleFileWriter] concatenates them into the engine's routes
 * file at engine start, and only when something changed.
 *
 * Nothing here runs on a timer: lists are refreshed only when the user taps refresh, so there is no
 * background work and no wake-ups for it.
 */
class RuleLists private constructor(private val context: Context) {

    companion object {
        /** Per-download cap: keeps a wrong link from filling storage or the heap. */
        const val MAX_BYTES = 40L * 1024 * 1024
        /** One imported list (after cleaning). Hagezi Pro is ~190k, 1Hosts Lite ~210k. */
        const val MAX_RULES_PER_SOURCE = 300_000
        /** What RuleFileWriter hands the engine per tab after removing duplicates between lists: the engine matches every connection against them. */
        const val MAX_RULES_WRITTEN = 500_000
        /** geoip.dat / geosite.dat are a few MB; refuse anything much bigger. */
        const val MAX_GEO_BYTES = 25L * 1024 * 1024

        @Volatile private var instance: RuleLists? = null
        fun get(context: Context): RuleLists =
            instance ?: synchronized(this) { instance ?: RuleLists(context.applicationContext).also { instance = it } }

        fun isHttps(url: String): Boolean = url.trim().startsWith("https://", ignoreCase = true)

        /** "example.com/list.txt" -> "https://example.com/list.txt"; http:// is left alone so it can be refused. */
        fun normalizeUrl(input: String): String {
            val t = input.trim()
            return if (t.contains("://")) t else "https://$t"
        }
    }

    private val dir: File = File(context.filesDir, "rules").also { it.mkdirs() }
    private val indexFile = File(dir, "sources.json")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()

    private val _sources = MutableStateFlow(readIndex())
    val sources: StateFlow<List<RuleSource>> = _sources.asStateFlow()

    private val _status = MutableStateFlow(RuleStatus())
    val status: StateFlow<RuleStatus> = _status.asStateFlow()

    fun clearMessage() { _status.value = _status.value.copy(message = null, error = false) }

    fun total(target: RuleTarget): Int =
        _sources.value.filter { it.enabled && it.target == target }.sumOf { it.count }

    fun fileOf(source: RuleSource): File = File(dir, source.id + ".txt")

    // ------------------------------------------------------------------ import

    /** Imports a list the user picked with the system file picker. */
    fun importFile(uri: Uri, target: RuleTarget) {
        launchJob {
            val name = queryName(uri) ?: "list"
            val geo = GeoDat.isGeoFile(name)
            if (geo && target != RuleTarget.DIRECT) throw IOException(context.getString(R.string.rules_geo_direct_only))
            val stream = context.contentResolver.openInputStream(uri) ?: throw IOException("cannot open file")
            val id = UUID.randomUUID().toString().substring(0, 8)
            val result = stream.use { ingest(it, id, target, geo) }
            commit(RuleSource(id, name, null, target, result.count, System.currentTimeMillis(), true, result.dropped))
            done(name, result.count)
        }
    }

    /**
     * Adds a list from a link. [viaSocksPort] is the engine's SOCKS port when the tunnel is up: the app itself
     * is kept out of the VPN, and many list hosts are unreachable from a filtered network, so the download
     * goes through the tunnel first and falls back to the plain connection.
     */
    fun addUrl(url: String, target: RuleTarget, viaSocksPort: Int?, displayName: String? = null) {
        val clean = normalizeUrl(url)
        if (!isHttps(clean)) { fail(context.getString(R.string.rules_https_only)); return }
        if (GeoDat.isGeoFile(clean) && target != RuleTarget.DIRECT) { fail(context.getString(R.string.rules_geo_direct_only)); return }
        if (_sources.value.any { it.url.equals(clean, ignoreCase = true) && it.target == target }) {
            fail(context.getString(R.string.rules_already_added)); return
        }
        launchJob {
            val src = download(clean, target, viaSocksPort, displayName)
            done(src.name, src.count)
        }
    }

    /**
     * Adds several links one after another (the "Add all recommended" button). One failing link does not stop
     * the others; the result line says how many worked.
     */
    fun addMany(items: List<Pair<String, String>>, target: RuleTarget, viaSocksPort: Int?) {
        val todo = items.filter { (url, _) ->
            _sources.value.none { it.url.equals(url, ignoreCase = true) && it.target == target }
        }
        if (todo.isEmpty()) { fail(context.getString(R.string.rules_already_added)); return }
        launchJob {
            var ok = 0
            var failed = 0
            for ((url, name) in todo) {
                try {
                    _status.value = RuleStatus(true, context.getString(R.string.rules_working_named, name), false)
                    download(url, target, viaSocksPort, name)
                    ok++
                } catch (t: Throwable) {
                    failed++
                }
            }
            _status.value = RuleStatus(false, context.getString(R.string.rules_batch_done, ok, failed), failed > 0)
        }
    }

    /** Downloads, cleans and stores one list; must run inside [launchJob]. */
    private fun download(url: String, target: RuleTarget, viaSocksPort: Int?, displayName: String?): RuleSource {
        val id = UUID.randomUUID().toString().substring(0, 8)
        val geo = GeoDat.isGeoFile(url)
        val name = displayName ?: runCatching { URL(url).host }.getOrNull()?.takeIf { it.isNotBlank() } ?: url
        val result = fetch(url, viaSocksPort) { ingest(it, id, target, geo) }
        val src = RuleSource(id, name, url, target, result.count, System.currentTimeMillis(), true, result.dropped)
        commit(src)
        return src
    }

    /** Downloads a link-based list again and replaces its rules. */
    fun refresh(id: String, viaSocksPort: Int?) {
        val src = _sources.value.firstOrNull { it.id == id } ?: return
        val url = src.url ?: return
        launchJob {
            val result = fetch(url, viaSocksPort) { ingest(it, id, src.target, GeoDat.isGeoFile(url)) }
            commit(src.copy(count = result.count, updatedAt = System.currentTimeMillis(), dropped = result.dropped))
            done(src.name, result.count)
        }
    }

    fun setEnabled(id: String, enabled: Boolean) {
        scope.launch {
            lock.withLock {
                _sources.value = _sources.value.map { if (it.id == id) it.copy(enabled = enabled) else it }
                writeIndex(_sources.value)
            }
        }
    }

    fun remove(id: String) {
        scope.launch {
            lock.withLock {
                File(dir, "$id.txt").delete()
                _sources.value = _sources.value.filterNot { it.id == id }
                writeIndex(_sources.value)
            }
        }
    }

    // ------------------------------------------------------------------ internals

    private class Ingested(val count: Int, val dropped: Int)

    private fun launchJob(block: suspend () -> Unit) {
        if (_status.value.busy) return // one import at a time keeps memory use flat
        _status.value = RuleStatus(busy = true, message = context.getString(R.string.rules_working))
        scope.launch {
            try {
                lock.withLock { block() }
            } catch (t: Throwable) {
                _status.value = RuleStatus(false, context.getString(R.string.rules_import_failed, describe(t)), true)
            }
        }
    }

    private fun done(name: String, count: Int) {
        _status.value = RuleStatus(false, context.getString(R.string.rules_import_done, name, count), false)
    }

    private fun fail(msg: String) { _status.value = RuleStatus(false, msg, true) }

    private fun describe(t: Throwable): String = (t.message ?: t::class.java.simpleName).take(120)

    /**
     * Reads the list line by line (never the whole text at once), cleans it and writes rules/<id>.txt through a
     * temp file, so a failed or interrupted import leaves the previous version of the list untouched.
     */
    private fun ingest(input: InputStream, id: String, target: RuleTarget, geo: Boolean): Ingested {
        val seen = LinkedHashSet<String>()
        var overflow = 0
        if (geo) {
            // v2ray geoip.dat / geosite.dat: a binary protobuf. Only the Iran entries are taken.
            val bytes = LimitedInputStream(input, MAX_GEO_BYTES).readBytes()
            for (r in GeoDat.extract(bytes, GeoDat.IRAN_CODES)) {
                if (seen.size < MAX_RULES_PER_SOURCE) seen.add(r) else overflow++
            }
            if (seen.isEmpty()) throw IOException(context.getString(R.string.rules_geo_none))
        } else {
            val limited = LimitedInputStream(input, MAX_BYTES)
            BufferedReader(InputStreamReader(limited, Charsets.UTF_8), 64 * 1024).use { r ->
                while (true) {
                    val line = r.readLine() ?: break
                    RuleParser.parse(line) { rule ->
                        if (seen.size < MAX_RULES_PER_SOURCE) seen.add(rule) else overflow++
                    }
                }
            }
            if (seen.isEmpty()) throw IOException(context.getString(R.string.rules_nothing_found))
        }
        val rules = RuleParser.collapse(seen)
        val tmp = File(dir, "$id.tmp")
        tmp.bufferedWriter().use { w -> rules.forEach { w.write(it); w.write("\n") } }
        val dest = File(dir, "$id.txt")
        if (!tmp.renameTo(dest)) { tmp.copyTo(dest, overwrite = true); tmp.delete() }
        return Ingested(rules.size, overflow)
    }

    private fun commit(src: RuleSource) {
        val list = _sources.value
        _sources.value = if (list.any { it.id == src.id }) list.map { if (it.id == src.id) src else it } else list + src
        writeIndex(_sources.value)
    }

    /** Opens [url] (through the tunnel's SOCKS port first when given) and hands the stream to [use]. */
    private fun <T> fetch(url: String, viaSocksPort: Int?, consume: (InputStream) -> T): T {
        var last: Throwable? = null
        val routes: List<Int?> = if (viaSocksPort != null) listOf(viaSocksPort, null) else listOf(null)
        for (port in routes) {
            try {
                return openUrl(url, port).let { conn ->
                    try { conn.inputStream.use { consume(it) } } finally { conn.disconnect() }
                }
            } catch (e: IOException) {
                last = e
            }
        }
        throw last ?: IOException("download failed")
    }

    private fun openUrl(url: String, socksPort: Int?): HttpURLConnection {
        val proxy = if (socksPort != null) Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort)) else Proxy.NO_PROXY
        val conn = URL(url).openConnection(proxy) as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "MadShield")
        val code = conn.responseCode
        if (code != HttpURLConnection.HTTP_OK) {
            conn.disconnect()
            throw IOException("HTTP $code")
        }
        val len = conn.contentLengthLong
        if (len > MAX_BYTES) {
            conn.disconnect()
            throw IOException(context.getString(R.string.rules_too_big))
        }
        return conn
    }

    private fun queryName(uri: Uri): String? = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()

    private fun readIndex(): List<RuleSource> {
        if (!indexFile.isFile) return emptyList()
        return runCatching {
            val arr = JSONArray(indexFile.readText())
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.getJSONObject(i)
                val id = o.getString("id")
                if (!File(dir, "$id.txt").isFile) null
                else RuleSource(
                    id = id,
                    name = o.optString("name", id),
                    url = o.optString("url", "").ifEmpty { null },
                    target = RuleTarget.valueOf(o.getString("target")),
                    count = o.optInt("count"),
                    updatedAt = o.optLong("updatedAt"),
                    enabled = o.optBoolean("enabled", true),
                    dropped = o.optInt("dropped")
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun writeIndex(list: List<RuleSource>) {
        val arr = JSONArray()
        list.forEach { s ->
            arr.put(JSONObject().apply {
                put("id", s.id); put("name", s.name); put("url", s.url ?: "")
                put("target", s.target.name); put("count", s.count); put("updatedAt", s.updatedAt)
                put("enabled", s.enabled); put("dropped", s.dropped)
            })
        }
        val tmp = File(dir, "sources.tmp")
        tmp.writeText(arr.toString())
        if (!tmp.renameTo(indexFile)) { tmp.copyTo(indexFile, overwrite = true); tmp.delete() }
    }
}

/** Stops reading after [left] bytes with an IOException, so a huge or endless response cannot fill memory. */
private class LimitedInputStream(private val inner: InputStream, private var left: Long) : InputStream() {
    override fun read(): Int {
        if (left <= 0) return endOrFail()
        val b = inner.read()
        if (b >= 0) left--
        return b
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (left <= 0) return endOrFail()
        val n = inner.read(b, off, minOf(len.toLong(), left).toInt())
        if (n > 0) left -= n
        return n
    }

    private fun endOrFail(): Int {
        if (inner.read() < 0) return -1
        throw IOException("file is larger than ${RuleLists.MAX_BYTES / (1024 * 1024)} MB")
    }

    override fun close() = inner.close()
}
