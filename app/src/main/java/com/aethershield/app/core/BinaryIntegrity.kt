package com.aethershield.app.core

import java.io.File
import java.security.MessageDigest

/**
 * What this checks, and what it does not.
 *
 * CI stamps the SHA-256 of every native file it packages into an asset (`native_hashes.properties`,
 * written by the "Stamp native hashes" step of build.yml). At the first engine start of a process the
 * files really installed on this phone are hashed and compared. A mismatch means the native file on
 * disk is not what CI built: corruption, a partial install, or a binary swapped after the build.
 *
 * It does NOT stop an attacker who can re-sign a modified APK (they can change this check and the
 * hash list too), and it does not make the upstream source trustworthy. The trust anchors are the
 * pinned upstream commits (the files in native/ ending in .pin) and the signing key. This is a tripwire for accidental or
 * partial tampering, nothing more.
 */
object BinaryIntegrity {

    /** The native files CI stamps. Order is only for stable output. */
    val COVERED_FILES = listOf("libaether.so", "libpsiphon.so", "libhev-socks5-tunnel.so", "libaethertun.so")

    data class Result(val ok: Boolean, val details: List<String>)

    /**
     * Compares the files in [nativeDir] with [expected] (file name -> sha256 hex).
     * An empty [expected] means "no hashes stamped" (a debug build) and passes.
     */
    fun verifyDir(nativeDir: File, expected: Map<String, String>): Result {
        if (expected.isEmpty()) return Result(true, listOf("no hashes stamped (debug build), skipped"))
        val details = mutableListOf<String>()
        var allOk = true
        for ((fileName, expectedHash) in expected.toSortedMap()) {
            val f = File(nativeDir, fileName)
            if (!f.isFile) {
                allOk = false
                details += "$fileName: MISSING"
                continue
            }
            val actual = sha256(f)
            if (actual.equals(expectedHash, ignoreCase = true)) {
                details += "$fileName: ok"
            } else {
                allOk = false
                details += "$fileName: MISMATCH"
            }
        }
        return Result(allOk, details)
    }

    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                digest.update(buf, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}

/**
 * Parsing of the stamped hash list. One line per file: `<abi>/<file name>=<sha256>`, `#` comments allowed.
 * Pure text handling so it can be tested without a device.
 */
object NativeHashes {

    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

    /** abi -> (file name -> sha256). Malformed lines are ignored, never guessed at. */
    fun parse(text: String): Map<String, Map<String, String>> {
        val out = linkedMapOf<String, MutableMap<String, String>>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            val key = line.substring(0, eq).trim()
            val hash = line.substring(eq + 1).trim()
            val slash = key.indexOf('/')
            if (slash <= 0 || slash == key.lastIndex) continue
            if (!HEX64.matches(hash)) continue
            val abi = key.substring(0, slash)
            val name = key.substring(slash + 1)
            if ('/' in name) continue
            out.getOrPut(abi) { linkedMapOf() }[name] = hash.lowercase()
        }
        return out
    }

    /**
     * The expected hashes for the ABI Android really installed: the first of the device's supported
     * ABIs (in preference order) that this build carries, which is how the package manager chooses.
     */
    fun forDevice(all: Map<String, Map<String, String>>, supportedAbis: List<String>): Map<String, String> {
        for (abi in supportedAbis) all[abi]?.let { return it }
        return emptyMap()
    }
}
