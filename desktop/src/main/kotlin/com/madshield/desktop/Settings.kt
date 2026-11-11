package com.madshield.desktop

import com.madshield.app.core.EngineKind
import com.madshield.app.core.FxPortPolicy
import com.madshield.app.core.MiniJson
import com.madshield.app.core.PrivacyChain
import com.madshield.app.core.Protocol
import java.io.File

/** What the user chose. The personal link is a secret: it is kept only in memory and, when DPAPI works, encrypted on disk. */
data class DesktopSettings(
    val language: String = "fa",
    val engine: EngineKind = EngineKind.WARP,
    val protocol: Protocol = Protocol.MASQUE_H2,
    val chain: PrivacyChain = PrivacyChain.NONE,
    val psiphonRegion: String? = null,
    val link: String = "",
    val scanMode: String = "turbo",
    val noizeProfile: String = "balanced",
    val directRules: String = "",
    val blockRules: String = "",
    val fxLocation: String = "",
    val fxPortPolicy: FxPortPolicy = FxPortPolicy.BLOCK,
    val connectOnStart: Boolean = false
) {
    /** The protocols the desktop version offers: HTTP/3 is not among them (owner decision, 10 Nov 2026). */
    companion object {
        val PROTOCOLS = listOf(Protocol.MASQUE_H2, Protocol.SMART, Protocol.WIREGUARD, Protocol.GOOL)
    }
}

object SettingsStore {
    private val file = File(DataDir.root, "settings.json")

    fun load(): DesktopSettings {
        val j = try { MiniJson.parseObject(file.readText(Charsets.UTF_8)) } catch (_: Exception) { null } ?: return DesktopSettings()
        fun s(k: String, d: String) = (j[k] as? String) ?: d
        val protocol = Protocol.fromStored(j["protocol"] as? String).let { if (it in DesktopSettings.PROTOCOLS) it else Protocol.MASQUE_H2 }
        val link = (j["linkEnc"] as? String)?.let { Secrets.unprotect(it) } ?: ""
        return DesktopSettings(
            language = s("language", "fa").let { if (it == "en") "en" else "fa" },
            engine = EngineKind.fromStored(j["engine"] as? String),
            protocol = protocol,
            chain = PrivacyChain.fromStored(j["chain"] as? String),
            psiphonRegion = (j["psiphonRegion"] as? String)?.takeIf { it.isNotBlank() },
            link = link,
            scanMode = s("scanMode", "turbo"),
            noizeProfile = s("noizeProfile", "balanced"),
            directRules = s("directRules", ""),
            blockRules = s("blockRules", ""),
            fxLocation = s("fxLocation", ""),
            fxPortPolicy = FxPortPolicy.fromStored(j["fxPortPolicy"] as? String),
            connectOnStart = (j["connectOnStart"] as? Boolean) ?: false
        )
    }

    fun save(s: DesktopSettings) {
        val enc = if (s.link.isEmpty()) "" else Secrets.protect(s.link) // null = DPAPI failed: the link is not written
        val map = linkedMapOf<String, Any?>(
            "language" to s.language, "engine" to s.engine.stored, "protocol" to s.protocol.name, "chain" to s.chain.name,
            "psiphonRegion" to (s.psiphonRegion ?: ""), "scanMode" to s.scanMode, "noizeProfile" to s.noizeProfile,
            "directRules" to s.directRules, "blockRules" to s.blockRules, "fxLocation" to s.fxLocation,
            "fxPortPolicy" to s.fxPortPolicy.stored, "connectOnStart" to s.connectOnStart
        )
        if (enc != null) map["linkEnc"] = enc
        try {
            val tmp = File(DataDir.root, "settings.tmp")
            tmp.writeText(MiniJson.write(map), Charsets.UTF_8)
            if (!tmp.renameTo(file)) { tmp.copyTo(file, overwrite = true); tmp.delete() }
        } catch (_: Exception) { /* not saved: the next start uses the defaults */ }
    }
}
