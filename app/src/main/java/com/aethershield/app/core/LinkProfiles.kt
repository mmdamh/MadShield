package com.aethershield.app.core

/**
 * The saved share links of the custom chain (the "Link" profile), update17.
 *
 * Before: one link, stored under `chain_link`. Now: a small list of named links plus the one that is ACTIVE.
 * The engine still reads ONE link (`SettingsStore.chainLinkFor`); [SettingsStore.saveLinkBook] copies the active link
 * into `chain_link` in the same commit, so nothing in the services, the preflight or the sing-box config changed:
 * switching a profile just changes which link `chain_link` holds, and it takes effect on the next connect like every
 * other profile change.
 *
 * Pure Kotlin (no Android types) so every rule here is covered by tests/pure. A link is secret material (UUID or
 * password): nothing here logs it, and the UI only ever shows [LinkProfile.name] and the credential-free summary.
 */
data class LinkProfile(val id: String, val name: String, val link: String)

data class LinkProfileBook(val profiles: List<LinkProfile> = emptyList(), val activeId: String? = null) {
    /** The active profile, or null when none is chosen (or the chosen id no longer exists). */
    val active: LinkProfile? get() = profiles.firstOrNull { it.id == activeId }
}

sealed interface LinkAdd {
    data class Added(val book: LinkProfileBook, val profile: LinkProfile) : LinkAdd
    /** The same link is already saved: nothing was added; [existing] is the one that has it. */
    data class Duplicate(val existing: LinkProfile) : LinkAdd
    object Full : LinkAdd
    data class Invalid(val error: LinkParse.Err) : LinkAdd
}

object LinkProfiles {
    const val MAX_PROFILES = 30
    const val MAX_NAME = 40
    /** Id given to a link that was saved by update16 (single link) and is migrated into the list. */
    const val LEGACY_ID = "legacy"

    fun cleanName(raw: String): String =
        raw.replace(Regex("[\\r\\n\\t]+"), " ").trim().take(MAX_NAME).trim()

    /** "My server" from the link's #name, or "VLESS · host" when the link has none. Never contains the credential. */
    fun defaultName(p: LinkParse.Ok): String {
        val fromLink = cleanName(p.name)
        if (fromLink.isNotEmpty()) return fromLink
        return cleanName("${p.protocol.uppercase()} · ${p.server}")
    }

    /**
     * Adds [rawLink]. [name] blank = take the link's own name. A profile added while NOTHING is active (the very first one, or
     * after the active one was removed) becomes active by itself; otherwise a new one never takes over silently: switching is always the user's tap.
     */
    fun add(
        book: LinkProfileBook,
        rawLink: String,
        name: String = "",
        makeId: () -> String = { java.util.UUID.randomUUID().toString().take(8) }
    ): LinkAdd {
        val link = rawLink.trim()
        val parsed = ProxyLink.parse(link)
        if (parsed is LinkParse.Err) return LinkAdd.Invalid(parsed)
        parsed as LinkParse.Ok
        book.profiles.firstOrNull { it.link == link }?.let { return LinkAdd.Duplicate(it) }
        if (book.profiles.size >= MAX_PROFILES) return LinkAdd.Full
        var id = makeId()
        while (book.profiles.any { it.id == id }) id = makeId()
        val profile = LinkProfile(id, cleanName(name).ifEmpty { defaultName(parsed) }, link)
        val next = book.profiles + profile
        return LinkAdd.Added(LinkProfileBook(next, book.activeId?.takeIf { a -> next.any { it.id == a } } ?: id), profile)
    }

    fun rename(book: LinkProfileBook, id: String, name: String): LinkProfileBook {
        val clean = cleanName(name)
        if (clean.isEmpty()) return book
        return book.copy(profiles = book.profiles.map { if (it.id == id) it.copy(name = clean) else it })
    }

    fun activate(book: LinkProfileBook, id: String): LinkProfileBook =
        if (book.profiles.any { it.id == id }) book.copy(activeId = id) else book

    /**
     * Removes one profile. If it was the active one, NOTHING takes its place: silently moving traffic to a different
     * server is not something a privacy tool should do, so the chain simply has no link until the user picks one.
     */
    fun remove(book: LinkProfileBook, id: String): LinkProfileBook {
        val rest = book.profiles.filter { it.id != id }
        return LinkProfileBook(rest, if (book.activeId == id) null else book.activeId)
    }

    /** A book that is empty but has an old single link (update16) becomes a one-item book with that link active. */
    fun migrate(book: LinkProfileBook, legacyLink: String?): LinkProfileBook {
        val link = legacyLink?.trim().orEmpty()
        if (book.profiles.isNotEmpty() || link.isEmpty()) return book
        val parsed = ProxyLink.parse(link) as? LinkParse.Ok
        val name = parsed?.let { defaultName(it) } ?: "Link"
        return LinkProfileBook(listOf(LinkProfile(LEGACY_ID, name, link)), LEGACY_ID)
    }

    // ------------------------------------------------------------------------------------------------ storage text

    fun encode(book: LinkProfileBook): String {
        val root = linkedMapOf<String, Any?>(
            "v" to 1,
            "active" to book.activeId,
            "items" to book.profiles.map { linkedMapOf<String, Any?>("id" to it.id, "name" to it.name, "link" to it.link) }
        )
        return MiniJson.write(root)
    }

    /** Never throws: damaged or missing text gives an empty book (the old single link, if any, is migrated by the caller). */
    fun decode(text: String?): LinkProfileBook {
        if (text.isNullOrBlank()) return LinkProfileBook()
        val root = MiniJson.parseObject(text) ?: return LinkProfileBook()
        val items = (root["items"] as? List<*>).orEmpty().mapNotNull { raw ->
            val m = raw as? Map<*, *> ?: return@mapNotNull null
            val id = (m["id"] as? String)?.trim().orEmpty()
            val link = (m["link"] as? String)?.trim().orEmpty()
            if (id.isEmpty() || link.isEmpty()) return@mapNotNull null
            LinkProfile(id, cleanName((m["name"] as? String).orEmpty()).ifEmpty { "Link" }, link)
        }.distinctBy { it.id }.take(MAX_PROFILES)
        val active = (root["active"] as? String)?.takeIf { a -> items.any { it.id == a } }
        return LinkProfileBook(items, active)
    }

}
