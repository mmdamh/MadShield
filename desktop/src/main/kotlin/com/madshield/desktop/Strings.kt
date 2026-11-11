package com.madshield.desktop

import androidx.compose.runtime.compositionLocalOf

val LocalLang = compositionLocalOf { "fa" }

/** English and Persian texts of the desktop app. A missing Persian text falls back to English, never to a blank. */
object Strings {
    private val en = mapOf(
        "app" to "MadShield",
        "nav.home" to "Home", "nav.engine" to "Engine", "nav.foxy" to "Foxy", "nav.rules" to "Routing",
        "nav.conns" to "Connections", "nav.logs" to "Logs", "nav.settings" to "Settings",
        "home.connect" to "Connect", "home.disconnect" to "Disconnect", "home.cancel" to "Cancel",
        "home.idle" to "Not connected", "home.connected" to "Connected", "home.stopping" to "Disconnecting…",
        "home.connecting" to "Connecting…", "home.waiting" to "Retrying in %s s", "home.failed" to "Cannot connect",
        "home.exit" to "Exit", "home.since" to "Connected for %s",
        "home.engine.warp" to "WARP (Aether)", "home.engine.fx" to "Foxy",
        "step.check" to "Checking", "step.front" to "Starting the router", "step.tun" to "Creating the tunnel",
        "step.engine" to "Starting the engine", "step.wait" to "Waiting for the tunnel",
        "home.vpn" to "Through the tunnel", "home.direct" to "Direct", "home.blocked" to "Blocked requests",
        "home.admin" to "MadShield needs administrator rights to create the tunnel.",
        "engine.title" to "Engine", "engine.kind" to "Engine", "engine.protocol" to "Protocol", "engine.chain" to "Chain on top",
        "engine.chain.none" to "None", "engine.chain.psiphon" to "Psiphon", "engine.chain.tor" to "Tor", "engine.chain.link" to "Personal link",
        "engine.region" to "Psiphon exit country", "engine.region.auto" to "Automatic",
        "engine.link" to "Personal link (vless:// vmess:// trojan:// ss://)", "engine.link.hint" to "The link is stored encrypted for your Windows user only.",
        "engine.scan" to "Gateway scan", "engine.noize" to "Noize profile",
        "engine.applies" to "Changes apply at the next connection.",
        "proto.MASQUE_H2" to "MASQUE over HTTP/2 (recommended)", "proto.SMART" to "Smart", "proto.WIREGUARD" to "WireGuard", "proto.GOOL" to "Gool (warp-in-warp)",
        "foxy.title" to "Foxy (Mozilla VPN)", "foxy.account" to "Firefox Account", "foxy.none" to "No account yet.",
        "foxy.signin" to "Sign in with a browser", "foxy.remove" to "Remove account", "foxy.refresh" to "Refresh",
        "foxy.location" to "Location", "foxy.recommended" to "Recommended", "foxy.ports" to "Ports Mozilla does not carry",
        "foxy.ports.block" to "Block", "foxy.ports.direct" to "Send direct",
        "foxy.quota" to "Data used", "foxy.loading" to "Starting the Foxy core…", "foxy.error" to "Foxy problem",
        "foxy.web.title" to "Sign in to your Firefox Account", "foxy.web.close" to "Close", "foxy.web.working" to "Finishing the sign-in…",
        "foxy.web.confirm" to "Confirm the sign-in in your e-mail…", "foxy.web.done" to "Signed in.",
        "foxy.connected.note" to "A Foxy connection is running: the account is read from it.",
        "rules.title" to "Routing rules", "rules.direct" to "Direct (these go outside the tunnel)", "rules.block" to "Block",
        "rules.hint" to "One rule per line: example.com, full:host.example.com, keyword:ads, 10.0.0.0/8, port:25. Applies at the next connection.",
        "conns.title" to "Connections", "conns.none" to "No connection is open.", "conns.closeAll" to "Close all",
        "conns.route.PROXY" to "Tunnel", "conns.route.DIRECT" to "Direct", "conns.route.BLOCK" to "Blocked",
        "logs.title" to "Log (memory only)", "logs.copy" to "Copy", "logs.clear" to "Clear",
        "set.title" to "Settings", "set.language" to "Language", "set.connectOnStart" to "Connect when MadShield starts",
        "set.folder" to "Open the data folder", "set.about" to "MadShield for Windows. GPL-3.0. Engines: Aether (AGPL-3.0), sing-box, Psiphon, Foxy core.",
        "set.licenses" to "Open the licenses folder",
        "err.generic" to "Something went wrong"
    )

    private val fa = mapOf(
        "app" to "مدشیلد",
        "nav.home" to "خانه", "nav.engine" to "موتور", "nav.foxy" to "Foxy", "nav.rules" to "مسیریابی",
        "nav.conns" to "اتصال‌ها", "nav.logs" to "لاگ", "nav.settings" to "تنظیمات",
        "home.connect" to "اتصال", "home.disconnect" to "قطع", "home.cancel" to "لغو",
        "home.idle" to "متصل نیست", "home.connected" to "متصل", "home.stopping" to "در حال قطع…",
        "home.connecting" to "در حال اتصال…", "home.waiting" to "تلاش دوباره تا %s ثانیه", "home.failed" to "اتصال ممکن نشد",
        "home.exit" to "خروجی", "home.since" to "مدت اتصال %s",
        "home.engine.warp" to "WARP (Aether)", "home.engine.fx" to "Foxy",
        "step.check" to "بررسی", "step.front" to "راه‌اندازی مسیریاب", "step.tun" to "ساخت تونل",
        "step.engine" to "راه‌اندازی موتور", "step.wait" to "منتظر برقراری تونل",
        "home.vpn" to "از تونل", "home.direct" to "مستقیم", "home.blocked" to "درخواست‌های بلاک‌شده",
        "home.admin" to "برای ساخت تونل، مدشیلد باید با دسترسی Administrator اجرا شود.",
        "engine.title" to "موتور", "engine.kind" to "موتور", "engine.protocol" to "پروتکل", "engine.chain" to "زنجیره روی WARP",
        "engine.chain.none" to "هیچ", "engine.chain.psiphon" to "Psiphon", "engine.chain.tor" to "Tor", "engine.chain.link" to "لینک شخصی",
        "engine.region" to "کشور خروجی Psiphon", "engine.region.auto" to "خودکار",
        "engine.link" to "لینک شخصی (vless:// vmess:// trojan:// ss://)", "engine.link.hint" to "لینک فقط برای کاربر ویندوز شما و رمزشده ذخیره می‌شود.",
        "engine.scan" to "اسکن گیت‌وی", "engine.noize" to "پروفایل noize",
        "engine.applies" to "تغییرها در اتصال بعدی اعمال می‌شوند.",
        "proto.MASQUE_H2" to "MASQUE روی HTTP/2 (پیشنهادی)", "proto.SMART" to "هوشمند", "proto.WIREGUARD" to "WireGuard", "proto.GOOL" to "Gool (warp-in-warp)",
        "foxy.title" to "Foxy (Mozilla VPN)", "foxy.account" to "حساب Firefox", "foxy.none" to "هنوز حسابی نیست.",
        "foxy.signin" to "ورود با مرورگر", "foxy.remove" to "حذف حساب", "foxy.refresh" to "تازه‌سازی",
        "foxy.location" to "لوکیشن", "foxy.recommended" to "پیشنهادی", "foxy.ports" to "پورت‌هایی که Mozilla نمی‌گذراند",
        "foxy.ports.block" to "بلاک", "foxy.ports.direct" to "مستقیم",
        "foxy.quota" to "حجم مصرف‌شده", "foxy.loading" to "در حال راه‌اندازی هستهٔ Foxy…", "foxy.error" to "مشکل Foxy",
        "foxy.web.title" to "ورود به حساب Firefox", "foxy.web.close" to "بستن", "foxy.web.working" to "در حال تکمیل ورود…",
        "foxy.web.confirm" to "ورود را در ایمیل خود تأیید کنید…", "foxy.web.done" to "وارد شدید.",
        "foxy.connected.note" to "اتصال Foxy فعال است؛ حساب از همان خوانده می‌شود.",
        "rules.title" to "قوانین مسیریابی", "rules.direct" to "مستقیم (خارج از تونل)", "rules.block" to "بلاک",
        "rules.hint" to "هر خط یک قانون: example.com ، full:host.example.com ، keyword:ads ، 10.0.0.0/8 ، port:25. در اتصال بعدی اعمال می‌شود.",
        "conns.title" to "اتصال‌ها", "conns.none" to "اتصالی باز نیست.", "conns.closeAll" to "بستن همه",
        "conns.route.PROXY" to "تونل", "conns.route.DIRECT" to "مستقیم", "conns.route.BLOCK" to "بلاک",
        "logs.title" to "لاگ (فقط در حافظه)", "logs.copy" to "کپی", "logs.clear" to "پاک کردن",
        "set.title" to "تنظیمات", "set.language" to "زبان", "set.connectOnStart" to "اتصال خودکار هنگام باز شدن برنامه",
        "set.folder" to "باز کردن پوشهٔ داده", "set.about" to "مدشیلد برای ویندوز. GPL-3.0. موتورها: Aether (AGPL-3.0)، sing-box، Psiphon، هستهٔ Foxy.",
        "set.licenses" to "باز کردن پوشهٔ لایسنس‌ها",
        "err.generic" to "مشکلی پیش آمد"
    )

    fun get(lang: String, key: String): String = (if (lang == "fa") fa[key] else null) ?: en[key] ?: key
}
