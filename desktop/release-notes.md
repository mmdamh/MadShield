## مدشیلد برای ویندوز (نسخه‌ی آزمایشی)

نسخه‌ی دسکتاپ مدشیلد با همه‌ی موتورها: **WARP (Aether)** با Tor و Psiphon، **لینک شخصی** (sing-box) و **Foxy**. کل ترافیک سیستم از یک تونل (wintun) می‌گذرد. فقط HTTP/2 (h3 در دسکتاپ نیست).

### نصب و اجرا
1. فایل `MadShield-desktop-windows-x64.zip` را در یک پوشه Extract کنید (Windows 10/11، 64 بیتی).
2. `MadShield.exe` را اجرا کنید و پنجره‌ی UAC را تأیید کنید (ساخت تونل به دسترسی Administrator نیاز دارد).
3. دکمه‌ی «اتصال» را بزنید.

برای حذف: پوشه را پاک کنید و `%LOCALAPPDATA%\MadShield` را هم حذف کنید. اگر برنامه ناگهانی بسته شد، پروسه‌های موتور خودکار بسته می‌شوند و تونل برداشته می‌شود.

### چه چیزی تست شده
- روی ماشین Windows در CI (حالت Administrator): اتصال WARP با HTTP/2 از طریق تونل، تغییر IP عمومی سیستم به آدرس WARP، قطع اتصال و برگشت شبکه، و نبودن پروسه‌ی باقی‌مانده. این تست روی خود برنامه‌ی بسته‌بندی‌شده هم اجرا شد.

### چه چیزی هنوز تست نشده (صادقانه)
- روی یک کامپیوتر واقعی با کاربر واقعی اجرا نشده.
- Psiphon، Tor و Foxy روی ویندوز اجرا نشده‌اند؛ ورود به Foxy (پنجره‌ی مرورگر داخلی) با صفحه‌ی واقعی Mozilla تست نشده.
- IPv6 تأیید نشده.
- برنامه امضای دیجیتال ندارد؛ ممکن است SmartScreen یا آنتی‌ویروس هشدار بدهد.
- محدوده‌ی 100.64.0.0/10 برای DNS نگاشت‌شده استفاده می‌شود و با Tailscale یا شبکه‌های CGNAT ممکن است تداخل کند.

اگر مشکلی دیدید لاگ برنامه (صفحه‌ی لاگ، بدون اطلاعات حساس) را بفرستید.

SHA-256: `{{SHA256}}`

---

## MadShield for Windows (beta)

The desktop version of MadShield with every engine: **WARP (Aether)** with Tor and Psiphon, **personal link** (sing-box) and **Foxy**. All system traffic goes through one tunnel (wintun). HTTP/2 only (no h3 on desktop).

**Run:** extract the zip, start `MadShield.exe`, accept the UAC prompt (the tunnel needs administrator rights), press Connect. **Remove:** delete the folder and `%LOCALAPPDATA%\MadShield`.

**Tested (CI Windows runner, administrator):** WARP over HTTP/2 through the tunnel, the system's public address changes to a WARP address, disconnect restores the network, no engine process left behind; also run on the packaged program itself.

**Not tested:** a real PC with a real user; Psiphon, Tor and Foxy on Windows (including the Foxy sign-in window against the live page); IPv6. The program is unsigned (SmartScreen or antivirus may warn). The 100.64.0.0/10 range is used for mapped DNS and can clash with Tailscale or CGNAT networks.
