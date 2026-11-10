# MadShield Desktop، فاز ۰ (تست TUN روی ویندوز)

هدف: ثابت کنیم sing-box با TUN کل سیستم را از Aether (WARP) رد می‌کند، **بدون حلقهٔ ترافیک و بدون نشت DNS**.

## اجرا روی PC
1. فایل `madshield-desktop-phase0.zip` را از Artifacts همین workflow بگیرید و Extract کنید (مثلاً `C:\madshield-p0`).
2. PowerShell را **Run as administrator** باز کنید:
   ```
   cd C:\madshield-p0
   powershell -ExecutionPolicy Bypass -File .\phase0\run-test.ps1
   ```
   حدود یک دقیقه اینترنت PC از تونل رد می‌شود و آخر کار همه‌چیز بسته می‌شود.
3. حالت‌های دیگر: `-Carrier h3`، `-NoStrict`، `-CheckOnly` (فقط بررسی config).
4. اگر وسط کار قطع شد و اینترنت برنگشت: `.\phase0\run-test.ps1 -Cleanup`

## خروجی
هر بررسی PASS / FAIL / INFO می‌دهد و خلاصه در `%TEMP%\madshield-phase0\result.md` است. لاگ‌ها (`singbox.err.log`، `aether.err.log`) کنار آن است. اگر FAIL بود، همین پوشه را بفرستید.

## معیار Go / No-go
- تونل Aether بالا بیاید (`warp=on` از SOCKS)
- برنامه‌ای که از تونل خبر ندارد از WARP خارج شود (بدون proxy)
- DNS سیستم جواب بدهد و صفحه باز شود
- CPU آرام sing-box و aether بالا نرود (نشانهٔ نبودن loop)
- هر دو پروسه تا آخر زنده بمانند
