# راهنمای ساخت APK با GitHub Actions و Termux (از صفر)

همه چیز روی گوشی انجام می‌شود. ساخت روی سرور گیت‌هاب انجام می‌شود، نه روی گوشی.

## ۰. پیش‌نیاز
- یک حساب GitHub (رایگان) — اگر ندارید در مرورگر گوشی در github.com بسازید.
- Termux را از **F-Droid** نصب کنید (نسخهٔ Google Play قدیمی است و کار نمی‌کند).
- فایل `AetherShieldVPN-main.zip` را در پوشهٔ Download گوشی بگذارید.

## ۱. آماده‌سازی Termux
```
pkg update -y && pkg upgrade -y
pkg install -y git gh unzip
termux-setup-storage
```
پنجرهٔ اجازهٔ دسترسی به حافظه باز می‌شود، Allow بزنید.

## ۲. ورود به گیت‌هاب
```
gh auth login
```
به ترتیب انتخاب کنید: `GitHub.com` ← `HTTPS` ← `Y` (برای git credentials) ← `Login with a web browser`.
یک کد ۸ حرفی نشان می‌دهد. آن را کپی کنید، در مرورگر `github.com/login/device` را باز کنید، کد را بزنید و تأیید کنید.

نام و ایمیل برای commit:
```
git config --global user.name "اسم شما"
git config --global user.email "ایمیل گیت‌هاب شما"
```

## ۳. باز کردن پروژه
```
cd ~
unzip ~/storage/downloads/AetherShieldVPN-main.zip
cd AetherShieldVPN-main
```
اگر بعد از unzip پوشهٔ داخلی دیگری هم ساخته شد، با `ls` ببینید و وارد پوشه‌ای شوید که `app` و `.github` در آن است.

## ۴. ساخت مخزن و آپلود
```
git init -b main
git add .
git commit -m "first commit"
gh repo create aethershield --private --source=. --remote=origin --push
```
- `--private` یعنی مخزن خصوصی. ساخت در مخزن خصوصی از دقایق رایگان ماهانهٔ Actions کم می‌کند. اگر تمام شد، می‌توانید مخزن را public کنید (ولی کد و APK برای همه دیده می‌شود).
- هیچ ساب‌ماژولی لازم نیست؛ ورکفلو موتورها را خودش با commit ثابت دانلود می‌کند.

## ۵. شروع و پیگیری ساخت
Push خودش ساخت را شروع می‌کند. برای دیدن:
```
gh run list --limit 3
gh run watch
```
(اگر `gh run watch` پرسید کدام اجرا، همان اجرای در حال کار را انتخاب کنید.)
بار اول Rust دو بار (arm64 و armv7) کامپایل می‌شود، حدوداً ۲۰ تا ۴۰ دقیقه (تخمین). بعدی‌ها با cache سریع‌ترند.

اگر بخواهید دوباره دستی اجرا کنید:
```
gh workflow run "Build AetherShield APK"
```

## ۶. اگر خطا داد
```
gh run view --log-failed | tail -n 80
```
آخرین ۸۰ خط را برای من بفرستید تا درست کنم. کد اندروید روی سرور من کامپایل نشده بود، پس احتمال خطای کامپایل در اولین ساخت هست و عادی است.

بعد از اصلاح فایل‌ها:
```
git add . && git commit -m "fix" && git push
```

## ۷. دانلود و نصب APK
بعد از موفق شدن، در مخزن یک Release ساخته می‌شود:
```
gh release list
gh release download --pattern "*.apk" --dir ~/storage/downloads
```
فایل در Download گوشی است. روی آن بزنید و در صورت پرسش «نصب از منابع ناشناس» را برای مدیر فایل مجاز کنید.

## ۸. امضا (اختیاری)
بدون کلید امضا، APK با کلید debug امضا می‌شود و نصب می‌شود. اگر بعداً کلید ثابت اضافه کنید، باید یک بار نسخهٔ قبلی را پاک کنید.
برای کلید ثابت:
```
pkg install -y openjdk-17 openssl
keytool -genkeypair -v -keystore release.keystore -alias aether -keyalg RSA -keysize 2048 -validity 10000
gh secret set SIGNING_KEY_BASE64 < <(base64 -w0 release.keystore)
gh secret set KEYSTORE_PASSWORD
gh secret set KEY_ALIAS
gh secret set KEY_PASSWORD
```
فایل `release.keystore` را جای امن نگه دارید و هرگز آپلودش نکنید (در `.gitignore` هست).
