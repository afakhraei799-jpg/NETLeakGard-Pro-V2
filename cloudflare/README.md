# راهنمای استقرار رایگان Cloudflare و معماری تشخیص واقعی نشت DNS

این پوشه حاوی فایل‌های لازم برای اجرای بدون هزینهٔ **NETLeakGuard Pro V2** بر پایهٔ **Cloudflare Workers + KV + Static Assets** و راهنمای دقیق بخش **Authoritative DNS** است.

---

## ۱. واقعیت فنی: چرا Cloudflare Workers به‌تنهایی نمی‌تواند پورت UDP/53 را شنود کند؟

برای اینکه یک تست **Authoritative DNS Leak** از نظر علمی و امنیتی معتبر باشد:
1. مرورگر کاربر باید زیردامنه‌های یکتا با الگوی `<probe>.<runId>.<DNS_LEAK_DOMAIN>` را استعلام کند.
2. سیستم‌عامل یا مرورگر این درخواست را به **Recursive DNS Resolver** تنظیم‌شده روی سیستم (مثلاً DNS شرکت اینترنت یا DNS داخل تونل VPN) می‌فرستد.
3. آن Recursive Resolver رکورد `NS` دامنهٔ `<DNS_LEAK_DOMAIN>` را پیدا کرده و یک بستهٔ **UDP/TCP روی پورت 53** مستقیماً به سرور Authoritative DNS ارسال می‌کند.
4. سرور Authoritative DNS باید **آدرس IP مبدأ بستهٔ UDP/53** (که همان IP واقعی Recursive Resolver است) را ثبت کند.

### محدودیت ذاتی Cloudflare Workers در لایهٔ پورت 53:
- **Cloudflare Workers و Cloudflare Pages فقط ترافیک HTTP/HTTPS (پورت‌های 80 و 443) را دریافت می‌کنند** و امکان باز کردن سوکت شنونده روی پورت **UDP/53** به عنوان Authoritative Name Server را ندارند.
- در درخواست‌های HTTP که به Cloudflare Worker می‌رسند، هدر `CF-Connecting-IP` نشان‌دهندهٔ **آدرس IP مرورگر کاربر در لایهٔ HTTP** است، **نه آدرس IP سرور DNS Resolver**! ثبت کردن `CF-Connecting-IP` به‌جای Resolver یک خطای علمی فاحش است و در این پروژه به‌طور کامل ممنوع شده است.
- همچنین در سرویس DNS رایگان کلادفلر، دسترسی به لاگ لحظه‌ای درخواست‌های DNS (ویژگی DNS Logpush) صرفاً مخصوص پلن سازمانی (**Enterprise**) است.

---

## ۲. معماری ترکیبی با هزینهٔ صفر (Zero-Cost Architecture)

| جزء | نقش در معماری | سرویس رایگان مورد استفاده |
|---|---|---|
| **فرانت‌اند + Edge API** (`/cloudflare/worker.ts`) | میزبانی رابط کاربری React، سرویس `/api/ip-info`، `/api/ping`، `/api/speed-test/chunk` و API دریافت و خوانش لاگ‌های DNS | **Cloudflare Workers & Static Assets** (پلن رایگان: ۱۰۰,۰۰۰ درخواست در روز) |
| **مخزن موقت لاگ‌های نشست DNS** (`DNS_LOGS_KV`) | ذخیرهٔ موقت Resolverهای مشاهده‌شده به ازای هر `runId` با انقضای خودکار ۳۰۰ ثانیه (`expirationTtl: 300`) | **Cloudflare Workers KV** (پلن رایگان: ۱۰۰,۰۰۰ خوانش و ۱,۰۰۰ نوشتن در روز) |
| **شنوندهٔ بستهٔ UDP/53** (`/cloudflare/authoritative-dns-udp53.mjs`) | دریافت کوئری‌های واقعی پورت `UDP/53` برای `*.<runId>.<DNS_LEAK_DOMAIN>`، استخراج IP واقعی Recursive Resolver و ارسال امن آن به `/api/dns-collector/ingest` در Worker | اسکریپت بدون وابستگی Node.js قابل اجرا روی هر میکروماشین رایگان دارای پورت UDP/53 باز (مانند Oracle Cloud Free Tier یا GCP Free Tier e2-micro) |

> **نکتهٔ بسیار مهم (حفظ وضعیت «پیکربندی نشده» پیش از تأیید نهایی):**  
> تا زمانی که شنوندهٔ UDP/53 را راه‌اندازی نکرده و متغیر `DNS_UDP53_VERIFIED` را برابر `"true"` قرار نداده‌اید، برنامه در حالت ایمن پیش‌فرض باقی می‌ماند و وضعیت تست Authoritative DNS را صراحتاً **«پیکربندی نشده» (`NOT_CONFIGURED`)** نمایش می‌دهد و هیچ نتیجهٔ «امن» یا «بدون نشت» کاذبی تولید نمی‌کند.

---

## ۳. مراحل گام‌به‌گام استقرار در Cloudflare (بدون تغییر در DNS دامنهٔ اصلی)

### گام ۱: ساخت باندل فرانت‌اند
در ریشهٔ پروژه دستور زیر را اجرا کنید تا پوشهٔ `dist` ساخته شود:
```bash
npm run build
```

### گام ۲: ورود به حساب رایگان Cloudflare با Wrangler
```bash
npx wrangler login
```

### گام ۳: ایجاد فضای ذخیره‌سازی رایگان KV (اختیاری در مرحلهٔ اول)
اگر قصد فعال‌سازی کلکتور را دارید، یک فضای KV بسازید:
```bash
npx wrangler kv namespace create DNS_LOGS_KV
```
سپس شناسهٔ `id` خروجی را در فایل `cloudflare/wrangler.toml` در بخش `[[kv_namespaces]]` جایگزین کنید.

### گام ۴: ثبت توکن محرمانه در Cloudflare Secrets (هرگز در کد یا گیت قرار ندهید)
یک توکن تصادفی قوی تولید کرده و با دستور زیر مستقیماً در بخش رمزنگاری‌شدهٔ Cloudflare ثبت کنید:
```bash
npx wrangler secret put DNS_COLLECTOR_API_TOKEN --config cloudflare/wrangler.toml
```
*(در صورت نیاز به کلید تحلیل هوش مصنوعی Gemini یا AbuseIPDB نیز می‌توانید از `npx wrangler secret put GEMINI_API_KEY --config cloudflare/wrangler.toml` استفاده کنید).*

### گام ۵: استقرار روی زیردامنهٔ رایگان `*.workers.dev` (بدون دست زدن به DNS دامنهٔ اصلی)
```bash
npx wrangler deploy --config cloudflare/wrangler.toml
```
پس از اجرای این دستور، برنامه روی آدرس رایگان `https://netleakguard-pro-v2.<your-subdomain>.workers.dev` بالا می‌آید و وضعیت تست Authoritative DNS به درستی **«پیکربندی نشده»** خواهد بود.

---

## ۴. نحوهٔ فعال‌سازی اختیاری شنوندهٔ UDP/53 (فقط در صورت تمایل و پس از تأیید شما)

1. اسکریپت `cloudflare/authoritative-dns-udp53.mjs` را روی محیطی که پورت `UDP/53` ورودی باز دارد اجرا کنید:
   ```bash
   DNS_LEAK_DOMAIN="leak.yourdomain.com" \
   WORKER_INGEST_URL="https://netleakguard-pro-v2.<your-subdomain>.workers.dev/api/dns-collector/ingest" \
   DNS_COLLECTOR_API_TOKEN="<YOUR_SECRET_TOKEN>" \
   node cloudflare/authoritative-dns-udp53.mjs
   ```
2. فقط برای یک زیردامنهٔ فرعی ایزوله (مثلاً `leak.yourdomain.com`) رکورد `NS` تعریف کنید که به IP شنوندهٔ UDP/53 اشاره کند (هیچ تغییری در رکوردهای اصلی دامنهٔ ریشه ندهید).
3. پس از اطمینان از دریافت لاگ واقعی با همان `runId`، در فایل `cloudflare/wrangler.toml` مقدار `DNS_LEAK_DOMAIN` را تنظیم کرده و `DNS_UDP53_VERIFIED = "true"` قرار دهید و مجدداً `npx wrangler deploy --config cloudflare/wrangler.toml` را اجرا کنید.
