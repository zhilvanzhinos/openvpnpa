# شواهد نسخه آزمایشی پنل و نود

| بررسی | نتیجه و مرز اعتبار |
|---|---|
| تصویر runtime و آزمایشگاه Ubuntu 24.04، amd64 | ساخته شدند؛ تصویر پایه با digest ثابت |
| اجرای نهایی آزمایشگاه Docker | ۴۷ تست؛ ۴۷ پاس، صفر fail، صفر skip |
| رابط مدیریت HTTPS واقعی | احراز هویت، CSRF، ایجاد کاربر در API شبیه‌سازی‌شده، انتخاب پایدار گروه و دانلود پروفایل تأیید شد |
| پروفایل و PKI | گواهی کلاینت با CA و purpose=sslclient اعتبارسنجی شد؛ کلید و CA در volume باقی می‌مانند |
| اجرای `--init` در تصویر runtime و تکرار آن | موفق؛ گواهی CA موجود تغییر نکرد |
| REST با SDK رسمی | TLS، Start، آمار سیستم/backend، خواندن و reset مصرف، partial chunked sync، full sync و Stop پاس شدند |
| UID و مصرف | توابع جمع مصرف رسمی، کاربر فقط OpenVPN و جمع دو نود/دو جهت آزمایش شدند |
| دفتر SQLite | نمونه نهایی، تکرار، ری‌استارت، epoch مستقل، reset هم‌زمان و مرگ ناگهانی فرآیند پس از commit پاس شدند |
| نمونه رویدادهای management | مجوز CONNECT، بایت‌های تجمعی، DISCONNECT نهایی و فرمان client-kill/client-deny بررسی شدند |
| انقضا و سهمیه مشترک | تغییر وضعیت/حجم در API شبیه‌سازی‌شده، لغو مجوز نود و ارسال فرمان قطع در مسیر واقعی برنامه تأیید شد |
| تنظیمات واقعی OpenVPN سرور | تا مرحله بازکردن TUN پردازش شد؛ مانع نهایی نبود دستگاه TUN بود |
| preflight نصب‌کننده | روی Ubuntu 24.04 فاقد TUN، پیش از نصب با پیام مشخص متوقف شد |
| پرسش‌نامه و خلاصه پایان نصب | ورود API با نام کاربری/رمز، روش توکن، عدم ذخیره رمز اصلی، چاپ کل Certificate و API Key و رد چاپ کلید خصوصی بررسی شدند |
| پیکربندی نصب | حالت 0600، حفظ فایل موجود، رد HTTP و ورودی مخرب تأیید شد؛ Bash syntax و Compose config معتبرند |
| نقص reset پروتکل اصلی | پاسخ گم‌شده و خرابی پیش از commit موجب کم‌شماری؛ replay گزارش موفق موجب دوباره‌شماری می‌شود؛ هر دو بازتولید شدند |
| تونل واقعی، انتقال ترافیک، NAT و قطع session واقعی | اجرا نشده؛ محیط ابری /dev/net/tun ندارد و ساخت device در Docker مجاز نبود |
| نصب کامل روی VPS و apt/systemd آن | اجرا نشده؛ پیش‌نیاز TUN در محیط آزمایش موجود نیست |
| پنل کامل PasarGuard، دیتابیس و scheduler آن | اجرا نشده؛ نسخه فعال پنل اعلام نشده است |
| پنل فعال و نود فعلی | متصل یا تغییر داده نشده‌اند |
| انتشار محیط ابری و بازیابی در task تازه | توسط این آزمایش‌ها تأیید نشده |

SDK رسمی از `PasarGuard/node_bridge_py` در commit
`c5632b65a10a0af5d5d322e7169ef5069128d8a2`، نسخه 0.10.0، در یک Python
جدا نصب شد تا descriptorهای protobuf دو پروژه در یک interpreter تداخل نکنند.
این تست تطابق SDK و adapter است، نه تست کل پنل.

بازاجرای مجموعه اصلی:

```sh
cd /workspace/openvpnpa
docker compose -f compose.yaml -f compose.cloud.yaml build
docker compose run --rm compatibility
```

ساخت تصویر سرویس:

```sh
docker compose -f deploy/compose.yaml -f deploy/compose.cloud.yaml build
```

بازاجرای SDK اختیاری، با محیط پایتون جدا:

```sh
python3 -m venv /tmp/openvpnpa-sdk
/tmp/openvpnpa-sdk/bin/pip install 'git+https://github.com/PasarGuard/node_bridge_py.git@c5632b65a10a0af5d5d322e7169ef5069128d8a2'
/workspace/.venvs/openvpnpa/bin/python -m scripts.check_bridge --bridge-python /tmp/openvpnpa-sdk/bin/python
```

CA پراکسی در build فقط با BuildKit secret mount می‌شود؛ TLS verification خاموش
نشده و CA در لایه تصویر کپی نشده است. تست تنظیم سرور یک مقدار نامعتبر
`management-log-cache=0` را آشکار کرد؛ مقدار ۱ جایگزین شد و تست تا مرز TUN
پیش رفت. در تست SDK تفاوت مسیر `/stats` و `/stats/` آشکار و هر دو پشتیبانی شدند.

سبزشدن تست‌های fault injection یعنی نقص قرارداد با موفقیت بازتولید شده، نه
آنکه تحویل مصرف دقیقاً یک‌باره تضمین شده باشد. وضعیت این نسخه beta است؛
آزمون پذیرش تونل روی ماشین آزمایشی دارای TUN پیش از بهره‌برداری لازم است.
