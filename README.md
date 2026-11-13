# OpenVPN × PasarGuard: isolated compatibility lab

**وضعیت: بررسی سازگاری و نمونه آزمایش؛ نود قابل استقرار نیست.**

طبق کد رسمی بررسی‌شده، جمع‌شدن مصرف OpenVPN و V2Ray با شناسه عددی مشترک
امکان‌پذیر است. اما تضمین هم‌زمان «عدم اتلاف مصرف» و «عدم دوباره‌شماری» در
قطع گزارش با پروتکل فعلی نود، بدون تغییر پنل، ممکن نیست. نتیجه کامل و مرز
آزمایش‌ها در [گزارش سازگاری](docs/compatibility.fa.md) آمده است.

این مخزن شامل دفتر مصرف آزمایشی SQLite، protobuf رسمی، گزیده توابع واقعی
جمع مصرف پنل و آزمایش قطع پاسخ HTTP است. کانتینر Ubuntu 24.04 فقط آزمایش‌ها
را اجرا می‌کند؛ هیچ پورتی منتشر نمی‌کند، به پنل وصل نمی‌شود و VPN ایجاد نمی‌کند.

```sh
docker compose build
docker compose run --rm compatibility
```

در محیط ابری دارای پراکسی HTTPS، گواهی قابل اعتماد میزبان فقط هنگام build
mount می‌شود و در تصویر ذخیره نمی‌شود؛ TLS verification فعال می‌ماند:

```sh
docker compose -f compose.yaml -f compose.cloud.yaml build
docker compose run --rm compatibility
```

توسعه محلی (Python 3.12+):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -v
```

آزمایش OpenVPN management در صورت نبودن OpenVPN/openssl در میزبان skip می‌شود؛
در تصویر Docker این وابستگی‌ها نصب هستند. این آزمایش فقط رابط مدیریت فرآیند
واقعی را بررسی می‌کند، نه احراز هویت، انتقال ترافیک یا قطع یک تونل واقعی.

هیچ پیکربندی یا اعتبارنامه پنل فعال نیاز نیست. فایل‌های نمونه از پروتکل رسمی
در [vendor](vendor/README.md) با commit و hash منبع ثبت شده‌اند.

**تصمیم لازم پیش از توسعه نود:** پذیرش محدودیت ثبت مصرف پروتکل فعلی، یا تغییر
قرارداد تحویل مصرف در سمت دریافت‌کننده برای ثبت idempotent و تأیید تراکنش.
گزینه دوم خارج از شرط فعلی «عدم تغییر پنل» است و در این پروژه انجام نشده است.
