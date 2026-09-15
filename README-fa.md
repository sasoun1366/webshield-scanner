# WebShield Scanner 1.0 و WebShield Security Audit

اسکنر دفاعی و کم‌خطر برای بررسی اولیه‌ی هدرهای امنیتی HTTP، وضعیت HTTPS و پرچم‌های رایج کوکی‌ها، به‌همراه ممیزی خواندنیِ میزبان‌های Windows و Linux. این ابزار فقط روی سامانه‌هایی استفاده شود که مالک آن هستید یا مجوز صریح ارزیابی آن‌ها را دارید.

## محدوده و ایمنی

Audit فقط وضعیت سیستم‌عامل، به‌روزرسانی، فایروال، سرویس‌های مدیریتی SSH/RDP و چند تنظیم مهم را می‌خواند. هیچ exploit، brute-force، crawl، payload یا تغییر خودکاری در سیستم انجام نمی‌دهد. گزارش شامل شدت، توضیح، شواهد و پیشنهاد اصلاح است؛ اصلاحات باید جداگانه و پس از بازبینی مدیر سیستم انجام شوند.

## نصب

Python 3.10 یا جدیدتر پیشنهاد می‌شود:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.\\.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
```

`requests` برای اسکنر HTTP و `pywinrm` برای ممیزی Windows راه‌دور استفاده می‌شود.

## Local Scanner در Linux

```bash
python -m src.security_audit local --json linux-audit.json --html linux-audit.html
```

اسکریپت را ترجیحاً با حساب عادی اجرا کنید. برای برخی شواهد ممکن است دسترسی خواندن محدود باشد؛ فقط در صورت نیاز سازمانی و طبق رویه تغییرات از `sudo` استفاده کنید.

## Local Scanner در Windows

PowerShell را در پوشه پروژه باز کنید:

```powershell
python -m src.security_audit local --json windows-audit.json --html windows-audit.html
```

وضعیت Windows Firewall، چند hotfix اخیر و فعال‌بودن Remote Desktop خوانده می‌شود و هیچ تنظیمی تغییر نمی‌کند.

## Remote Scanner برای Linux با SSH

SSH باید از قبل و به‌صورت امن تنظیم شده باشد. از کلید SSH، کاربر محدود، فایروال و ترجیحاً VPN یا شبکه مدیریت استفاده کنید. احراز هویت پسوردی در این ابزار پشتیبانی نشده است.

```bash
python -m src.security_audit ssh 192.0.2.10 --user audit --identity ~/.ssh/audit_ed25519 --json remote-linux.json --html remote-linux.html
```

کاربر `audit` فقط به اجرای چند دستور diagnostic نیاز دارد. fingerprint میزبان را مستقل بررسی کنید. فرمان‌های این ابزار allowlist‌شده و خواندنی هستند.

## Remote Scanner برای Windows با WinRM

برای محیط واقعی از WinRM روی HTTPS و پورت 5986 استفاده کنید و گواهی معتبر، کاربر محدود و فایروال شبکه داشته باشید. چون رمز عبور در خط فرمان ممکن است در history یا process list دیده شود، secret manager سازمانی یا اجرای تعاملی را ترجیح دهید:

```powershell
python -m src.security_audit winrm 192.0.2.20 --user 'CONTOSO\\audit' --password 'PASSWORD' --port 5986 --json remote-windows.json --html remote-windows.html
```

`--no-ssl` فقط برای آزمایشگاه جداشده است و برای شبکه واقعی توصیه نمی‌شود. WinRM باید از قبل در Windows هدف و فایروال آن پیکربندی شده باشد.

## اسکنر وب قبلی

```bash
python -m src.webshield https://example.com --json report.json --html report.html
```

این بخش نیز passive است و فقط روی مقصد مجاز اجرا شود.

## تست

```bash
python -m pytest -q
```

## تفسیر گزارش

`fail` یعنی وضعیت ناامن یا پرریسک محتمل دیده شده، `warn` نیازمند بازبینی است، و `pass` یا `info` وضعیت قابل‌قبول یا شواهد جمع‌آوری‌شده را نشان می‌دهد. قبل از اصلاح، یافته را با baseline سازمانی، مستندات سیستم‌عامل و تیم مسئول تأیید کنید؛ این ابزار جایگزین مدیریت وصله، EDR، اسکنر رسمی آسیب‌پذیری یا تست نفوذ مجاز نیست.

## استفاده مجاز و مجوز

فقط دامنه‌ها و سامانه‌هایی را بررسی کنید که مالک آن‌ها هستید یا مجوز کتبی برای ارزیابی‌شان دارید. نتیجه‌ی ابزار جایگزین تست نفوذ حرفه‌ای یا ممیزی کامل امنیتی نیست. خروجی‌ها را همراه با اطلاعات محرمانه منتشر نکنید. این محصول برای استفاده‌ی دفاعی و آموزشی عرضه می‌شود و کاربر مسئول رعایت قوانین، قراردادها و محدوده‌ی مجاز تست است.
