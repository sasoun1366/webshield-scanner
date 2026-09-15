# WebShield Scanner 1.0

اسکنر دفاعی و کم‌خطر برای بررسی اولیه‌ی هدرهای امنیتی HTTP، وضعیت HTTPS و پرچم‌های رایج کوکی‌ها. این ابزار فقط یک درخواست معمولی ارسال می‌کند و هیچ اکسپلویت، brute-force، crawl یا حمله‌ای انجام نمی‌دهد.

## استفاده مجاز

فقط دامنه‌ها و سامانه‌هایی را بررسی کنید که مالک آن هستید یا مجوز کتبی برای ارزیابی آن‌ها دارید. نتیجه‌ی این ابزار جایگزین تست نفوذ حرفه‌ای یا ممیزی کامل امنیتی نیست.

## نصب

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

## اجرا

```bash
python -m src.webshield https://example.com --json report.json --html report.html
```

گزارش JSON و HTML تولید می‌شود. خروجی‌ها را در معرض عموم یا همراه با اطلاعات محرمانه منتشر نکنید.

## موارد بررسی‌شده

HTTPS، HSTS، CSP، X-Content-Type-Options، X-Frame-Options، Referrer-Policy، Permissions-Policy و پرچم‌های Secure، HttpOnly و SameSite در Set-Cookie.

## مجوز

این محصول برای استفاده‌ی دفاعی و آموزشی عرضه می‌شود. خریدار مسئول رعایت قوانین، قراردادها و محدوده‌ی مجاز تست است.
اجرای ساده

مثلاً:

py .\webshield.py https://example.com
با Timeout مشخص
py .\webshield.py https://example.com --timeout 10
ذخیره نتیجه به JSON
py .\webshield.py https://example.com --json report.json
تولید گزارش HTML
py .\webshield.py https://example.com --html report.html
هر دو گزارش با هم
py .\webshield.py https://example.com --json report.json --html report.html

مثلاً برای سایت خودت:

py .\webshield.py https://luyava.com --json luyava-report.json --html luyava-report.html

بعد فایل luyava-report.html را با مرورگر باز کن.

نکته: فقط URLهایی را اسکن کن که مالکشان هستی یا اجازه تستشان را داری؛ این ابزار برای ارزیابی دفاعی هدرهای امنیتی طراحی شده.

