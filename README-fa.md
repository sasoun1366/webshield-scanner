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
