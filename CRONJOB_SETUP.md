# راهنمای نصب Cronjob

این فایل توضیح می‌دهد که چگونه وظایف زمان‌بندی شده را برای e-kiosque راه‌اندازی کنید.

## وظایف خودکار

فایل `cronjob_tasks.py` وظایف زیر را انجام می‌دهد:

1. **به‌روزرسانی وضعیت رویدادها**: رویدادهایی که تاریخشان گذشته را غیرفعال می‌کند
2. **پاک‌سازی بلیت‌های قدیمی**: بلیت‌های رویدادهای بیش از ۷ روز قبل را حذف می‌کند (برای حفظ حریم خصوصی)
3. **پاک‌سازی محدودیت‌های دسترسی منقضی شده**: رکوردهای موقت rate limiting را پاک می‌کند

## نصب Cronjob در سرور لینوکس

### گام ۱: ویرایش Crontab

```bash
crontab -e
```

### گام ۲: اضافه کردن خط Cronjob

برای اجرای هر ۵ دقیقه یکبار:

```bash
*/5 * * * * cd /path/to/e-kiosque && /usr/bin/python3 cronjob_tasks.py >> /path/to/e-kiosque/cronjob.log 2>&1
```

**توجه**: `/path/to/e-kiosque` را با مسیر واقعی پروژه خود جایگزین کنید.

### گام ۳ (اختیاری): اجرای روزانه برای پاک‌سازی کامل

اگر می‌خواهید یک پاک‌سازی کامل روزانه داشته باشید:

```bash
0 2 * * * cd /path/to/e-kiosque && /usr/bin/python3 cronjob_tasks.py >> /path/to/e-kiosque/cronjob.log 2>&1
```

این دستور هر روز ساعت ۲ صبح اجرا می‌شود.

## نصب در Toolforge

در Toolforge، می‌توانید از دستور زیر استفاده کنید:

```bash
toolforge jobs run update-events --command "cd $HOME/e-kiosque && python3 cronjob_tasks.py" --schedule "*/5 * * * *" --image python3.11
```

این یک job زمان‌بندی شده ایجاد می‌کند که هر ۵ دقیقه اجرا می‌شود.

## بررسی لاگ‌ها

لاگ‌ها در فایل `cronjob.log` ذخیره می‌شوند:

```bash
tail -f cronjob.log
```

## تست دستی

برای تست دستی:

```bash
cd /path/to/e-kiosque
python3 cronjob_tasks.py
```

## نکات مهم

1. **مجوزها**: اطمینان حاصل کنید که فایل `cronjob_tasks.py` قابل اجرا است:
   ```bash
   chmod +x cronjob_tasks.py
   ```

2. **Virtual Environment**: اگر از virtual environment استفاده می‌کنید، مسیر python را به درستی تنظیم کنید:
   ```bash
   */5 * * * * cd /path/to/e-kiosque && /path/to/venv/bin/python3 cronjob_tasks.py
   ```

3. **مسیر پروژه**: همیشه ابتدا با `cd` به دایرکتوری پروژه بروید تا Python بتواند ماژول‌ها را پیدا کند.

4. **لاگ‌ها**: لاگ‌های cronjob را به طور منظم بررسی کنید تا از اجرای صحیح آن مطمئن شوید.

