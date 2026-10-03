# منصة عالم المعلوماتية

منصة تعليمية لمادة المعلوماتية (السنة الثانية والثالثة متوسط) مبنية بـ **Flask + Jinja2 + SQLite**، تدعم العربية و RTL وتعمل على الهاتف والحاسوب.

## هيكلة المشروع

```
infoplatform/
├── app.py               # المسارات + قاعدة البيانات + الأمان + لوحة التحكم
├── seed_data.py         # المحتوى التجريبي الأولي
├── make_admin_hash.py   # يولّد ADMIN_PASSWORD_HASH (بصمة كلمة مرور المدير)
├── requirements.txt     # Flask + gunicorn
├── requirements-dev.txt # أدوات الفحص (pip-audit) — للتطوير فقط
├── render.yaml          # إعداد النشر على Render
├── SECURITY.md          # توثيق إعدادات الأمان وقائمة المراجعة
├── tests/               # اختبارات الأمان
├── database.db          # تُنشأ تلقائيًا عند أول تشغيل (لا تُرفع إلى GitHub)
├── templates/           # قوالب Jinja (base.html هو القالب الأساسي)
└── static/              # css/style.css, js/script.js, images/
```

## الميزات
- صفحة رئيسية (Hero، أقسام، آخر الدروس، آخر الأنشطة، سكراش) وتصميم متجاوب RTL.
- بحث + فلترة حسب المستوى والنوع + ترقيم صفحات (9 عناصر/صفحة، يمكن تغييرها من `PER_PAGE` في `app.py`).
- لوحة تحكم: إحصائيات، إضافة/تعديل/حذف الدروس والأنشطة والإنجازات، بحث وفلترة، ورسائل التواصل.

## 1) تثبيت Python
- حمّل Python 3.10 أو أحدث من https://www.python.org/downloads
- في Windows فعّل خيار **Add Python to PATH** أثناء التثبيت.
- تحقق: `python --version` (أو `python3 --version` في macOS/Linux).

## 2) إنشاء Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```
إذا منع PowerShell التفعيل: `Set-ExecutionPolicy -Scope Process Bypass` ثم أعد المحاولة.

## 3) تثبيت المتطلبات
```bash
pip install -r requirements.txt
```

## 4) كلمة مرور لوحة التحكم (لا توجد كلمة افتراضية)
بدون كلمة مرور مضبوطة يبقى الموقع العام يعمل لكن **دخول المدير معطّل**. اختر إحدى الطريقتين:

```bash
# الأفضل: بصمة مشفّرة (scrypt). ولّدها ثم ضعها في ADMIN_PASSWORD_HASH
python make_admin_hash.py

# macOS / Linux (انتبه للعلامات المفردة لأن البصمة تحتوي $)
export ADMIN_PASSWORD_HASH='scrypt:32768:8:1$...$...'
# أو للتجربة المحلية فقط:
export ADMIN_PASSWORD='كلمة-مرور-طويلة-12-حرفًا-أو-أكثر'

# Windows PowerShell
$env:ADMIN_PASSWORD_HASH='scrypt:32768:8:1$...$...'
```
`SECRET_KEY` اختياري محليًا (يُولَّد مفتاح عشوائي لكل تشغيل)، وإلزامي في الإنتاج.

## 5) تشغيل Flask محليًا
```bash
python app.py
```
أو: `flask --app app run`. لتفعيل وضع التطوير محليًا فقط: `FLASK_DEBUG=1 python app.py`
(يُتجاهل تلقائيًا في الإنتاج).

- الموقع: http://127.0.0.1:5000
- لوحة التحكم: http://127.0.0.1:5000/admin/login

قاعدة البيانات `database.db` تُنشأ وتُملأ بمحتوى تجريبي تلقائيًا. لإعادة التجهيز: احذف `database.db` ثم شغّل التطبيق من جديد.

## 6) تعديل الدروس وإضافتها مستقبلًا

**من لوحة التحكم (الأسهل):**
1. ادخل إلى `/admin/login` بكلمة المرور التي ضبطتها.
2. اضغط **+ إضافة محتوى**، واختر النوع (درس / نشاط / إنجاز) والمستوى (2 أو 3).
3. اكتب العنوان والملخص والمحتوى، وأضف رابطًا اختياريًا يبدأ بـ `https://` (مثل ملف PDF على Google Drive).
4. للتعديل أو الحذف استعمل الأزرار في جدول المحتوى. **الحذف يطلب إعادة إدخال كلمة المرور** إن مرّت أكثر من 10 دقائق على دخولك.

**من الكود:** أضف سطرًا إلى `seed_data.py` (يُستعمل فقط إذا كانت القاعدة فارغة).

**إضافة مستوى جديد (مثل الرابعة):** عدّل `LEVEL_LABELS` و `CHECK` في `app.py` وفي `parse_item_form`، ثم أضف رابطه في `base.html`.

## 7) النشر على Render (Web Service)

1. ارفع المشروع إلى GitHub. ملف `.gitignore` يمنع رفع `database.db` والأسرار (`.env`).
   إن كنت رفعت `database.db` سابقًا: `git rm --cached database.db` ثم commit.
2. في Render: **New → Blueprint** واختر المستودع، أو **New → Web Service** يدويًا:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 2 --timeout 60`
   - Health Check Path: `/healthz`
3. متغيرات البيئة (إلزامية؛ وإلا يتوقف التطبيق عند البدء برسالة واضحة بدل العمل بإعدادات غير آمنة):

   | المتغير | القيمة |
   |---|---|
   | `SECRET_KEY` | نص عشوائي لا يقل عن 32 حرفًا (Render يولّده في `render.yaml`) |
   | `ADMIN_PASSWORD_HASH` | ناتج `python make_admin_hash.py` (أو `ADMIN_PASSWORD` بـ 12 حرفًا فأكثر) |
   | `DATABASE_PATH` | `/var/data/database.db` (مسار داخل القرص الدائم) |

4. **حفظ البيانات:** SQLite ملف على القرص. أضف **Disk** (خطة مدفوعة) بمسار تركيب `/var/data`. على الخطة المجانية يُفقد المحتوى المُضاف ورسائل التواصل عند كل إعادة تشغيل أو نشر.
5. مع القرص الدائم يجب أن تبقى الخدمة على نسخة واحدة (instance واحد).

## 8) الاختبارات
```bash
python -m unittest discover -s tests -v
```
تعمل على قاعدة بيانات مؤقتة ولا تمسّ `database.db`. للتفاصيل الأمنية الكاملة انظر **SECURITY.md**.
