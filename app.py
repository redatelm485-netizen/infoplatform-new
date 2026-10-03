"""منصة المعلوماتية التعليمية — تطبيق Flask.
الأقسام: الإعداد والأسرار، قاعدة البيانات (SQLite)، الأمان (CSRF + جلسة المدير + تحديد المحاولات
+ رؤوس HTTP)، المسارات العامة، لوحة التحكم."""
import hashlib
import logging
import math
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import (Flask, abort, flash, g, has_request_context, make_response,
                   redirect, render_template, request, session, url_for)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from seed_data import SEED

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ------------------------------------------------------------------ بيئة التشغيل
# Render يضبط RENDER=true تلقائيًا. على استضافة أخرى اضبط APP_ENV=production.
ON_RENDER = bool(os.environ.get("RENDER"))
IS_PRODUCTION = ON_RENDER or os.environ.get("APP_ENV", "").strip().lower() == "production"
# نثق بترويسات X-Forwarded-* فقط عند وجود وكيل عكسي معروف (Render) أو بطلب صريح؛
# وإلا يستطيع أي زائر تزوير عنوانه والتهرّب من تحديد المحاولات.
BEHIND_PROXY = ON_RENDER or os.environ.get("TRUST_PROXY") == "1"

# ------------------------------------------------------------------ السجلات الأمنية
# تُكتب إلى stdout فتظهر في سجلات Render. لا نسجّل كلمات المرور أو الكوكيز أو المفاتيح
# أو محتوى النماذج أبدًا؛ فقط أحداث وعناوين IP ومعرّفات.
audit_log = logging.getLogger("infoplatform.security")
if not audit_log.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    audit_log.addHandler(_handler)
    audit_log.setLevel(logging.INFO)
    audit_log.propagate = False


def _log_value(value):
    # repr يهرّب الأسطر الجديدة ورموز التحكم، فلا يمكن حقن أسطر مزيفة في السجل
    return repr(str(value)[:120])


def audit(event, level=logging.INFO, **fields):
    ip = (request.remote_addr or "unknown") if has_request_context() else "-"
    extra = " ".join(f"{k}={_log_value(v)}" for k, v in fields.items())
    audit_log.log(level, "%s ip=%s %s", event, ip, extra)


# ------------------------------------------------------------------ الأسرار (لا قيم افتراضية في الإنتاج)
KNOWN_BAD_SECRETS = {"dev-secret-change-me", "change-me", "changeme", "secret", "dev",
                     "development", "test", "default"}
KNOWN_BAD_PASSWORDS = {"admin", "admin123", "password", "password123", "12345678", "123456789",
                       "qwerty123", "letmein", "changeme", "change-me"}


def load_secret_key():
    key = os.environ.get("SECRET_KEY", "")
    if key:
        if IS_PRODUCTION and (len(key) < 32 or key.lower() in KNOWN_BAD_SECRETS):
            raise RuntimeError("SECRET_KEY ضعيف أو قصير: استعمل نصًا عشوائيًا لا يقل عن 32 حرفًا.")
        return key
    if IS_PRODUCTION:
        raise RuntimeError("يجب ضبط متغير البيئة SECRET_KEY في الإنتاج.")
    # تطوير محلي فقط: مفتاح عشوائي لكل تشغيل، بدل مفتاح ثابت معروف في الكود
    return secrets.token_hex(32)


def password_is_strong(pw):
    return len(pw) >= 12 and pw.lower() not in KNOWN_BAD_PASSWORDS and len(set(pw)) >= 5


def load_admin_hash():
    """يعيد بصمة كلمة مرور المدير (scrypt). لا نخزّن كلمة المرور نفسها في الذاكرة بعد البدء.
    الأفضل ضبط ADMIN_PASSWORD_HASH؛ ويُقبل ADMIN_PASSWORD (نص) وتُحوَّل بصمةً عند التشغيل."""
    stored = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
    if stored:
        if not (stored.startswith(("scrypt:", "pbkdf2:")) and stored.count("$") == 2):
            raise RuntimeError("ADMIN_PASSWORD_HASH بصيغة غير صالحة. ولّده بالأمر: python make_admin_hash.py")
        return stored
    plain = os.environ.get("ADMIN_PASSWORD", "")
    if not plain:
        if IS_PRODUCTION:
            raise RuntimeError("يجب ضبط ADMIN_PASSWORD_HASH (الأفضل) أو ADMIN_PASSWORD في الإنتاج.")
        return None  # محليًا بلا كلمة مرور: تسجيل دخول المدير معطّل (لا كلمة مرور افتراضية)
    if IS_PRODUCTION and not password_is_strong(plain):
        raise RuntimeError("ADMIN_PASSWORD ضعيف: يلزم 12 حرفًا على الأقل وألا تكون كلمة شائعة.")
    return generate_password_hash(plain)


SECRET_KEY = load_secret_key()
ADMIN_HASH = load_admin_hash()

# ------------------------------------------------------------------ ثوابت الأمان
ABSOLUTE_SESSION = 8 * 3600     # أقصى عمر لجلسة المدير مهما كان النشاط
IDLE_SESSION = 2 * 3600         # انتهاء الجلسة عند الخمول
REAUTH_WINDOW = 10 * 60         # العمليات الحساسة تتطلب كلمة المرور إن مرّت أكثر من 10 دقائق
LOGIN_MAX_FAILS = 5             # بعد 5 فشل خلال النافذة يبدأ الحظر المتصاعد
LOGIN_WINDOW = 15 * 60
LOGIN_BASE_DELAY = 30           # ثم 30ث، 60ث، 120ث ... حتى 15 دقيقة
LOGIN_MAX_DELAY = 15 * 60
CONTACT_MAX = 10                # عدد رسائل التواصل المسموح لكل IP في الساعة
CONTACT_WINDOW = 3600
MAX_ID = 2 ** 31 - 1            # sqlite يرمي OverflowError فوق 2**63؛ نرفض مبكرًا بـ 404

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    # على Render ضع المسار داخل القرص الدائم، مثال: /var/data/database.db
    DATABASE=os.environ.get("DATABASE_PATH") or os.path.join(BASE_DIR, "database.db"),
    SESSION_COOKIE_NAME="__Host-session" if IS_PRODUCTION else "session",  # البادئة تُلزم Secure و Path=/ وبلا Domain
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,  # الكوكي عبر HTTPS فقط في الإنتاج
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=ABSOLUTE_SESSION),
    MAX_CONTENT_LENGTH=1024 * 1024,  # الحد الأقصى لحجم الطلب: 1MB
)
if IS_PRODUCTION:
    app.debug = False  # حتى لو وُجد FLASK_DEBUG=1 بالخطأ

if BEHIND_PROXY:
    # خلف وكيل عكسي: نثق بمستوى واحد فقط من X-Forwarded-* (العنوان الذي أضافه Render)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SITE_NAME = "عالم المعلوماتية"
KIND_LABELS = {"lesson": "درس", "activity": "نشاط", "achievement": "إنجاز"}
LEVEL_LABELS = {2: "السنة الثانية متوسط", 3: "السنة الثالثة متوسط"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # رموز تحكم (نُبقي \t و \n)

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('lesson','activity','achievement')),
    level INTEGER CHECK (level IN (2,3)),
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- جداول الأمان (إضافية، لا تمسّ بيانات items و messages):
-- أحداث تحديد المعدّل مشتركة بين عمّال Gunicorn، وجلسات المدير قابلة للإبطال من الخادم
CREATE TABLE IF NOT EXISTS rate_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket TEXT NOT NULL,
    ident TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_events ON rate_events (bucket, ident, ts);
CREATE TABLE IF NOT EXISTS admin_sessions (
    sid_hash TEXT PRIMARY KEY,
    created REAL NOT NULL,
    last_seen REAL NOT NULL
);
"""


# ------------------------------------------------------------------ قاعدة البيانات
def get_db():
    if "db" not in g:
        db = sqlite3.connect(app.config["DATABASE"], timeout=15)
        db.row_factory = sqlite3.Row
        # أقل صلاحية: الاتصال للقراءة فقط افتراضيًا؛ execute() وحدها تفتح الكتابة لحظيًا.
        # فلو وُجدت ثغرة حقن في استعلام قراءة لما استطاعت الكتابة أو الحذف.
        db.execute("PRAGMA query_only=ON")
        g.db = db
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    db.execute("PRAGMA query_only=OFF")
    try:
        cur = db.execute(sql, args)
        db.commit()
        return cur.lastrowid
    except Exception:
        db.rollback()
        raise
    finally:
        db.execute("PRAGMA query_only=ON")


def init_db():
    """ينشئ الجداول ويضيف المحتوى التجريبي إذا كانت القاعدة فارغة.
    آمن عند تشغيل عدة عمّال Gunicorn في وقت واحد: الإدراج يتم داخل معاملة حصرية."""
    db_dir = os.path.dirname(app.config["DATABASE"])
    if db_dir:
        os.makedirs(db_dir, mode=0o700, exist_ok=True)
    db = sqlite3.connect(app.config["DATABASE"], timeout=30)
    try:
        try:
            db.execute("PRAGMA journal_mode=WAL")  # قراءة وكتابة متزامنتان بين العمّال
        except sqlite3.DatabaseError:
            pass
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0:
            db.executemany(
                "INSERT INTO items (kind, level, title, summary, content, link) VALUES (?,?,?,?,?,?)",
                SEED)
        db.commit()
    finally:
        db.close()
    try:  # ملف القاعدة لمالك العملية فقط
        os.chmod(app.config["DATABASE"], 0o600)
    except OSError:
        pass


@app.cli.command("init-db")
def init_db_command():
    """flask init-db : إنشاء الجداول وإضافة المحتوى التجريبي."""
    init_db()
    print("تم تجهيز قاعدة البيانات.")


# ------------------------------------------------------------------ تحديد المعدّل (مخزّن في SQLite فيعمل مع عدة عمّال)
def rate_count(bucket, ident, window):
    row = query("SELECT COUNT(*) AS n, MAX(ts) AS last FROM rate_events "
                "WHERE bucket=? AND ident=? AND ts>?", (bucket, ident, time.time() - window), one=True)
    return row["n"], row["last"]


def rate_add(bucket, ident):
    now = time.time()
    execute("INSERT INTO rate_events (bucket, ident, ts) VALUES (?,?,?)", (bucket, ident, now))
    execute("DELETE FROM rate_events WHERE ts < ?", (now - 86400,))  # تنظيف الأحداث القديمة


def rate_clear(bucket, ident):
    execute("DELETE FROM rate_events WHERE bucket=? AND ident=?", (bucket, ident))


def client_ip():
    return request.remote_addr or "unknown"


def login_lock_remaining(ip):
    """الثواني المتبقية للحظر المؤقت (0 = غير محظور). يتضاعف الانتظار مع كل فشل إضافي."""
    fails, last = rate_count("login_fail", ip, LOGIN_WINDOW)
    if fails < LOGIN_MAX_FAILS:
        return 0
    delay = min(LOGIN_MAX_DELAY, LOGIN_BASE_DELAY * 2 ** min(fails - LOGIN_MAX_FAILS, 10))
    return max(0, last + delay - time.time())


def attempt_password(context):
    """يتحقق من كلمة المرور المُرسلة مع الحظر المتصاعد. يعيد (الحالة, ثواني الانتظار):
    ok | bad | locked | disabled"""
    if ADMIN_HASH is None:
        return "disabled", 0
    ip = client_ip()
    wait = login_lock_remaining(ip)
    if wait > 0:
        audit(f"{context}_blocked", logging.WARNING, retry_after=int(wait))
        return "locked", wait
    pw = request.form.get("password", "")
    if 0 < len(pw) <= 256 and check_password_hash(ADMIN_HASH, pw):
        rate_clear("login_fail", ip)
        return "ok", 0
    rate_add("login_fail", ip)
    audit(f"{context}_failed", logging.WARNING)
    return "bad", 0


def too_many(template, wait, **ctx):
    resp = make_response(render_template(template, **ctx), 429)
    resp.headers["Retry-After"] = str(int(wait) + 1)
    return resp


# ------------------------------------------------------------------ جلسة المدير (قابلة للإبطال من الخادم)
def _sid_hash(sid):
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


def start_admin_session():
    """جلسة جديدة بعد الدخول: تُبطل كل الجلسات السابقة وتُصدر معرّفًا جديدًا (منع تثبيت الجلسة)."""
    session.clear()
    sid = secrets.token_urlsafe(32)
    now = time.time()
    execute("DELETE FROM admin_sessions")
    execute("INSERT INTO admin_sessions (sid_hash, created, last_seen) VALUES (?,?,?)",
            (_sid_hash(sid), now, now))
    session["sid"] = sid
    session["reauth_at"] = now
    session.permanent = True
    csrf_token()  # رمز CSRF جديد مرتبط بالجلسة الجديدة


def current_admin():
    """هل الطلب الحالي من مدير بجلسة صالحة؟ (يُتحقق منها من قاعدة البيانات، لا من الكوكي وحده)"""
    if hasattr(g, "_admin"):
        return g._admin
    ok = False
    sid = session.get("sid")
    if isinstance(sid, str) and sid:
        try:
            row = query("SELECT created, last_seen FROM admin_sessions WHERE sid_hash=?",
                        (_sid_hash(sid),), one=True)
            now = time.time()
            if row and now - row["created"] < ABSOLUTE_SESSION and now - row["last_seen"] < IDLE_SESSION:
                ok = True
                if now - row["last_seen"] > 60:
                    execute("UPDATE admin_sessions SET last_seen=? WHERE sid_hash=?", (now, _sid_hash(sid)))
            elif row:
                execute("DELETE FROM admin_sessions WHERE sid_hash=?", (_sid_hash(sid),))
        except sqlite3.Error:
            ok = False  # عند أي عطل نغلق الباب (fail closed)
    if not ok:
        for key in ("sid", "reauth_at"):
            session.pop(key, None)
    g._admin = ok
    return ok


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_admin():
            audit("admin_unauthorized", logging.WARNING, path=request.path, method=request.method)
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


def reauth_required(view):
    """للعمليات الحساسة (مثل الحذف): يلزم إدخال كلمة المرور مجددًا إن مرّت REAUTH_WINDOW ثانية."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if time.time() - float(session.get("reauth_at", 0)) > REAUTH_WINDOW:
            flash("لأمان أكبر، أدخل كلمة المرور مجددًا ثم كرّر العملية.", "error")
            return redirect(url_for("admin_reauth"))
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------------ CSRF ورؤوس HTTP
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = (request.form.get("_csrf") or request.headers.get("X-CSRFToken", "")).encode("utf-8")
        expected = str(session.get("_csrf", "")).encode("utf-8")
        # المقارنة على bytes: نص غير ASCII كان يسبب TypeError (خطأ 500) بدل 400
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            audit("csrf_rejected", logging.WARNING, path=request.path)
            abort(400)


# الخطوط من Google Fonts هي المصدر الخارجي الوحيد (انظر base.html)؛ كل شيء آخر من نفس الموقع.
# لا unsafe-inline ولا unsafe-eval: القوالب تخلو من style= و on*= ومن السكربتات المضمّنة.
CSP_DIRECTIVES = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "frame-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
]
if IS_PRODUCTION:
    CSP_DIRECTIVES.append("upgrade-insecure-requests")  # يمنع المحتوى المختلط HTTP/HTTPS
CSP = "; ".join(CSP_DIRECTIVES)
PERMISSIONS_POLICY = ("accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
                      "magnetometer=(), microphone=(), payment=(), usb=()")


@app.after_request
def security_headers(resp):
    h = resp.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Content-Security-Policy"] = CSP
    h["Referrer-Policy"] = "same-origin"
    h["Permissions-Policy"] = PERMISSIONS_POLICY
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    # HSTS فقط في الإنتاج وفوق اتصال HTTPS فعلي (Render يوفر TLS)
    if IS_PRODUCTION and request.is_secure:
        h["Strict-Transport-Security"] = "max-age=31536000"
    # الصفحات الحساسة (الإدارة، صفحة التواصل التي تحمل رمز CSRF، أي صفحة لمدير مسجّل) لا تُخزَّن
    if request.path.startswith("/admin") or request.path == "/contact" or "sid" in session:
        h["Cache-Control"] = "no-store, max-age=0"
        h["Pragma"] = "no-cache"
    return resp


def page_url(page):
    """رابط الصفحة الحالية مع تغيير رقم الصفحة فقط (يحافظ على البحث والفلاتر)."""
    if not request.endpoint:  # مثلًا داخل صفحة 404 لا يوجد endpoint
        return request.path
    args = {k: v for k, v in request.args.items() if k != "page" and v}
    args.update(request.view_args or {})
    if page > 1:
        args["page"] = page
    return url_for(request.endpoint, **args)


@app.context_processor
def inject_globals():
    return dict(site_name=SITE_NAME, kind_labels=KIND_LABELS,
                level_labels=LEVEL_LABELS, csrf_token=csrf_token, page_url=page_url,
                is_admin=current_admin())


# ------------------------------------------------------------------ تنظيف المدخلات
def clean_text(value, multiline=False):
    """يزيل رموز التحكم ويوحّد نهايات الأسطر. الحقل ذو السطر الواحد تُدمج مسافاته وأسطره."""
    value = CTRL_RE.sub("", value or "").replace("\r\n", "\n").replace("\r", "\n")
    if not multiline:
        value = " ".join(value.split())
    return value.strip()


def valid_url(url):
    if len(url) > 500 or re.search(r"\s", url):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def check_id(value):
    if not 1 <= value <= MAX_ID:
        abort(404)


def search_term():
    return clean_text(request.args.get("q", ""))[:80]


# ------------------------------------------------------------------ الصفحات العامة
@app.route("/")
def index():
    counts = {(r["kind"], r["level"]): r["n"] for r in query(
        "SELECT kind, level, COUNT(*) AS n FROM items GROUP BY kind, level")}
    latest_lessons = query("SELECT * FROM items WHERE kind='lesson' ORDER BY created_at DESC, id DESC LIMIT 3")
    latest_activities = query("SELECT * FROM items WHERE kind='activity' ORDER BY created_at DESC, id DESC LIMIT 3")
    return render_template("index.html", counts=counts, latest_lessons=latest_lessons,
                           latest_activities=latest_activities)


PER_PAGE = 9


def like_pattern(q):
    """يحوّل نص البحث إلى نمط LIKE آمن (مع تهريب الرموز الخاصة)."""
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def find_items(kinds, level=None, q="", page=1):
    """بحث + فلترة + ترقيم صفحات. يعيد (العناصر, معلومات الترقيم).
    ملاحظة أمنية: {clause} يُبنى من أجزاء ثابتة وعلامات ? فقط؛ كل القيم تمر عبر المعاملات."""
    where, args = ["kind IN (%s)" % ",".join("?" * len(kinds))], list(kinds)
    if level:
        where.append("level = ?")
        args.append(level)
    if q:
        like = like_pattern(q)
        where.append("(title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\')")
        args += [like, like, like]
    clause = " AND ".join(where)
    total = query(f"SELECT COUNT(*) AS n FROM items WHERE {clause}", args, one=True)["n"]
    pages = max(1, -(-total // PER_PAGE))
    page = min(max(page, 1), pages)
    rows = query(f"SELECT * FROM items WHERE {clause} ORDER BY level, id LIMIT ? OFFSET ?",
                 args + [PER_PAGE, (page - 1) * PER_PAGE])
    return rows, {"page": page, "pages": pages, "total": total}


def page_arg():
    return request.args.get("page", 1, type=int) or 1


def listing(kind, level, template):
    if level not in LEVEL_LABELS:
        abort(404)
    q = search_term()
    items, pager = find_items([kind], level, q, page_arg())
    return render_template(template, items=items, level=level, kind=kind, q=q, pager=pager)


@app.route("/lessons/<int:level>")
def lessons(level):
    return listing("lesson", level, "lessons.html")


@app.route("/activities/<int:level>")
def activities(level):
    return listing("activity", level, "activities.html")


@app.route("/item/<int:item_id>")
def item_detail(item_id):
    check_id(item_id)
    item = query("SELECT * FROM items WHERE id=?", (item_id,), one=True)
    if item is None:
        abort(404)
    related = query("SELECT * FROM items WHERE kind=? AND level IS ? AND id != ? "
                    "ORDER BY id LIMIT 3", (item["kind"], item["level"], item_id))
    return render_template("item.html", item=item, related=related)


@app.route("/scratch")
def scratch():
    return render_template("scratch.html")


@app.route("/achievements")
def achievements():
    items = query("SELECT * FROM items WHERE kind='achievement' ORDER BY id DESC")
    return render_template("achievements.html", items=items)


@app.route("/search")
def search():
    """مكتبة البحث: كلمة + فلتر النوع + فلتر المستوى + ترقيم."""
    q = search_term()
    kind = request.args.get("kind", "")
    level = request.args.get("level", 0, type=int)
    kinds = [kind] if kind in ("lesson", "activity") else ["lesson", "activity"]
    level = level if level in LEVEL_LABELS else 0
    results, pager = find_items(kinds, level, q, page_arg())
    return render_template("search.html", q=q, kind=kind if kind in ("lesson", "activity") else "",
                           level=level, results=results, pager=pager)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = {"name": "", "email": "", "message": ""}
    if request.method == "POST":
        form = {"name": clean_text(request.form.get("name", "")),
                "email": clean_text(request.form.get("email", "")),
                "message": clean_text(request.form.get("message", ""), multiline=True)}
        ip = client_ip()
        if rate_count("contact", ip, CONTACT_WINDOW)[0] >= CONTACT_MAX:
            audit("contact_rate_limited", logging.WARNING)
            flash("أرسلت رسائل كثيرة خلال وقت قصير. حاول مرة أخرى لاحقًا.", "error")
            return too_many("contact.html", CONTACT_WINDOW, form=form)
        errors = []
        if not 2 <= len(form["name"]) <= 80:
            errors.append("الاسم يجب أن يكون بين 2 و80 حرفًا.")
        if not EMAIL_RE.match(form["email"]) or len(form["email"]) > 120:
            errors.append("البريد الإلكتروني غير صحيح.")
        if not 10 <= len(form["message"]) <= 2000:
            errors.append("الرسالة يجب أن تكون بين 10 و2000 حرف.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            execute("INSERT INTO messages (name, email, message) VALUES (?,?,?)",
                    (form["name"], form["email"], form["message"]))
            rate_add("contact", ip)
            flash("تم إرسال رسالتك بنجاح، شكرًا لك.", "success")
            return redirect(url_for("contact"))
    return render_template("contact.html", form=form)


# ------------------------------------------------------------------ لوحة التحكم
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        status, wait = attempt_password("admin_login")
        if status == "ok":
            start_admin_session()
            audit("admin_login_success")
            flash("مرحبًا بك في لوحة التحكم.", "success")
            return redirect(url_for("admin_dashboard"))
        if status == "locked":
            flash(f"محاولات دخول كثيرة. أعد المحاولة بعد {max(1, math.ceil(wait / 60))} دقيقة.", "error")
            return too_many("admin_login.html", wait)
        if status == "disabled":
            flash("دخول المدير غير مفعّل: اضبط ADMIN_PASSWORD أو ADMIN_PASSWORD_HASH.", "error")
            return make_response(render_template("admin_login.html"), 503)
        flash("كلمة المرور غير صحيحة.", "error")
    return render_template("admin_login.html")


@app.route("/admin/reauth", methods=["GET", "POST"])
@admin_required
def admin_reauth():
    """إعادة التحقق من كلمة المرور قبل العمليات الحساسة. الوجهة ثابتة (لا next) فلا إعادة توجيه مفتوحة."""
    if request.method == "POST":
        status, wait = attempt_password("admin_reauth")
        if status == "ok":
            session["reauth_at"] = time.time()
            audit("admin_reauth_success")
            flash("تم التحقق. كرّر العملية المطلوبة الآن.", "success")
            return redirect(url_for("admin_dashboard"))
        if status == "locked":
            flash(f"محاولات كثيرة. أعد المحاولة بعد {max(1, math.ceil(wait / 60))} دقيقة.", "error")
            return too_many("admin_reauth.html", wait)
        flash("كلمة المرور غير صحيحة.", "error")
    return render_template("admin_reauth.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    was_admin = current_admin()
    sid = session.get("sid")
    if isinstance(sid, str) and sid:
        execute("DELETE FROM admin_sessions WHERE sid_hash=?", (_sid_hash(sid),))  # إبطال فعلي من الخادم
    session.clear()
    if was_admin:
        audit("admin_logout")
    flash("تم تسجيل الخروج.", "success")
    return redirect(url_for("index"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    fkind = request.args.get("kind", "")
    q = search_term()
    where, args = [], []
    if fkind in KIND_LABELS:
        where.append("kind = ?")
        args.append(fkind)
    if q:
        where.append("title LIKE ? ESCAPE '\\'")
        args.append(like_pattern(q))
    sql = "SELECT * FROM items" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY kind, level, id"
    items = query(sql, args)
    stats = {r["kind"]: r["n"] for r in query("SELECT kind, COUNT(*) AS n FROM items GROUP BY kind")}
    stats["messages"] = query("SELECT COUNT(*) AS n FROM messages", one=True)["n"]
    stats["total"] = sum(stats.get(k, 0) for k in KIND_LABELS)
    messages = query("SELECT * FROM messages ORDER BY id DESC LIMIT 20")
    return render_template("admin.html", items=items, messages=messages, stats=stats,
                           fkind=fkind if fkind in KIND_LABELS else "", q=q)


def parse_item_form(form):
    data = {k: clean_text(form.get(k, ""), multiline=k in ("summary", "content"))
            for k in ("kind", "title", "summary", "content", "link")}
    errors = []
    if data["kind"] not in KIND_LABELS:
        errors.append("نوع المحتوى غير صالح.")
    level = form.get("level", "").strip()
    if data["kind"] == "achievement":
        data["level"] = None
    elif level in ("2", "3"):
        data["level"] = int(level)
    else:
        data["level"] = None
        errors.append("اختر المستوى الدراسي.")
    if not 3 <= len(data["title"]) <= 150:
        errors.append("العنوان يجب أن يكون بين 3 و150 حرفًا.")
    if len(data["summary"]) > 300:
        errors.append("الملخص طويل (الحد 300 حرف).")
    if len(data["content"]) > 20000:
        errors.append("المحتوى طويل جدًا.")
    if data["link"] and not valid_url(data["link"]):
        errors.append("الرابط يجب أن يبدأ بـ http:// أو https:// وأن يكون صالحًا.")
    return data, errors


@app.route("/admin/new", methods=["GET", "POST"])
@admin_required
def admin_new():
    preset = request.args.get("kind", "lesson")
    data = {"kind": preset if preset in KIND_LABELS else "lesson", "level": 2,
            "title": "", "summary": "", "content": "", "link": ""}
    if request.method == "POST":
        data, errors = parse_item_form(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            new_id = execute(
                "INSERT INTO items (kind, level, title, summary, content, link) VALUES (?,?,?,?,?,?)",
                (data["kind"], data["level"], data["title"], data["summary"], data["content"], data["link"]))
            audit("admin_create_item", id=new_id, kind=data["kind"])
            flash("تمت الإضافة بنجاح.", "success")
            return redirect(url_for("item_detail", item_id=new_id))
    return render_template("admin_form.html", item=data, editing=False)


@app.route("/admin/edit/<int:item_id>", methods=["GET", "POST"])
@admin_required
def admin_edit(item_id):
    check_id(item_id)
    item = query("SELECT * FROM items WHERE id=?", (item_id,), one=True)
    if item is None:
        abort(404)
    if request.method == "POST":
        data, errors = parse_item_form(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            item = data
        else:
            execute("UPDATE items SET kind=?, level=?, title=?, summary=?, content=?, link=? WHERE id=?",
                    (data["kind"], data["level"], data["title"], data["summary"],
                     data["content"], data["link"], item_id))
            audit("admin_update_item", id=item_id, kind=data["kind"])
            flash("تم حفظ التعديلات.", "success")
            return redirect(url_for("admin_dashboard"))
    return render_template("admin_form.html", item=item, editing=True, item_id=item_id)


@app.route("/admin/delete/<int:item_id>", methods=["POST"])
@admin_required
@reauth_required
def admin_delete(item_id):
    check_id(item_id)
    if query("SELECT 1 FROM items WHERE id=?", (item_id,), one=True) is None:
        abort(404)
    execute("DELETE FROM items WHERE id=?", (item_id,))
    audit("admin_delete_item", id=item_id)
    flash("تم الحذف.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/healthz")
def healthz():
    """مسار فحص الصحة لـ Render (Health Check Path): يتأكد أن قاعدة البيانات تُقرأ."""
    try:
        query("SELECT 1", one=True)
    except sqlite3.Error:
        return "db error", 503
    return "ok", 200


# ------------------------------------------------------------------ صفحات الأخطاء (لا تظهر تفاصيل بايثون للمستخدم)
def error_page(code, title, msg):
    return render_template("error.html", code=code, title=title, msg=msg), code


@app.errorhandler(400)
def bad_request(_e):
    return error_page(400, "طلب غير صالح", "انتهت صلاحية الجلسة أو الطلب غير صحيح. ارجع وحاول مجددًا.")


@app.errorhandler(403)
def forbidden(_e):
    return error_page(403, "غير مسموح", "ليس لديك صلاحية الوصول إلى هذه الصفحة.")


@app.errorhandler(404)
def not_found(_e):
    return error_page(404, "الصفحة غير موجودة", "الرابط الذي طلبته غير موجود أو تم نقله.")


@app.errorhandler(405)
def method_not_allowed(_e):
    return error_page(405, "طريقة الطلب غير مسموحة", "لا يمكن فتح هذا الرابط بهذه الطريقة.")


@app.errorhandler(413)
def too_large(_e):
    return error_page(413, "الطلب كبير جدًا", "حجم البيانات المرسلة أكبر من الحد المسموح (1MB).")


@app.errorhandler(429)
def rate_limited(_e):
    return error_page(429, "طلبات كثيرة", "أرسلت طلبات كثيرة خلال وقت قصير. حاول مجددًا بعد قليل.")


@app.errorhandler(500)
def server_error(_e):
    return error_page(500, "خطأ في الخادم", "حدث خطأ غير متوقع. حاول مرة أخرى لاحقًا.")


@app.errorhandler(HTTPException)
def http_error(e):
    if e.code and 300 <= e.code < 400:  # إعادات التوجيه (مثل دمج //) ليست أخطاء
        return e
    return error_page(e.code or 500, "تعذّر إكمال الطلب", "تعذّر إكمال هذا الطلب.")


@app.errorhandler(Exception)
def unexpected_error(e):
    # التفاصيل (traceback) تذهب إلى سجل الخادم فقط، والمستخدم يرى صفحة عامة
    app.logger.error("unexpected_error %s %s: %s", request.method, _log_value(request.path),
                     type(e).__name__, exc_info=True)
    return server_error(e)


init_db()

if __name__ == "__main__":
    # للتشغيل المحلي فقط. على Render يُشغَّل التطبيق عبر gunicorn (انظر render.yaml).
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1" and not IS_PRODUCTION)
