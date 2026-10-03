"""اختبارات الأمان والتشغيل. التشغيل من مجلد المشروع:

    python -m unittest discover -s tests -v

تعمل على قاعدة بيانات مؤقتة ولا تمسّ database.db.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "Str0ng-Admin-Pass!"
SECRET = "k" * 48

# بيئة الاختبار: قاعدة مؤقتة، وضع تطوير، كلمة مرور قوية (يجب ضبطها قبل استيراد التطبيق)
_TMP = tempfile.mkdtemp(prefix="infoplatform-test-")
for _var in ("RENDER", "APP_ENV", "TRUST_PROXY", "FLASK_DEBUG", "ADMIN_PASSWORD_HASH"):
    os.environ.pop(_var, None)
os.environ.update(DATABASE_PATH=os.path.join(_TMP, "test.db"), SECRET_KEY=SECRET, ADMIN_PASSWORD=PASSWORD)
sys.path.insert(0, str(ROOT))

import app as appmod  # noqa: E402

app = appmod.app
_real_time = time.time


@contextmanager
def shifted(seconds):
    """يقدّم الساعة (لاختبار انتهاء الحظر وإعادة التحقق) دون انتظار فعلي."""
    with mock.patch("time.time", side_effect=lambda: _real_time() + seconds):
        yield


def csrf_of(client, path="/contact", **kw):
    html = client.get(path, **kw).get_data(as_text=True)
    m = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert m, f"لا يوجد رمز CSRF في {path}"
    return m.group(1)


def login(client, password=PASSWORD):
    token = csrf_of(client, "/admin/login")
    return client.post("/admin/login", data={"_csrf": token, "password": password})


def count(sql, args=()):
    import sqlite3
    db = sqlite3.connect(app.config["DATABASE"])
    try:
        return db.execute(sql, args).fetchone()[0]
    finally:
        db.close()


def run_py(code, **env):
    """يشغّل كودًا في عملية منفصلة ببيئة محددة (لاختبار إعدادات الإنتاج)."""
    base = {k: v for k, v in os.environ.items()
            if k not in ("RENDER", "APP_ENV", "TRUST_PROXY", "FLASK_DEBUG", "SECRET_KEY",
                         "ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH", "DATABASE_PATH")}
    base.update(env)
    base.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(prefix="infoplatform-sub-"), "t.db"))
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=base,
                          capture_output=True, text=True, timeout=120)


class Base(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = False  # نريد معالجات الأخطاء الحقيقية كما في الإنتاج
        self.c = app.test_client()
        with app.app_context():
            appmod.execute("DELETE FROM rate_events")
            appmod.execute("DELETE FROM admin_sessions")
            appmod.execute("DELETE FROM messages")
            appmod.execute("DELETE FROM items WHERE title LIKE 'TEST%'")


class TestRoutes(Base):
    def test_major_routes_ok(self):
        for path in ["/", "/lessons/2", "/lessons/3", "/activities/2", "/activities/3", "/scratch",
                     "/achievements", "/search", "/search?q=خوارزمية&level=2&kind=lesson", "/contact",
                     "/admin/login", "/item/1", "/healthz", "/static/css/style.css",
                     "/static/js/script.js", "/static/images/logo.svg"]:
            self.assertEqual(self.c.get(path).status_code, 200, path)

    def test_invalid_ids_and_urls_never_500(self):
        for path in ["/item/0", "/item/-1", "/item/abc", "/item/99999999999999999999999",
                     "/item/9223372036854775808", "/item/%00", "/item/%D9%A1", "/lessons/9",
                     "/lessons/99999999999999999999", "/activities/0", "/nope", "/%00", "/..%2f..%2fetc/passwd",
                     "//admin", "/static/../app.py", "/static/..%2fapp.py", "/search?page=99999999999999999999",
                     "/search?level=99999999999999999999&page=-5", "/search?kind=%00&q=%00"]:
            self.assertLess(self.c.get(path).status_code, 500, path)
        self.assertEqual(self.c.get("/item/99999999999999999999999").status_code, 404)
        self.assertEqual(self.c.get("/static/../app.py").status_code, 404)

    def test_method_not_allowed_is_clean(self):
        r = self.c.get("/admin/logout")
        self.assertEqual(r.status_code, 405)
        self.assertNotIn("Traceback", r.get_data(as_text=True))


class TestAuth(Base):
    def test_admin_routes_require_login(self):
        for path in ["/admin", "/admin/new", "/admin/edit/1", "/admin/reauth"]:
            r = self.c.get(path)
            self.assertEqual(r.status_code, 302, path)
            self.assertIn("/admin/login", r.headers["Location"])
        token = csrf_of(self.c)
        r = self.c.post("/admin/delete/1", data={"_csrf": token})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/admin/login", r.headers["Location"])
        self.assertEqual(count("SELECT COUNT(*) FROM items WHERE id=1"), 1)
        r = self.c.post("/admin/new", data={"_csrf": token, "kind": "lesson", "level": "2", "title": "TEST hack"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(count("SELECT COUNT(*) FROM items WHERE title='TEST hack'"), 0)

    def test_login_and_logout(self):
        self.assertEqual(login(self.c, "wrong-password").status_code, 200)
        self.assertEqual(self.c.get("/admin").status_code, 302)
        r = login(self.c)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get("/admin").status_code, 200)
        cookie = self.c.get_cookie("session")
        self.assertTrue(cookie.http_only)
        self.assertEqual(str(cookie.same_site).lower(), "lax")
        stolen = cookie.value
        token = csrf_of(self.c, "/admin")
        self.assertEqual(self.c.post("/admin/logout", data={"_csrf": token}).status_code, 302)
        self.assertEqual(self.c.get("/admin").status_code, 302)
        # إعادة استعمال الكوكي القديم بعد الخروج يجب أن تفشل: الإبطال من الخادم لا من المتصفح فقط
        replay = app.test_client()
        replay.set_cookie("session", stolen)
        r = replay.get("/admin")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/admin/login", r.headers["Location"])

    def test_session_fixation_and_rotation(self):
        before_token = csrf_of(self.c, "/admin/login")
        before_cookie = self.c.get_cookie("session").value
        login(self.c)
        self.assertNotEqual(before_cookie, self.c.get_cookie("session").value)
        r = self.c.post("/contact", data={"_csrf": before_token, "name": "TESTname",
                                          "email": "a@b.co", "message": "رسالة طويلة بما يكفي"})
        self.assertEqual(r.status_code, 400)  # رمز CSRF القديم لم يعد صالحًا بعد الدخول

    def test_new_login_revokes_old_sessions(self):
        login(self.c)
        other = app.test_client()
        login(other)
        self.assertEqual(self.c.get("/admin").status_code, 302)
        self.assertEqual(other.get("/admin").status_code, 200)

    def test_brute_force_lockout_and_backoff(self):
        for _ in range(5):
            self.assertEqual(login(self.c, "bad-guess-xx").status_code, 200)
        r = login(self.c)  # حتى كلمة المرور الصحيحة مرفوضة أثناء الحظر
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r.headers)
        self.assertEqual(self.c.get("/admin").status_code, 302)
        with shifted(35):  # الحظر الأول 30 ثانية
            self.assertEqual(login(self.c, "bad-guess-xx").status_code, 200)  # فشل سادس
            r = login(self.c)
            self.assertEqual(r.status_code, 429)  # الحظر الآن 60 ثانية: تصاعد
        with shifted(35 + 70):
            self.assertEqual(login(self.c).status_code, 302)  # بعد انتهاء الحظر ينجح الدخول الصحيح

    def test_reauth_for_sensitive_actions(self):
        with app.app_context():
            iid = appmod.execute("INSERT INTO items (kind, level, title) VALUES ('lesson', 2, 'TEST del')")
        login(self.c)
        token = csrf_of(self.c, "/admin")
        with shifted(11 * 60):
            r = self.c.post(f"/admin/delete/{iid}", data={"_csrf": token})
            self.assertEqual(r.status_code, 302)
            self.assertIn("/admin/reauth", r.headers["Location"])
            self.assertEqual(count("SELECT COUNT(*) FROM items WHERE id=?", (iid,)), 1)
            t2 = csrf_of(self.c, "/admin/reauth")
            bad = self.c.post("/admin/reauth", data={"_csrf": t2, "password": "nope-nope-nope"})
            self.assertEqual(bad.status_code, 200)
            ok = self.c.post("/admin/reauth", data={"_csrf": t2, "password": PASSWORD})
            self.assertEqual(ok.status_code, 302)
            r = self.c.post(f"/admin/delete/{iid}", data={"_csrf": token})
            self.assertEqual(r.status_code, 302)
            self.assertEqual(count("SELECT COUNT(*) FROM items WHERE id=?", (iid,)), 0)

    def test_idle_session_expires(self):
        login(self.c)
        with shifted(2 * 3600 + 120):
            self.assertEqual(self.c.get("/admin").status_code, 302)

    def test_delete_missing_item_is_404(self):
        login(self.c)
        token = csrf_of(self.c, "/admin")
        self.assertEqual(self.c.post("/admin/delete/987654", data={"_csrf": token}).status_code, 404)
        self.assertEqual(self.c.post("/admin/delete/99999999999999999999", data={"_csrf": token}).status_code, 404)


class TestCsrf(Base):
    def test_missing_invalid_csrf_rejected(self):
        form = {"name": "TESTname", "email": "a@b.co", "message": "رسالة طويلة بما يكفي"}
        self.assertEqual(self.c.post("/contact", data=form).status_code, 400)
        self.assertEqual(self.c.post("/contact", data={**form, "_csrf": "garbage"}).status_code, 400)
        self.assertEqual(self.c.post("/contact", data={**form, "_csrf": "ñé–رمز"}).status_code, 400)
        csrf_of(self.c)  # يهيّئ الجلسة
        self.assertEqual(self.c.post("/contact", data={**form, "_csrf": ""}).status_code, 400)
        self.assertEqual(self.c.post("/admin/login", data={"password": PASSWORD}).status_code, 400)
        self.assertEqual(self.c.post("/admin/logout").status_code, 400)
        self.assertEqual(count("SELECT COUNT(*) FROM messages"), 0)

    def test_valid_csrf_accepted(self):
        token = csrf_of(self.c)
        r = self.c.post("/contact", data={"_csrf": token, "name": "TESTname", "email": "a@b.co",
                                          "message": "رسالة طويلة بما يكفي"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(count("SELECT COUNT(*) FROM messages"), 1)

    def test_every_post_form_has_csrf_field(self):
        for tpl in (ROOT / "templates").glob("*.html"):
            text = tpl.read_text(encoding="utf-8")
            for form in re.findall(r"<form\b[^>]*>.*?</form>", text, re.S):
                if re.search(r'method="post"', form, re.I):
                    self.assertIn('name="_csrf"', form, f"{tpl.name}: نموذج POST بلا رمز CSRF")


class TestInput(Base):
    def test_sql_special_characters(self):
        before = count("SELECT COUNT(*) FROM items")
        for q in ["' OR 1=1 --", "'; DROP TABLE items; --", '" OR ""="', "%", "_", "\\", "a' UNION SELECT * FROM messages--"]:
            r = self.c.get("/search", query_string={"q": q})
            self.assertEqual(r.status_code, 200, q)
        self.assertEqual(self.c.get("/search", query_string={"q": "' OR 1=1 --"}).get_data(as_text=True).count('class="card '), 0)
        self.assertEqual(count("SELECT COUNT(*) FROM items"), before)
        token = csrf_of(self.c)
        msg = "O'Brien said \"hi\"; DROP TABLE messages;-- أكثر من عشرة"
        r = self.c.post("/contact", data={"_csrf": token, "name": "TEST O'Neil", "email": "a@b.co", "message": msg})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(count("SELECT message FROM messages"), msg)

    def test_oversized_input(self):
        token = csrf_of(self.c)
        r = self.c.post("/contact", data={"_csrf": token, "name": "x", "email": "a@b.co", "message": "m" * (2 * 1024 * 1024)})
        self.assertEqual(r.status_code, 413)
        r = self.c.post("/contact", data={"_csrf": token, "name": "n" * 500, "email": "a@b.co" + "c" * 300,
                                          "message": "m" * 5000})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(count("SELECT COUNT(*) FROM messages"), 0)
        self.assertEqual(self.c.get("/search", query_string={"q": "z" * 100000}).status_code, 200)

    def test_control_chars_stripped(self):
        token = csrf_of(self.c)
        self.c.post("/contact", data={"_csrf": token, "name": "TEST\x00na\x07me\nx", "email": "a@b.co",
                                      "message": "سطر\x00 أول طويل\r\nسطر ثان"})
        self.assertEqual(count("SELECT name FROM messages"), "TESTname x")
        self.assertEqual(count("SELECT message FROM messages"), "سطر أول طويل\nسطر ثان")

    def test_admin_form_validation(self):
        login(self.c)
        token = csrf_of(self.c, "/admin/new")
        base = {"_csrf": token, "kind": "lesson", "level": "2", "title": "TEST valid", "summary": "", "content": "", "link": ""}
        bad = [{"link": "javascript:alert(1)"}, {"link": "data:text/html,<script>1</script>"}, {"link": "https://"},
               {"link": "https://a b.com"}, {"link": "ftp://x.com"}, {"link": "https://x.com/" + "a" * 600},
               {"kind": "hacker"}, {"level": "7"}, {"level": "abc"}, {"title": "ab"}, {"title": "t" * 151},
               {"summary": "s" * 301}, {"content": "c" * 20001}]
        for patch in bad:
            before = count("SELECT COUNT(*) FROM items")
            r = self.c.post("/admin/new", data={**base, **patch})
            self.assertEqual(r.status_code, 200, patch)
            self.assertEqual(count("SELECT COUNT(*) FROM items"), before, patch)
        ok = self.c.post("/admin/new", data={**base, "link": "https://example.com/x?a=1"})
        self.assertEqual(ok.status_code, 302)

    def test_xss_is_escaped(self):
        login(self.c)
        token = csrf_of(self.c, "/admin/new")
        payload = '<script>alert(1)</script><img src=x onerror=alert(2)>'
        self.c.post("/admin/new", data={"_csrf": token, "kind": "lesson", "level": "2",
                                        "title": "TEST " + payload, "summary": payload, "content": payload, "link": ""})
        iid = count("SELECT id FROM items WHERE title LIKE 'TEST <script>%'")
        for path in [f"/item/{iid}", "/lessons/2", "/search?q=TEST", "/admin"]:
            html = self.c.get(path).get_data(as_text=True)
            self.assertNotIn("<script>alert", html, path)
            self.assertNotIn("<img src=x", html, path)
        self.assertIn("&lt;script&gt;", self.c.get(f"/item/{iid}").get_data(as_text=True))
        # رسالة تواصل تحمل HTML تظهر مهرَّبة في لوحة التحكم
        t = csrf_of(self.c, "/contact")
        self.c.post("/contact", data={"_csrf": t, "name": "TEST <b>x</b>", "email": "a@b.co", "message": payload + " نص كاف"})
        html = self.c.get("/admin").get_data(as_text=True)
        self.assertNotIn("<b>x</b>", html)
        self.assertNotIn("<script>alert", html)

    def test_unsafe_link_never_rendered_even_if_in_db(self):
        with app.app_context():
            iid = appmod.execute("INSERT INTO items (kind, level, title, link) VALUES "
                                 "('lesson', 2, 'TEST evil', 'javascript:alert(1)')")
        self.assertNotIn("javascript:", self.c.get(f"/item/{iid}").get_data(as_text=True))

    def test_contact_rate_limit(self):
        token = csrf_of(self.c)
        form = {"_csrf": token, "name": "TESTname", "email": "a@b.co", "message": "رسالة طويلة بما يكفي"}
        for _ in range(appmod.CONTACT_MAX):
            self.assertEqual(self.c.post("/contact", data=form).status_code, 302)
        r = self.c.post("/contact", data=form)
        self.assertEqual(r.status_code, 429)
        self.assertEqual(count("SELECT COUNT(*) FROM messages"), appmod.CONTACT_MAX)


class TestHeaders(Base):
    def test_security_headers(self):
        h = self.c.get("/").headers
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Referrer-Policy"], "same-origin")
        self.assertIn("camera=()", h["Permissions-Policy"])
        csp = h["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertNotIn("Strict-Transport-Security", h)  # HSTS لا يُرسل خارج الإنتاج/HTTPS
        for name in h.keys():
            self.assertFalse(name.lower().startswith("access-control-"), name)

    def test_no_cors_even_with_origin(self):
        r = self.c.get("/", headers={"Origin": "https://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", r.headers)
        r = self.c.options("/", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertNotIn("Access-Control-Allow-Origin", r.headers)

    def test_sensitive_pages_not_cached(self):
        for path in ["/admin/login", "/contact", "/admin"]:
            cc = self.c.get(path).headers.get("Cache-Control", "")
            self.assertIn("no-store", cc, path)
        login(self.c)
        self.assertIn("no-store", self.c.get("/admin").headers["Cache-Control"])
        self.assertIn("no-store", self.c.get("/").headers["Cache-Control"])  # مدير مسجّل: لا تخزين

    def test_csp_covers_all_resources_in_templates(self):
        """كل مورد خارجي في القوالب يجب أن يكون ضمن CSP، ولا شيء مضمّن."""
        csp = appmod.CSP
        for tpl in (ROOT / "templates").glob("*.html"):
            text = tpl.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"<script(?![^>]*\bsrc=)", f"{tpl.name}: سكربت مضمّن")
            self.assertNotRegex(text, r"\sstyle\s*=", f"{tpl.name}: style مضمّن")
            self.assertNotRegex(text, r"\son[a-z]+\s*=", f"{tpl.name}: معالج حدث مضمّن")
            self.assertNotRegex(text, r"<style", f"{tpl.name}: وسم style مضمّن")
            # الموارد الخارجية المحمَّلة (لا روابط التنقل <a>) يجب أن يسمح بها CSP
            for host in re.findall(r'<(?:link|script|img)\b[^>]*(?:src|href)="(https?://[^/"]+)', text):
                self.assertIn(host, csp, f"{tpl.name}: {host} غير مسموح في CSP")
        css = (ROOT / "static/css/style.css").read_text(encoding="utf-8")
        self.assertNotRegex(css, r"@import|url\(\s*['\"]?https?:")

    def test_session_cookie_not_in_urls(self):
        login(self.c)
        r = self.c.get("/admin")
        html = r.get_data(as_text=True)
        self.assertNotRegex(html, r"(?i)(sid|session|jsessionid|token)=")
        self.assertNotIn(self.c.get_cookie("session").value, html)


class TestTemplates(unittest.TestCase):
    def test_no_unsafe_rendering_constructs(self):
        for tpl in (ROOT / "templates").glob("*.html"):
            text = tpl.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\|\s*safe\b", f"{tpl.name}: |safe")
            self.assertNotRegex(text, r"Markup|autoescape\s+false|\|\s*striptags\s*\|\s*safe", tpl.name)
        self.assertTrue(app.jinja_env.autoescape)  # التهريب مفعّل للقوالب .html


class TestErrors(Base):
    def test_unexpected_error_hides_details(self):
        secret_detail = "INTERNAL-DETAIL-XYZ-/srv/app.py"
        with mock.patch.object(appmod, "query", side_effect=RuntimeError(secret_detail)):
            with self.assertLogs(app.logger.name, level="ERROR") as logs:
                r = self.c.get("/achievements")
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 500)
        for needle in (secret_detail, "Traceback", "RuntimeError", "app.py", "Werkzeug"):
            self.assertNotIn(needle, body)
        self.assertTrue(any("unexpected_error" in line for line in logs.output))  # التفاصيل في السجل فقط

    def test_http_errors_use_clean_page(self):
        for path, code in [("/nope", 404), ("/lessons/9", 404)]:
            r = self.c.get(path)
            self.assertEqual(r.status_code, code)
            self.assertNotIn("Traceback", r.get_data(as_text=True))


class TestLogging(Base):
    def test_audit_events_without_secrets(self):
        with self.assertLogs("infoplatform.security", level="INFO") as logs:
            self.c.get("/admin")
            login(self.c, "TOP-SECRET-WRONG-PW")
            login(self.c)
            token = csrf_of(self.c, "/admin")
            self.c.post("/admin/logout", data={"_csrf": token})
            self.c.post("/contact", data={"name": "x"})  # CSRF مفقود
        text = "\n".join(logs.output)
        for event in ("admin_unauthorized", "admin_login_failed", "admin_login_success", "admin_logout", "csrf_rejected"):
            self.assertIn(event, text)
        for secret in ("TOP-SECRET-WRONG-PW", PASSWORD, SECRET, "session=", "password="):
            self.assertNotIn(secret, text)

    def test_log_injection_neutralized(self):
        with self.assertLogs("infoplatform.security", level="INFO") as logs:
            self.c.get("/admin/%0A%0Afake_event%20ip=1.1.1.1")
            self.c.get("/admin")
        for line in logs.output:
            self.assertNotIn("\nfake_event", line)


class TestStartupConfig(unittest.TestCase):
    """إعدادات الإنتاج تُختبر في عمليات منفصلة لأنها تُقرأ عند الاستيراد."""

    def test_production_refuses_missing_or_weak_secrets(self):
        good_pw = {"ADMIN_PASSWORD": PASSWORD}
        cases = {
            "no SECRET_KEY": {"RENDER": "1", **good_pw},
            "short SECRET_KEY": {"RENDER": "1", "SECRET_KEY": "short", **good_pw},
            "default SECRET_KEY": {"RENDER": "1", "SECRET_KEY": "dev-secret-change-me", **good_pw},
            "no admin secret": {"RENDER": "1", "SECRET_KEY": SECRET},
            "default ADMIN_PASSWORD": {"RENDER": "1", "SECRET_KEY": SECRET, "ADMIN_PASSWORD": "admin123"},
            "weak ADMIN_PASSWORD": {"RENDER": "1", "SECRET_KEY": SECRET, "ADMIN_PASSWORD": "short1"},
            "bad hash format": {"RENDER": "1", "SECRET_KEY": SECRET, "ADMIN_PASSWORD_HASH": "plaintext-not-a-hash"},
            "APP_ENV production": {"APP_ENV": "production"},
        }
        for name, env in cases.items():
            r = run_py("import app", **env)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn("RuntimeError", r.stderr, name)
            self.assertNotIn(SECRET, r.stderr + r.stdout)
            self.assertNotIn("admin123", r.stderr.replace("ADMIN_PASSWORD", ""))

    def test_production_mode_behaviour(self):
        code = """
import json, re
import app as m
c = m.app.test_client()
H = "https://example.test"
r = c.get("/", base_url=H)
tok = re.search(r'name="_csrf" value="([^"]+)"', c.get("/admin/login", base_url=H).get_data(as_text=True)).group(1)
login = c.post("/admin/login", data={"_csrf": tok, "password": PW}, base_url=H)
cookie = c.get_cookie("__Host-session", domain="example.test")
print(json.dumps({
  "debug": m.app.debug, "hsts": r.headers.get("Strict-Transport-Security"),
  "csp": r.headers["Content-Security-Policy"], "login": login.status_code,
  "cookie_name": m.app.config["SESSION_COOKIE_NAME"], "secure": m.app.config["SESSION_COOKIE_SECURE"],
  "cookie_secure": bool(cookie and cookie.secure), "cookie_http_only": bool(cookie and cookie.http_only),
  "cookie_path": cookie.path if cookie else None,
  "http_hsts": c.get("/", base_url="http://example.test").headers.get("Strict-Transport-Security"),
  "not_found": c.get("/missing", base_url=H).status_code,
}))
""".replace("PW", repr(PASSWORD))
        r = run_py(code, RENDER="1", SECRET_KEY=SECRET, ADMIN_PASSWORD=PASSWORD, FLASK_DEBUG="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertFalse(out["debug"])  # FLASK_DEBUG=1 لا يفعّل التصحيح في الإنتاج
        self.assertIn("max-age=31536000", out["hsts"])
        self.assertIsNone(out["http_hsts"])  # لا HSTS على اتصال غير آمن
        self.assertIn("upgrade-insecure-requests", out["csp"])
        self.assertEqual(out["login"], 302)
        self.assertEqual(out["cookie_name"], "__Host-session")
        self.assertTrue(out["secure"] and out["cookie_secure"] and out["cookie_http_only"])
        self.assertEqual(out["cookie_path"], "/")
        self.assertEqual(out["not_found"], 404)

    def test_hash_based_admin_password(self):
        from werkzeug.security import generate_password_hash
        pw_hash = generate_password_hash(PASSWORD, method="scrypt")
        code = """
import re
import app as m
c = m.app.test_client()
def attempt(pw):
    tok = re.search(r'name="_csrf" value="([^"]+)"', c.get("/admin/login").get_data(as_text=True)).group(1)
    return c.post("/admin/login", data={"_csrf": tok, "password": pw}).status_code
print(attempt("wrong"), attempt(PW))
""".replace("PW", repr(PASSWORD))
        r = run_py(code, RENDER="1", SECRET_KEY=SECRET, ADMIN_PASSWORD_HASH=pw_hash)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1].split(), ["200", "302"])

    def test_dev_without_password_has_no_default_login(self):
        code = """
import re
import app as m
c = m.app.test_client()
tok = re.search(r'name="_csrf" value="([^"]+)"', c.get("/admin/login").get_data(as_text=True)).group(1)
print(c.post("/admin/login", data={"_csrf": tok, "password": "admin123"}).status_code, c.get("/admin").status_code)
"""
        r = run_py(code)  # بلا SECRET_KEY ولا كلمة مرور
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1].split(), ["503", "302"])

    def test_concurrent_init_does_not_duplicate_seed(self):
        db = os.path.join(tempfile.mkdtemp(prefix="infoplatform-race-"), "race.db")
        env = {**os.environ, "DATABASE_PATH": db, "SECRET_KEY": SECRET, "ADMIN_PASSWORD": PASSWORD}
        for var in ("RENDER", "APP_ENV"):
            env.pop(var, None)
        procs = [subprocess.Popen([sys.executable, "-c", "import app"], cwd=ROOT, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(6)]
        for p in procs:
            p.wait(timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr.read().decode())
        import sqlite3
        d = sqlite3.connect(db)
        self.assertEqual(d.execute("SELECT COUNT(*) FROM items").fetchone()[0], len(appmod.SEED))
        d.close()
        self.assertEqual(oct(os.stat(db).st_mode & 0o777), "0o600")

    def test_read_path_cannot_write(self):
        """الاتصال الافتراضي للقراءة فقط: أي استعلام قراءة لا يقدر على التعديل."""
        import sqlite3
        with app.app_context():
            with self.assertRaises(sqlite3.OperationalError):
                appmod.query("DELETE FROM items WHERE id=-1")


class TestRepoHygiene(unittest.TestCase):
    def test_no_hardcoded_secrets_or_debug(self):
        src = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("dev-secret-change-me\")", src)
        self.assertNotRegex(src, r"environ\.get\(\s*[\"'](SECRET_KEY|ADMIN_PASSWORD)[\"']\s*,\s*[\"'][^\"']+[\"']")
        self.assertNotRegex(src, r"debug\s*=\s*True")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("admin123", readme)  # لا كلمة مرور افتراضية في التوثيق

    def test_requirements_and_gitignore(self):
        reqs = (ROOT / "requirements.txt").read_text()
        self.assertRegex(reqs, r"(?im)^gunicorn")
        self.assertRegex(reqs, r"(?im)^flask")
        ignore = (ROOT / ".gitignore").read_text()
        for pattern in (".env", "database.db", "*.bak"):
            self.assertIn(pattern, ignore)
        render = (ROOT / "render.yaml").read_text()
        self.assertIn("gunicorn app:app", render)
        self.assertNotRegex(render, r"flask run|python app\.py")
        self.assertNotRegex(render, r"(?i)value:\s*(admin|password)")


if __name__ == "__main__":
    unittest.main()
