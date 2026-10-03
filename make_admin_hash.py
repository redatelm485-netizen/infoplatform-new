"""يولّد قيمة ADMIN_PASSWORD_HASH (بصمة scrypt) لوضعها في متغيرات بيئة Render.

الاستعمال:  python make_admin_hash.py
لا تُحفظ كلمة المرور في أي ملف ولا تُطبع؛ تُطبع البصمة فقط.
"""
import getpass
import sys

from werkzeug.security import generate_password_hash


def main():
    pw = getpass.getpass("كلمة مرور المدير (12 حرفًا على الأقل): ")
    if len(pw) < 12:
        sys.exit("كلمة المرور قصيرة: يلزم 12 حرفًا على الأقل.")
    if pw != getpass.getpass("أعد كتابتها للتأكيد: "):
        sys.exit("كلمتا المرور غير متطابقتين.")
    print(generate_password_hash(pw, method="scrypt"))


if __name__ == "__main__":
    main()
