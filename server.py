"""WISD Science Academy small, dependency-free web server.

Run with WISD_ADMIN_PASSWORD set on first start. SQLite data and private uploads
are kept beside this file in wisd_data/.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import getpass
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("WISD_DATA_DIR", str(ROOT / "wisd_data"))).expanduser().resolve()
FILES = DATA / "library"
DB = DATA / "academy.sqlite3"
PHONE = "0727650086"
PAYEE = "MASENGESHO Bertin"
ADMIN_NAME = "MASENGESHO Bertin"
PORT = int(os.environ.get("PORT", "8000"))
MAX_BODY = 21 * 1024 * 1024
SESSION_SECONDS = 60 * 60 * 24 * 14
LOGIN_FAILURES: dict[str, list[int]] = {}

DATA.mkdir(exist_ok=True)
FILES.mkdir(exist_ok=True)


@contextmanager
def connect():
    con = sqlite3.connect(DB, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        with con:
            yield con
    finally:
        con.close()


def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL,
          email TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'applicant',
          membership_status TEXT NOT NULL DEFAULT 'none', created_at INTEGER NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS users_phone ON users(phone);
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS password_setup_tokens(
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS applications(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL,
          details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'payment_pending', created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS payments(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL,
          target_id INTEGER, amount INTEGER NOT NULL CHECK(amount=100), transaction_ref TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, reviewed_at INTEGER);
        CREATE TABLE IF NOT EXISTS books(
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, author TEXT DEFAULT '', category TEXT DEFAULT '',
          description TEXT DEFAULT '', filename TEXT NOT NULL, original_name TEXT NOT NULL,
          content_type TEXT NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS entitlements(
          user_id INTEGER NOT NULL REFERENCES users(id), book_id INTEGER NOT NULL REFERENCES books(id),
          payment_id INTEGER NOT NULL REFERENCES payments(id), PRIMARY KEY(user_id,book_id));
        CREATE TABLE IF NOT EXISTS posts(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL,
          body TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS post_replies(
          id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
          admin_user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at INTEGER NOT NULL);
        """)
        password = os.environ.get("WISD_ADMIN_PASSWORD", "")
        admin = db.execute("SELECT id FROM users WHERE role='admin'").fetchone()
        if not admin and password:
            db.execute("INSERT INTO users(name,phone,email,password_hash,role,membership_status,created_at) VALUES(?,?,?,?,?,?,?)",
                       (ADMIN_NAME, PHONE, "", hash_password(password), "admin", "active", int(time.time())))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return base64.b64encode(salt + digest).decode()


def check_password(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], 310_000)
        return hmac.compare_digest(raw[16:], actual)
    except (ValueError, TypeError):
        return False


def normalize_phone(value: str) -> str:
    phone = re.sub(r"\s+", "", value)
    if phone.startswith("+250"): phone = "0" + phone[4:]
    elif phone.startswith("250"): phone = "0" + phone[3:]
    elif len(phone) == 9 and phone.startswith("7"): phone = "0" + phone
    return phone


class Handler(BaseHTTPRequestHandler):
    server_version = "WISD/1.0"

    def log_message(self, fmt, *args):
        # Keep request details (which may include personal data) out of terminal logs.
        return

    def send_json(self, status, payload, headers=None):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' https: data:; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https:; frame-ancestors 'none'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > MAX_BODY:
            raise ValueError("Request is too large (20 MB maximum).")
        return json.loads(self.rfile.read(size) or b"{}")

    def current_user(self):
        cookie = self.headers.get("Cookie", "")
        token = next((part.split("=", 1)[1] for part in cookie.split("; ") if part.startswith("wisd_session=")), "")
        if not token:
            return None
        with connect() as db:
            return db.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
                              (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()

    def require_user(self, admin=False, member=False):
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "Sign in is required."})
            return None
        if admin and user["role"] != "admin":
            self.send_json(403, {"error": "Administrator access required."})
            return None
        if member and user["membership_status"] != "active" and user["role"] != "admin":
            self.send_json(403, {"error": "An approved academy membership is required."})
            return None
        return user

    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        try:
            if path == "/api/session":
                user = self.current_user()
                if not user:
                    return self.send_json(200, {"user": None})
                with connect() as db:
                    application = db.execute("SELECT status,kind FROM applications WHERE user_id=? ORDER BY created_at DESC LIMIT 1", (user["id"],)).fetchone()
                return self.send_json(200, {"user": {"id": user["id"], "name": user["name"], "role": user["role"], "membershipStatus": user["membership_status"], "applicationStatus": application["status"] if application else None, "applicationKind": application["kind"] if application else None}})
            if path == "/api/books":
                with connect() as db:
                    rows = db.execute("SELECT id,title,author,category,description,size,created_at FROM books ORDER BY created_at DESC").fetchall()
                return self.send_json(200, {"books": [dict(r) for r in rows]})
            if path == "/api/community":
                user = self.require_user(member=True)
                if not user: return
                with connect() as db:
                    rows = db.execute("SELECT p.id,p.title,p.body,p.created_at,u.name FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 100").fetchall()
                    posts = [dict(r) for r in rows]
                    if posts:
                        placeholders = ",".join("?" for _ in posts)
                        replies = db.execute(f"SELECT id,post_id,body,created_at FROM post_replies WHERE post_id IN ({placeholders}) ORDER BY created_at", [post["id"] for post in posts]).fetchall()
                        by_post = {}
                        for reply in replies: by_post.setdefault(reply["post_id"], []).append({"body": reply["body"], "created_at": reply["created_at"], "name": "Wisdom Science Academy"})
                        for post in posts: post["replies"] = by_post.get(post["id"], [])
                return self.send_json(200, {"posts": posts})
            access = re.fullmatch(r"/api/books/(\d+)/access", path)
            if access:
                user = self.current_user()
                if not user: return self.send_json(401, {"error": "Sign in first."})
                book_id = int(access.group(1))
                with connect() as db:
                    exists = db.execute("SELECT id FROM books WHERE id=?", (book_id,)).fetchone()
                    allowed = user["role"] == "admin" or bool(db.execute("SELECT 1 FROM entitlements WHERE user_id=? AND book_id=?", (user["id"], book_id)).fetchone())
                if not exists: return self.send_json(404, {"error": "Resource not found."})
                return self.send_json(200, {"entitled": allowed})
            match = re.fullmatch(r"/api/books/(\d+)/(read|download)", path)
            if match:
                book_id, action = int(match.group(1)), match.group(2)
                user = self.current_user() if action == "download" else None
                with connect() as db:
                    book = db.execute("SELECT * FROM books WHERE id=?", (book_id,)).fetchone()
                    if not book: return self.send_json(404, {"error": "Resource not found."})
                    if action == "download":
                        if not user: return self.send_json(401, {"error": "Sign in and submit a 100 RWF download payment for this resource."})
                        if user["role"] != "admin" and not db.execute("SELECT 1 FROM entitlements WHERE user_id=? AND book_id=?", (user["id"], book_id)).fetchone():
                            return self.send_json(402, {"error": "A 100 RWF payment for this download must be verified by the administrator first."})
                return self.file_response(book, inline=(action == "read"))
            if path == "/api/admin/overview":
                if not self.require_user(admin=True): return
                with connect() as db:
                    apps = db.execute("SELECT a.id,a.user_id,a.kind,a.details,a.status,a.created_at,u.name,u.phone,u.email,EXISTS(SELECT 1 FROM password_setup_tokens t WHERE t.user_id=u.id) AS setup_pending FROM applications a JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC").fetchall()
                    pays = db.execute("SELECT p.*,u.name,u.phone FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC").fetchall()
                    books = db.execute("SELECT id,title,author,category,created_at FROM books ORDER BY created_at DESC").fetchall()
                    posts = db.execute("SELECT p.id,p.title,p.body,p.created_at,u.name FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 100").fetchall()
                    thread_posts = [dict(r) for r in posts]
                    if thread_posts:
                        placeholders = ",".join("?" for _ in thread_posts)
                        replies = db.execute(f"SELECT post_id,body,created_at FROM post_replies WHERE post_id IN ({placeholders}) ORDER BY created_at", [post["id"] for post in thread_posts]).fetchall()
                        by_post = {}
                        for reply in replies: by_post.setdefault(reply["post_id"], []).append({"body": reply["body"], "created_at": reply["created_at"]})
                        for post in thread_posts: post["replies"] = by_post.get(post["id"], [])
                return self.send_json(200, {"applications": [dict(r) for r in apps], "payments": [dict(r) for r in pays], "books": [dict(r) for r in books], "posts": thread_posts})
            if path in ("/", "/mywebsite.html", "/programs", "/library", "/community", "/register", "/admin", "/set-password"):
                data = (ROOT / "mywebsite.html").read_bytes()
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data); return
            if path.startswith("/api/"):
                return self.send_json(404, {"error": "API route not found."})
            return self.send_json(404, {"error": "Page not found."})
        except (ValueError, sqlite3.Error) as exc:
            self.send_json(400, {"error": str(exc)})

    def file_response(self, book, inline=False):
        file_path = FILES / book["filename"]
        if not file_path.is_file(): return self.send_json(404, {"error": "Stored resource file is missing."})
        data = file_path.read_bytes()
        disposition = "inline" if inline and book["content_type"] == "application/pdf" else "attachment"
        if inline and book["content_type"] == "text/plain":
            return self.send_json(200, {"title": book["title"], "text": data.decode("utf-8", errors="replace")})
        self.send_response(200)
        self.send_header("Content-Type", book["content_type"])
        self.send_header("Content-Disposition", f'{disposition}; filename="{book["original_name"]}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        try:
            payload = self.body()
            if path == "/api/register": return self.register(payload)
            if path == "/api/login": return self.login(payload)
            if path == "/api/logout":
                user = self.current_user()
                if user:
                    token = next((part.split("=", 1)[1] for part in self.headers.get("Cookie", "").split("; ") if part.startswith("wisd_session=")), "")
                    with connect() as db: db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
                return self.send_json(200, {"ok": True}, {"Set-Cookie": "wisd_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            if path == "/api/account/password": return self.change_password(payload)
            if path == "/api/account/setup-password": return self.setup_password(payload)
            if path == "/api/payment": return self.payment(payload)
            if path == "/api/community": return self.post_discussion(payload)
            if path == "/api/admin/reply": return self.reply_to_post(payload)
            if path == "/api/admin/review": return self.review(payload)
            if path == "/api/admin/users": return self.add_user(payload)
            if path == "/api/admin/setup-code": return self.issue_setup_code(payload)
            if path == "/api/admin/books": return self.add_book(payload)
            if path.startswith("/api/"): return self.send_json(404, {"error": "API route not found."})
            return self.send_json(404, {"error": "Page not found."})
        except (ValueError, KeyError, TypeError, sqlite3.Error) as exc:
            return self.send_json(400, {"error": str(exc)})

    def do_DELETE(self):
        path = unquote(urlparse(self.path).path)
        match = re.fullmatch(r"/api/admin/books/(\d+)", path)
        if not match: return self.send_json(404, {"error": "API route not found."})
        if not self.require_user(admin=True): return
        book_id = int(match.group(1))
        with connect() as db:
            book = db.execute("SELECT filename FROM books WHERE id=?", (book_id,)).fetchone()
            if not book: return self.send_json(404, {"error": "Resource not found."})
            db.execute("DELETE FROM entitlements WHERE book_id=?", (book_id,))
            db.execute("DELETE FROM books WHERE id=?", (book_id,))
        try: (FILES / book["filename"]).unlink(missing_ok=True)
        except OSError: pass
        self.send_json(200, {"ok": True})

    def register(self, p):
        kind = str(p.get("kind", ""))
        name, phone, password = str(p.get("name", "")).strip(), normalize_phone(str(p.get("phone", ""))), str(p.get("password", ""))
        if kind not in ("member", "student"): return self.send_json(400, {"error": "Choose membership or student enrollment."})
        if len(name) < 2 or len(name) > 100: return self.send_json(400, {"error": "Enter your full name."})
        if not re.fullmatch(r"(?:\+?250|0)?7\d{8}", phone): return self.send_json(400, {"error": "Enter a valid Rwanda mobile number."})
        if len(password) < 12: return self.send_json(400, {"error": "Password must be at least 12 characters."})
        details = {k: str(p.get(k, "")).strip()[:500] for k in ("email", "program", "level", "mode", "goals")}
        ref = re.sub(r"[^A-Za-z0-9 ._/-]", "", str(p.get("transactionRef", ""))).strip()[:80]
        if len(ref) < 4: return self.send_json(400, {"error": "Enter the 100 RWF mobile money transaction reference."})
        with connect() as db:
            if db.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone(): return self.send_json(409, {"error": "An account with this phone already exists. Sign in instead."})
            if db.execute("SELECT id FROM payments WHERE transaction_ref=?", (ref,)).fetchone(): return self.send_json(409, {"error": "This transaction reference has already been submitted."})
            cur = db.execute("INSERT INTO users(name,phone,email,password_hash,created_at) VALUES(?,?,?,?,?)", (name, phone, details["email"], hash_password(password), int(time.time())))
            user_id = cur.lastrowid
            app = db.execute("INSERT INTO applications(user_id,kind,details,created_at) VALUES(?,?,?,?)", (user_id, kind, json.dumps(details), int(time.time())))
            db.execute("INSERT INTO payments(user_id,kind,amount,transaction_ref,created_at) VALUES(?,?,100,?,?)", (user_id, kind, ref, int(time.time())))
        return self.send_json(201, {"ok": True, "applicationId": app.lastrowid, "message": "Account and payment reference recorded. Approval follows manual administrator verification."})

    def login(self, p):
        phone = normalize_phone(str(p.get("phone", "")))
        ip = self.client_address[0]
        now = int(time.time())
        recent = [stamp for stamp in LOGIN_FAILURES.get(ip, []) if stamp > now - 900]
        if len(recent) >= 8:
            return self.send_json(429, {"error": "Too many unsuccessful sign-in attempts. Wait 15 minutes, then try again."}, {"Retry-After": "900"})
        with connect() as db: user = db.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        if not user or not check_password(str(p.get("password", "")), user["password_hash"]):
            recent.append(now); LOGIN_FAILURES[ip] = recent
            return self.send_json(401, {"error": "Phone number or password is incorrect."})
        LOGIN_FAILURES.pop(ip, None)
        token = secrets.token_urlsafe(32)
        with connect() as db: db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"], int(time.time())+SESSION_SECONDS))
        cookie = f"wisd_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}" + ("; Secure" if os.environ.get("WISD_HTTPS") == "1" else "")
        self.send_json(200, {"ok": True, "user": {"name": user["name"], "role": user["role"], "membershipStatus": user["membership_status"]}}, {"Set-Cookie": cookie})

    def change_password(self, p):
        user = self.require_user()
        if not user: return
        current = str(p.get("currentPassword", ""))
        new = str(p.get("newPassword", ""))
        if not check_password(current, user["password_hash"]): return self.send_json(401, {"error": "Current password is incorrect."})
        if len(new) < 12: return self.send_json(400, {"error": "Choose a new password with at least 12 characters."})
        if hmac.compare_digest(current, new): return self.send_json(400, {"error": "Choose a password different from your current one."})
        token = secrets.token_urlsafe(32)
        with connect() as db:
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), user["id"]))
            db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
            db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"], int(time.time())+SESSION_SECONDS))
        cookie = f"wisd_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}" + ("; Secure" if os.environ.get("WISD_HTTPS") == "1" else "")
        self.send_json(200, {"ok": True, "message": "Password changed. Your other signed-in sessions have been ended."}, {"Set-Cookie": cookie})

    def setup_password(self, p):
        phone = normalize_phone(str(p.get("phone", "")))
        code = str(p.get("setupCode", "")).strip()
        password = str(p.get("newPassword", ""))
        if len(password) < 12: return self.send_json(400, {"error": "Choose a password with at least 12 characters."})
        if len(code) < 20: return self.send_json(400, {"error": "Enter the complete one-time setup code."})
        token_hash = hashlib.sha256(code.encode()).hexdigest()
        with connect() as db:
            user = db.execute("SELECT u.id,u.name,u.role,t.expires_at FROM password_setup_tokens t JOIN users u ON u.id=t.user_id WHERE u.phone=? AND t.token_hash=?", (phone, token_hash)).fetchone()
            if not user: return self.send_json(400, {"error": "Phone number and setup code did not match."})
            if user["expires_at"] < int(time.time()):
                db.execute("DELETE FROM password_setup_tokens WHERE token_hash=?", (token_hash,))
                return self.send_json(400, {"error": "This setup code has expired. Ask the academy to issue a new one."})
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), user["id"]))
            db.execute("DELETE FROM password_setup_tokens WHERE token_hash=?", (token_hash,))
        self.send_json(200, {"ok": True, "role": user["role"], "message": "Your password is set. You can now sign in."})

    def payment(self, p):
        user = self.require_user()
        if not user: return
        kind = str(p.get("kind", ""))
        if kind not in ("member", "student", "download"): return self.send_json(400, {"error": "Unknown payment purpose."})
        target_id = int(p["bookId"]) if kind == "download" else None
        ref = re.sub(r"[^A-Za-z0-9 ._/-]", "", str(p.get("transactionRef", ""))).strip()[:80]
        if len(ref) < 4: return self.send_json(400, {"error": "Enter the mobile money transaction reference."})
        with connect() as db:
            if kind == "download" and not db.execute("SELECT id FROM books WHERE id=?", (target_id,)).fetchone(): return self.send_json(404, {"error": "Resource not found."})
            if kind in ("member", "student"):
                application = db.execute("SELECT * FROM applications WHERE user_id=? AND kind=? ORDER BY created_at DESC LIMIT 1", (user["id"], kind)).fetchone()
                if not application: return self.send_json(400, {"error": "No matching enrollment request was found."})
                if application["status"] == "approved": return self.send_json(409, {"error": "This request is already approved."})
                if application["status"] == "payment_pending": return self.send_json(409, {"error": "Your current payment reference is still awaiting review."})
            prior = db.execute("SELECT id FROM payments WHERE transaction_ref=?", (ref,)).fetchone()
            if prior: return self.send_json(409, {"error": "This transaction reference has already been submitted."})
            cur = db.execute("INSERT INTO payments(user_id,kind,target_id,amount,transaction_ref,created_at) VALUES(?,?,?,100,?,?)", (user["id"], kind, target_id, ref, int(time.time())))
            if kind in ("member", "student"):
                db.execute("UPDATE applications SET status='payment_pending' WHERE id=?", (application["id"],))
        self.send_json(201, {"ok": True, "paymentId": cur.lastrowid, "message": "Submitted for manual review. Your access changes after administrator approval."})

    def post_discussion(self, p):
        user = self.require_user(member=True)
        if not user: return
        title, body = str(p.get("title", "")).strip(), str(p.get("body", "")).strip()
        if not 3 <= len(title) <= 120 or not 1 <= len(body) <= 2000: return self.send_json(400, {"error": "Use a title (3–120 characters) and message (up to 2,000 characters)."})
        with connect() as db: db.execute("INSERT INTO posts(user_id,title,body,created_at) VALUES(?,?,?,?)", (user["id"], title, body, int(time.time())))
        self.send_json(201, {"ok": True})

    def reply_to_post(self, p):
        admin = self.require_user(admin=True)
        if not admin: return
        post_id = int(p.get("postId", 0))
        body = str(p.get("body", "")).strip()
        if not 1 <= len(body) <= 2000: return self.send_json(400, {"error": "Write a reply of up to 2,000 characters."})
        with connect() as db:
            if not db.execute("SELECT id FROM posts WHERE id=?", (post_id,)).fetchone(): return self.send_json(404, {"error": "Discussion post not found."})
            db.execute("INSERT INTO post_replies(post_id,admin_user_id,body,created_at) VALUES(?,?,?,?)", (post_id, admin["id"], body, int(time.time())))
        self.send_json(201, {"ok": True, "message": "Reply posted as Wisdom Science Academy."})

    def review(self, p):
        admin = self.require_user(admin=True)
        if not admin: return
        payment_id, status = int(p.get("paymentId", 0)), str(p.get("status", ""))
        if status not in ("approved", "rejected"): return self.send_json(400, {"error": "Choose approved or rejected."})
        with connect() as db:
            payment = db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
            if not payment: return self.send_json(404, {"error": "Payment record not found."})
            db.execute("UPDATE payments SET status=?,reviewed_at=? WHERE id=?", (status, int(time.time()), payment_id))
            if status == "approved":
                if payment["kind"] == "download": db.execute("INSERT OR IGNORE INTO entitlements(user_id,book_id,payment_id) VALUES(?,?,?)", (payment["user_id"], payment["target_id"], payment_id))
                elif payment["kind"] == "member": db.execute("UPDATE users SET membership_status='active',role='member' WHERE id=?", (payment["user_id"],))
                elif payment["kind"] == "student": db.execute("UPDATE users SET role='student' WHERE id=?", (payment["user_id"],))
                db.execute("UPDATE applications SET status='approved' WHERE user_id=? AND kind=? AND status='payment_pending'", (payment["user_id"], payment["kind"]))
            elif payment["kind"] != "download":
                db.execute("UPDATE applications SET status='payment_rejected' WHERE user_id=? AND kind=? AND status='payment_pending'", (payment["user_id"], payment["kind"]))
        self.send_json(200, {"ok": True})

    def add_user(self, p):
        admin = self.require_user(admin=True)
        if not admin: return
        kind = str(p.get("kind", ""))
        name = str(p.get("name", "")).strip()[:100]
        phone = normalize_phone(str(p.get("phone", "")))
        ref = re.sub(r"[^A-Za-z0-9 ._/-]", "", str(p.get("transactionRef", ""))).strip()[:80]
        if kind not in ("member", "student"): return self.send_json(400, {"error": "Choose a member or student account."})
        if len(name) < 2: return self.send_json(400, {"error": "Enter the person's full name."})
        if not re.fullmatch(r"(?:\+?250|0)?7\d{8}", phone): return self.send_json(400, {"error": "Enter a valid Rwanda mobile number."})
        if len(ref) < 4: return self.send_json(400, {"error": "Enter the transaction reference you have verified."})
        if p.get("paymentVerified") is not True: return self.send_json(400, {"error": "Confirm that you checked the 100 RWF payment before creating this account."})
        details = {"program": str(p.get("program", ""))[:160], "level": str(p.get("level", ""))[:60], "createdByAdmin": True}
        now = int(time.time())
        setup_code = secrets.token_urlsafe(24)
        with connect() as db:
            if db.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone(): return self.send_json(409, {"error": "An account already uses this phone number."})
            if db.execute("SELECT id FROM payments WHERE transaction_ref=?", (ref,)).fetchone(): return self.send_json(409, {"error": "This transaction reference has already been recorded."})
            cur = db.execute("INSERT INTO users(name,phone,password_hash,role,membership_status,created_at) VALUES(?,?,?,?,?,?)",
                             (name, phone, hash_password(secrets.token_urlsafe(48)), kind, "active" if kind == "member" else "none", now))
            user_id = cur.lastrowid
            db.execute("INSERT INTO applications(user_id,kind,details,status,created_at) VALUES(?,?,?,'approved',?)", (user_id, kind, json.dumps(details), now))
            db.execute("INSERT INTO payments(user_id,kind,amount,transaction_ref,status,created_at,reviewed_at) VALUES(?,?,100,?,'approved',?,?)", (user_id, kind, ref, now, now))
            db.execute("INSERT INTO password_setup_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)", (hashlib.sha256(setup_code.encode()).hexdigest(), user_id, now + 60*60*24*30))
        self.send_json(201, {"ok": True, "setupCode": setup_code, "message": f"{kind.title()} account created and approved. Give this one-time code to the person so they can choose their own password. The code expires in 30 days."})

    def issue_setup_code(self, p):
        if not self.require_user(admin=True): return
        user_id = int(p.get("userId", 0))
        now = int(time.time())
        setup_code = secrets.token_urlsafe(24)
        with connect() as db:
            user = db.execute("SELECT id,role FROM users WHERE id=?", (user_id,)).fetchone()
            if not user or user["role"] == "admin": return self.send_json(404, {"error": "Member or student account not found."})
            db.execute("INSERT INTO password_setup_tokens(token_hash,user_id,expires_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at",
                       (hashlib.sha256(setup_code.encode()).hexdigest(), user_id, now + 60*60*24*30))
        self.send_json(200, {"ok": True, "setupCode": setup_code, "message": "Share this new one-time code privately. It expires in 30 days."})

    def add_book(self, p):
        if not self.require_user(admin=True): return
        title = str(p.get("title", "")).strip()[:160]
        filename = Path(str(p.get("filename", "resource"))).name
        filename = re.sub(r"[^A-Za-z0-9._ -]", "_", filename)[:120] or "resource"
        ext = Path(filename).suffix.lower()
        allowed = {".pdf": "application/pdf", ".txt": "text/plain"}
        if len(title) < 2 or ext not in allowed: return self.send_json(400, {"error": "Add a title and a PDF or plain text file."})
        try: data = base64.b64decode(str(p.get("data", "")), validate=True)
        except ValueError: return self.send_json(400, {"error": "File data is invalid."})
        if not data or len(data) > 15 * 1024 * 1024: return self.send_json(400, {"error": "File must be under 15 MB."})
        if ext == ".pdf" and not data.startswith(b"%PDF-"): return self.send_json(400, {"error": "That file is not a valid PDF."})
        if ext == ".txt":
            try: data.decode("utf-8")
            except UnicodeDecodeError: return self.send_json(400, {"error": "Text files must use UTF-8 encoding."})
        stored = uuid.uuid4().hex + ext
        (FILES / stored).write_bytes(data)
        with connect() as db:
            cur = db.execute("INSERT INTO books(title,author,category,description,filename,original_name,content_type,size,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                             (title, str(p.get("author", ""))[:120], str(p.get("category", "General"))[:80], str(p.get("description", ""))[:1000], stored, filename, allowed[ext], len(data), int(time.time())))
        self.send_json(201, {"ok": True, "id": cur.lastrowid})


if __name__ == "__main__":
    init_db()
    if sys.argv[1:] == ["--reset-admin-password"]:
        first = getpass.getpass("New administrator password (12+ characters): ")
        second = getpass.getpass("Confirm new password: ")
        if len(first) < 12 or first != second:
            raise SystemExit("Passwords must match and be at least 12 characters long.")
        with connect() as db:
            admin = db.execute("SELECT id FROM users WHERE role='admin'").fetchone()
            if not admin: raise SystemExit("No administrator account exists. Start once with WISD_ADMIN_PASSWORD set to create it.")
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(first), admin["id"]))
            db.execute("DELETE FROM sessions WHERE user_id=?", (admin["id"],))
        raise SystemExit("Administrator password reset. Sign in with 0727650086 and the new password.")
    with connect() as db:
        has_admin = db.execute("SELECT id FROM users WHERE role='admin'").fetchone()
    if not has_admin:
        print("No administrator set up. Set WISD_ADMIN_PASSWORD to a strong password and restart.", file=sys.stderr)
    print(f"WISD Science Academy running at http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
