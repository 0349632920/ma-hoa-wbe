# -*- coding: utf-8 -*-
"""Flask app chính cho ma-hoa-wbe"""
import os
import re
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, jsonify, session,
                   redirect, url_for, flash)
from dotenv import load_dotenv
import bcrypt

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    DB_OK = True
except ImportError:
    DB_OK = False

from werkzeug.middleware.proxy_fix import ProxyFix
from crypto_utils import ENCODERS, get_grouped, GROUP_ORDER

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

DATABASE_URL = os.getenv("DATABASE_URL", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = bcrypt.hashpw(
    os.getenv("ADMIN_PASSWORD", "admin123").encode(), bcrypt.gensalt()
).decode()


# ==================== DATABASE ====================
def get_db():
    if not DB_OK or not DATABASE_URL:
        return None
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    conn = get_db()
    if not conn:
        print("[DB] Không kết nối được DB - chạy không lưu lịch sử")
        return
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'user',
                    status VARCHAR(20) DEFAULT 'active',
                    warning_count INT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS history (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES users(id) ON DELETE CASCADE,
                    algo_key VARCHAR(50),
                    operation VARCHAR(10),
                    input_text TEXT,
                    output_text TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS deleted_users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50),
                    reason TEXT,
                    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_history_user
                    ON history(user_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS warnings (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES users(id) ON DELETE CASCADE,
                    title VARCHAR(200) NOT NULL,
                    reason TEXT NOT NULL,
                    moderator VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) DEFAULT 'warning',
                    acknowledged BOOLEAN DEFAULT FALSE,
                    acknowledged_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_warnings_user
                    ON warnings(user_id, acknowledged, created_at DESC);

                CREATE TABLE IF NOT EXISTS bans (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES users(id) ON DELETE CASCADE,
                    reason TEXT,
                    moderator VARCHAR(50),
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_permanent BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE
                );
                CREATE INDEX IF NOT EXISTS idx_bans_user
                    ON bans(user_id, is_active);
            """)
        print("[DB] Khởi tạo thành công")
    finally:
        conn.close()


# ==================== DECORATORS ====================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") and session.get("role") != "admin":
            if request.is_json:
                return jsonify({"error": "Chưa đăng nhập"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            if request.is_json:
                return jsonify({"error": "Không có quyền"}), 403
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper


# ==================== ROUTES: AUTH ====================
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get("user_id") or session.get("role") == "admin":
            return redirect(url_for("index"))
        return render_template("login.html")

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    action = data.get("action", "login")

    if not re.match(r"^[a-zA-Z0-9_]{3,50}$", username):
        return jsonify({"error": "Username 3-50 ký tự, chỉ a-z 0-9 _"}), 400

    # Admin login
    if username == ADMIN_USERNAME:
        if bcrypt.checkpw(password.encode(), ADMIN_PASSWORD_HASH.encode()):
            session.permanent = True
            session["user_id"] = 0
            session["username"] = username
            session["role"] = "admin"
            return jsonify({"ok": True, "redirect": url_for("admin_page")})
        return jsonify({"error": "Sai mật khẩu admin"}), 401

    conn = get_db()
    if not conn:
        return jsonify({"error": "DB chưa cấu hình"}), 500

    try:
        with conn, conn.cursor() as cur:
            if action == "register":
                if len(password) < 6:
                    return jsonify({"error": "Mật khẩu ≥ 6 ký tự"}), 400
                cur.execute("SELECT id FROM users WHERE username=%s", (username,))
                if cur.fetchone():
                    return jsonify({"error": "Username đã tồn tại"}), 409
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                cur.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s,%s) RETURNING id",
                    (username, pw_hash)
                )
                uid = cur.fetchone()["id"]
                session.permanent = True
                session["user_id"] = uid
                session["username"] = username
                session["role"] = "user"
                return jsonify({"ok": True, "redirect": url_for("index")})

            # login
            cur.execute(
                "SELECT id, password_hash, status, role FROM users WHERE username=%s",
                (username,)
            )
            row = cur.fetchone()
            if not row or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
                return jsonify({"error": "Sai tài khoản hoặc mật khẩu"}), 401

            # Kiểm tra ban
            cur.execute("""
                SELECT reason, expires_at, is_permanent FROM bans
                WHERE user_id=%s AND is_active=TRUE
                  AND (is_permanent=TRUE OR expires_at > NOW())
                ORDER BY banned_at DESC LIMIT 1
            """, (row["id"],))
            ban = cur.fetchone()
            if ban:
                return jsonify({
                    "error": "Tài khoản đã bị khóa",
                    "banned": True,
                    "reason": ban["reason"],
                    "expires_at": ban["expires_at"].isoformat() if ban["expires_at"] else None,
                    "is_permanent": ban["is_permanent"],
                    "redirect": url_for("banned_page",
                                        reason=ban["reason"],
                                        exp=ban["expires_at"].isoformat() if ban["expires_at"] else "0",
                                        u=username)
                }), 403

            if row["status"] == "banned":
                return jsonify({
                    "error": "Tài khoản đã bị khóa",
                    "banned": True,
                    "redirect": url_for("banned_page", reason="Vi phạm quy định",
                                        exp="0", u=username)
                }), 403

            cur.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (row["id"],))
            session.permanent = True
            session["user_id"] = row["id"]
            session["username"] = username
            session["role"] = row["role"]
            return jsonify({"ok": True, "redirect": url_for("index")})
    finally:
        conn.close()


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ==================== ROUTES: MAIN ====================
@app.route("/")
def index():
    if not session.get("user_id") and session.get("role") != "admin":
        return redirect(url_for("login_page"))
    grouped = get_grouped()
    return render_template("index.html",
                           grouped=grouped,
                           group_order=GROUP_ORDER,
                           username=session.get("username"),
                           is_admin=session.get("role") == "admin")


@app.route("/api/algorithms")
def api_algorithms():
    return jsonify(get_grouped())


@app.route("/api/process", methods=["POST"])
def api_process():
    data = request.get_json() or {}
    algo_key = data.get("algo")
    text = data.get("text", "")
    key = data.get("key", "")
    operation = data.get("operation", "encode")

    if algo_key not in ENCODERS:
        return jsonify({"error": "Thuật toán không hợp lệ"}), 400
    if len(text) > 100_000:
        return jsonify({"error": "Văn bản quá dài (max 100KB)"}), 400

    label, group, enc, dec = ENCODERS[algo_key]
    func = enc if operation == "encode" else dec

    t0 = time.time()
    try:
        result = func(text, key)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    elapsed = round((time.time() - t0) * 1000, 2)

    if session.get("user_id") and session.get("role") != "admin":
        conn = get_db()
        if conn:
            try:
                with conn, conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO history (user_id, algo_key, operation, input_text, output_text)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (session["user_id"], algo_key, operation,
                          text[:5000], str(result)[:5000]))
            except Exception:
                pass
            finally:
                conn.close()

    return jsonify({
        "ok": True,
        "result": result,
        "elapsed_ms": elapsed,
        "algo": label,
        "operation": operation,
    })


@app.route("/api/history")
@login_required
def api_history():
    conn = get_db()
    if not conn:
        return jsonify([])
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT id, algo_key, operation, input_text, output_text, created_at
                FROM history WHERE user_id=%s
                ORDER BY created_at DESC LIMIT 50
            """, (session["user_id"],))
            rows = cur.fetchall()
        for r in rows:
            r["created_at"] = r["created_at"].isoformat()
            r["algo_label"] = ENCODERS.get(r["algo_key"], ("?",))[0]
        return jsonify(rows)
    finally:
        conn.close()


@app.route("/api/history/<int:hid>", methods=["DELETE"])
@login_required
def api_delete_history(hid):
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB lỗi"}), 500
    try:
        with conn, conn.cursor() as cur:
            cur.execute("DELETE FROM history WHERE id=%s AND user_id=%s",
                        (hid, session["user_id"]))
        return jsonify({"ok": True})
    finally:
        conn.close()


# ==================== ROUTES: WARNINGS ====================
@app.route("/api/warnings/pending")
@login_required
def api_warnings_pending():
    uid = session.get("user_id")
    conn = get_db()
    if not conn:
        return jsonify({"warnings": [], "warning_count": 0})
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, reason, moderator, severity, created_at
                FROM warnings
                WHERE user_id=%s AND acknowledged=FALSE
                ORDER BY created_at ASC
            """, (uid,))
            rows = cur.fetchall()
            cur.execute("SELECT warning_count FROM users WHERE id=%s", (uid,))
            wc = cur.fetchone()
            warning_count = wc["warning_count"] if wc else 0
        for r in rows:
            r["created_at"] = r["created_at"].isoformat() if r["created_at"] else None
        return jsonify({"warnings": rows, "warning_count": warning_count})
    finally:
        conn.close()


@app.route("/api/warnings/<int:wid>/acknowledge", methods=["POST"])
@login_required
def api_warning_acknowledge(wid):
    uid = session.get("user_id")
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB lỗi"}), 500
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                UPDATE warnings SET acknowledged=TRUE, acknowledged_at=NOW()
                WHERE id=%s AND user_id=%s RETURNING id
            """, (wid, uid))
            if not cur.fetchone():
                return jsonify({"error": "Không tìm thấy"}), 404
        return jsonify({"ok": True})
    finally:
        conn.close()


@app.route("/api/warnings/me")
@login_required
def api_warnings_me():
    uid = session.get("user_id")
    conn = get_db()
    if not conn:
        return jsonify([])
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, reason, moderator, severity,
                       acknowledged, acknowledged_at, created_at
                FROM warnings WHERE user_id=%s
                ORDER BY created_at DESC LIMIT 50
            """, (uid,))
            rows = cur.fetchall()
        for r in rows:
            for k in ("created_at", "acknowledged_at"):
                r[k] = r[k].isoformat() if r[k] else None
        return jsonify(rows)
    finally:
        conn.close()


@app.route("/api/ban/status")
@login_required
def api_ban_status():
    uid = session.get("user_id")
    conn = get_db()
    if not conn:
        return jsonify({"banned": False})
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT reason, moderator, banned_at, expires_at, is_permanent
                FROM bans WHERE user_id=%s AND is_active=TRUE
                  AND (is_permanent=TRUE OR expires_at > NOW())
                ORDER BY banned_at DESC LIMIT 1
            """, (uid,))
            row = cur.fetchone()
        if not row:
            return jsonify({"banned": False})
        return jsonify({
            "banned": True, "reason": row["reason"],
            "moderator": row["moderator"],
            "banned_at": row["banned_at"].isoformat() if row["banned_at"] else None,
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
            "is_permanent": row["is_permanent"],
        })
    finally:
        conn.close()


# ==================== ROUTES: ADMIN ====================
@app.route("/admin")
@admin_required
def admin_page():
    return render_template("admin.html", username=session.get("username"))


@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    conn = get_db()
    if not conn:
        return jsonify([])
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, role, status, warning_count,
                       created_at, last_login
                FROM users ORDER BY created_at DESC
            """)
            rows = cur.fetchall()
        for r in rows:
            r["created_at"] = r["created_at"].isoformat() if r["created_at"] else None
            r["last_login"] = r["last_login"].isoformat() if r["last_login"] else None
        return jsonify(rows)
    finally:
        conn.close()


@app.route("/api/admin/user/<int:uid>", methods=["DELETE"])
@admin_required
def api_admin_delete(uid):
    data = request.get_json() or {}
    reason = data.get("reason", "Vi phạm")
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB lỗi"}), 500
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE id=%s", (uid,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Không tìm thấy user"}), 404
            cur.execute("INSERT INTO deleted_users (username, reason) VALUES (%s,%s)",
                        (row["username"], reason))
            cur.execute("DELETE FROM users WHERE id=%s", (uid,))
        return jsonify({"ok": True})
    finally:
        conn.close()


# ==================== ADMIN: WARN ====================
@app.route("/api/admin/warn/<int:uid>", methods=["POST"])
@admin_required
def api_admin_warn_user(uid):
    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    reason = (data.get("reason") or "").strip()
    severity = data.get("severity", "warning")

    if not title or len(title) > 200:
        return jsonify({"error": "Tiêu đề 1-200 ký tự"}), 400
    if not reason:
        return jsonify({"error": "Lý do không được rỗng"}), 400
    if severity not in ("notice", "warning", "danger"):
        return jsonify({"error": "Severity không hợp lệ"}), 400

    conn = get_db()
    if not conn:
        return jsonify({"error": "DB lỗi"}), 500
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE id=%s", (uid,))
            if not cur.fetchone():
                return jsonify({"error": "User không tồn tại"}), 404

            cur.execute("""
                INSERT INTO warnings (user_id, title, reason, moderator, severity)
                VALUES (%s, %s, %s, %s, %s) RETURNING id
            """, (uid, title, reason, session.get("username"), severity))
            wid = cur.fetchone()["id"]

            cur.execute("""
                UPDATE users SET warning_count = warning_count + 1
                WHERE id=%s RETURNING warning_count
            """, (uid,))
            new_count = cur.fetchone()["warning_count"]

            auto_banned = False
            if new_count >= 3:
                cur.execute("""
                    INSERT INTO bans (user_id, reason, moderator, is_permanent)
                    VALUES (%s, %s, %s, TRUE)
                """, (uid, f"Tự động khóa: {new_count} lần vi phạm",
                      session.get("username")))
                cur.execute("UPDATE users SET status='banned' WHERE id=%s", (uid,))
                auto_banned = True

        return jsonify({
            "ok": True, "warning_id": wid,
            "warning_count": new_count, "auto_banned": auto_banned
        })
    finally:
        conn.close()


@app.route("/api/admin/warnings", methods=["GET"])
@admin_required
def api_admin_list_warnings():
    conn = get_db()
    if not conn:
        return jsonify([])
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT w.id, w.title, w.reason, w.moderator, w.severity,
                       w.acknowledged, w.created_at,
                       u.username, u.id AS user_id
                FROM warnings w LEFT JOIN users u ON u.id = w.user_id
                ORDER BY w.created_at DESC LIMIT 200
            """)
            rows = cur.fetchall()
        for r in rows:
            r["created_at"] = r["created_at"].isoformat() if r["created_at"] else None
        return jsonify(rows)
    finally:
        conn.close()


@app.route("/api/admin/warnings/<int:wid>", methods=["DELETE"])
@admin_required
def api_admin_delete_warning(wid):
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB lỗi"}), 500
    try:
        with conn, conn.cursor() as cur:
            cur.execute("DELETE FROM warnings WHERE id=%s", (wid,))
        return jsonify({"ok": True})
    finally:
        conn.close()


@app.route("/api/admin/ban/<int:uid>", methods=["POST"])
@admin_required
def api_admin_ban_user(uid):
    data = request.get_json() or {}
    reason = (data.get("reason") or "Vi phạm quy định").strip()
    duration_hours = int(data.get("duration_hours", 0))

    conn = get_db()
    if not conn:
        return jsonify({"error": "DB lỗi"}), 500
    try:
        with conn, conn.cursor() as cur:
            if duration_hours == 0:
                cur.execute("""
                    INSERT INTO bans (user_id, reason, moderator, is_permanent)
                    VALUES (%s, %s, %s, TRUE)
                """, (uid, reason, session.get("username")))
            else:
                cur.execute("""
                    INSERT INTO bans (user_id, reason, moderator, expires_at)
                    VALUES (%s, %s, %s, NOW() + INTERVAL '%s hours')
                """, (uid, reason, session.get("username"), duration_hours))
            cur.execute("UPDATE users SET status='banned' WHERE id=%s", (uid,))
        return jsonify({"ok": True})
    finally:
        conn.close()


@app.route("/api/admin/unban/<int:uid>", methods=["POST"])
@admin_required
def api_admin_unban_user(uid):
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB lỗi"}), 500
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                UPDATE bans SET is_active=FALSE
                WHERE user_id=%s AND is_active=TRUE
            """, (uid,))
            cur.execute("UPDATE users SET status='active' WHERE id=%s", (uid,))
        return jsonify({"ok": True})
    finally:
        conn.close()


@app.route("/api/admin/bans", methods=["GET"])
@admin_required
def api_admin_list_bans():
    conn = get_db()
    if not conn:
        return jsonify([])
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT b.id, b.reason, b.moderator, b.banned_at,
                       b.expires_at, b.is_permanent, b.is_active,
                       u.username, u.id AS user_id
                FROM bans b LEFT JOIN users u ON u.id = b.user_id
                ORDER BY b.banned_at DESC LIMIT 100
            """)
            rows = cur.fetchall()
        for r in rows:
            for k in ("banned_at", "expires_at"):
                r[k] = r[k].isoformat() if r[k] else None
        return jsonify(rows)
    finally:
        conn.close()


@app.route("/api/admin/history")
@admin_required
def api_admin_history():
    conn = get_db()
    if not conn:
        return jsonify([])
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT h.id, u.username, h.algo_key, h.operation,
                       h.input_text, h.output_text, h.created_at
                FROM history h LEFT JOIN users u ON u.id = h.user_id
                ORDER BY h.created_at DESC LIMIT 200
            """)
            rows = cur.fetchall()
        for r in rows:
            r["created_at"] = r["created_at"].isoformat()
            r["algo_label"] = ENCODERS.get(r["algo_key"], ("?",))[0]
        return jsonify(rows)
    finally:
        conn.close()


@app.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    conn = get_db()
    if not conn:
        return jsonify({})
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM users")
            total = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE status='banned'")
            banned = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM history")
            history = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM deleted_users")
            deleted = cur.fetchone()["c"]
        return jsonify({"total_users": total, "banned_users": banned,
                        "total_history": history, "deleted_users": deleted})
    finally:
        conn.close()


# ==================== MIDDLEWARE: CHECK BAN ====================
@app.before_request
def check_ban():
    if request.endpoint in ("login_page", "logout", "static",
                            "banned_page", None):
        return
    uid = session.get("user_id")
    if not uid or session.get("role") == "admin":
        return
    last_check = session.get("_ban_check_at", 0)
    now = time.time()
    if now - last_check < 60:
        return
    session["_ban_check_at"] = now

    conn = get_db()
    if not conn:
        return
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                SELECT reason, expires_at, is_permanent FROM bans
                WHERE user_id=%s AND is_active=TRUE
                  AND (is_permanent=TRUE OR expires_at > NOW())
                ORDER BY banned_at DESC LIMIT 1
            """, (uid,))
            row = cur.fetchone()
        if row:
            if request.is_json:
                return jsonify({
                    "error": "Tài khoản đã bị khóa",
                    "banned": True,
                    "reason": row["reason"],
                    "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
                    "is_permanent": row["is_permanent"],
                }), 403
            username = session.get("username", "Người dùng")
            session.clear()
            return redirect(url_for("banned_page",
                                    reason=row["reason"],
                                    exp=row["expires_at"].isoformat() if row["expires_at"] else "0",
                                    u=username))
    finally:
        conn.close()


@app.route("/banned")
def banned_page():
    reason = request.args.get("reason", "Vi phạm quy định")
    exp = request.args.get("exp", "0")
    username = request.args.get("u", "Người dùng")
    session.clear()
    return render_template("banned.html", reason=reason, exp=exp, username=username)


# ==================== MAIN ====================
if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
else:
    init_db()
