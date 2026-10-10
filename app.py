# -*- coding: utf-8 -*-
"""
Mã Hóa Chữ - Web App với Admin Panel (ban vĩnh viễn)
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from datetime import datetime
import os
import bcrypt
import secrets
import psycopg2
import psycopg2.extras

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from crypto_utils import ENCODERS, GROUP_ORDER, get_grouped

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates"),
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))

app.secret_key = os.environ.get("SECRET_KEY", "mahoa-chu-secret-key-2024-fixed-do-not-change")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400 * 7,
)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

# ============================================================
# DATABASE
# ============================================================
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123456")

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("Chưa cấu hình DATABASE_URL")
    url = DATABASE_URL
    if "sslmode" not in url:
        url += "?sslmode=require" if "?" not in url else "&sslmode=require"
    return psycopg2.connect(url)

def init_db():
    if not DATABASE_URL:
        print("⚠ Chưa có DATABASE_URL")
        return
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(30) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                is_banned BOOLEAN DEFAULT FALSE,
                ban_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Migration — chỉ giữ is_admin, is_banned, ban_reason
        try:
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE")
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE")
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT")
            # Xóa cột banned_until nếu tồn tại
            c.execute("ALTER TABLE users DROP COLUMN IF EXISTS banned_until")
        except Exception as e:
            print(f"⚠ Migration: {e}")

        c.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                mode VARCHAR(10) NOT NULL,
                algo VARCHAR(50) NOT NULL,
                input_text TEXT,
                output_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id, id DESC)")
        conn.commit()

        # Tạo admin mặc định
        c.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(%s)", (ADMIN_USERNAME,))
        if not c.fetchone():
            pwd_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, TRUE)",
                      (ADMIN_USERNAME, pwd_hash))
            conn.commit()
            print(f"✅ Đã tạo admin: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")

        c.close()
        conn.close()
        print("✅ Đã khởi tạo database")
    except Exception as e:
        print(f"❌ Lỗi init_db: {e}")

init_db()

# ============================================================
# AUTH HELPERS
# ============================================================
def is_logged_in():
    return "user_id" in session

def is_admin():
    return session.get("is_admin", False)

def get_username():
    return session.get("username", "Khách")

def login_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return jsonify({"error": "Chưa đăng nhập"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return jsonify({"error": "Chưa đăng nhập"}), 401
        if not is_admin():
            return jsonify({"error": "Không có quyền admin"}), 403
        return f(*args, **kwargs)
    return decorated

def get_ban_info(user_id):
    """Trả về dict thông tin ban — chỉ ban vĩnh viễn."""
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT is_banned, ban_reason FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        c.close(); conn.close()

        if not row:
            return {"is_banned": False}

        is_banned = bool(row["is_banned"]) if row["is_banned"] is not None else False
        if not is_banned:
            return {"is_banned": False}

        ban_reason = str(row["ban_reason"]) if row["ban_reason"] else ""

        return {
            "is_banned": True,
            "ban_reason": ban_reason,
            "permanent": True,
        }
    except Exception as e:
        print(f"❌ Lỗi get_ban_info: {e}")
        return {"is_banned": False}

def check_banned(user_id):
    try:
        return bool(get_ban_info(user_id).get("is_banned", False))
    except Exception:
        return False

# ============================================================
# PAGES
# ============================================================
@app.route("/")
def index():
    if is_logged_in():
        if check_banned(session["user_id"]):
            return redirect(url_for("banned_page"))
    return render_template("index.html", username=get_username())

@app.route("/login")
def login_page():
    if is_logged_in():
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/banned")
def banned_page():
    if not is_logged_in():
        return redirect(url_for("login_page"))

    try:
        ban_info = get_ban_info(session["user_id"])
    except Exception as e:
        print(f"Lỗi get_ban_info ở /banned: {e}")
        return redirect(url_for("index"))

    if not ban_info.get("is_banned"):
        return redirect(url_for("index"))

    safe_ban_info = {
        "is_banned": True,
        "ban_reason": str(ban_info.get("ban_reason", "")),
        "permanent": True,
    }

    return render_template("banned.html",
                            username=session.get("username", "User"),
                            ban_info=safe_ban_info)

@app.route("/admin")
def admin_page():
    if not is_logged_in():
        return redirect(url_for("login_page"))
    if not is_admin():
        return redirect(url_for("index") + "?error=no_permission")
    return render_template("admin.html", username=get_username())

# ============================================================
# AUTH API
# ============================================================
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Thiếu dữ liệu"}), 400

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if len(username) < 3:
        return jsonify({"error": "Tên đăng nhập phải từ 3 ký tự"}), 400
    if len(username) > 30:
        return jsonify({"error": "Tên đăng nhập tối đa 30 ký tự"}), 400
    if not username.replace("_", "").isalnum():
        return jsonify({"error": "Tên chỉ được chứa chữ, số và _"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mật khẩu phải từ 6 ký tự"}), 400

    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
        if c.fetchone():
            c.close(); conn.close()
            return jsonify({"error": "Tên đăng nhập đã tồn tại"}), 400

        pwd_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
                  (username, pwd_hash))
        user_id = c.fetchone()["id"]
        conn.commit()
        c.close(); conn.close()

        session.permanent = True
        session["user_id"] = user_id
        session["username"] = username
        session["is_admin"] = False
        return jsonify({"success": True, "username": username})
    except Exception as e:
        print(f"Lỗi api_register: {e}")
        return jsonify({"error": f"Lỗi: {e}"}), 500

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Thiếu dữ liệu"}), 400

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Vui lòng nhập đầy đủ"}), 400

    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute(
            "SELECT id, username, password_hash, is_admin FROM users WHERE LOWER(username) = LOWER(%s)",
            (username,)
        )
        user = c.fetchone()
        c.close(); conn.close()

        if not user:
            return jsonify({"error": "Sai tên đăng nhập hoặc mật khẩu"}), 401
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return jsonify({"error": "Sai tên đăng nhập hoặc mật khẩu"}), 401

        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])

        # Kiểm tra ban
        is_banned = False
        ban_info = {"is_banned": False}
        try:
            ban_info = get_ban_info(user["id"])
            is_banned = bool(ban_info.get("is_banned", False))
        except Exception as e:
            print(f"Lỗi check banned trong api_login: {e}")

        safe_ban_info = {
            "is_banned": is_banned,
            "ban_reason": str(ban_info.get("ban_reason", "")),
            "permanent": True,
        }

        return jsonify({
            "success": True,
            "username": user["username"],
            "is_admin": bool(user["is_admin"]),
            "is_banned": is_banned,
            "ban_info": safe_ban_info,
        })
    except Exception as e:
        print(f"Lỗi api_login: {e}")
        return jsonify({"error": f"Lỗi server: {str(e)}"}), 500

@app.route("/api/guest", methods=["POST"])
def api_guest():
    try:
        guest_name = f"guest_{secrets.token_hex(4)}"
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        fake_pwd = secrets.token_hex(16)
        pwd_hash = bcrypt.hashpw(fake_pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id, username",
                  (guest_name, pwd_hash))
        row = c.fetchone()
        conn.commit()
        c.close(); conn.close()

        session.permanent = True
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        session["is_guest"] = True
        session["is_admin"] = False

        return jsonify({"success": True, "username": row["username"], "is_guest": True})
    except Exception as e:
        print(f"Lỗi api_guest: {e}")
        return jsonify({"error": f"Lỗi: {e}"}), 500

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
def api_me():
    if not is_logged_in():
        return jsonify({"logged_in": False, "username": "Khách"})

    try:
        ban_info = get_ban_info(session["user_id"])
    except Exception as e:
        print(f"Lỗi get_ban_info ở api_me: {e}")
        ban_info = {"is_banned": False}

    safe_ban_info = {
        "is_banned": bool(ban_info.get("is_banned", False)),
        "ban_reason": str(ban_info.get("ban_reason", "")),
        "permanent": True,
    }

    return jsonify({
        "logged_in": True,
        "user_id": session["user_id"],
        "username": session["username"],
        "is_guest": session.get("is_guest", False),
        "is_admin": is_admin(),
        "is_banned": safe_ban_info["is_banned"],
        "ban_info": safe_ban_info,
    })

@app.route("/api/ban-status")
def api_ban_status():
    if not is_logged_in():
        return jsonify({"logged_in": False})

    try:
        ban_info = get_ban_info(session["user_id"])
    except Exception as e:
        print(f"Lỗi api_ban_status: {e}")
        ban_info = {"is_banned": False}

    safe_ban_info = {
        "is_banned": bool(ban_info.get("is_banned", False)),
        "ban_reason": str(ban_info.get("ban_reason", "")),
        "permanent": True,
    }

    return jsonify({
        "logged_in": True,
        "username": session["username"],
        "ban_info": safe_ban_info,
    })

# ============================================================
# APP API
# ============================================================
@app.route("/api/algos")
def api_algos():
    return jsonify({
        "grouped": get_grouped(),
        "order": GROUP_ORDER,
        "total": len(ENCODERS)
    })

@app.route("/api/process", methods=["POST"])
@login_required_api
def api_process():
    # Kiểm tra ban
    ban_info = {"is_banned": False}
    try:
        ban_info = get_ban_info(session["user_id"])
    except Exception as e:
        print(f"Lỗi check ban ở process: {e}")

    if ban_info.get("is_banned"):
        safe_ban_info = {
            "is_banned": True,
            "ban_reason": str(ban_info.get("ban_reason", "")),
            "permanent": True,
        }
        return jsonify({
            "error": "Tài khoản đã bị cấm",
            "banned": True,
            "ban_info": safe_ban_info
        }), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "Thiếu dữ liệu"}), 400

    mode = data.get("mode", "encode")
    algo = data.get("algo", "base64")
    text = data.get("text", "")
    key = data.get("key", "")

    if algo not in ENCODERS:
        return jsonify({"error": f"Không tìm thấy thuật toán: {algo}"}), 400
    if not text:
        return jsonify({"error": "Chưa nhập văn bản"}), 400

    label, group, enc_fn, dec_fn = ENCODERS[algo]
    fn = enc_fn if mode == "encode" else dec_fn

    try:
        result = fn(text, key)
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute(
                "INSERT INTO history (user_id, mode, algo, input_text, output_text) VALUES (%s, %s, %s, %s, %s)",
                (session["user_id"], mode, algo, text[:500], result[:500])
            )
            conn.commit()
            c.close(); conn.close()
        except Exception as e:
            print(f"Lỗi lưu history: {e}")

        return jsonify({"success": True, "result": result, "algo_label": label, "mode": mode})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/history")
@login_required_api
def api_history():
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute(
            "SELECT mode, algo, input_text, output_text, created_at FROM history WHERE user_id = %s ORDER BY id DESC LIMIT 50",
            (session["user_id"],)
        )
        rows = c.fetchall()
        c.close(); conn.close()

        result = []
        for r in rows:
            d = dict(r)
            if d.get("created_at"):
                d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            result.append(d)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
# ADMIN API
# ============================================================
@app.route("/api/admin/stats")
@admin_required_api
def api_admin_stats():
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        c.execute("SELECT COUNT(*) as total FROM users")
        total_users = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM users WHERE is_banned = TRUE")
        banned_users = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM users WHERE is_admin = TRUE")
        admin_users = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM history")
        total_ops = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM history WHERE mode = 'encode'")
        total_encodes = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM history WHERE mode = 'decode'")
        total_decodes = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM users WHERE username LIKE 'guest_%'")
        guest_users = c.fetchone()["total"]

        c.close(); conn.close()

        return jsonify({
            "total_users": total_users,
            "banned_users": banned_users,
            "admin_users": admin_users,
            "guest_users": guest_users,
            "total_ops": total_ops,
            "total_encodes": total_encodes,
            "total_decodes": total_decodes,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users")
@admin_required_api
def api_admin_users():
    try:
        search = request.args.get("search", "").strip().lower()
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        if search:
            c.execute("""
                SELECT id, username, is_admin, is_banned, ban_reason, created_at,
                       (SELECT COUNT(*) FROM history WHERE user_id = users.id) as op_count
                FROM users
                WHERE LOWER(username) LIKE %s
                ORDER BY id DESC
            """, (f"%{search}%",))
        else:
            c.execute("""
                SELECT id, username, is_admin, is_banned, ban_reason, created_at,
                       (SELECT COUNT(*) FROM history WHERE user_id = users.id) as op_count
                FROM users
                ORDER BY id DESC
            """)

        rows = c.fetchall()
        c.close(); conn.close()

        result = []
        for r in rows:
            d = dict(r)
            if d.get("created_at"):
                d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            result.append(d)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users/<int:user_id>/ban", methods=["POST"])
@admin_required_api
def api_admin_ban(user_id):
    """Cấm user vĩnh viễn."""
    if user_id == session["user_id"]:
        return jsonify({"error": "Không thể tự cấm chính mình"}), 400

    data = request.get_json() or {}
    reason = (data.get("reason") or "").strip()[:500]

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin, username FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        if not row:
            c.close(); conn.close()
            return jsonify({"error": "Không tìm thấy user"}), 404
        if row[0]:
            c.close(); conn.close()
            return jsonify({"error": "Không thể cấm admin khác"}), 400

        c.execute(
            "UPDATE users SET is_banned = TRUE, ban_reason = %s WHERE id = %s",
            (reason, user_id)
        )
        conn.commit()
        c.close(); conn.close()
        return jsonify({"success": True, "username": row[1]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users/<int:user_id>/unban", methods=["POST"])
@admin_required_api
def api_admin_unban(user_id):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "UPDATE users SET is_banned = FALSE, ban_reason = NULL WHERE id = %s",
            (user_id,)
        )
        conn.commit()
        c.close(); conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required_api
def api_admin_delete_user(user_id):
    if user_id == session["user_id"]:
        return jsonify({"error": "Không thể tự xóa chính mình"}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        if not row:
            c.close(); conn.close()
            return jsonify({"error": "Không tìm thấy user"}), 404
        if row[0]:
            c.close(); conn.close()
            return jsonify({"error": "Không thể xóa admin khác"}), 400

        c.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        c.close(); conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/history")
@admin_required_api
def api_admin_history():
    try:
        mode_filter = request.args.get("mode", "").strip()
        user_filter = request.args.get("username", "").strip()
        limit = min(int(request.args.get("limit", 100)), 500)

        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        query = """
            SELECT h.id, h.mode, h.algo, h.input_text, h.output_text,
                   h.created_at, u.username
            FROM history h
            JOIN users u ON u.id = h.user_id
            WHERE 1=1
        """
        params = []

        if mode_filter in ("encode", "decode"):
            query += " AND h.mode = %s"
            params.append(mode_filter)

        if user_filter:
            query += " AND LOWER(u.username) LIKE %s"
            params.append(f"%{user_filter.lower()}%")

        query += " ORDER BY h.id DESC LIMIT %s"
        params.append(limit)

        c.execute(query, params)
        rows = c.fetchall()
        c.close(); conn.close()

        result = []
        for r in rows:
            d = dict(r)
            if d.get("created_at"):
                d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            result.append(d)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/history/clear", methods=["POST"])
@admin_required_api
def api_admin_history_clear():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM history")
        conn.commit()
        c.close(); conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/health")
def health():
    db_ok = False
    try:
        conn = get_db(); conn.close(); db_ok = True
    except Exception:
        pass
    return jsonify({
        "status": "ok",
        "algos": len(ENCODERS),
        "db": "connected" if db_ok else "disconnected"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
