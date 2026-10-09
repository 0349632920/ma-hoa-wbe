# -*- coding: utf-8 -*-
"""Mã Hóa Chữ - Web App hoàn chỉnh"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os, bcrypt, secrets
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

app.secret_key = os.environ.get("SECRET_KEY", "mahoa-chu-secret-key-2024-fixed")
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
        try:
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE")
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE")
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT")
        except Exception:
            pass

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

        c.execute("""
            CREATE TABLE IF NOT EXISTS deleted_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(30) NOT NULL,
                deleted_by VARCHAR(30) NOT NULL,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS warnings (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                username VARCHAR(30) NOT NULL,
                reason TEXT NOT NULL,
                warned_by VARCHAR(30) NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_warnings_user ON warnings(user_id, is_read)")

        conn.commit()

        c.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(%s)", (ADMIN_USERNAME,))
        if not c.fetchone():
            pwd_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, TRUE)",
                      (ADMIN_USERNAME, pwd_hash))
            conn.commit()
            print(f"✅ Đã tạo admin: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")

        c.close(); conn.close()
        print("✅ Đã khởi tạo database")
    except Exception as e:
        print(f"❌ Lỗi init_db: {e}")

init_db()

# ============================================================
# AUTH HELPERS
# ============================================================
def is_logged_in(): return "user_id" in session
def is_admin(): return session.get("is_admin", False)
def get_username(): return session.get("username", "Khách")

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
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT is_banned, ban_reason FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        c.close(); conn.close()
        if not row: return {"is_banned": False}
        is_banned = bool(row["is_banned"]) if row["is_banned"] is not None else False
        if not is_banned: return {"is_banned": False}
        return {"is_banned": True,
                "ban_reason": str(row["ban_reason"]) if row["ban_reason"] else "",
                "permanent": True}
    except Exception as e:
        print(f"❌ Lỗi get_ban_info: {e}")
        return {"is_banned": False}

def check_banned(user_id):
    try: return bool(get_ban_info(user_id).get("is_banned", False))
    except Exception: return False

def user_exists(user_id):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        c.close(); conn.close()
        return row is not None
    except Exception:
        return True

# ============================================================
# PAGES
# ============================================================
@app.route("/")
def index():
    if is_logged_in():
        if not user_exists(session["user_id"]):
            session.clear()
            return redirect(url_for("login_page"))
        if check_banned(session["user_id"]):
            return redirect(url_for("banned_page"))
    return render_template("index.html", username=get_username())

@app.route("/login")
def login_page():
    if is_logged_in():
        if not user_exists(session["user_id"]):
            session.clear()
        else:
            return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/banned")
def banned_page():
    if not is_logged_in(): return redirect(url_for("login_page"))
    if not user_exists(session["user_id"]):
        session.clear()
        return redirect(url_for("login_page"))
    try: ban_info = get_ban_info(session["user_id"])
    except Exception: return redirect(url_for("index"))
    if not ban_info.get("is_banned"): return redirect(url_for("index"))
    return render_template("banned.html",
                            username=session.get("username", "User"),
                            ban_info=ban_info)

@app.route("/deleted")
def deleted_page():
    return render_template("deleted.html")

@app.route("/admin")
def admin_page():
    if not is_logged_in(): return redirect(url_for("login_page"))
    if not user_exists(session["user_id"]):
        session.clear()
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
    if not data: return jsonify({"error": "Thiếu dữ liệu"}), 400
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if len(username) < 3: return jsonify({"error": "Tên đăng nhập phải từ 3 ký tự"}), 400
    if len(username) > 30: return jsonify({"error": "Tên đăng nhập tối đa 30 ký tự"}), 400
    if not username.replace("_", "").isalnum(): return jsonify({"error": "Tên chỉ được chứa chữ, số và _"}), 400
    if len(password) < 6: return jsonify({"error": "Mật khẩu phải từ 6 ký tự"}), 400

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
        conn.commit(); c.close(); conn.close()

        session.permanent = True
        session["user_id"] = user_id
        session["username"] = username
        session["is_admin"] = False
        return jsonify({"success": True, "username": username})
    except Exception as e:
        return jsonify({"error": f"Lỗi: {e}"}), 500

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data: return jsonify({"error": "Thiếu dữ liệu"}), 400
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password: return jsonify({"error": "Vui lòng nhập đầy đủ"}), 400

    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT id, username, password_hash, is_admin FROM users WHERE LOWER(username) = LOWER(%s)",
                  (username,))
        user = c.fetchone()
        c.close(); conn.close()
        if not user: return jsonify({"error": "Sai tên đăng nhập hoặc mật khẩu"}), 401
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return jsonify({"error": "Sai tên đăng nhập hoặc mật khẩu"}), 401

        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])

        is_banned = False
        ban_info = {"is_banned": False}
        try:
            ban_info = get_ban_info(user["id"])
            is_banned = bool(ban_info.get("is_banned", False))
        except Exception: pass

        return jsonify({"success": True, "username": user["username"],
                        "is_admin": bool(user["is_admin"]),
                        "is_banned": is_banned, "ban_info": ban_info})
    except Exception as e:
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
        conn.commit(); c.close(); conn.close()

        session.permanent = True
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        session["is_guest"] = True
        session["is_admin"] = False
        return jsonify({"success": True, "username": row["username"], "is_guest": True})
    except Exception as e:
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
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT id FROM users WHERE id = %s", (session["user_id"],))
        exists = c.fetchone()
        if not exists:
            username = session.get("username", "User")
            c.execute("SELECT deleted_by FROM deleted_users WHERE username = %s ORDER BY id DESC LIMIT 1",
                      (username,))
            log = c.fetchone()
            deleted_by = log["deleted_by"] if log else "Admin"
            c.close(); conn.close()
            session.clear()
            return jsonify({"logged_in": False, "deleted": True,
                            "username": username, "deleted_by": deleted_by})
        ban_info = get_ban_info(session["user_id"])
        c.close(); conn.close()
        return jsonify({"logged_in": True, "user_id": session["user_id"],
                        "username": session["username"],
                        "is_guest": session.get("is_guest", False),
                        "is_admin": is_admin(),
                        "is_banned": ban_info.get("is_banned", False),
                        "ban_info": ban_info})
    except Exception as e:
        print(f"Lỗi api_me: {e}")
        return jsonify({"logged_in": False})

@app.route("/api/check-user-exists")
def api_check_user_exists():
    if not is_logged_in():
        return jsonify({"exists": False, "logged_in": False})
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute("SELECT id, username FROM users WHERE id = %s", (session["user_id"],))
        row = c.fetchone()
        if not row:
            username = session.get("username", "User")
            c.execute("SELECT deleted_by FROM deleted_users WHERE username = %s ORDER BY id DESC LIMIT 1",
                      (username,))
            log = c.fetchone()
            deleted_by = log["deleted_by"] if log else "Admin"
            c.close(); conn.close()
            session.clear()
            return jsonify({"exists": False, "logged_in": False, "deleted": True,
                            "username": username, "deleted_by": deleted_by})
        c.close(); conn.close()
        return jsonify({"exists": True, "logged_in": True, "username": row["username"]})
    except Exception as e:
        return jsonify({"exists": True, "error": str(e)})

# ============================================================
# APP API
# ============================================================
@app.route("/api/algos")
def api_algos():
    return jsonify({"grouped": get_grouped(), "order": GROUP_ORDER, "total": len(ENCODERS)})

@app.route("/api/process", methods=["POST"])
@login_required_api
def api_process():
    if not user_exists(session["user_id"]):
        session.clear()
        return jsonify({"error": "Tài khoản đã bị xóa", "deleted": True}), 404
    ban_info = {"is_banned": False}
    try: ban_info = get_ban_info(session["user_id"])
    except Exception: pass
    if ban_info.get("is_banned"):
        return jsonify({"error": "Tài khoản đã bị cấm", "banned": True, "ban_info": ban_info}), 403

    data = request.get_json()
    if not data: return jsonify({"error": "Thiếu dữ liệu"}), 400
    mode = data.get("mode", "encode")
    algo = data.get("algo", "base64")
    text = data.get("text", "")
    key = data.get("key", "")

    if algo not in ENCODERS: return jsonify({"error": f"Không tìm thấy thuật toán: {algo}"}), 400
    if not text: return jsonify({"error": "Chưa nhập
