# -*- coding: utf-8 -*-
"""
Mã Hóa Chữ - Web App với PostgreSQL
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import bcrypt
import secrets
import psycopg2
import psycopg2.extras
from urllib.parse import urlparse

# Load .env nếu có
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from crypto_utils import ENCODERS, GROUP_ORDER, get_grouped

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ============================================================
# DATABASE CONFIG
# ============================================================
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Render cung cấp URL dạng postgres://... (cần đổi thành postgresql://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

def get_db():
    """Kết nối PostgreSQL."""
    if not DATABASE_URL:
        raise RuntimeError("Chưa cấu hình DATABASE_URL")
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """Tạo bảng nếu chưa có."""
    if not DATABASE_URL:
        print("⚠ Chưa có DATABASE_URL — bỏ qua init_db")
        return
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(30) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE
            )
        """)
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
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_history_user
            ON history(user_id, id DESC)
        """)
        conn.commit()
        c.close()
        conn.close()
        print("✅ Đã khởi tạo database")
    except Exception as e:
        print(f"❌ Lỗi init_db: {e}")

init_db()

# ============================================================
# AUTH DECORATOR
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Chưa đăng nhập"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ============================================================
# ROUTES - PAGES
# ============================================================
@app.route("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/")
@login_required
def index():
    return render_template("index.html",
                            username=session.get("username", "User"))

# ============================================================
# ROUTES - AUTH API
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

        # Check trùng
        c.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
        if c.fetchone():
            c.close(); conn.close()
            return jsonify({"error": "Tên đăng nhập đã tồn tại"}), 400

        # Hash
        pwd_hash = bcrypt.hashpw(password.encode("utf-8"),
                                  bcrypt.gensalt()).decode("utf-8")

        # Insert
        c.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
            (username, pwd_hash)
        )
        user_id = c.fetchone()["id"]
        conn.commit()
        c.close()
        conn.close()

        # Auto login
        session["user_id"] = user_id
        session["username"] = username

        return jsonify({"success": True, "username": username})
    except Exception as e:
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
            "SELECT id, username, password_hash FROM users WHERE LOWER(username) = LOWER(%s)",
            (username,)
        )
        user = c.fetchone()
        c.close()
        conn.close()

        if not user:
            return jsonify({"error": "Sai tên đăng nhập hoặc mật khẩu"}), 401

        if not bcrypt.checkpw(password.encode("utf-8"),
                              user["password_hash"].encode("utf-8")):
            return jsonify({"error": "Sai tên đăng nhập hoặc mật khẩu"}), 401

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return jsonify({"success": True, "username": user["username"]})
    except Exception as e:
        return jsonify({"error": f"Lỗi: {e}"}), 500

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "user_id": session["user_id"],
        "username": session["username"],
    })

# ============================================================
# ROUTES - APP API
# ============================================================
@app.route("/api/algos")
@login_required
def api_algos():
    return jsonify({
        "grouped": get_grouped(),
        "order": GROUP_ORDER,
        "total": len(ENCODERS)
    })

@app.route("/api/process", methods=["POST"])
@login_required
def api_process():
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

        # Lưu lịch sử
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute(
                "INSERT INTO history (user_id, mode, algo, input_text, output_text) "
                "VALUES (%s, %s, %s, %s, %s)",
                (session["user_id"], mode, algo, text[:500], result[:500])
            )
            conn.commit()
            c.close()
            conn.close()
        except Exception as e:
            print(f"Lỗi lưu history: {e}")

        return jsonify({
            "success": True,
            "result": result,
            "algo_label": label,
            "mode": mode,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/history")
@login_required
def api_history():
    try:
        conn = get_db()
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute(
            "SELECT mode, algo, input_text, output_text, created_at "
            "FROM history WHERE user_id = %s ORDER BY id DESC LIMIT 50",
            (session["user_id"],)
        )
        rows = c.fetchall()
        c.close()
        conn.close()

        # Convert timestamp → string
        result = []
        for r in rows:
            d = dict(r)
            if d.get("created_at"):
                d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            result.append(d)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history/clear", methods=["POST"])
@login_required
def api_history_clear():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM history WHERE user_id = %s", (session["user_id"],))
        conn.commit()
        c.close()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/health")
def health():
    db_ok = False
    try:
        conn = get_db()
        conn.close()
        db_ok = True
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
