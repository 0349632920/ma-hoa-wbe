from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
from poi_utils import boi_vui, tho_fallback, LOI_KHUYEN
from ten_utils import generate_name
from truyen_utils import get_truyen_fallback
from music_utils import list_music_files, get_file_info, stream_file, has_google_api
from crypto_utils import (
    process, METHODS, ONE_WAY_ONLY,
    translate, to_english, to_vietnamese, auto_translate, detect_language,
    LANGUAGES,
    get_methods_by_group, GROUP_NAMES, METHODS_REGISTRY,
)
from two_factor import (
    generate_secret,
    get_totp_uri,
    generate_qr_base64,
    verify_code,
    generate_backup_codes,
    hash_backup_code,
    verify_backup_code,
    get_remaining_seconds,
)
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
from contextlib import contextmanager
import unicodedata
import requests
import os
import json
import hashlib
import secrets
import random
import psycopg2
from psycopg2.extras import Json, RealDictCursor

load_dotenv()

# ═══════════════════════════════════════════════════════════
# GROQ AI — Import an toàn, không crash nếu thiếu key/package
# ═══════════════════════════════════════════════════════════
groq_client = None
try:
    from groq import Groq
    GROQ_API_KEY = os.getenv('GROQ_API_KEY', '').strip()
    if GROQ_API_KEY:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("✅ Groq AI đã sẵn sàng")
    else:
        print("⚠️ Chưa có GROQ_API_KEY — dùng fallback từ điển")
except ImportError:
    print("⚠️ Chưa cài groq — dùng fallback từ điển")
except Exception as e:
    print(f"⚠️ Lỗi khởi tạo Groq: {e}")

# ═══ Import ten_utils (fallback) ═══
try:
    from ten_utils import generate_name
    print("✅ ten_utils đã sẵn sàng")
except ImportError:
    print("⚠️ Chưa có ten_utils.py — không có fallback!")
    def generate_name(name, mode='nghiem'):
        return {'error': 'Chưa có ten_utils.py'}

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-production')
app.permanent_session_lifetime = timedelta(days=7)

# ============================================================
# CẤU HÌNH
# ============================================================
DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
USERS_FILE = 'users.json'
SEED_FILE = 'seed_accounts.json'

SUPER_ADMIN_USERNAME = os.getenv('ADMIN_USER', 'Hùng')
SUPER_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
SUPER_ADMIN_DISPLAY = 'Hùng'

SUSPICIOUS_THRESHOLD = 50
WARN_THRESHOLD = 30
MAX_WARN_BEFORE_BAN_OPTION = 3
PENDING_DELETE_DAYS = 7


# ============================================================
# DATABASE LAYER
# ============================================================
def has_database():
    return bool(DATABASE_URL)


@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_db():
    if not has_database():
        print("⚠️ Không có DATABASE_URL — dùng JSON local")
        return
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        data JSONB NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW(),
                        updated_at TIMESTAMP DEFAULT NOW()
                    );
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_users_data
                    ON users USING GIN (data);
                """)
        print("✅ Đã khởi tạo bảng users trên Supabase")
    except Exception as e:
        print(f"❌ Lỗi init_db: {e}")


def load_users():
    if has_database():
        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT username, data FROM users")
                    rows = cur.fetchall()
                    return {row['username']: row['data'] for row in rows}
        except Exception as e:
            print(f"⚠️ Lỗi load từ DB: {e}")

    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Lỗi đọc JSON: {e}")
        return {}


def save_users(users):
    if has_database():
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    for username, data in users.items():
                        cur.execute("""
                            INSERT INTO users (username, data, updated_at)
                            VALUES (%s, %s, NOW())
                            ON CONFLICT (username)
                            DO UPDATE SET
                                data = EXCLUDED.data,
                                updated_at = NOW()
                        """, (username, Json(data)))
            return
        except Exception as e:
            print(f"❌ Lỗi save vào DB: {e}")

    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"❌ Lỗi ghi JSON: {e}")


def save_user(username, user_data):
    if has_database():
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (username, data, updated_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (username)
                        DO UPDATE SET
                            data = EXCLUDED.data,
                            updated_at = NOW()
                    """, (username, Json(user_data)))
            return
        except Exception as e:
            print(f"❌ Lỗi save_user: {e}")

    users = load_users()
    users[username] = user_data
    save_users(users)


def delete_user_db(username):
    if has_database():
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE username = %s", (username,))
            return
        except Exception as e:
            print(f"❌ Lỗi delete_user: {e}")

    users = load_users()
    if username in users:
        del users[username]
        save_users(users)


# ============================================================
# XỬ LÝ USERNAME
# ============================================================
def normalize_username(username):
    if not username:
        return ''
    return unicodedata.normalize('NFC', username.strip())


def remove_accents(s):
    if not s:
        return ''
    nfd = unicodedata.normalize('NFD', s)
    return ''.join(c for c in nfd if unicodedata.category(c) != 'Mn')


def usernames_match(a, b):
    if not a or not b:
        return False
    a_norm = normalize_username(a)
    b_norm = normalize_username(b)
    if a_norm.lower() == b_norm.lower():
        return True
    return remove_accents(a_norm).lower() == remove_accents(b_norm).lower()


def is_super_admin(username):
    return usernames_match(username, SUPER_ADMIN_USERNAME)


# ============================================================
# HASH PASSWORD
# ============================================================
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'),
        salt.encode('utf-8'), 100000
    ).hex()
    return f"{salt}${hashed}"


def verify_password(password, stored):
    try:
        salt, _ = stored.split('$', 1)
        return hash_password(password, salt) == stored
    except:
        return False


# ============================================================
# TẠO ID NGƯỜI DÙNG
# ============================================================
def generate_user_id(users=None):
    if users is None:
        users = load_users()
    existing_ids = set()
    for u_data in users.values():
        if u_data.get('user_id'):
            existing_ids.add(str(u_data['user_id']))
    for _ in range(100):
        new_id = str(random.randint(1000000000, 9999999999))
        if new_id not in existing_ids:
            return new_id
    base_id = 1000000000
    while str(base_id) in existing_ids:
        base_id += 1
    return str(base_id)


# ============================================================
# SEED ACCOUNTS
# ============================================================
def seed_accounts():
    seed_data = None
    source = None

    if os.path.exists(SEED_FILE):
        try:
            with open(SEED_FILE, 'r', encoding='utf-8') as f:
                seed_data = json.load(f)
            source = f"file {SEED_FILE}"
        except Exception as e:
            print(f"❌ Lỗi đọc {SEED_FILE}: {e}")

    if seed_data is None:
        env_seed = os.getenv('SEED_ACCOUNTS_JSON', '').strip()
        if env_seed:
            try:
                seed_data = json.loads(env_seed)
                source = "env SEED_ACCOUNTS_JSON"
            except Exception as e:
                print(f"❌ Lỗi parse SEED_ACCOUNTS_JSON: {e}")

    if seed_data is None:
        print("ℹ️ Không có seed data")
        return

    accounts = seed_data.get('accounts', [])
    if not accounts:
        print(f"ℹ️ Seed không có tài khoản")
        return

    print(f"📁 Đọc seed từ: {source}")
    print(f"🌱 Bắt đầu seed {len(accounts)} tài khoản...")

    users = load_users()
    created = 0
    skipped = 0
    failed = 0

    for acc in accounts:
        try:
            username = normalize_username(acc.get('username', ''))
            password = acc.get('password', '')
            role = acc.get('role', 'user')
            display_name = acc.get('display_name', username)
            status = acc.get('status', 'active')

            if not username or not password:
                failed += 1
                continue
            if len(password) < 6:
                failed += 1
                continue
            if role not in ('super_admin', 'admin', 'user'):
                role = 'user'

            exists = False
            for u in users.keys():
                if usernames_match(u, username):
                    exists = True
                    break
            if exists:
                skipped += 1
                continue

            now = datetime.now().isoformat()
            user_id = generate_user_id(users)

            users[username] = {
                'user_id': user_id,
                'password': hash_password(password),
                'role': role,
                'display_name': display_name,
                'created_at': now,
                'last_login': None,
                'login_count': 0,
                'history': [],
                'status': status,
                'warnings': [],
                'ban_info': None,
                'delete_info': None,
                'game_ban': None,                       # ⭐ MỚI
                'activity_log': [{'action': 'seed', 'detail': f'Tạo tự động — ID: {user_id}', 'time': now}],
                'suspicious_score': 0,
                'warnings_shown': True,
                'protected': (role == 'super_admin'),
                'game': {}
            }
            created += 1
            print(f"  ✅ Đã tạo: {username} ({role}) — ID: {user_id}")
        except Exception as e:
            print(f"  ❌ Lỗi: {acc.get('username', '?')}: {e}")
            failed += 1

    if created > 0:
        save_users(users)
    print(f"📊 Seed: {created} tạo mới, {skipped} bỏ qua, {failed} lỗi")


# ============================================================
# KHỞI TẠO SUPER ADMIN
# ============================================================
def init_super_admin():
    users = load_users()
    now = datetime.now().isoformat()
    admin_name = normalize_username(SUPER_ADMIN_USERNAME)

    existing_admin = None
    for u in users.keys():
        if usernames_match(u, admin_name):
            existing_admin = u
            break

    if existing_admin is None:
        user_id = generate_user_id(users)
        users[admin_name] = {
            'user_id': user_id,
            'password': hash_password(SUPER_ADMIN_PASSWORD),
            'role': 'super_admin',
            'display_name': SUPER_ADMIN_DISPLAY,
            'created_at': now,
            'last_login': None,
            'login_count': 0,
            'history': [],
            'status': 'active',
            'warnings': [],
            'ban_info': None,
            'delete_info': None,
            'game_ban': None,                            # ⭐ MỚI
            'activity_log': [{'action': 'system', 'detail': f'Super Admin — ID: {user_id}', 'time': now}],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': True,
            'game': {}
        }
        save_user(admin_name, users[admin_name])
        print(f"👑 Đã tạo SUPER ADMIN: {admin_name} — ID: {user_id}")
        return

    changed = False
    user = users[existing_admin]

    if existing_admin != admin_name:
        users[admin_name] = user
        delete_user_db(existing_admin)
        existing_admin = admin_name
        changed = True
    if user.get('role') != 'super_admin':
        user['role'] = 'super_admin'; changed = True
    if user.get('display_name') != SUPER_ADMIN_DISPLAY:
        user['display_name'] = SUPER_ADMIN_DISPLAY; changed = True
    if not user.get('user_id'):
        user['user_id'] = generate_user_id(users); changed = True
    if user.get('status') != 'active':
        user['status'] = 'active'; user['ban_info'] = None; user['delete_info'] = None; changed = True
    if not verify_password(SUPER_ADMIN_PASSWORD, user.get('password', '')):
        user['password'] = hash_password(SUPER_ADMIN_PASSWORD); changed = True
    if user.get('warnings'):
        user['warnings'] = []; user['warnings_shown'] = True; changed = True
    if not user.get('protected'):
        user['protected'] = True; changed = True
    if 'game' not in user:
        user['game'] = {}; changed = True
    if 'game_ban' not in user:
        user['game_ban'] = None; changed = True

    defaults = {'created_at': now, 'last_login': None, 'login_count': 0,
                'history': [], 'warnings': [], 'ban_info': None,
                'delete_info': None, 'activity_log': [],
                'suspicious_score': 0, 'warnings_shown': True}
    for k, v in defaults.items():
        if k not in user:
            user[k] = v; changed = True

    if changed:
        save_user(admin_name, user)
        print(f"👑 Đã cập nhật SUPER ADMIN: {admin_name}")
    else:
        print(f"✓ Super Admin {admin_name} đã sẵn sàng")


# ============================================================
# AUTO UNBAN / DELETE
# ============================================================
def auto_unban_expired():
    users = load_users()
    now = datetime.now()
    for username, user in users.items():
        if user.get('status') != 'banned': continue
        ban_info = user.get('ban_info', {}) or {}
        if not ban_info.get('is_temp_ban'): continue
        ban_until = ban_info.get('ban_until')
        if not ban_until: continue
        try:
            ban_until_dt = datetime.fromisoformat(ban_until)
            if now >= ban_until_dt:
                user['status'] = 'warned' if user.get('warnings') else 'active'
                user['ban_info'] = None
                user['warnings_shown'] = False
                save_user(username, user)
        except Exception as e:
            print(f"⚠️ Lỗi auto-unban {username}: {e}")


def auto_delete_expired():
    users = load_users()
    now = datetime.now()
    for username, user in users.items():
        if user.get('status') != 'pending_delete': continue
        delete_info = user.get('delete_info', {}) or {}
        expires_at = delete_info.get('expires_at')
        if not expires_at: continue
        try:
            expires_at_dt = datetime.fromisoformat(expires_at)
            if now >= expires_at_dt:
                delete_user_db(username)
                print(f"🗑️ Auto-delete: {username}")
        except Exception as e:
            print(f"⚠️ Lỗi auto-delete {username}: {e}")


def check_and_auto_unban(username):
    users = load_users()
    if username not in users: return {}
    user = users[username]
    if user.get('status') != 'banned': return user
    ban_info = user.get('ban_info', {}) or {}
    if not ban_info.get('is_temp_ban'): return user
    ban_until = ban_info.get('ban_until')
    if not ban_until: return user
    try:
        ban_until_dt = datetime.fromisoformat(ban_until)
        if datetime.now() >= ban_until_dt:
            user['status'] = 'warned' if user.get('warnings') else 'active'
            user['ban_info'] = None
            user['warnings_shown'] = False
            save_user(username, user)
    except Exception as e:
        print(f"⚠️ Lỗi auto-unban {username}: {e}")
    return user


def log_activity(username, action, detail=''):
    users = load_users()
    if username not in users: return
    user = users[username]
    log = user.get('activity_log', [])
    log.insert(0, {'action': action, 'detail': detail, 'time': datetime.now().isoformat()})
    user['activity_log'] = log[:50]
    try:
        five_min_ago = datetime.now() - timedelta(minutes=5)
        recent = [l for l in log if datetime.fromisoformat(l['time']) > five_min_ago]
        user['suspicious_score'] = len(recent)
        if (len(recent) >= SUSPICIOUS_THRESHOLD
            and user.get('status') == 'active'
            and user.get('role') != 'super_admin'):
            warnings = user.get('warnings', [])
            warnings.append({
                'user_id': user.get('user_id', '—'),
                'reason': f'Hoạt động bất thường: {len(recent)} thao tác/5 phút',
                'time': datetime.now().isoformat(),
                'by': 'system'
            })
            user['warnings'] = warnings
            user['status'] = 'warned'
            user['warnings_shown'] = False
    except Exception as e:
        print(f"⚠️ Lỗi log_activity: {e}")
    save_user(username, user)


def _format_duration(delta):
    total_seconds = int(delta.total_seconds())
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    parts = []
    if days: parts.append(f'{days} ngày')
    if hours: parts.append(f'{hours} giờ')
    if minutes: parts.append(f'{minutes} phút')
    if not parts and seconds: parts.append(f'{seconds} giây')
    return ' '.join(parts) if parts else '0 phút'


# ============================================================
# ⭐ GAME BAN — KIỂM TRA & XỬ LÝ (MỚI)
# ============================================================
def is_game_banned(user):
    """Kiểm tra user có bị cấm chơi game không.
    Trả về (True, game_ban_dict) hoặc (False, None)."""
    if not user:
        return False, None

    gb = user.get('game_ban')
    if not gb or not gb.get('is_banned'):
        return False, None

    # Nếu là cấm tạm thời → kiểm tra hết hạn
    if gb.get('is_temp'):
        ban_until = gb.get('ban_until')
        if ban_until:
            try:
                if datetime.now() >= datetime.fromisoformat(ban_until):
                    return False, None
            except Exception:
                pass

    return True, gb


def clear_expired_game_ban(username):
    """Nếu user có game_ban đã hết hạn → xóa khỏi DB."""
    users = load_users()
    if username not in users:
        return False

    user = users[username]
    gb = user.get('game_ban')

    if not gb or not gb.get('is_banned'):
        return False
    if not gb.get('is_temp'):
        return False

    ban_until = gb.get('ban_until')
    if not ban_until:
        return False

    try:
        if datetime.now() >= datetime.fromisoformat(ban_until):
            user['game_ban'] = None
            save_user(username, user)
            print(f"🔓 Auto-unban game: {username} (hết hạn lúc {ban_until})")
            return True
    except Exception as e:
        print(f"⚠️ Lỗi clear_expired_game_ban {username}: {e}")

    return False


def check_and_auto_unban_game(username):
    """Tự clear game_ban hết hạn, trả về user dict MỚI NHẤT."""
    clear_expired_game_ban(username)
    users = load_users()
    return users.get(username, {})


def auto_unban_expired_game():
    """Quét toàn bộ users, clear game_ban đã hết hạn (chạy lúc startup)."""
    users = load_users()
    now = datetime.now()
    count = 0
    for username, user in users.items():
        gb = user.get('game_ban')
        if not gb or not gb.get('is_banned'):
            continue
        if not gb.get('is_temp'):
            continue
        ban_until = gb.get('ban_until')
        if not ban_until:
            continue
        try:
            if now >= datetime.fromisoformat(ban_until):
                user['game_ban'] = None
                save_user(username, user)
                count += 1
                print(f"🔓 Auto-unban game: {username}")
        except Exception as e:
            print(f"⚠️ Lỗi auto_unban_game {username}: {e}")
    if count:
        print(f"📊 Auto game-unban: {count} user")


# ============================================================
# DECORATORS
# ============================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Chưa đăng nhập!', 'need_login': True}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Chưa đăng nhập!', 'need_login': True}), 401
            return redirect(url_for('login_page'))
        users = load_users()
        user = users.get(session['username'], {})
        if user.get('role') not in ('admin', 'super_admin'):
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Không có quyền admin!'}), 403
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


def super_admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Chưa đăng nhập!', 'need_login': True}), 401
            return redirect(url_for('login_page'))
        if not is_super_admin(session['username']):
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Chỉ Super Admin!'}), 403
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# AUTH ROUTES
# ============================================================
@app.route('/login')
def login_page():
    if 'username' in session:
        users = load_users()
        user = users.get(session['username'], {})
        if session['username'] not in users:
            session.clear()
            return redirect(url_for('login_page'))
        if user.get('status') == 'banned' and not is_super_admin(session['username']):
            uname = session.get('username', '')
            session.clear()
            return redirect(url_for('banned_page', user=uname))
        if user.get('status') == 'pending_delete':
            return redirect(url_for('deleted_page'))
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = normalize_username(data.get('username', ''))
        password = data.get('password', '')

        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Tên đăng nhập phải có ít nhất 3 ký tự!'}), 400
        if len(username) > 30:
            return jsonify({'success': False, 'error': 'Tên đăng nhập tối đa 30 ký tự!'}), 400
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Mật khẩu phải có ít nhất 6 ký tự!'}), 400
        if usernames_match(username, SUPER_ADMIN_USERNAME):
            return jsonify({'success': False, 'error': 'Tên này đã được bảo vệ!'}), 400

        users = load_users()
        for u in users.keys():
            if usernames_match(u, username):
                return jsonify({'success': False, 'error': 'Tên đăng nhập đã tồn tại!'}), 400

        now = datetime.now().isoformat()
        user_id = generate_user_id(users)

        users[username] = {
            'user_id': user_id,
            'password': hash_password(password),
            'role': 'user',
            'display_name': username,
            'created_at': now,
            'last_login': now,
            'login_count': 1,
            'history': [],
            'status': 'active',
            'warnings': [],
            'ban_info': None,
            'delete_info': None,
            'game_ban': None,                       # ⭐ MỚI
            'activity_log': [{'action': 'register', 'detail': f'Đăng ký — ID: {user_id}', 'time': now}],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': False,
            'game': {}
        }
        save_user(username, users[username])

        session.permanent = True
        session['username'] = username
        session['login_time'] = now

        return jsonify({
            'success': True,
            'message': f'Chào mừng {username}!',
            'username': username,
            'user_id': user_id,
            'role': 'user'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember = data.get('remember', False)

        if not username or not password:
            return jsonify({'success': False, 'error': 'Vui lòng nhập đầy đủ!'}), 400

        users = load_users()

        if usernames_match(username, SUPER_ADMIN_USERNAME):
            found_admin = None
            for u in users.keys():
                if usernames_match(u, SUPER_ADMIN_USERNAME):
                    found_admin = u
                    break
            if not found_admin:
                init_super_admin()
                users = load_users()
                for u in users.keys():
                    if usernames_match(u, SUPER_ADMIN_USERNAME):
                        found_admin = u
                        break
            if not found_admin:
                return jsonify({'success': False, 'error': 'Lỗi tạo admin!'}), 500
            if password != SUPER_ADMIN_PASSWORD and not verify_password(password, users[found_admin]['password']):
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
            found_user = found_admin
        else:
            found_user = None
            for u in users.keys():
                if usernames_match(u, username):
                    found_user = u
                    break
            if not found_user:
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
            if not verify_password(password, users[found_user]['password']):
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

        user = check_and_auto_unban(found_user)

        if user.get('status') == 'banned' and not is_super_admin(found_user):
            ban_info = user.get('ban_info', {}) or {}
            return jsonify({
                'success': False, 'error': 'Tài khoản đã bị BAN!',
                'banned': True, 'ban_info': ban_info,
                'ban_until': ban_info.get('ban_until'),
                'user_id': user.get('user_id', '—'),
                'redirect': f'/banned?user={found_user}'
            }), 403

        if user.get('status') == 'pending_delete':
            delete_info = user.get('delete_info', {}) or {}
            return jsonify({
                'success': False, 'error': 'Tài khoản đã bị đánh dấu xóa!',
                'pending_delete': True, 'delete_info': delete_info,
                'user_id': user.get('user_id', '—'),
                'redirect': '/deleted'
            }), 403

        # ═══ KIỂM TRA 2FA ═══
        totp_enabled = user.get('totp_enabled', False)
        if totp_enabled:
            return jsonify({
                'success': False,
                'need_2fa': True,
                'username': found_user,
                'message': 'Nhập mã 2FA từ Google Authenticator',
            }), 202

        users = load_users()
        now = datetime.now().isoformat()
        users[found_user]['last_login'] = now
        users[found_user]['login_count'] = users[found_user].get('login_count', 0) + 1
        log = users[found_user].get('activity_log', [])
        log.insert(0, {'action': 'login', 'detail': f'Đăng nhập lần {users[found_user]["login_count"]}', 'time': now})
        users[found_user]['activity_log'] = log[:50]
        save_user(found_user, users[found_user])

        session.permanent = remember
        session['username'] = found_user
        session['login_time'] = now

        warnings = users[found_user].get('warnings', [])
        return jsonify({
            'success': True,
            'message': f'Chào mừng trở lại, {users[found_user].get("display_name", found_user)}!',
            'username': found_user,
            'user_id': users[found_user].get('user_id', '—'),
            'role': users[found_user].get('role', 'user'),
            'is_super_admin': is_super_admin(found_user),
            'has_warnings': len(warnings) > 0,
            'warnings_count': len(warnings)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/login/2fa', methods=['POST'])
def login_2fa():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        code = data.get('code', '').strip()

        if not username or not code:
            return jsonify({'success': False, 'error': 'Thiếu username hoặc mã!'}), 400

        users = load_users()
        found_user = None
        for u in users.keys():
            if usernames_match(u, username):
                found_user = u
                break

        if not found_user:
            return jsonify({'success': False, 'error': 'User không tồn tại!'}), 404

        user = users[found_user]

        if not user.get('totp_enabled'):
            return jsonify({'success': False, 'error': 'Tài khoản không bật 2FA!'}), 400

        secret = user.get('totp_secret', '')
        backup_hashes = user.get('totp_backup_codes', [])

        if verify_code(secret, code):
            session.permanent = True
            session['username'] = found_user
            session['login_time'] = datetime.now().isoformat()
            session['2fa_verified'] = True

            log = user.get('activity_log', [])
            log.insert(0, {
                'action': 'login_2fa',
                'detail': 'Đăng nhập với 2FA',
                'time': datetime.now().isoformat(),
            })
            user['activity_log'] = log[:50]
            save_user(found_user, user)

            return jsonify({
                'success': True,
                'message': '✅ Đăng nhập thành công!',
                'username': found_user,
                'redirect': '/',
            })

        matched_hash = verify_backup_code(code, backup_hashes)
        if matched_hash:
            backup_hashes.remove(matched_hash)
            user['totp_backup_codes'] = backup_hashes
            save_user(found_user, user)

            session.permanent = True
            session['username'] = found_user
            session['login_time'] = datetime.now().isoformat()
            session['2fa_verified'] = True

            return jsonify({
                'success': True,
                'message': f'✅ Đăng nhập bằng backup code! Còn {len(backup_hashes)} mã.',
                'username': found_user,
                'redirect': '/',
            })

        return jsonify({'success': False, 'error': 'Mã 2FA không đúng!'}), 401

    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    if 'username' in session:
        log_activity(session['username'], 'logout', 'Đăng xuất')
    session.clear()
    return jsonify({'success': True, 'message': 'Đã đăng xuất'})


@app.route('/api/me')
@login_required
def me():
    users = load_users()
    username = session['username']

    if username not in users:
        session.clear()
        return jsonify({'success': False, 'deleted': True, 'kicked': True,
                        'error': 'Tài khoản đã bị xóa!', 'redirect': '/deleted-force'}), 403

    user = check_and_auto_unban(username)

    if user.get('status') == 'banned' and not is_super_admin(username):
        ban_info = user.get('ban_info', {}) or {}
        return jsonify({'success': False, 'banned': True,
                        'error': 'Tài khoản đã bị ban!',
                        'ban_info': ban_info, 'user_id': user.get('user_id', '—'),
                        'ban_until': ban_info.get('ban_until'),
                        'redirect': f'/banned?user={username}'}), 403

    if user.get('status') == 'pending_delete':
        delete_info = user.get('delete_info', {}) or {}
        return jsonify({'success': False, 'pending_delete': True,
                        'error': 'Tài khoản đã bị đánh dấu xóa!',
                        'delete_info': delete_info, 'user_id': user.get('user_id', '—'),
                        'redirect': '/deleted'}), 403

    return jsonify({
        'success': True, 'logged_in': True,
        'username': session['username'],
        'user_id': user.get('user_id', '—'),
        'display_name': user.get('display_name', session['username']),
        'role': user.get('role', 'user'),
        'is_super_admin': is_super_admin(session['username']),
        'login_time': session.get('login_time'),
        'login_count': user.get('login_count', 0),
        'created_at': user.get('created_at'),
        'status': user.get('status', 'active'),
        'warnings': user.get('warnings', []),
        'warnings_shown': user.get('warnings_shown', False),
        'history_count': len(user.get('history', []))
    })


# ============================================================
# BAN PAGE
# ============================================================
@app.route('/banned')
def banned_page():
    username = request.args.get('user', '').strip()
    check_and_auto_unban(username)
    users = load_users()
    found_user = None
    for u in users.keys():
        if usernames_match(u, username):
            found_user = u
            break
    if not found_user:
        return redirect(url_for('login_page'))
    user = users[found_user]
    if user.get('status') != 'banned':
        return redirect(url_for('login_page'))

    ban_info = user.get('ban_info', {}) or {}
    ban_id = hashlib.md5(f"{found_user}{ban_info.get('time', '')}".encode()).hexdigest()[:12].upper()

    banned_at = ban_info.get('time', '')
    if banned_at:
        try: banned_at = datetime.fromisoformat(banned_at).strftime('%d/%m/%Y %H:%M:%S')
        except: banned_at = banned_at[:19].replace('T', ' ')

    ban_until_display = None
    ban_until_iso = None
    ban_until = ban_info.get('ban_until')
    if ban_until:
        ban_until_iso = ban_until
        try:
            ban_until_dt = datetime.fromisoformat(ban_until)
            ban_until_display = ban_until_dt.strftime('%d/%m/%Y %H:%M:%S')
        except: ban_until_display = ban_until[:19].replace('T', ' ')

    return render_template('banned.html',
        username=user.get('display_name', found_user),
        user_id=user.get('user_id', '—'),
        reason=ban_info.get('reason', 'Vi phạm điều khoản'),
        banned_at=banned_at or '—',
        banned_by=ban_info.get('by', 'System'),
        ban_id=ban_id,
        ban_until_display=ban_until_display,
        ban_until_iso=ban_until_iso,
        is_temp_ban=ban_info.get('is_temp_ban', False),
        duration_label=ban_info.get('duration_label', 'Vĩnh viễn'))


# ============================================================
# DELETED PAGES
# ============================================================
@app.route('/deleted-force')
def deleted_force_page():
    return render_template('deleted_force.html',
        username=request.args.get('user', 'Unknown'),
        user_id=request.args.get('id', '—'),
        reason=request.args.get('reason', 'Vi phạm điều khoản nghiêm trọng'),
        deleted_by=request.args.get('by', 'Admin'))


@app.route('/deleted')
def deleted_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    users = load_users()
    username = session['username']
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = users[username]
    if user.get('status') != 'pending_delete':
        return redirect(url_for('index'))

    delete_info = user.get('delete_info', {}) or {}
    deleted_at = delete_info.get('time', '')
    if deleted_at:
        try: deleted_at = datetime.fromisoformat(deleted_at).strftime('%d/%m/%Y %H:%M:%S')
        except: deleted_at = deleted_at[:19].replace('T', ' ')
    expires_at_display = None
    expires_at = delete_info.get('expires_at')
    if expires_at:
        try: expires_at_display = datetime.fromisoformat(expires_at).strftime('%d/%m/%Y %H:%M:%S')
        except: expires_at_display = expires_at[:19].replace('T', ' ')
    delete_id = hashlib.md5(f"{username}{delete_info.get('time', '')}".encode()).hexdigest()[:12].upper()

    return render_template('deleted.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'),
        reason=delete_info.get('reason', 'Vi phạm điều khoản'),
        deleted_at=deleted_at or '—',
        deleted_by=delete_info.get('by', 'System'),
        expires_at_display=expires_at_display,
        delete_id=delete_id)


@app.route('/api/confirm-delete', methods=['POST'])
def confirm_delete():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Chưa đăng nhập!'}), 401
    users = load_users()
    username = session['username']
    if username not in users:
        session.clear()
        return jsonify({'success': False, 'error': 'Tài khoản không tồn tại!'}), 404
    user = users[username]
    if user.get('status') != 'pending_delete':
        return jsonify({'success': False, 'error': 'Không ở trạng thái chờ xóa!'}), 400
    delete_user_db(username)
    session.clear()
    return jsonify({'success': True, 'message': f'Đã xóa tài khoản {username}', 'deleted': True})


# ============================================================
# WARNED PAGE
# ============================================================
@app.route('/warned')
def warned_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    users = load_users()
    user = users.get(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))
    if user.get('status') == 'banned' and not is_super_admin(session['username']):
        return redirect(url_for('banned_page', user=session['username']))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))
    return render_template('warned.html',
        username=user.get('display_name', session['username']),
        user_id=user.get('user_id', '—'),
        warnings=user.get('warnings', []))


@app.route('/api/acknowledge-warnings', methods=['POST'])
def acknowledge_warnings():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Chưa đăng nhập!'}), 401
    users = load_users()
    if session['username'] in users:
        users[session['username']]['warnings_shown'] = True
        save_user(session['username'], users[session['username']])
    return jsonify({'success': True, 'message': 'Đã ghi nhận'})


# ============================================================
# MAIN PAGES
# ============================================================
@app.route('/')
@login_required
def index():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('deleted_force_page', user=username))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        session.clear()
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('index.html',
        methods=METHODS,
        methods_by_group=get_methods_by_group(),
        group_names=GROUP_NAMES,
        total_methods=len(METHODS),
        username=user.get('display_name', username),
        real_username=username,
        user_id=user.get('user_id', '—'),
        role=user.get('role', 'user'),
        is_super_admin=is_super_admin(username))


@app.route('/translate')
@login_required
def translate_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))
    return render_template('translate.html')


@app.route('/api/translate', methods=['GET', 'POST'])
@login_required
def api_translate():
    if request.method == 'GET':
        return jsonify({'languages': LANGUAGES, 'modes': ['manual', 'auto']})
    data = request.get_json(silent=True) or request.form
    text   = (data.get('text')   or '').strip()
    source = (data.get('source') or 'auto').strip()
    target = (data.get('target') or 'en').strip()
    mode   = (data.get('mode')   or 'manual').strip().lower()
    if not text:
        return jsonify({'error': 'Văn bản trống!'}), 400
    try:
        if mode == 'auto':
            info = auto_translate(text)
            return jsonify({'result': info['result'], 'source': info['detected'],
                            'target': info['target'], 'detected': info['detected']})
        if target not in LANGUAGES:
            return jsonify({'error': f'Ngôn ngữ đích không hỗ trợ: {target}'}), 400
        result = translate(text, source=source, target=target)
        return jsonify({'result': result, 'source': source, 'target': target})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Lỗi server: {e}'}), 500


@app.route('/api/detect', methods=['POST'])
@login_required
def api_detect():
    data = request.get_json(silent=True) or request.form
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Văn bản trống!'}), 400
    try:
        return jsonify({'detected': detect_language(text)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/process', methods=['POST'])
@login_required
def api_process():
    try:
        users = load_users()
        username = session['username']
        if username not in users:
            session.clear()
            return jsonify({'success': False, 'deleted': True, 'kicked': True,
                            'error': 'Tài khoản đã bị xóa!', 'redirect': '/deleted-force'}), 403
        user = check_and_auto_unban(username)
        if user.get('status') == 'banned' and not is_super_admin(username):
            ban_info = user.get('ban_info', {}) or {}
            return jsonify({'success': False, 'error': 'Tài khoản đã bị BAN!',
                            'banned': True, 'blocked': True, 'ban_info': ban_info,
                            'user_id': user.get('user_id', '—'), 'username': username}), 403
        if user.get('status') == 'pending_delete':
            return jsonify({'success': False, 'error': 'Tài khoản đã bị đánh dấu xóa!',
                            'pending_delete': True, 'blocked': True,
                            'user_id': user.get('user_id', '—'), 'redirect': '/deleted'}), 403

        data = request.get_json()
        text = data.get('text', '').strip()
        method = data.get('method', 'base64')
        action = data.get('action', 'encrypt')
        key = data.get('key', '')

        if not text:
            return jsonify({'success': False, 'error': 'Văn bản trống!'}), 400
        if method not in METHODS:
            return jsonify({'success': False, 'error': 'Phương pháp không hợp lệ!'}), 400
        if action == 'decrypt' and method in ONE_WAY_ONLY:
            return jsonify({'success': False, 'error': f'PP "{METHODS[method]}" là 1 chiều!'}), 400

        result = process(text, method, action, key)
        history = user.get('history', [])
        history.insert(0, {'method': method, 'action': action,
                          'input_preview': text[:50], 'output_preview': result[:50],
                          'time': datetime.now().isoformat()})
        users[username]['history'] = history[:20]
        save_user(username, users[username])
        log_activity(username, action, f'{method}: {text[:30]}')
        return jsonify({'success': True, 'result': result, 'method': method,
                        'action': action, 'one_way': method in ONE_WAY_ONLY})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/history')
@login_required
def api_history():
    users = load_users()
    user = users.get(session['username'], {})
    return jsonify({'success': True, 'history': user.get('history', [])})


# ============================================================
# GAME HUB - CHỈ CÓ 2 GAME
# ============================================================
@app.route('/game')
@login_required
def game_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    # ⭐ Check cấm game (tự clear nếu hết hạn)
    user = check_and_auto_unban_game(username)
    banned, gb = is_game_banned(user)
    if banned and not is_super_admin(username):
        return render_template('game_banned.html',
            username=user.get('display_name', username),
            user_id=user.get('user_id', '—'),
            reason=gb.get('reason', 'Vi phạm quy định game'),
            banned_at=gb.get('banned_at', '—'),
            banned_by=gb.get('banned_by', 'Admin'),
            is_temp=gb.get('is_temp', False),
            ban_until=gb.get('ban_until'),
            duration_label=gb.get('duration_label', 'Vĩnh viễn'))

    return render_template('game.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


# ============================================================
# GAME 1: ĐOÁN SỐ
# ============================================================
@app.route('/game/guess')
@login_required
def game_guess_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    # ⭐ Check cấm game
    user = check_and_auto_unban_game(username)
    banned, gb = is_game_banned(user)
    if banned and not is_super_admin(username):
        return redirect(url_for('game_page'))

    session['guess_secret'] = random.randint(1, 100)
    session['guess_count'] = 0
    return render_template('game_guess.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


@app.route('/api/game/guess/check', methods=['POST'])
@login_required
def api_guess_check():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    # ⭐ Check cấm game
    user = check_and_auto_unban_game(username)
    banned, gb = is_game_banned(user)
    if banned and not is_super_admin(username):
        return jsonify({
            'success': False, 'game_banned': True,
            'error': 'Bạn đã bị cấm chơi game!',
            'reason': gb.get('reason', ''),
            'redirect': '/game'
        }), 403

    data = request.get_json() or {}
    try:
        guess = int(data.get('guess', 0))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'Vui lòng nhập số hợp lệ!'}), 400

    if guess < 1 or guess > 100:
        return jsonify({'success': False, 'error': 'Số phải từ 1 đến 100!'}), 400

    secret = session.get('guess_secret')
    if secret is None:
        return jsonify({'success': False, 'error': 'Phiên chơi hết hạn, tải lại trang!'}), 400

    session['guess_count'] = session.get('guess_count', 0) + 1
    count = session['guess_count']

    if guess == secret:
        if count <= 3:    points = 50
        elif count <= 6:  points = 30
        elif count <= 10: points = 15
        else:             points = 5

        user = users[username]
        game = user.setdefault('game', {})
        best = game.get('guess_best_count')
        if best is None or count < best:
            game['guess_best_count'] = count
        game['guess_total_wins'] = game.get('guess_total_wins', 0) + 1
        game['points'] = game.get('points', 0) + points
        users[username] = user
        save_user(username, user)

        session.pop('guess_secret', None)
        return jsonify({
            'success': True, 'result': 'correct',
            'message': f'🎉 Chính xác! Đoán đúng sau {count} lần. +{points} điểm!',
            'count': count, 'points_earned': points,
        })
    elif guess < secret:
        return jsonify({
            'success': True, 'result': 'low',
            'message': '⬆️ Số bí mật LỚN HƠN!', 'count': count
        })
    else:
        return jsonify({
            'success': True, 'result': 'high',
            'message': '⬇️ Số bí mật NHỎ HƠN!', 'count': count
        })


@app.route('/api/game/guess/reset', methods=['POST'])
@login_required
def api_guess_reset():
    session['guess_secret'] = random.randint(1, 100)
    session['guess_count'] = 0
    return jsonify({'success': True, 'message': 'Đã tạo số mới!'})


# ============================================================
# GAME 2: RẮN SĂN MỒI
# ============================================================
@app.route('/game/snake')
@login_required
def game_snake_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    # ⭐ Check cấm game
    user = check_and_auto_unban_game(username)
    banned, gb = is_game_banned(user)
    if banned and not is_super_admin(username):
        return redirect(url_for('game_page'))

    return render_template('game_snake.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


@app.route('/api/game/snake/score', methods=['POST'])
@login_required
def api_snake_score():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    # ⭐ Check cấm game
    user = check_and_auto_unban_game(username)
    banned, gb = is_game_banned(user)
    if banned and not is_super_admin(username):
        return jsonify({
            'success': False, 'game_banned': True,
            'error': 'Bạn đã bị cấm chơi game!',
            'reason': gb.get('reason', ''),
            'redirect': '/game'
        }), 403

    data = request.get_json() or {}
    try:
        score = int(data.get('score', 0))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'Điểm không hợp lệ!'}), 400

    if score < 0 or score > 100000:
        return jsonify({'success': False, 'error': 'Điểm không hợp lệ!'}), 400

    user = users[username]
    game = user.setdefault('game', {})
    best = game.get('snake_best', 0)
    is_new_record = score > best

    if is_new_record:
        game['snake_best'] = score
        bonus_points = score // 10
        if bonus_points > 0:
            game['points'] = game.get('points', 0) + bonus_points

    users[username] = user
    save_user(username, user)

    return jsonify({
        'success': True,
        'best': game.get('snake_best', 0),
        'is_new_record': is_new_record,
        'points_earned': (score // 10) if is_new_record else 0,
    })

# ============================================================
# API CHECK BAN — DÙNG CHO POLLING TRANG GAME
# ============================================================
@app.route('/api/game/check-ban')
@login_required
def api_game_check_ban():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({
            'success': True, 'account_banned': True,
            'redirect': f'/banned?user={username}'
        })
    if user.get('status') == 'pending_delete':
        return jsonify({
            'success': True, 'pending_delete': True,
            'redirect': '/deleted'
        })

    user = check_and_auto_unban_game(username)
    banned, gb = is_game_banned(user)

    return jsonify({
        'success': True,
        'is_banned': banned,
        'account_banned': False,
        'pending_delete': False,
        'game_ban': gb,
        'user_id': user.get('user_id', '—'),
        'username': user.get('display_name', username),
    })

@app.route('/api/game/snake/best')
@login_required
def api_snake_best():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    # ⭐ Check cấm game
    user = check_and_auto_unban_game(username)
    banned, gb = is_game_banned(user)
    if banned and not is_super_admin(username):
        return jsonify({
            'success': False, 'game_banned': True,
            'error': 'Bạn đã bị cấm chơi game!',
            'reason': gb.get('reason', ''),
            'redirect': '/game'
        }), 403

    game = users[username].get('game', {})
    return jsonify({'success': True, 'best': game.get('snake_best', 0)})


# ============================================================
# LEADERBOARD
# ============================================================
@app.route('/api/game/leaderboard')
@login_required
def api_leaderboard():
    users = load_users()
    board = []
    for uname, udata in users.items():
        game = udata.get('game', {})
        points = game.get('points', 0)
        snake_best = game.get('snake_best', 0)
        guess_best = game.get('guess_best_count')
        if points > 0 or snake_best > 0 or guess_best:
            board.append({
                'username': udata.get('display_name', uname),
                'real_username': uname,
                'user_id': udata.get('user_id', '—'),
                'points': points,
                'snake_best': snake_best,
                'guess_best_count': guess_best,
                'is_super_admin': is_super_admin(uname)
            })
    board.sort(key=lambda x: -x['points'])
    for i, u in enumerate(board):
        u['rank'] = i + 1
        if i == 0: u['medal'] = '🥇'
        elif i == 1: u['medal'] = '🥈'
        elif i == 2: u['medal'] = '🥉'
        else: u['medal'] = f'#{i+1}'
    return jsonify({'success': True, 'leaderboard': board[:50]})


# ============================================================
# ADMIN PANEL
# ============================================================
@app.route('/admin')
@admin_required
def admin_panel():
    users = load_users()
    user = users.get(session['username'], {})
    return render_template('admin.html',
        username=user.get('display_name', session['username']),
        real_username=session['username'],
        user_id=user.get('user_id', '—'),
        is_super_admin=is_super_admin(session['username']),
        role=user.get('role', 'user'))


@app.route('/api/admin/users')
@admin_required
def admin_users():
    users = load_users()
    result = []
    for username, data in users.items():
        result.append({
            'username': username,
            'user_id': data.get('user_id', '—'),
            'display_name': data.get('display_name', username),
            'role': data.get('role', 'user'),
            'status': data.get('status', 'active'),
            'login_count': data.get('login_count', 0),
            'created_at': data.get('created_at'),
            'last_login': data.get('last_login'),
            'warnings_count': len(data.get('warnings', [])),
            'history_count': len(data.get('history', [])),
            'suspicious_score': data.get('suspicious_score', 0),
            'ban_info': data.get('ban_info'),
            'delete_info': data.get('delete_info'),
            'game_ban': data.get('game_ban'),                                       # ⭐ MỚI
            'is_game_banned': bool(data.get('game_ban') and data.get('game_ban', {}).get('is_banned')),  # ⭐ MỚI
            'protected': data.get('protected', False),
            'is_super_admin': is_super_admin(username),
            'can_ban_1_day': len(data.get('warnings', [])) >= (MAX_WARN_BEFORE_BAN_OPTION - 1)
        })

    def sort_key(u):
        if u['is_super_admin']: return (0, 0, 0, u['username'].lower())
        if u['role'] == 'admin': return (1, 0, 0, u['username'].lower())
        if u['status'] == 'banned': return (2, 0, 0, u['username'].lower())
        if u['status'] == 'pending_delete': return (2, 0, 1, u['username'].lower())
        if u['status'] == 'warned': return (2, 1, 0, u['username'].lower())
        return (2, 2, 0, u['username'].lower())

    result.sort(key=sort_key)
    return jsonify({'success': True, 'users': result})


@app.route('/api/admin/ban', methods=['POST'])
@super_admin_required
def admin_ban():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Vi phạm điều khoản').strip() or 'Vi phạm điều khoản'
        duration = data.get('duration', 'permanent')
        custom_value = data.get('custom_value')
        custom_unit = data.get('custom_unit', 'hours')

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400
        if usernames_match(target, session['username']):
            return jsonify({'success': False, 'error': '🚫 KHÔNG THỂ TỰ BAN!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if is_super_admin(target):
            return jsonify({'success': False, 'error': '🚫 Không thể ban Super Admin!'}), 403

        target_id = users[target].get('user_id', '—')
        now = datetime.now()
        ban_info = {'user_id': target_id, 'reason': reason,
                    'time': now.isoformat(), 'by': session['username'],
                    'duration_label': 'Vĩnh viễn', 'is_temp_ban': False}

        duration_map = {
            '15min': timedelta(minutes=15), '30min': timedelta(minutes=30),
            '1h': timedelta(hours=1), '6h': timedelta(hours=6),
            '12h': timedelta(hours=12), '1day': timedelta(days=1),
            '3days': timedelta(days=3), '7days': timedelta(days=7),
            '30days': timedelta(days=30),
        }

        if duration == 'permanent':
            ban_info['duration_label'] = 'Vĩnh viễn'
            ban_info['is_temp_ban'] = False
        elif duration in duration_map:
            delta = duration_map[duration]
            ban_info['ban_until'] = (now + delta).isoformat()
            ban_info['is_temp_ban'] = True
            ban_info['duration_label'] = _format_duration(delta)
        elif duration == 'custom':
            try: custom_value = int(custom_value)
            except (TypeError, ValueError):
                return jsonify({'success': False, 'error': 'Giá trị thời gian không hợp lệ!'}), 400
            if custom_value <= 0:
                return jsonify({'success': False, 'error': 'Thời gian phải > 0!'}), 400
            if custom_value > 3650:
                return jsonify({'success': False, 'error': 'Tối đa 3650!'}), 400
            if custom_unit == 'minutes': delta = timedelta(minutes=custom_value)
            elif custom_unit == 'hours': delta = timedelta(hours=custom_value)
            elif custom_unit == 'days': delta = timedelta(days=custom_value)
            else:
                return jsonify({'success': False, 'error': 'Đơn vị không hợp lệ!'}), 400
            ban_info['ban_until'] = (now + delta).isoformat()
            ban_info['is_temp_ban'] = True
            ban_info['duration_label'] = _format_duration(delta)
        else:
            return jsonify({'success': False, 'error': f'Thời gian không hợp lệ: {duration}'}), 400

        users[target]['status'] = 'banned'
        users[target]['ban_info'] = ban_info
        save_user(target, users[target])
        return jsonify({'success': True,
                        'message': f'🚫 Đã ban user ID {target_id} ({ban_info["duration_label"]})',
                        'ban_info': ban_info})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/unban', methods=['POST'])
@super_admin_required
def admin_unban():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        target_id = users[target].get('user_id', '—')
        users[target]['status'] = 'warned' if users[target].get('warnings') else 'active'
        users[target]['ban_info'] = None
        users[target]['warnings_shown'] = False
        save_user(target, users[target])
        return jsonify({'success': True, 'message': f'✅ Đã gỡ ban user ID {target_id}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/warn', methods=['POST'])
@super_admin_required
def admin_warn():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Cảnh báo từ admin').strip() or 'Cảnh báo từ admin'
        ban_1_day = data.get('ban_1_day', False)

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400
        if usernames_match(target, session['username']):
            return jsonify({'success': False, 'error': '🚫 KHÔNG THỂ TỰ CẢNH BÁO!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if is_super_admin(target):
            return jsonify({'success': False, 'error': '🚫 Không thể cảnh báo Super Admin!'}), 403

        target_id = users[target].get('user_id', '—')
        warnings = users[target].get('warnings', [])
        warnings.append({'user_id': target_id, 'reason': reason,
                        'time': datetime.now().isoformat(), 'by': session['username']})
        users[target]['warnings'] = warnings
        users[target]['warnings_shown'] = False

        if users[target].get('status') == 'active':
            users[target]['status'] = 'warned'

        if ban_1_day:
            users[target]['status'] = 'banned'
            users[target]['ban_info'] = {
                'user_id': target_id,
                'reason': f'{reason} (Ban 1 ngày vì có {len(warnings)} cảnh báo)',
                'time': datetime.now().isoformat(),
                'by': session['username'],
                'ban_until': (datetime.now() + timedelta(days=1)).isoformat(),
                'is_temp_ban': True,
                'duration_label': '1 ngày'
            }

        save_user(target, users[target])
        if ban_1_day:
            return jsonify({'success': True, 'message': f'⚠️🚫 Đã warn + ban 1 ngày user ID {target_id}',
                            'total_warnings': len(warnings), 'banned': True})
        else:
            return jsonify({'success': True, 'message': f'⚠️ Đã cảnh báo user ID {target_id}',
                            'total_warnings': len(warnings), 'banned': False})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/reset-warnings', methods=['POST'])
@super_admin_required
def admin_reset_warnings():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        target_id = users[target].get('user_id', '—')
        users[target]['warnings'] = []
        users[target]['warnings_shown'] = True
        if users[target].get('status') == 'warned':
            users[target]['status'] = 'active'
        save_user(target, users[target])
        return jsonify({'success': True, 'message': f'🔄 Đã xóa cảnh báo của user ID {target_id}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/user/<username>')
@admin_required
def admin_user_detail(username):
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
    return jsonify({
        'success': True,
        'user': {
            'username': username,
            'user_id': user.get('user_id', '—'),
            'display_name': user.get('display_name', username),
            'role': user.get('role', 'user'),
            'status': user.get('status', 'active'),
            'created_at': user.get('created_at'),
            'last_login': user.get('last_login'),
            'login_count': user.get('login_count', 0),
            'warnings': user.get('warnings', []),
            'ban_info': user.get('ban_info'),
            'delete_info': user.get('delete_info'),
            'game_ban': user.get('game_ban'),                        # ⭐ MỚI
            'activity_log': user.get('activity_log', [])[:20],
            'history_count': len(user.get('history', [])),
            'suspicious_score': user.get('suspicious_score', 0),
            'is_super_admin': is_super_admin(username)
        }
    })


@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    users = load_users()
    total = len(users)
    active = sum(1 for u in users.values() if u.get('status') == 'active')
    warned = sum(1 for u in users.values() if u.get('status') == 'warned')
    banned = sum(1 for u in users.values() if u.get('status') == 'banned')
    pending_delete = sum(1 for u in users.values() if u.get('status') == 'pending_delete')
    admins = sum(1 for u in users.values() if u.get('role') in ('admin', 'super_admin'))
    suspicious = sum(1 for u in users.values() if u.get('suspicious_score', 0) >= WARN_THRESHOLD)
    game_banned = sum(1 for u in users.values()
                      if u.get('game_ban') and u.get('game_ban', {}).get('is_banned'))   # ⭐ MỚI
    return jsonify({'success': True, 'stats': {
        'total': total, 'active': active, 'warned': warned, 'banned': banned,
        'pending_delete': pending_delete, 'admins': admins, 'suspicious': suspicious,
        'game_banned': game_banned                                                       # ⭐ MỚI
    }})


@app.route('/api/admin/delete', methods=['POST'])
@super_admin_required
def admin_delete():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Vi phạm điều khoản nghiêm trọng').strip() or 'Vi phạm điều khoản nghiêm trọng'
        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400
        if usernames_match(target, session['username']):
            return jsonify({'success': False, 'error': '🚫 KHÔNG THỂ TỰ XÓA!'}), 400
        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if is_super_admin(target):
            return jsonify({'success': False, 'error': '🚫 Không thể xóa Super Admin!'}), 403
        target_id = users[target].get('user_id', '—')
        users[target]['status'] = 'pending_delete'
        users[target]['delete_info'] = {
            'user_id': target_id, 'reason': reason,
            'time': datetime.now().isoformat(), 'by': session['username'],
            'expires_at': (datetime.now() + timedelta(days=PENDING_DELETE_DAYS)).isoformat()
        }
        save_user(target, users[target])
        return jsonify({'success': True, 'message': f'⚠️ Đã đánh dấu xóa user ID {target_id}',
                        'delete_info': users[target]['delete_info']})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/force-delete', methods=['POST'])
@super_admin_required
def admin_force_delete():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Vi phạm nghiêm trọng').strip() or 'Vi phạm nghiêm trọng'
        confirm_text = data.get('confirm_text', '').strip()
        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400
        if usernames_match(target, session['username']):
            return jsonify({'success': False, 'error': '🚫 KHÔNG THỂ TỰ XÓA CHÍNH MÌNH!'}), 400
        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if is_super_admin(target):
            return jsonify({'success': False, 'error': '🚫 Không thể xóa Super Admin!'}), 403
        target_id = users[target].get('user_id', '—')
        if confirm_text != target_id:
            return jsonify({'success': False, 'error': f'⚠️ Phải gõ chính xác ID "{target_id}"!'}), 400
        log_activity(session['username'], 'force_delete', f"Ép buộc xóa ID {target_id} — {reason}")
        delete_user_db(target)
        return jsonify({'success': True, 'message': f'⚡ Đã ÉP BUỘC XÓA vĩnh viễn user ID {target_id}',
                        'deleted_username': target, 'deleted_user_id': target_id,
                        'reason': reason, 'kicked': True})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/cancel-delete', methods=['POST'])
@super_admin_required
def admin_cancel_delete():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        target_id = users[target].get('user_id', '—')
        users[target]['status'] = 'warned' if users[target].get('warnings') else 'active'
        users[target]['delete_info'] = None
        users[target]['warnings_shown'] = False
        save_user(target, users[target])
        return jsonify({'success': True, 'message': f'✅ Đã hủy xóa user ID {target_id}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/refresh-status', methods=['POST'])
@super_admin_required
def admin_refresh_status():
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        keep_history = data.get('keep_history', True)
        keep_log = data.get('keep_log', True)
        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400
        if usernames_match(target, session['username']):
            return jsonify({'success': False, 'error': '🚫 Không thể tự làm mới!'}), 400
        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if is_super_admin(target):
            return jsonify({'success': False, 'error': '🚫 Không thể làm mới Super Admin!'}), 403
        user = users[target]
        target_id = user.get('user_id', '—')
        old_status = user.get('status', 'active')
        user['status'] = 'active'
        user['warnings'] = []
        user['ban_info'] = None
        user['delete_info'] = None
        user['suspicious_score'] = 0
        user['warnings_shown'] = True
        if not keep_history: user['history'] = []
        if not keep_log: user['activity_log'] = []
        log = user.get('activity_log', [])
        log.insert(0, {'action': 'refresh_status',
                      'detail': f'Admin {session["username"]} đã làm mới',
                      'time': datetime.now().isoformat()})
        user['activity_log'] = log[:50]
        save_user(target, user)
        return jsonify({'success': True, 'message': f'♻️ Đã làm mới user ID {target_id} (cũ: {old_status})',
                        'old_status': old_status})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/refresh-multiple', methods=['POST'])
@super_admin_required
def admin_refresh_multiple():
    try:
        data = request.get_json()
        targets = data.get('usernames', [])
        if not isinstance(targets, list) or len(targets) == 0:
            return jsonify({'success': False, 'error': 'Danh sách trống!'}), 400
        users = load_users()
        refreshed = 0
        failed = 0
        for target in targets:
            target = target.strip()
            if not target or target not in users:
                failed += 1; continue
            if usernames_match(target, session['username']) or is_super_admin(target):
                failed += 1; continue
            user = users[target]
            user['status'] = 'active'
            user['warnings'] = []
            user['ban_info'] = None
            user['delete_info'] = None
            user['suspicious_score'] = 0
            user['warnings_shown'] = True
            save_user(target, user)
            refreshed += 1
        return jsonify({'success': True, 'message': f'♻️ Đã làm mới {refreshed} user, {failed} lỗi',
                        'refreshed': refreshed, 'failed': failed})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/seed', methods=['POST'])
@super_admin_required
def admin_seed():
    try:
        seed_accounts()
        users = load_users()
        return jsonify({'success': True, 'message': f'✅ Đã chạy seed. Tổng user: {len(users)}',
                        'total_users': len(users)})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


# ============================================================
# ⭐ ADMIN — QUẢN LÝ CẤM GAME (MỚI)
# ============================================================
GAME_BAN_DURATIONS = {
    '1h':     ('1 giờ',    timedelta(hours=1)),
    '6h':     ('6 giờ',    timedelta(hours=6)),
    '12h':    ('12 giờ',   timedelta(hours=12)),
    '1day':   ('1 ngày',   timedelta(days=1)),
    '3days':  ('3 ngày',   timedelta(days=3)),
    '7days':  ('7 ngày',   timedelta(days=7)),
    '30days': ('30 ngày',  timedelta(days=30)),
}


@app.route('/admin/game-ban')
@admin_required
def admin_game_ban_page():
    return render_template('admin_game_ban.html',
        username=session['username'],
        is_super_admin=is_super_admin(session['username']))


@app.route('/api/admin/game-ban', methods=['POST'])
@super_admin_required
def admin_game_ban():
    """Cấm 1 hoặc nhiều user chơi game."""
    try:
        data = request.get_json() or {}
        targets = data.get('usernames', [])
        if isinstance(targets, str):
            targets = [targets]
        reason = (data.get('reason') or '').strip() or 'Vi phạm quy định game'
        duration = data.get('duration', 'permanent')
        custom_value = data.get('custom_value')
        custom_unit = data.get('custom_unit', 'hours')

        if not targets:
            return jsonify({'success': False, 'error': 'Chưa chọn user nào!'}), 400

        delta = None
        is_temp = False
        duration_label = 'Vĩnh viễn'

        if duration == 'permanent':
            is_temp = False
            duration_label = 'Vĩnh viễn'
        elif duration in GAME_BAN_DURATIONS:
            duration_label, delta = GAME_BAN_DURATIONS[duration]
            is_temp = True
        elif duration == 'custom':
            try:
                custom_value = int(custom_value)
            except (TypeError, ValueError):
                return jsonify({'success': False, 'error': 'Giá trị thời gian không hợp lệ!'}), 400
            if custom_value <= 0 or custom_value > 3650:
                return jsonify({'success': False, 'error': 'Thời gian phải từ 1–3650!'}), 400
            if custom_unit == 'minutes':
                delta = timedelta(minutes=custom_value)
                duration_label = f'{custom_value} phút'
            elif custom_unit == 'hours':
                delta = timedelta(hours=custom_value)
                duration_label = f'{custom_value} giờ'
            elif custom_unit == 'days':
                delta = timedelta(days=custom_value)
                duration_label = f'{custom_value} ngày'
            else:
                return jsonify({'success': False, 'error': 'Đơn vị không hợp lệ!'}), 400
            is_temp = True
        else:
            return jsonify({'success': False, 'error': f'Thời gian không hợp lệ: {duration}'}), 400

        users = load_users()
        now = datetime.now()
        banned_list = []
        skipped_list = []

        for target in targets:
            target = (target or '').strip()
            if not target:
                continue
            if target not in users:
                skipped_list.append({'username': target, 'reason': 'Không tồn tại'})
                continue
            if usernames_match(target, session['username']):
                skipped_list.append({'username': target, 'reason': 'Không thể tự cấm chính mình'})
                continue
            if is_super_admin(target):
                skipped_list.append({'username': target, 'reason': 'Không thể cấm Super Admin'})
                continue

            target_id = users[target].get('user_id', '—')
            game_ban = {
                'is_banned': True,
                'reason': reason,
                'banned_at': now.isoformat(),
                'banned_by': session['username'],
                'is_temp': is_temp,
                'ban_until': (now + delta).isoformat() if is_temp and delta else None,
                'duration_label': duration_label,
            }
            users[target]['game_ban'] = game_ban
            save_user(target, users[target])
            banned_list.append({'username': target, 'user_id': target_id})

        names = ', '.join(b['username'] for b in banned_list)
        if banned_list:
            log_activity(session['username'], 'game_ban',
                        f"Cấm game [{names}] ({duration_label}) — {reason}")

        return jsonify({
            'success': True,
            'banned_count': len(banned_list),
            'skipped_count': len(skipped_list),
            'banned': banned_list,
            'skipped': skipped_list,
            'duration_label': duration_label,
            'message': f'🚫 Đã cấm game {len(banned_list)} user ({duration_label})'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/game-unban', methods=['POST'])
@super_admin_required
def admin_game_unban():
    """Bỏ cấm game cho 1 hoặc nhiều user."""
    try:
        data = request.get_json() or {}
        targets = data.get('usernames', [])
        if isinstance(targets, str):
            targets = [targets]
        if not targets:
            return jsonify({'success': False, 'error': 'Chưa chọn user nào!'}), 400

        users = load_users()
        unbanned = []
        skipped = []

        for target in targets:
            target = (target or '').strip()
            if not target or target not in users:
                skipped.append(target)
                continue
            if not users[target].get('game_ban'):
                skipped.append(target)
                continue
            users[target]['game_ban'] = None
            save_user(target, users[target])
            unbanned.append(target)

        if unbanned:
            log_activity(session['username'], 'game_unban',
                        f"Bỏ cấm game [{', '.join(unbanned)}]")

        return jsonify({
            'success': True,
            'unbanned_count': len(unbanned),
            'skipped_count': len(skipped),
            'unbanned': unbanned,
            'message': f'✅ Đã bỏ cấm game {len(unbanned)} user'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/game-ban-list')
@admin_required
def admin_game_ban_list():
    """Danh sách user đang bị cấm game."""
    users = load_users()
    banned_users = []
    now = datetime.now()
    for uname, udata in users.items():
        gb = udata.get('game_ban')
        if not gb or not gb.get('is_banned'):
            continue
        if gb.get('is_temp') and gb.get('ban_until'):
            try:
                if now >= datetime.fromisoformat(gb['ban_until']):
                    continue
            except Exception:
                pass
        banned_users.append({
            'username': uname,
            'user_id': udata.get('user_id', '—'),
            'display_name': udata.get('display_name', uname),
            'is_super_admin': is_super_admin(uname),
            'reason': gb.get('reason'),
            'banned_at': gb.get('banned_at'),
            'banned_by': gb.get('banned_by'),
            'is_temp': gb.get('is_temp', False),
            'ban_until': gb.get('ban_until'),
            'duration_label': gb.get('duration_label', 'Vĩnh viễn'),
        })
    banned_users.sort(key=lambda x: x.get('banned_at', ''), reverse=True)
    return jsonify({'success': True, 'users': banned_users, 'total': len(banned_users)})


@app.route('/api/admin/game-ban-search')
@admin_required
def admin_game_ban_search():
    """Tìm user để cấm game (chỉ user thường, không phải admin/super_admin)."""
    q = (request.args.get('q') or '').strip().lower()
    users = load_users()
    result = []
    for uname, udata in users.items():
        if is_super_admin(uname):
            continue
        if udata.get('role') in ('admin', 'super_admin'):
            continue
        if q and q not in uname.lower() and q not in udata.get('display_name', '').lower():
            continue
        gb = udata.get('game_ban')
        is_banned = bool(gb and gb.get('is_banned'))
        if is_banned and gb.get('is_temp') and gb.get('ban_until'):
            try:
                if datetime.now() >= datetime.fromisoformat(gb['ban_until']):
                    is_banned = False
            except Exception:
                pass
        result.append({
            'username': uname,
            'user_id': udata.get('user_id', '—'),
            'display_name': udata.get('display_name', uname),
            'status': udata.get('status', 'active'),
            'is_banned': is_banned,
        })
    result.sort(key=lambda x: x['username'].lower())
    return jsonify({'success': True, 'users': result[:200]})


@app.route('/api/admin/game-ban-status/<username>')
@admin_required
def admin_game_ban_status(username):
    users = load_users()
    if username not in users:
        return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
    clear_expired_game_ban(username)
    users = load_users()
    user = users.get(username, {})
    banned, gb = is_game_banned(user)
    return jsonify({'success': True, 'is_banned': banned, 'game_ban': gb})


# ============================================================
# 2FA — TWO FACTOR AUTHENTICATION
# ============================================================
@app.route('/admin/2fa')
@admin_required
def admin_2fa_page():
    return render_template('admin_2fa.html')


@app.route('/api/2fa/status')
@admin_required
def api_2fa_status():
    users = load_users()
    user = users.get(session['username'], {})
    return jsonify({
        'success': True,
        'enabled': user.get('totp_enabled', False),
        'enabled_at': user.get('totp_enabled_at'),
        'backup_codes_remaining': len(user.get('totp_backup_codes', [])),
    })


@app.route('/api/2fa/setup', methods=['POST'])
@admin_required
def api_2fa_setup():
    try:
        users = load_users()
        username = session['username']
        user = users.get(username)
        if not user:
            return jsonify({'success': False, 'error': 'User không tồn tại!'}), 404
        if user.get('totp_enabled'):
            return jsonify({'success': False, 'error': '2FA đã được bật!'}), 400

        secret = generate_secret()
        uri = get_totp_uri(secret, username)
        qr_base64 = generate_qr_base64(uri)

        user['totp_secret_pending'] = secret
        save_user(username, user)

        return jsonify({
            'success': True,
            'secret': secret,
            'uri': uri,
            'qr': qr_base64,
            'manual_entry': secret,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/2fa/verify-setup', methods=['POST'])
@admin_required
def api_2fa_verify_setup():
    try:
        data = request.get_json()
        code = data.get('code', '').strip()
        if not code:
            return jsonify({'success': False, 'error': 'Nhập mã OTP!'}), 400

        users = load_users()
        username = session['username']
        user = users.get(username)
        if not user:
            return jsonify({'success': False, 'error': 'User không tồn tại!'}), 404

        secret = user.get('totp_secret_pending', '')
        if not secret:
            return jsonify({'success': False, 'error': 'Chưa gọi /api/2fa/setup!'}), 400
        if not verify_code(secret, code):
            return jsonify({'success': False, 'error': 'Mã OTP không đúng!'}), 401

        user['totp_enabled'] = True
        user['totp_secret'] = secret
        user['totp_secret_pending'] = None
        user['totp_enabled_at'] = datetime.now().isoformat()

        backup_plain = generate_backup_codes()
        user['totp_backup_codes'] = [hash_backup_code(c) for c in backup_plain]

        log = user.get('activity_log', [])
        log.insert(0, {'action': 'enable_2fa', 'detail': 'Đã bật 2FA', 'time': datetime.now().isoformat()})
        user['activity_log'] = log[:50]
        save_user(username, user)

        return jsonify({
            'success': True,
            'message': '✅ Đã bật 2FA!',
            'backup_codes': backup_plain,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/2fa/disable', methods=['POST'])
@admin_required
def api_2fa_disable():
    try:
        data = request.get_json()
        code = data.get('code', '').strip()

        users = load_users()
        username = session['username']
        user = users.get(username)

        if not user.get('totp_enabled'):
            return jsonify({'success': False, 'error': '2FA chưa được bật!'}), 400

        secret = user.get('totp_secret', '')
        if not verify_code(secret, code):
            return jsonify({'success': False, 'error': 'Mã OTP không đúng!'}), 401

        user['totp_enabled'] = False
        user['totp_secret'] = None
        user['totp_backup_codes'] = []
        save_user(username, user)

        return jsonify({'success': True, 'message': '🔓 Đã tắt 2FA!'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/2fa/regenerate-backup', methods=['POST'])
@admin_required
def api_2fa_regenerate_backup():
    try:
        data = request.get_json()
        code = data.get('code', '').strip()

        users = load_users()
        username = session['username']
        user = users.get(username)

        if not user.get('totp_enabled'):
            return jsonify({'success': False, 'error': '2FA chưa bật!'}), 400

        secret = user.get('totp_secret', '')
        if not verify_code(secret, code):
            return jsonify({'success': False, 'error': 'Mã OTP không đúng!'}), 401

        backup_plain = generate_backup_codes()
        user['totp_backup_codes'] = [hash_backup_code(c) for c in backup_plain]
        save_user(username, user)

        return jsonify({'success': True, 'backup_codes': backup_plain})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500

# ============================================================
# VÒNG QUAY NGẪU NHIÊN
# ============================================================
@app.route('/wheel')
@login_required
def wheel_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('wheel.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))

# ============================================================
# CHẾ TÊN — AI (GROQ) + FALLBACK TỪ ĐIỂN
# ============================================================
@app.route('/ten')
@login_required
def ten_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('ten.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


@app.route('/api/ten/generate', methods=['POST'])
@login_required
def api_ten_generate():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!', 'redirect': '/banned'}), 403

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    mode = (data.get('mode') or 'nghiem').strip().lower()

    if not name:
        return jsonify({'success': False, 'error': 'Vui lòng nhập tên!'}), 400
    if len(name) > 50:
        return jsonify({'success': False, 'error': 'Tên quá dài (tối đa 50 ký tự)!'}), 400
    if mode not in ('nghiem', 'ngau', 'mix'):
        mode = 'nghiem'

    # ═══ THỬ AI TRƯỚC ═══
    if groq_client:
        try:
            result = _generate_name_with_ai(name, mode)
            return jsonify({'success': True, 'data': result, 'ai': True})
        except Exception as e:
            print(f"⚠️ Groq error: {e}")

    # ═══ FALLBACK TỪ ĐIỂN ═══
    try:
        result = generate_name(name, mode=mode)
        if 'error' in result:
            return jsonify({'success': False, 'error': result['error']}), 400
        return jsonify({'success': True, 'data': result, 'ai': False})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


def _generate_name_with_ai(name, mode):
    """Gọi Groq AI để chế tên."""
    system_prompt = """Bạn là chuyên gia phân tích tên tiếng Việt.
Trả về JSON hợp lệ, KHÔNG thêm text khác, KHÔNG dùng markdown."""

    mode_prompts = {
        'nghiem': 'NGHIÊM TÚC — giải nghĩa Hán Việt thật, trang trọng.',
        'ngau': 'NGẦU — khen quá đà, hào hùng, có thể dùng emoji ⚔️👑🔥⚡.',
        'mix': 'RANDOM MIX — 3 câu với 3 phong cách khác nhau: nghiêm túc, ngầu, vui.'
    }

    user_prompt = f"""Phân tích tên: "{name}"
Phong cách: {mode_prompts.get(mode, mode_prompts['nghiem'])}

Trả về JSON:
{{
  "name": "{name}",
  "parts": ["âm1", "âm2"],
  "meanings": [
    {{"part": "Âm1", "meaning": "nghĩa Hán Việt"}},
    {{"part": "Âm2", "meaning": "nghĩa Hán Việt"}}
  ],
  "results": [
    "Câu 1 diễn giải ý nghĩa tên",
    "Câu 2",
    "Câu 3"
  ]
}}"""

    chat_completion = groq_client.chat.completions.create(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        model="openai/gpt-oss-120b",
        temperature=0.9,
        max_tokens=800,
        response_format={"type": "json_object"}
    )

    response_text = chat_completion.choices[0].message.content.strip()

    if response_text.startswith('```'):
        parts = response_text.split('```')
        if len(parts) >= 2:
            response_text = parts[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
    response_text = response_text.strip()

    import json as _json
    result = _json.loads(response_text)

    result.setdefault('name', name)
    result.setdefault('parts', name.split())
    result.setdefault('meanings', [])
    result.setdefault('results', [])
    result['mode'] = mode

    return result


# ============================================================
# HEALTH CHECK
# ============================================================
@app.route('/health')
def health():
    users = load_users()
    return jsonify({
        'status': 'ok',
        'database': 'supabase' if has_database() else 'json_local',
        'total_methods': len(METHODS),
        'total_users': len(users),
        'super_admin': SUPER_ADMIN_USERNAME,
        'super_admin_exists': any(usernames_match(u, SUPER_ADMIN_USERNAME) for u in users.keys())
    })


@app.route('/ping')
def ping():
    return 'pong', 200

# ============================================================
# CHẾ THƠ AI + BÓI VUI
# ============================================================
@app.route('/tho')
@login_required
def tho_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('tho.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


@app.route('/api/tho/generate', methods=['POST'])
@login_required
def api_tho_generate():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!', 'redirect': '/banned'}), 403

    data = request.get_json() or {}
    chu_de = (data.get('chu_de') or '').strip()
    chu_de_type = (data.get('chu_de_type') or 'tinh_yeu').strip()
    phong_cach = (data.get('phong_cach') or 'tho_bay').strip()

    if not chu_de:
        return jsonify({'success': False, 'error': 'Vui lòng nhập chủ đề!'}), 400
    if len(chu_de) > 200:
        return jsonify({'success': False, 'error': 'Chủ đề quá dài (tối đa 200 ký tự)!'}), 400

    # Thử AI trước
    if groq_client:
        try:
            result = _generate_tho_with_ai(chu_de, chu_de_type, phong_cach)
            return jsonify({'success': True, 'data': result, 'ai': True})
        except Exception as e:
            print(f"⚠️ Groq error: {e}")

    # Fallback
    try:
        result = tho_fallback(chu_de_type)
        result['chu_de'] = chu_de
        return jsonify({'success': True, 'data': result, 'ai': False})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


def _generate_tho_with_ai(chu_de, chu_de_type, phong_cach):
    """Gọi Groq AI để làm thơ."""
    system_prompt = """Bạn là nhà thơ Việt Nam tài ba.
Trả về JSON hợp lệ, KHÔNG thêm text khác, KHÔNG dùng markdown."""

    phong_cach_map = {
        'tho_bay': 'thơ 7 chữ (thất ngôn), mỗi câu 7 chữ',
        'tho_luc_bat': 'thơ lục bát (câu 6 chữ xen câu 8 chữ)',
        'tho_tu_do': 'thơ tự do, không gò bó số chữ',
        'tho_duong': 'thơ Đường luật, 8 câu 7 chữ, có niêm luật',
    }

    pc = phong_cach_map.get(phong_cach, phong_cach_map['tho_bay'])

    user_prompt = f"""Viết một bài thơ về chủ đề: "{chu_de}"

Phong cách: {pc}
Yêu cầu:
- Bài thơ phải HAY, có cảm xúc
- Vần điệu hài hòa
- Có thể dùng hình ảnh ẩn dụ, so sánh
- Độ dài: 4-8 câu (tùy phong cách)

Trả về JSON:
{{
  "chu_de": "{chu_de}",
  "loai": "{pc}",
  "bai_tho": "Bài thơ đầy đủ, dùng \\n để xuống dòng",
  "y_nghia": "1-2 câu giải thích ý nghĩa bài thơ"
}}"""

    chat_completion = groq_client.chat.completions.create(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        model="openai/gpt-oss-120b",
        temperature=1.0,
        max_tokens=1000,
        response_format={"type": "json_object"}
    )

    response_text = chat_completion.choices[0].message.content.strip()

    if response_text.startswith('```'):
        parts = response_text.split('```')
        if len(parts) >= 2:
            response_text = parts[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
    response_text = response_text.strip()

    import json as _json
    result = _json.loads(response_text)

    result.setdefault('chu_de', chu_de)
    result.setdefault('bai_tho', '')
    result.setdefault('y_nghia', '')

    return result


@app.route('/boi')
@login_required
def boi_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('boi.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


@app.route('/api/boi', methods=['POST'])
@login_required
def api_boi():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!', 'redirect': '/banned'}), 403

    data = request.get_json() or {}
    ten = (data.get('ten') or '').strip()
    chu_de = (data.get('chu_de') or 'tinh_duyen').strip()

    if len(ten) > 100:
        return jsonify({'success': False, 'error': 'Tên quá dài (tối đa 100 ký tự)!'}), 400
    if chu_de not in ('tinh_duyen', 'su_nghiep', 'tai_loc', 'suc_khoe', 'hoc_tap'):
        chu_de = 'tinh_duyen'

    try:
        result = boi_vui(chu_de=chu_de, ten=ten)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500

# ============================================================
# NHẠC FUNK — GOOGLE DRIVE
# ============================================================
@app.route('/nhac')
@login_required
def nhac_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('nhac.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'),
        has_api=has_google_api())


@app.route('/api/music/list')
@login_required
def api_music_list():
    """Lấy danh sách file nhạc từ Google Drive."""
    force = request.args.get('refresh', '').lower() == 'true'
    result = list_music_files(force_refresh=force)
    return jsonify(result)


@app.route('/api/music/stream/<file_id>')
@login_required
def api_music_stream(file_id):
    """Stream file nhạc từ Google Drive (hỗ trợ Range request để seek)."""
    # Lấy size file
    info = get_file_info(file_id)
    if not info.get('success'):
        return jsonify({'error': 'File không tồn tại'}), 404

    file_data = info['file']
    file_size = int(file_data.get('size', 0))

    # Range request
    range_header = request.headers.get('Range')

    drive_res = stream_file(file_id, range_header=range_header)
    if not drive_res:
        return jsonify({'error': 'Không thể tải file'}), 500

    # Nếu client yêu cầu Range
    if range_header and drive_res.status_code == 206:
        try:
            byte_range = range_header.replace('bytes=', '').split('-')
            start = int(byte_range[0]) if byte_range[0] else 0
            end = int(byte_range[1]) if len(byte_range) > 1 and byte_range[1] else file_size - 1
            length = end - start + 1

            def generate():
                for chunk in drive_res.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        yield chunk

            response = Response(
                generate(),
                status=206,
                mimetype='audio/mpeg',
                direct_passthrough=True,
            )
            response.headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'
            response.headers['Accept-Ranges'] = 'bytes'
            response.headers['Content-Length'] = str(length)
            response.headers['Content-Type'] = 'audio/mpeg'
            response.headers['Cache-Control'] = 'no-cache'
            return response
        except Exception as e:
            print(f'⚠️ Range error: {e}')

    # Full file
    def generate():
        for chunk in drive_res.iter_content(chunk_size=64 * 1024):
            if chunk:
                yield chunk

    response = Response(
        generate(),
        status=200,
        mimetype='audio/mpeg',
        direct_passthrough=True,
    )
    response.headers['Accept-Ranges'] = 'bytes'
    response.headers['Content-Length'] = str(file_size)
    response.headers['Content-Type'] = 'audio/mpeg'
    response.headers['Cache-Control'] = 'no-cache'
    return response

# ============================================================
# TẠO TRUYỆN — AI
# ============================================================
@app.route('/truyen')
@login_required
def truyen_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('truyen.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


@app.route('/api/truyen/generate', methods=['POST'])
@login_required
def api_truyen_generate():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!', 'redirect': '/banned'}), 403

    data = request.get_json() or {}
    the_loai = (data.get('the_loai') or 'boylove').strip()
    ten_nv1 = (data.get('ten_nv1') or '').strip()
    ten_nv2 = (data.get('ten_nv2') or '').strip()
    boi_canh = (data.get('boi_canh') or '').strip()
    noi_dung = (data.get('noi_dung') or '').strip()
    do_dai = (data.get('do_dai') or 'ngan').strip()

    valid_the_loai = ['boylove', 'girllove', 'tinh_cam', 'vo_hiep', 'co_dai',
                      'hoc_duong', 'huyen_huyen', 'kinh_di', 'hai_huoc', 'scifi']
    if the_loai not in valid_the_loai:
        the_loai = 'boylove'

    if len(ten_nv1) > 50 or len(ten_nv2) > 50:
        return jsonify({'success': False, 'error': 'Tên nhân vật quá dài!'}), 400
    if len(boi_canh) > 200 or len(noi_dung) > 300:
        return jsonify({'success': False, 'error': 'Nội dung quá dài!'}), 400

    # Thử AI trước
    if groq_client:
        try:
            result = _generate_truyen_with_ai(the_loai, ten_nv1, ten_nv2, boi_canh, noi_dung, do_dai)
            return jsonify({'success': True, 'data': result, 'ai': True})
        except Exception as e:
            print(f"⚠️ Groq truyen error: {e}")

    # Fallback
    result = get_truyen_fallback(the_loai)
    return jsonify({'success': True, 'data': result, 'ai': False})
    
# ============================================================
# TRANG CÁ NHÂN — PROFILE
# ============================================================
@app.route('/profile')
@login_required
def profile_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('profile.html',
        username=user.get('display_name', username),
        real_username=username,
        user_id=user.get('user_id', '—'))


@app.route('/api/profile/stats')
@login_required
def api_profile_stats():
    """Lấy thông tin + thống kê cá nhân."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!', 'redirect': '/banned'}), 403

    history = user.get('history', [])
    game = user.get('game', {})

    # Đếm số lần mã hóa/giải mã
    encrypt_count = sum(1 for h in history if h.get('action') == 'encrypt')
    decrypt_count = sum(1 for h in history if h.get('action') == 'decrypt')

    # Đếm số methods đã dùng
    unique_methods = set(h.get('method') for h in history if h.get('method'))

    # Đếm số ngày active (dựa vào history)
    active_days = set()
    for h in history:
        try:
            date = h.get('time', '')[:10]
            if date:
                active_days.add(date)
        except:
            pass

    warnings = user.get('warnings', [])

    return jsonify({
        'success': True,
        'user': {
            'username': username,
            'display_name': user.get('display_name', username),
            'user_id': user.get('user_id', '—'),
            'role': user.get('role', 'user'),
            'status': user.get('status', 'active'),
            'created_at': user.get('created_at'),
            'last_login': user.get('last_login'),
            'login_count': user.get('login_count', 0),
            'is_super_admin': is_super_admin(username),
        },
        'stats': {
            'encrypt_count': encrypt_count,
            'decrypt_count': decrypt_count,
            'total_actions': len(history),
            'unique_methods': len(unique_methods),
            'active_days': len(active_days),
            'game_points': game.get('points', 0),
            'snake_best': game.get('snake_best', 0),
            'guess_best': game.get('guess_best_count'),
            'warnings_count': len(warnings),
        },
        'warnings': warnings,
    })


@app.route('/api/profile/history')
@login_required
def api_profile_history():
    """Lấy lịch sử đầy đủ (100 lần gần nhất)."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = users[username]
    history = user.get('history', [])[:100]

    return jsonify({'success': True, 'history': history})


@app.route('/api/profile/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Đổi mật khẩu."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = users[username]
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!'}), 403

    data = request.get_json() or {}
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    # Validate
    if not old_password or not new_password or not confirm_password:
        return jsonify({'success': False, 'error': 'Vui lòng nhập đầy đủ!'}), 400

    if not verify_password(old_password, user.get('password', '')):
        return jsonify({'success': False, 'error': 'Mật khẩu cũ không đúng!'}), 401

    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Mật khẩu mới phải từ 6 ký tự!'}), 400

    if new_password != confirm_password:
        return jsonify({'success': False, 'error': 'Mật khẩu xác nhận không khớp!'}), 400

    if new_password == old_password:
        return jsonify({'success': False, 'error': 'Mật khẩu mới phải khác mật khẩu cũ!'}), 400

    # Cập nhật
    user['password'] = hash_password(new_password)
    log = user.get('activity_log', [])
    log.insert(0, {
        'action': 'change_password',
        'detail': 'Đổi mật khẩu thành công',
        'time': datetime.now().isoformat()
    })
    user['activity_log'] = log[:50]
    users[username] = user
    save_user(username, user)

    return jsonify({'success': True, 'message': '✅ Đổi mật khẩu thành công!'})


@app.route('/api/profile/logout-all', methods=['POST'])
@login_required
def api_logout_all():
    """Đăng xuất tất cả thiết bị (xóa session hiện tại)."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = users[username]
    log = user.get('activity_log', [])
    log.insert(0, {
        'action': 'logout_all',
        'detail': 'Đăng xuất tất cả thiết bị',
        'time': datetime.now().isoformat()
    })
    user['activity_log'] = log[:50]
    save_user(username, user)

    session.clear()
    return jsonify({'success': True, 'message': 'Đã đăng xuất tất cả thiết bị', 'redirect': '/login'})

# ============================================================
# CHAT — TIN NHẮN (POLLING)
# ============================================================
@app.route('/chat')
@login_required
def chat_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('chat.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))


@app.route('/api/chat/conversations')
@login_required
def api_chat_conversations():
    """Lấy danh sách cuộc trò chuyện (người đã chat)."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = users[username]
    messages = user.get('messages', [])

    # Nhóm theo người chat
    conversations = {}
    for msg in messages:
        partner = msg.get('to') if msg.get('from') == username else msg.get('from')
        if not partner or partner == username:
            continue

        if partner not in conversations:
            conversations[partner] = {
                'username': partner,
                'last_message': '',
                'last_time': '',
                'unread': 0,
            }

        # Cập nhật tin nhắn cuối
        msg_time = msg.get('time', '')
        if msg_time > conversations[partner]['last_time']:
            conversations[partner]['last_message'] = msg.get('content', '')[:50]
            conversations[partner]['last_time'] = msg_time

        # Đếm tin chưa đọc (gửi đến mình)
        if msg.get('to') == username and not msg.get('read', False):
            conversations[partner]['unread'] += 1

    # Sắp xếp theo thời gian
    result = []
    for partner_name, conv in conversations.items():
        partner_data = users.get(partner_name, {})
        conv['display_name'] = partner_data.get('display_name', partner_name)
        conv['user_id'] = partner_data.get('user_id', '—')
        conv['online'] = False  # TODO: check last_active
        conv['is_super_admin'] = is_super_admin(partner_name)
        result.append(conv)

    result.sort(key=lambda x: x.get('last_time', ''), reverse=True)

    return jsonify({'success': True, 'conversations': result})


@app.route('/api/chat/search')
@login_required
def api_chat_search():
    """Tìm user để bắt đầu chat."""
    q = (request.args.get('q') or '').strip().lower()
    if not q or len(q) < 1:
        return jsonify({'success': True, 'users': []})

    username = session.get('username', '')
    users = load_users()
    result = []

    for uname, udata in users.items():
        if uname == username:
            continue
        if usernames_match(uname, SUPER_ADMIN_USERNAME) and not is_super_admin(username):
            # Không cho chat với super admin nếu mình không phải
            pass
        if q in uname.lower() or q in udata.get('display_name', '').lower():
            result.append({
                'username': uname,
                'display_name': udata.get('display_name', uname),
                'user_id': udata.get('user_id', '—'),
                'is_super_admin': is_super_admin(uname),
            })

    return jsonify({'success': True, 'users': result[:20]})


@app.route('/api/chat/messages/<partner>')
@login_required
def api_chat_messages(partner):
    """Lấy tin nhắn giữa mình và partner."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    if partner not in users:
        return jsonify({'success': False, 'error': 'Người dùng không tồn tại!'}), 404

    user = users[username]
    messages = user.get('messages', [])

    # Lọc tin nhắn giữa 2 người
    conversation = [
        m for m in messages
        if (m.get('from') == username and m.get('to') == partner) or
           (m.get('from') == partner and m.get('to') == username)
    ]

    # Sắp xếp theo thời gian
    conversation.sort(key=lambda x: x.get('time', ''))

    # Đánh dấu đã đọc
    changed = False
    for m in messages:
        if m.get('from') == partner and m.get('to') == username and not m.get('read', False):
            m['read'] = True
            changed = True

    if changed:
        user['messages'] = messages
        users[username] = user
        save_user(username, user)

    # Format
    result = []
    for m in conversation[-100:]:  # 100 tin gần nhất
        partner_data = users.get(m.get('from'), {})
        result.append({
            'id': m.get('id', ''),
            'from': m.get('from', ''),
            'from_display': partner_data.get('display_name', m.get('from', '')),
            'content': m.get('content', ''),
            'time': m.get('time', ''),
            'is_me': m.get('from') == username,
            'read': m.get('read', False),
        })

    partner_data = users.get(partner, {})
    return jsonify({
        'success': True,
        'messages': result,
        'partner': {
            'username': partner,
            'display_name': partner_data.get('display_name', partner),
            'user_id': partner_data.get('user_id', '—'),
            'is_super_admin': is_super_admin(partner),
        }
    })


@app.route('/api/chat/send', methods=['POST'])
@login_required
def api_chat_send():
    """Gửi tin nhắn."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!'}), 403

    data = request.get_json() or {}
    to_user = (data.get('to') or '').strip()
    content = (data.get('content') or '').strip()

    if not to_user or not content:
        return jsonify({'success': False, 'error': 'Thiếu thông tin!'}), 400
    if len(content) > 1000:
        return jsonify({'success': False, 'error': 'Tin nhắn quá dài (tối đa 1000 ký tự)!'}), 400
    if to_user not in users:
        return jsonify({'success': False, 'error': 'Người nhận không tồn tại!'}), 404
    if to_user == username:
        return jsonify({'success': False, 'error': 'Không thể tự nhắn cho mình!'}), 400

    # Tạo tin nhắn
    msg = {
        'id': secrets.token_hex(8),
        'from': username,
        'to': to_user,
        'content': content,
        'time': datetime.now().isoformat(),
        'read': False,
    }

    # Lưu vào user hiện tại
    user_msgs = user.get('messages', [])
    user_msgs.append(msg)
    # Giữ 500 tin gần nhất
    user['messages'] = user_msgs[-500:]
    users[username] = user
    save_user(username, user)

    return jsonify({'success': True, 'message': msg})


@app.route('/api/chat/delete/<msg_id>', methods=['POST'])
@login_required
def api_chat_delete(msg_id):
    """Xóa tin nhắn."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = users[username]
    messages = user.get('messages', [])

    # Tìm và xóa tin nhắn
    new_messages = []
    deleted = False
    for m in messages:
        if m.get('id') == msg_id and m.get('from') == username:
            deleted = True
            continue
        new_messages.append(m)

    if not deleted:
        return jsonify({'success': False, 'error': 'Không tìm thấy tin nhắn!'}), 404

    user['messages'] = new_messages
    users[username] = user
    save_user(username, user)

    return jsonify({'success': True, 'message': 'Đã xóa tin nhắn'})


@app.route('/api/chat/unread-count')
@login_required
def api_chat_unread_count():
    """Đếm số tin nhắn chưa đọc."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = users[username]
    messages = user.get('messages', [])

    unread = sum(1 for m in messages
                 if m.get('to') == username and not m.get('read', False))

    return jsonify({'success': True, 'unread': unread})

# ============================================================
# VIẾT VĂN AI — ĐƠN GIẢN
# ============================================================
@app.route('/write')
@login_required
def write_page():
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))
    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    return render_template('write.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'))

@app.route('/api/write', methods=['POST'])
@login_required
def api_write():
    """Viết văn/thơ bằng Groq AI."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return jsonify({'success': False, 'error': 'Bạn đã bị ban!'}), 403

    data = request.get_json() or {}
    de_bai = (data.get('de_bai') or '').strip()
    so_cau = data.get('so_cau', 10)
    loai = (data.get('loai') or 'doan_van').strip()  # 'doan_van' hoặc 'bai_tho'

    if not de_bai:
        return jsonify({'success': False, 'error': 'Vui lòng nhập đề bài!'}), 400
    if len(de_bai) > 500:
        return jsonify({'success': False, 'error': 'Đề bài quá dài (tối đa 500 ký tự)!'}), 400

    try:
        so_cau = int(so_cau)
    except:
        so_cau = 10
    if so_cau < 3:
        so_cau = 3
    if so_cau > 50:
        so_cau = 50

    if loai not in ('doan_van', 'bai_tho'):
        loai = 'doan_van'

    if not groq_client:
        return jsonify({
            'success': False,
            'error': 'Chưa cấu hình Groq API. Liên hệ admin.'
        }), 500

    try:
        if loai == 'doan_van':
            prompt = f"""Viết một ĐOẠN VĂN LIỀN MẠCH theo đề bài sau:

ĐỀ BÀI: {de_bai}

Yêu cầu:
- Viết khoảng {so_cau} câu
- Viết LIỀN MẠCH, KHÔNG chia đoạn, KHÔNG xuống dòng giữa chừng
- Văn phong tự nhiên, có cảm xúc
- Có thể dùng biện pháp tu từ để sinh động
- Không cần mở bài/kết bài riêng

Chỉ trả về nội dung đoạn văn, không giải thích gì thêm."""

            chat_completion = groq_client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Bạn là giáo viên Ngữ văn Việt Nam. Viết văn hay, có cảm xúc."},
                    {"role": "user", "content": prompt}
                ],
                model="openai/gpt-oss-120b",
                temperature=0.8,
                max_tokens=3000,
            )

            result = chat_completion.choices[0].message.content.strip()

        else:  # bai_tho
            prompt = f"""Viết một BÀI THƠ theo đề bài sau:

ĐỀ BÀI: {de_bai}

Yêu cầu:
- Viết khoảng {so_cau} câu thơ (mỗi câu là 1 dòng thơ)
- Chia thành 3 phần rõ ràng:

**PHẦN 1: MỞ ĐẦU** (1-2 câu thơ)
- Giới thiệu chủ đề, cảm xúc ban đầu

**PHẦN 2: NỘI DUNG CHÍNH** (phần lớn số câu)
- Triển khai ý chính
- Có thể dùng hình ảnh, biện pháp tu từ

**PHẦN 3: KẾT** (1-2 câu thơ)
- Tổng kết, để lại cảm xúc

Định dạng trả về:
PHẦN 1: MỞ ĐẦU
[câu thơ 1]
[câu thơ 2]

PHẦN 2: NỘI DUNG
[câu thơ 3]
[câu thơ 4]
...

PHẦN 3: KẾT
[câu thơ cuối 1]
[câu thơ cuối 2]

Chỉ trả về bài thơ, không giải thích gì thêm."""

            chat_completion = groq_client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Bạn là nhà thơ Việt Nam tài ba. Thơ hay, có cảm xúc, có vần điệu."},
                    {"role": "user", "content": prompt}
                ],
                model="openai/gpt-oss-120b",
                temperature=0.9,
                max_tokens=3000,
            )

            result = chat_completion.choices[0].message.content.strip()

        # Đếm số câu thực tế
        if loai == 'bai_tho':
            # Đếm số dòng thơ (bỏ qua dòng trống và header)
            lines = [l.strip() for l in result.split('\n') if l.strip() and not l.strip().startswith('PHẦN')]
            actual_sentences = len(lines)
        else:
            actual_sentences = len([s for s in result.replace('!', '.').replace('?', '.').split('.') if s.strip()])

        return jsonify({
            'success': True,
            'de_bai': de_bai,
            'loai': loai,
            'so_cau_yeu_cau': so_cau,
            'so_cau_thuc_te': actual_sentences,
            'noi_dung': result,
        })

    except Exception as e:
        print(f"⚠️ Groq write error: {e}")
        return jsonify({'success': False, 'error': f'Lỗi AI: {str(e)}'}), 500

# ============================================================
# 🔐 TRANG BÍ MẬT — TẢI FILE .EXE
# ============================================================
import os

SECRET_FOLDER = 'secret_files'
SECRET_FILE_NAME = 'Lag.exe'  # ⭐ Đổi thành tên file .exe của bạn


@app.route('/secret')
@login_required
def secret_page():
    """Trang bí mật — tải file .exe."""
    users = load_users()
    username = session.get('username', '')
    if username not in users:
        session.clear()
        return redirect(url_for('login_page'))

    user = check_and_auto_unban(username)
    if user.get('status') == 'banned' and not is_super_admin(username):
        return redirect(url_for('banned_page', user=username))
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))

    # ⭐ Chỉ Super Admin mới vào được
    if not is_super_admin(username):
        return render_template('feature_removed.html',
            feature_path='/secret',
            feature_name='Trang bí mật',
            reason='Bạn không có quyền truy cập trang này.'), 403

    # Kiểm tra file tồn tại
    file_path = os.path.join(SECRET_FOLDER, SECRET_FILE_NAME)
    file_exists = os.path.exists(file_path)
    file_size_mb = 0

    if file_exists:
        file_size_mb = round(os.path.getsize(file_path) / (1024 * 1024), 2)

    return render_template('secret.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'),
        file_exists=file_exists,
        file_name=SECRET_FILE_NAME,
        file_size_mb=file_size_mb)


@app.route('/secret/download')
@login_required
def secret_download():
    """Download file .exe bí mật."""
    username = session.get('username', '')
    if not is_super_admin(username):
        return "🚫 Không có quyền truy cập", 403

    file_path = os.path.join(SECRET_FOLDER, SECRET_FILE_NAME)

    if not os.path.exists(file_path):
        return "❌ File không tồn tại", 404

    from flask import send_file
    return send_file(
        file_path,
        as_attachment=True,
        download_name=SECRET_FILE_NAME,
        mimetype='application/x-msdownload'
    )
    
# ============================================================
# KHỞI ĐỘNG
# ============================================================
init_db()
init_super_admin()
seed_accounts()
auto_unban_expired()
auto_delete_expired()
auto_unban_expired_game()      # ⭐ MỚI


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
