from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from crypto_utils import (
    process, METHODS, ONE_WAY_ONLY,
    translate, to_english, to_vietnamese, auto_translate, detect_language,
    LANGUAGES,
)
from game_utils import (
    # Daily / Rewards
    get_daily_challenge, check_rewards, pick_random_method,
    generate_meme_template,
    points_to_level, level_to_next, add_points, update_streak,
    ensure_game_data, init_game_data, REWARDS, MEME_TEMPLATES,
    # ⚔️ PvP mới
    create_pvp_room, join_pvp_room, start_pvp_room,
    submit_pvp_answer, get_pvp_room, leave_pvp_room,
    cleanup_old_rooms, QUESTIONS_PER_ROUND, TOTAL_ROUNDS,
)
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
from contextlib import contextmanager
import unicodedata
import os
import json
import hashlib
import secrets
import random
import psycopg2
from psycopg2.extras import Json, RealDictCursor

load_dotenv()

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
                print(f"  ⚠️ Bỏ qua {username}: password < 6 ký tự")
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
                'activity_log': [{
                    'action': 'seed',
                    'detail': f'Tạo tự động — ID: {user_id}',
                    'time': now
                }],
                'suspicious_score': 0,
                'warnings_shown': True,
                'protected': (role == 'super_admin'),
                'game': init_game_data()
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
            'activity_log': [{'action': 'system', 'detail': f'Super Admin tạo tự động — ID: {user_id}', 'time': now}],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': True,
            'game': init_game_data()
        }
        save_user(admin_name, users[admin_name])
        print(f"👑 Đã tạo SUPER ADMIN: {admin_name} — ID: {user_id}")
        return

    changed = False
    user = users[existing_admin]

    if existing_admin != admin_name:
        print(f"📝 Đổi tên admin: '{existing_admin}' → '{admin_name}'")
        users[admin_name] = user
        delete_user_db(existing_admin)
        existing_admin = admin_name
        changed = True

    if user.get('role') != 'super_admin':
        user['role'] = 'super_admin'
        changed = True

    if user.get('display_name') != SUPER_ADMIN_DISPLAY:
        user['display_name'] = SUPER_ADMIN_DISPLAY
        changed = True

    if not user.get('user_id'):
        user['user_id'] = generate_user_id(users)
        changed = True
        print(f"🆔 Đã cấp ID cho Super Admin: {user['user_id']}")

    if user.get('status') != 'active':
        user['status'] = 'active'
        user['ban_info'] = None
        user['delete_info'] = None
        changed = True

    if not verify_password(SUPER_ADMIN_PASSWORD, user.get('password', '')):
        user['password'] = hash_password(SUPER_ADMIN_PASSWORD)
        changed = True

    if user.get('warnings'):
        user['warnings'] = []
        user['warnings_shown'] = True
        changed = True

    if not user.get('protected'):
        user['protected'] = True
        changed = True

    if 'game' not in user:
        user['game'] = init_game_data()
        changed = True

    defaults = {
        'created_at': now, 'last_login': None, 'login_count': 0,
        'history': [], 'warnings': [], 'ban_info': None,
        'delete_info': None, 'activity_log': [],
        'suspicious_score': 0, 'warnings_shown': True
    }
    for k, v in defaults.items():
        if k not in user:
            user[k] = v
            changed = True

    if changed:
        save_user(admin_name, user)
        print(f"👑 Đã cập nhật SUPER ADMIN: {admin_name} — ID: {user.get('user_id')}")
    else:
        print(f"✓ Super Admin {admin_name} đã sẵn sàng — ID: {user.get('user_id')}")


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
                print(f"🔓 Auto-unban: {username}")
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


# ============================================================
# FORMAT DURATION
# ============================================================
def _format_duration(delta: timedelta) -> str:
    total_seconds = int(delta.total_seconds())
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    parts = []
    if days:    parts.append(f'{days} ngày')
    if hours:   parts.append(f'{hours} giờ')
    if minutes: parts.append(f'{minutes} phút')
    if not parts and seconds:
        parts.append(f'{seconds} giây')

    return ' '.join(parts) if parts else '0 phút'


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
                return jsonify({'success': False, 'error': 'Chỉ Super Admin mới có quyền!'}), 403
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
            'activity_log': [{'action': 'register', 'detail': f'Đăng ký — ID: {user_id}', 'time': now}],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': False,
            'game': init_game_data()
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
                'success': False,
                'error': 'Tài khoản đã bị BAN!',
                'banned': True,
                'ban_info': ban_info,
                'ban_until': ban_info.get('ban_until'),
                'user_id': user.get('user_id', '—'),
                'redirect': f'/banned?user={found_user}'
            }), 403

        if user.get('status') == 'pending_delete':
            delete_info = user.get('delete_info', {}) or {}
            return jsonify({
                'success': False,
                'error': 'Tài khoản đã bị đánh dấu xóa!',
                'pending_delete': True,
                'delete_info': delete_info,
                'user_id': user.get('user_id', '—'),
                'redirect': '/deleted'
            }), 403

        users = load_users()
        now = datetime.now().isoformat()
        users[found_user]['last_login'] = now
        users[found_user]['login_count'] = users[found_user].get('login_count', 0) + 1

        log = users[found_user].get('activity_log', [])
        log.insert(0, {
            'action': 'login',
            'detail': f'Đăng nhập lần {users[found_user]["login_count"]}',
            'time': now
        })
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
        return jsonify({
            'success': False,
            'deleted': True,
            'kicked': True,
            'error': 'Tài khoản đã bị xóa!',
            'redirect': '/deleted-force'
        }), 403

    user = check_and_auto_unban(username)

    if user.get('status') == 'banned' and not is_super_admin(username):
        ban_info = user.get('ban_info', {}) or {}
        return jsonify({
            'success': False, 'banned': True,
            'error': 'Tài khoản đã bị ban!',
            'ban_info': ban_info,
            'user_id': user.get('user_id', '—'),
            'ban_until': ban_info.get('ban_until'),
            'redirect': f'/banned?user={username}'
        }), 403

    if user.get('status') == 'pending_delete':
        delete_info = user.get('delete_info', {}) or {}
        return jsonify({
            'success': False,
            'pending_delete': True,
            'error': 'Tài khoản đã bị đánh dấu xóa!',
            'delete_info': delete_info,
            'user_id': user.get('user_id', '—'),
            'redirect': '/deleted'
        }), 403

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
        try:
            banned_at = datetime.fromisoformat(banned_at).strftime('%d/%m/%Y %H:%M:%S')
        except:
            banned_at = banned_at[:19].replace('T', ' ')

    ban_until_display = None
    ban_until_iso = None
    ban_until = ban_info.get('ban_until')
    if ban_until:
        ban_until_iso = ban_until
        try:
            ban_until_dt = datetime.fromisoformat(ban_until)
            ban_until_display = ban_until_dt.strftime('%d/%m/%Y %H:%M:%S')
        except:
            ban_until_display = ban_until[:19].replace('T', ' ')

    is_temp_ban = ban_info.get('is_temp_ban', False)
    duration_label = ban_info.get('duration_label', 'Vĩnh viễn')

    return render_template(
        'banned.html',
        username=user.get('display_name', found_user),
        user_id=user.get('user_id', '—'),
        reason=ban_info.get('reason', 'Vi phạm điều khoản'),
        banned_at=banned_at or '—',
        banned_by=ban_info.get('by', 'System'),
        ban_id=ban_id,
        ban_until_display=ban_until_display,
        ban_until_iso=ban_until_iso,
        is_temp_ban=is_temp_ban,
        duration_label=duration_label
    )


# ============================================================
# TRANG BỊ ÉP BUỘC XÓA
# ============================================================
@app.route('/deleted-force')
def deleted_force_page():
    username = request.args.get('user', '').strip()
    reason = request.args.get('reason', 'Vi phạm điều khoản nghiêm trọng').strip()
    user_id = request.args.get('id', '—').strip()
    deleted_by = request.args.get('by', 'Admin').strip()

    return render_template(
        'deleted_force.html',
        username=username or 'Unknown',
        user_id=user_id,
        reason=reason,
        deleted_by=deleted_by
    )


# ============================================================
# DELETED PAGE
# ============================================================
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
        try:
            deleted_at = datetime.fromisoformat(deleted_at).strftime('%d/%m/%Y %H:%M:%S')
        except:
            deleted_at = deleted_at[:19].replace('T', ' ')

    expires_at_display = None
    expires_at = delete_info.get('expires_at')
    if expires_at:
        try:
            expires_at_dt = datetime.fromisoformat(expires_at)
            expires_at_display = expires_at_dt.strftime('%d/%m/%Y %H:%M:%S')
        except:
            expires_at_display = expires_at[:19].replace('T', ' ')

    delete_id = hashlib.md5(f"{username}{delete_info.get('time', '')}".encode()).hexdigest()[:12].upper()

    return render_template(
        'deleted.html',
        username=user.get('display_name', username),
        user_id=user.get('user_id', '—'),
        reason=delete_info.get('reason', 'Vi phạm điều khoản'),
        deleted_at=deleted_at or '—',
        deleted_by=delete_info.get('by', 'System'),
        expires_at_display=expires_at_display,
        delete_id=delete_id
    )


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

    print(f"🗑️ XÓA VĨNH VIỄN: {username}")
    delete_user_db(username)
    session.clear()

    return jsonify({
        'success': True,
        'message': f'Đã xóa tài khoản {username}',
        'deleted': True
    })


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
    warnings = user.get('warnings', [])
    return render_template(
        'warned.html',
        username=user.get('display_name', session['username']),
        user_id=user.get('user_id', '—'),
        warnings=warnings
    )


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
# ROUTES CHÍNH
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

    return render_template(
        'index.html',
        methods=METHODS,
        username=user.get('display_name', username),
        real_username=username,
        user_id=user.get('user_id', '—'),
        role=user.get('role', 'user'),
        is_super_admin=is_super_admin(username)
    )


# ============================================================
# TRANG DỊCH THUẬT
# ============================================================
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


# ============================================================
# API DỊCH THUẬT
# ============================================================
@app.route('/api/translate', methods=['GET', 'POST'])
@login_required
def api_translate():
    if request.method == 'GET':
        return jsonify({
            'languages': LANGUAGES,
            'modes': ['manual', 'auto']
        })

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
            return jsonify({
                'result':   info['result'],
                'source':   info['detected'],
                'target':   info['target'],
                'detected': info['detected'],
            })

        if target not in LANGUAGES:
            return jsonify({'error': f'Ngôn ngữ đích không hỗ trợ: {target}'}), 400

        result = translate(text, source=source, target=target)
        return jsonify({
            'result': result,
            'source': source,
            'target': target,
        })
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
            return jsonify({
                'success': False,
                'deleted': True,
                'kicked': True,
                'error': 'Tài khoản đã bị xóa!',
                'redirect': '/deleted-force'
            }), 403

        user = check_and_auto_unban(username)

        if user.get('status') == 'banned' and not is_super_admin(username):
            ban_info = user.get('ban_info', {}) or {}
            return jsonify({
                'success': False, 'error': 'Tài khoản đã bị BAN!',
                'banned': True, 'blocked': True,
                'ban_info': ban_info,
                'user_id': user.get('user_id', '—'),
                'username': username
            }), 403

        if user.get('status') == 'pending_delete':
            return jsonify({
                'success': False, 'error': 'Tài khoản đã bị đánh dấu xóa!',
                'pending_delete': True, 'blocked': True,
                'user_id': user.get('user_id', '—'),
                'redirect': '/deleted'
            }), 403

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
            return jsonify({'success': False, 'error': f'PP "{METHODS[method]}" là mã hóa 1 chiều!'}), 400

        result = process(text, method, action, key)

        history = user.get('history', [])
        history.insert(0, {
            'method': method, 'action': action,
            'input_preview': text[:50], 'output_preview': result[:50],
            'time': datetime.now().isoformat()
        })
        users[username]['history'] = history[:20]
        save_user(username, users[username])

        log_activity(username, action, f'{method}: {text[:30]}')

        return jsonify({
            'success': True, 'result': result,
            'method': method, 'action': action,
            'one_way': method in ONE_WAY_ONLY
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/history')
@login_required
def api_history():
    users = load_users()
    user = users.get(session['username'], {})
    return jsonify({'success': True, 'history': user.get('history', [])})


# ============================================================
# 🎮 GAME HUB
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
    return render_template('game.html')


# ─── LEADERBOARD ───
@app.route('/api/game/leaderboard')
@login_required
def api_leaderboard():
    users = load_users()
    board = []
    for uname, udata in users.items():
        game = udata.get('game', {})
        points = game.get('points', 0)
        if points > 0 or game.get('pvp_stats', {}).get('total_matches', 0) > 0:
            board.append({
                'username': udata.get('display_name', uname),
                'real_username': uname,
                'user_id': udata.get('user_id', '—'),
                'points': points,
                'level': points_to_level(points),
                'pvp_wins': game.get('pvp_stats', {}).get('wins', 0),
                'streak': game.get('streak', 0),
                'daily_count': len(game.get('daily_completed', [])),
                'is_super_admin': is_super_admin(uname)
            })
    board.sort(key=lambda x: (-x['points'], -x['pvp_wins']))
    for i, u in enumerate(board):
        u['rank'] = i + 1
        if i == 0: u['medal'] = '🥇'
        elif i == 1: u['medal'] = '🥈'
        elif i == 2: u['medal'] = '🥉'
        else: u['medal'] = f'#{i+1}'
    return jsonify({'success': True, 'leaderboard': board[:50]})


# ─── DAILY ───
@app.route('/api/game/daily')
@login_required
def api_daily():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    user = users[username]
    game = ensure_game_data(user)
    challenge = get_daily_challenge()
    today = datetime.now().strftime('%Y-%m-%d')
    completed = today in game.get('daily_completed', [])
    return jsonify({
        'success': True,
        'challenge': {
            'id': challenge['id'],
            'description': challenge['description'],
            'method': challenge['method'],
            'method_name': METHODS.get(challenge['method'], challenge['method']),
            'action': challenge['action'],
            'text': challenge['text'],
            'points': challenge['points'],
            'key': challenge.get('key', '')
        },
        'completed': completed,
        'streak': game.get('streak', 0),
        'last_daily': game.get('last_daily')
    })


@app.route('/api/game/daily/submit', methods=['POST'])
@login_required
def api_daily_submit():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    data = request.get_json()
    answer = (data.get('answer') or '').strip()
    if not answer:
        return jsonify({'success': False, 'error': 'Chưa có câu trả lời!'}), 400
    user = users[username]
    game = ensure_game_data(user)
    challenge = get_daily_challenge()
    today = datetime.now().strftime('%Y-%m-%d')
    if today in game.get('daily_completed', []):
        return jsonify({'success': False, 'error': 'Hôm nay đã làm rồi!'}), 400
    correct = answer == challenge['expected'].strip()
    if correct:
        new_streak = update_streak(user)
        points_earned = challenge['points']
        bonus = 0
        if new_streak >= 7: bonus = 50
        elif new_streak >= 3: bonus = 20
        points_earned += bonus
        add_points(user, points_earned, f"Daily: {challenge['id']}")
        game['daily_completed'].append(today)
        game['daily_completed'] = game['daily_completed'][-30:]
        unlocked = check_rewards(game)
        users[username] = user
        save_user(username, user)
        return jsonify({
            'success': True,
            'correct': True,
            'points_earned': points_earned,
            'bonus': bonus,
            'streak': new_streak,
            'total_points': game['points'],
            'level': points_to_level(game['points']),
            'unlocked_rewards': unlocked
        })
    else:
        users[username] = user
        save_user(username, user)
        return jsonify({
            'success': True,
            'correct': False,
            'expected_preview': challenge['expected'][:30] + '...' if len(challenge['expected']) > 30 else challenge['expected'],
            'message': 'Sai rồi! Thử lại vào ngày mai nhé!'
        })


# ─── REWARDS ───
@app.route('/api/game/rewards')
@login_required
def api_rewards():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    user = users[username]
    game = ensure_game_data(user)
    unlocked_ids = {r['id'] for r in check_rewards(game)}
    claimed_ids = set(game.get('rewards_claimed', []))
    all_rewards = []
    for r in REWARDS:
        status = 'locked'
        if r['id'] in claimed_ids: status = 'claimed'
        elif r['id'] in unlocked_ids: status = 'unlocked'
        all_rewards.append({**r, 'status': status})
    return jsonify({
        'success': True,
        'rewards': all_rewards,
        'stats': {
            'points': game.get('points', 0),
            'level': points_to_level(game.get('points', 0)),
            'daily_count': len(game.get('daily_completed', [])),
            'pvp_wins': game.get('pvp_stats', {}).get('wins', 0),
            'streak': game.get('streak', 0)
        }
    })


@app.route('/api/game/rewards/claim', methods=['POST'])
@login_required
def api_claim_reward():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    data = request.get_json()
    reward_id = data.get('reward_id', '').strip()
    user = users[username]
    game = ensure_game_data(user)
    reward = next((r for r in REWARDS if r['id'] == reward_id), None)
    if not reward:
        return jsonify({'success': False, 'error': 'Reward không tồn tại!'}), 404
    if reward_id in game.get('rewards_claimed', []):
        return jsonify({'success': False, 'error': 'Đã claim rồi!'}), 400
    unlocked = {r['id'] for r in check_rewards(game)}
    if reward_id not in unlocked:
        return jsonify({'success': False, 'error': 'Chưa đủ điều kiện!'}), 403
    game.setdefault('rewards_claimed', []).append(reward_id)
    add_points(user, reward['points_reward'], f"Reward: {reward_id}")
    users[username] = user
    save_user(username, user)
    return jsonify({
        'success': True,
        'message': f'🎁 Nhận được {reward["points_reward"]} điểm!',
        'points_earned': reward['points_reward'],
        'total_points': game['points'],
        'level': points_to_level(game['points'])
    })


# ─── RANDOM METHOD ───
@app.route('/api/game/random-method')
@login_required
def api_random_method():
    exclude_one_way = request.args.get('exclude_one_way', 'false').lower() == 'true'
    exclude_key = request.args.get('exclude_key', 'false').lower() == 'true'
    result = pick_random_method(exclude_one_way, exclude_key)
    return jsonify({'success': True, **result})


# ═══════════════════════════════════════════════════════════
#  ⚔️ PVP — NHẬP CHỮ NHANH (3 ván × 10 câu)
# ═══════════════════════════════════════════════════════════
@app.route('/api/pvp/create', methods=['POST'])
@login_required
def api_pvp_create():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    user = users[username]
    display = user.get('display_name', username)
    try:
        room = create_pvp_room(username, display)
        return jsonify({
            'success': True,
            'code': room['code'],
            'room': _sanitize_room(room, username)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pvp/join', methods=['POST'])
@login_required
def api_pvp_join():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    data = request.get_json()
    code = (data.get('code') or '').strip().upper()
    if not code:
        return jsonify({'success': False, 'error': 'Nhập mã phòng!'}), 400
    user = users[username]
    display = user.get('display_name', username)
    result = join_pvp_room(code, username, display)
    if not result['success']:
        return jsonify(result), 404
    return jsonify({
        'success': True,
        'code': code,
        'room': _sanitize_room(result['room'], username)
    })


@app.route('/api/pvp/start', methods=['POST'])
@login_required
def api_pvp_start():
    username = session['username']
    data = request.get_json()
    code = (data.get('code') or '').strip().upper()
    result = start_pvp_room(code, username)
    if not result['success']:
        return jsonify(result), 400
    return jsonify({
        'success': True,
        'room': _sanitize_room(result['room'], username)
    })


@app.route('/api/pvp/room/<code>')
@login_required
def api_pvp_room(code):
    username = session['username']
    result = get_pvp_room(code)
    if not result['success']:
        return jsonify(result), 404
    return jsonify({
        'success': True,
        'room': _sanitize_room(result['room'], username)
    })


@app.route('/api/pvp/submit', methods=['POST'])
@login_required
def api_pvp_submit():
    username = session['username']
    data = request.get_json()
    code = (data.get('code') or '').strip().upper()
    answer = (data.get('answer') or '').strip()
    if not code or not answer:
        return jsonify({'success': False, 'error': 'Thiếu dữ liệu!'}), 400
    result = submit_pvp_answer(code, username, answer)
    if not result['success']:
        return jsonify(result), 400
    return jsonify({
        'success': True,
        'correct': result['correct'],
        'points': result['points'],
        'time_taken': result['time_taken'],
        'room': _sanitize_room(result['room'], username)
    })


@app.route('/api/pvp/leave', methods=['POST'])
@login_required
def api_pvp_leave():
    username = session['username']
    data = request.get_json()
    code = (data.get('code') or '').strip().upper()
    result = leave_pvp_room(code, username)
    return jsonify(result)


def _sanitize_room(room: dict, username: str) -> dict:
    """Chuẩn hóa room data — hiển thị điểm đối thủ realtime."""
    opponent = room["guest"] if room["host"] == username else room["host"]
    is_host = (room["host"] == username)

    safe = {
        "code": room["code"],
        "host": room["host"],
        "host_display": room["host_display"],
        "guest": room["guest"],
        "guest_display": room["guest_display"],
        "status": room["status"],
        "current_round": room["current_round"],
        "total_rounds": TOTAL_ROUNDS,
        "questions_per_round": QUESTIONS_PER_ROUND,
        "you": username,
        "is_host": is_host,
        "opponent": opponent,
        "opponent_display": room["guest_display"] if is_host else room["host_display"],
        "round_wins": {
            "you": room["round_wins"].get(username, 0),
            "opponent": room["round_wins"].get(opponent, 0) if opponent else 0,
        },
    }

    round_idx = room["current_round"]
    if 0 <= round_idx < TOTAL_ROUNDS:
        r = room["rounds"][round_idx]
        safe["round_info"] = {
            "index": round_idx,
            "current_index": r["current_index"],
            "total_questions": QUESTIONS_PER_ROUND,
            "scores": {
                "you": r["scores"].get(username, 0),
                "opponent": r["scores"].get(opponent, 0) if opponent else 0,
            },
            "winner": r["winner"],
        }

        q_idx = r["current_index"]
        if 0 <= q_idx < QUESTIONS_PER_ROUND:
            q = r["questions"][q_idx]
            safe["current_question"] = {
                "index": q_idx,
                "display": q["display"],
                "method": q["method"],
                "length": len(q["word"]),
            }
            opp_answered = q_idx in r["answers"].get(opponent, {}) if opponent else False
            safe["opponent_answered"] = opp_answered
            if opp_answered:
                opp_ans = r["answers"][opponent][q_idx]
                safe["opponent_answer"] = {
                    "answer": opp_ans["answer"],
                    "correct": opp_ans["correct"],
                    "points": opp_ans["points"],
                    "time_taken": opp_ans["time_taken"],
                }
            my_answered = q_idx in r["answers"].get(username, {})
            if my_answered:
                my_ans = r["answers"][username][q_idx]
                safe["current_question"]["your_answer"] = my_ans
                safe["current_question"]["correct_answer"] = q["word"]
        else:
            safe["current_question"] = None
            safe["opponent_answered"] = False
    else:
        safe["round_info"] = None
        safe["current_question"] = None

    if room["status"] == "finished":
        my_wins = room["round_wins"].get(username, 0)
        opp_wins = room["round_wins"].get(opponent, 0) if opponent else 0

        if my_wins > opp_wins:
            result = "win"
            message = "🏆 Bạn thắng trận!"
        elif my_wins < opp_wins:
            result = "loss"
            message = "😢 Bạn thua trận!"
        else:
            result = "draw"
            message = "🤝 Hòa!"

        total_you = 0
        total_opp = 0
        for r in room["rounds"]:
            total_you += r["scores"].get(username, 0)
            total_opp += r["scores"].get(opponent, 0) if opponent else 0

        safe["final_result"] = {
            "result": result,
            "message": message,
            "your_rounds_won": my_wins,
            "opponent_rounds_won": opp_wins,
            "total_score_you": total_you,
            "total_score_opponent": total_opp,
            "rounds": [
                {
                    "index": i,
                    "your_score": r["scores"].get(username, 0),
                    "opponent_score": r["scores"].get(opponent, 0) if opponent else 0,
                    "winner": "you" if r["winner"] == username else ("opponent" if r["winner"] == opponent else "draw"),
                }
                for i, r in enumerate(room["rounds"])
            ],
        }

    return safe


# ─── MEME ───
@app.route('/api/game/meme/templates')
@login_required
def api_meme_templates():
    return jsonify({'success': True, 'templates': MEME_TEMPLATES})


@app.route('/api/game/meme/generate', methods=['POST'])
@login_required
def api_meme_generate():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    data = request.get_json()
    input_text = data.get('input_text', '')
    output_text = data.get('output_text', '')
    template_id = data.get('template_id')
    if not input_text or not output_text:
        return jsonify({'success': False, 'error': 'Thiếu text!'}), 400
    meme = generate_meme_template(input_text, output_text, template_id)
    user = users[username]
    game = ensure_game_data(user)
    game['meme_count'] = game.get('meme_count', 0) + 1
    if game['meme_count'] <= 10:
        add_points(user, 10, "Meme created")
    users[username] = user
    save_user(username, user)
    return jsonify({'success': True, 'meme': meme})


# ─── USER GAME STATS ───
@app.route('/api/game/me')
@login_required
def api_game_me():
    users = load_users()
    username = session['username']
    if username not in users:
        return jsonify({'success': False, 'error': 'User không tồn tại'}), 404
    user = users[username]
    game = ensure_game_data(user)
    level_info = level_to_next(game.get('points', 0))
    board = []
    for uname, udata in users.items():
        g = udata.get('game', {})
        board.append((uname, g.get('points', 0)))
    board.sort(key=lambda x: -x[1])
    rank = next((i + 1 for i, (u, _) in enumerate(board) if u == username), 0)
    return jsonify({
        'success': True,
        'game': game,
        'level_info': level_info,
        'rank': rank,
        'total_users': len(board)
    })


# ============================================================
# ADMIN PANEL
# ============================================================
@app.route('/admin')
@admin_required
def admin_panel():
    users = load_users()
    user = users.get(session['username'], {})
    return render_template(
        'admin.html',
        username=user.get('display_name', session['username']),
        real_username=session['username'],
        user_id=user.get('user_id', '—'),
        is_super_admin=is_super_admin(session['username']),
        role=user.get('role', 'user')
    )


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


# ============================================================
# ADMIN ACTIONS
# ============================================================
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

        ban_info = {
            'user_id': target_id,
            'reason': reason,
            'time': now.isoformat(),
            'by': session['username'],
            'duration_label': 'Vĩnh viễn',
            'is_temp_ban': False
        }

        duration_map = {
            '15min':  timedelta(minutes=15),
            '30min':  timedelta(minutes=30),
            '1h':     timedelta(hours=1),
            '6h':     timedelta(hours=6),
            '12h':    timedelta(hours=12),
            '1day':   timedelta(days=1),
            '3days':  timedelta(days=3),
            '7days':  timedelta(days=7),
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
            try:
                custom_value = int(custom_value)
            except (TypeError, ValueError):
                return jsonify({'success': False, 'error': 'Giá trị thời gian không hợp lệ!'}), 400

            if custom_value <= 0:
                return jsonify({'success': False, 'error': 'Thời gian phải > 0!'}), 400
            if custom_value > 3650:
                return jsonify({'success': False, 'error': 'Thời gian tối đa 3650!'}), 400

            if custom_unit == 'minutes':
                delta = timedelta(minutes=custom_value)
            elif custom_unit == 'hours':
                delta = timedelta(hours=custom_value)
            elif custom_unit == 'days':
                delta = timedelta(days=custom_value)
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

        msg = f'🚫 Đã ban user ID {target_id} ({ban_info["duration_label"]})'
        return jsonify({'success': True, 'message': msg, 'ban_info': ban_info})
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
        warnings.append({
            'user_id': target_id,
            'reason': reason,
            'time': datetime.now().isoformat(),
            'by': session['username']
        })
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
            return jsonify({
                'success': True,
                'message': f'⚠️🚫 Đã warn + ban 1 ngày user ID {target_id}',
                'total_warnings': len(warnings),
                'banned': True
            })
        else:
            return jsonify({
                'success': True,
                'message': f'⚠️ Đã cảnh báo user ID {target_id}',
                'total_warnings': len(warnings),
                'banned': False
            })
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
    return jsonify({
        'success': True,
        'stats': {
            'total': total, 'active': active,
            'warned': warned, 'banned': banned,
            'pending_delete': pending_delete,
            'admins': admins, 'suspicious': suspicious
        }
    })


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
            'user_id': target_id,
            'reason': reason,
            'time': datetime.now().isoformat(),
            'by': session['username'],
            'expires_at': (datetime.now() + timedelta(days=PENDING_DELETE_DAYS)).isoformat()
        }
        save_user(target, users[target])

        return jsonify({
            'success': True,
            'message': f'⚠️ Đã đánh dấu xóa user ID {target_id}',
            'delete_info': users[target]['delete_info']
        })
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
            return jsonify({'success': False, 'error': '🚫 KHÔNG THỂ TỰ ÉP BUỘC XÓA CHÍNH MÌNH!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if is_super_admin(target):
            return jsonify({'success': False, 'error': '🚫 Không thể ép buộc xóa Super Admin!'}), 403

        target_id = users[target].get('user_id', '—')

        if confirm_text != target_id:
            return jsonify({
                'success': False,
                'error': f'⚠️ Bạn phải gõ chính xác ID "{target_id}" để xác nhận!'
            }), 400

        log_activity(session['username'], 'force_delete',
                     f"Ép buộc xóa user ID {target_id} — Lý do: {reason}")

        print(f"⚡ ÉP BUỘC XÓA: {target} (ID: {target_id}) — Bởi: {session['username']} — Lý do: {reason}")
        delete_user_db(target)

        return jsonify({
            'success': True,
            'message': f'⚡ Đã ÉP BUỘC XÓA vĩnh viễn user ID {target_id}',
            'deleted_username': target,
            'deleted_user_id': target_id,
            'reason': reason,
            'kicked': True
        })
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
        log.insert(0, {
            'action': 'refresh_status',
            'detail': f'Admin {session["username"]} đã làm mới trạng thái',
            'time': datetime.now().isoformat()
        })
        user['activity_log'] = log[:50]

        save_user(target, user)

        return jsonify({
            'success': True,
            'message': f'♻️ Đã làm mới user ID {target_id} (cũ: {old_status})',
            'old_status': old_status
        })
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
                failed += 1
                continue
            if usernames_match(target, session['username']) or is_super_admin(target):
                failed += 1
                continue

            user = users[target]
            user['status'] = 'active'
            user['warnings'] = []
            user['ban_info'] = None
            user['delete_info'] = None
            user['suspicious_score'] = 0
            user['warnings_shown'] = True
            save_user(target, user)
            refreshed += 1

        return jsonify({
            'success': True,
            'message': f'♻️ Đã làm mới {refreshed} user, {failed} lỗi',
            'refreshed': refreshed,
            'failed': failed
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/seed', methods=['POST'])
@super_admin_required
def admin_seed():
    try:
        seed_accounts()
        users = load_users()
        return jsonify({
            'success': True,
            'message': f'✅ Đã chạy seed. Tổng user: {len(users)}',
            'total_users': len(users)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


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
        'total_pvp_rooms': len(cleanup_old_rooms.__module__ and __import__('game_utils').PVP_ROOMS) if False else 0,
        'super_admin': SUPER_ADMIN_USERNAME,
        'super_admin_exists': any(usernames_match(u, SUPER_ADMIN_USERNAME) for u in users.keys())
    })


@app.route('/ping')
def ping():
    return 'pong', 200


# ============================================================
# KHỞI ĐỘNG
# ============================================================
init_db()
init_super_admin()
seed_accounts()
auto_unban_expired()
auto_delete_expired()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
