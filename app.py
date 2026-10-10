from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from crypto_utils import process, METHODS, ONE_WAY_ONLY
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import os
import json
import hashlib
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-production')
app.permanent_session_lifetime = timedelta(days=7)

USERS_FILE = 'users.json'

# 👑 SUPER ADMIN — người duy nhất có toàn quyền
SUPER_ADMIN_USERNAME = os.getenv('ADMIN_USER', 'admin')
SUPER_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

SUSPICIOUS_THRESHOLD = 50
WARN_THRESHOLD = 30


# ============================================================
# QUẢN LÝ USER
# ============================================================
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Lỗi đọc users.json: {e}")
        return {}


def save_users(users):
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"❌ Lỗi ghi users.json: {e}")


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


def is_super_admin(username):
    """Check xem có phải Super Admin không"""
    return username and username.lower() == SUPER_ADMIN_USERNAME.lower()


# ============================================================
# KHỞI TẠO SUPER ADMIN — BẤT TỬ
# ============================================================
def init_super_admin():
    """
    Tạo/nâng cấp SUPER ADMIN.
    Luôn đảm bảo:
      - role = 'super_admin'
      - status = 'active' (tự gỡ ban nếu bị ban)
      - password khớp env
      - không có warnings
    """
    users = load_users()
    now = datetime.now().isoformat()

    if SUPER_ADMIN_USERNAME not in users:
        users[SUPER_ADMIN_USERNAME] = {
            'password': hash_password(SUPER_ADMIN_PASSWORD),
            'role': 'super_admin',
            'created_at': now,
            'last_login': None,
            'login_count': 0,
            'history': [],
            'status': 'active',
            'warnings': [],
            'ban_info': None,
            'activity_log': [{
                'action': 'system',
                'detail': 'Super Admin được tạo tự động',
                'time': now
            }],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': True
        }
        save_users(users)
        print(f"👑 Đã tạo SUPER ADMIN: {SUPER_ADMIN_USERNAME}")
        return

    # Đã có → nâng cấp & bảo vệ
    changed = False
    user = users[SUPER_ADMIN_USERNAME]

    if user.get('role') != 'super_admin':
        user['role'] = 'super_admin'
        changed = True
        print(f"👑 Đã nâng cấp {SUPER_ADMIN_USERNAME} → SUPER ADMIN")

    if user.get('status') != 'active':
        user['status'] = 'active'
        user['ban_info'] = None
        changed = True
        print(f"✅ Đã tự gỡ ban cho Super Admin")

    if not verify_password(SUPER_ADMIN_PASSWORD, user.get('password', '')):
        user['password'] = hash_password(SUPER_ADMIN_PASSWORD)
        changed = True
        print(f"🔑 Đã đồng bộ mật khẩu Super Admin từ ENV")

    if user.get('warnings'):
        user['warnings'] = []
        user['warnings_shown'] = True
        changed = True
        print(f"🧹 Đã xóa cảnh báo của Super Admin")

    if not user.get('protected'):
        user['protected'] = True
        changed = True

    defaults = {
        'created_at': now,
        'last_login': None,
        'login_count': 0,
        'history': [],
        'warnings': [],
        'ban_info': None,
        'activity_log': [],
        'suspicious_score': 0,
        'warnings_shown': True
    }
    for k, v in defaults.items():
        if k not in user:
            user[k] = v
            changed = True

    if changed:
        save_users(users)
    else:
        print(f"✓ Super Admin {SUPER_ADMIN_USERNAME} đã sẵn sàng")


def log_activity(username, action, detail=''):
    users = load_users()
    if username not in users:
        return

    log = users[username].get('activity_log', [])
    log.insert(0, {
        'action': action,
        'detail': detail,
        'time': datetime.now().isoformat()
    })
    users[username]['activity_log'] = log[:50]

    try:
        five_min_ago = datetime.now() - timedelta(minutes=5)
        recent = [l for l in log if datetime.fromisoformat(l['time']) > five_min_ago]
        users[username]['suspicious_score'] = len(recent)

        # Auto-warn TRỪ super admin
        if (len(recent) >= SUSPICIOUS_THRESHOLD
            and users[username].get('status') == 'active'
            and users[username].get('role') != 'super_admin'):
            warnings = users[username].get('warnings', [])
            warnings.append({
                'reason': f'Hoạt động bất thường: {len(recent)} thao tác trong 5 phút',
                'time': datetime.now().isoformat(),
                'by': 'system'
            })
            users[username]['warnings'] = warnings
            users[username]['status'] = 'warned'
            users[username]['warnings_shown'] = False
    except Exception as e:
        print(f"⚠️ Lỗi log_activity: {e}")

    save_users(users)


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
    """Chỉ admin/super_admin"""
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
    """CHỈ Super Admin"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Chưa đăng nhập!', 'need_login': True}), 401
            return redirect(url_for('login_page'))

        if not is_super_admin(session['username']):
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Chỉ Super Admin mới có quyền này!'}), 403
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# AUTH
# ============================================================
@app.route('/login')
def login_page():
    if 'username' in session:
        users = load_users()
        user = users.get(session['username'], {})
        if user.get('status') == 'banned' and not is_super_admin(session['username']):
            uname = session.get('username', '')
            session.clear()
            return redirect(url_for('banned_page', user=uname))
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Tên đăng nhập phải có ít nhất 3 ký tự!'}), 400
        if len(username) > 30:
            return jsonify({'success': False, 'error': 'Tên đăng nhập tối đa 30 ký tự!'}), 400
        if not username.replace('_', '').replace('.', '').isalnum():
            return jsonify({'success': False, 'error': 'Tên chỉ được chứa chữ, số, dấu _ và .'}), 400
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Mật khẩu phải có ít nhất 6 ký tự!'}), 400

        # Không cho đăng ký trùng tên super admin
        if username.lower() == SUPER_ADMIN_USERNAME.lower():
            return jsonify({'success': False, 'error': 'Tên này đã được bảo vệ!'}), 400

        users = load_users()
        if username.lower() in [u.lower() for u in users.keys()]:
            return jsonify({'success': False, 'error': 'Tên đăng nhập đã tồn tại!'}), 400

        now = datetime.now().isoformat()
        users[username] = {
            'password': hash_password(password),
            'role': 'user',
            'created_at': now,
            'last_login': now,
            'login_count': 1,
            'history': [],
            'status': 'active',
            'warnings': [],
            'ban_info': None,
            'activity_log': [{
                'action': 'register',
                'detail': 'Đăng ký tài khoản mới',
                'time': now
            }],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': False
        }
        save_users(users)

        session.permanent = True
        session['username'] = username
        session['login_time'] = now
        session['warnings_shown'] = True

        return jsonify({
            'success': True,
            'message': f'Chào mừng {username}!',
            'username': username,
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

        # Nếu là super admin → ưu tiên check env
        if username.lower() == SUPER_ADMIN_USERNAME.lower():
            if SUPER_ADMIN_USERNAME not in users:
                init_super_admin()
                users = load_users()

            if password != SUPER_ADMIN_PASSWORD and not verify_password(password, users[SUPER_ADMIN_USERNAME]['password']):
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

            found_user = SUPER_ADMIN_USERNAME
        else:
            found_user = None
            for u in users.keys():
                if u.lower() == username.lower():
                    found_user = u
                    break

            if not found_user:
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

            if not verify_password(password, users[found_user]['password']):
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

        user = users[found_user]

        # Kiểm tra ban (super admin miễn nhiễm)
        if user.get('status') == 'banned' and not is_super_admin(found_user):
            return jsonify({
                'success': False,
                'error': 'Tài khoản đã bị BAN!',
                'banned': True,
                'redirect': f'/banned?user={found_user}'
            }), 403

        # Cập nhật login info
        now = datetime.now().isoformat()
        users[found_user]['last_login'] = now
        users[found_user]['login_count'] = user.get('login_count', 0) + 1

        log = users[found_user].get('activity_log', [])
        log.insert(0, {
            'action': 'login',
            'detail': f'Đăng nhập lần {users[found_user]["login_count"]}',
            'time': now
        })
        users[found_user]['activity_log'] = log[:50]

        users[found_user]['warnings_shown'] = False
        save_users(users)

        session.permanent = remember
        session['username'] = found_user
        session['login_time'] = now
        session['warnings_shown'] = False

        warnings = user.get('warnings', [])

        return jsonify({
            'success': True,
            'message': f'Chào mừng trở lại, {found_user}!',
            'username': found_user,
            'role': user.get('role', 'user'),
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
    user = users.get(session['username'], {})

    if user.get('status') == 'banned' and not is_super_admin(session['username']):
        uname = session.get('username', '')
        session.clear()
        return jsonify({
            'success': False,
            'banned': True,
            'error': 'Tài khoản đã bị ban!',
            'redirect': f'/banned?user={uname}'
        }), 403

    return jsonify({
        'success': True,
        'logged_in': True,
        'username': session['username'],
        'role': user.get('role', 'user'),
        'is_super_admin': is_super_admin(session['username']),
        'login_time': session.get('login_time'),
        'login_count': user.get('login_count', 0),
        'created_at': user.get('created_at'),
        'status': user.get('status', 'active'),
        'warnings': user.get('warnings', []),
        'history_count': len(user.get('history', []))
    })


# ============================================================
# BAN & WARNING PAGES
# ============================================================
@app.route('/banned')
def banned_page():
    username = request.args.get('user', '').strip()
    users = load_users()

    found_user = None
    for u in users.keys():
        if u.lower() == username.lower():
            found_user = u
            break

    if not found_user:
        return redirect(url_for('login_page'))

    user = users[found_user]

    if user.get('status') != 'banned':
        return redirect(url_for('login_page'))

    ban_info = user.get('ban_info', {}) or {}

    ban_id = hashlib.md5(
        f"{found_user}{ban_info.get('time', '')}".encode()
    ).hexdigest()[:12].upper()

    banned_at = ban_info.get('time', '')
    if banned_at:
        try:
            banned_at = datetime.fromisoformat(banned_at).strftime('%d/%m/%Y %H:%M:%S')
        except:
            banned_at = banned_at[:19].replace('T', ' ')

    return render_template(
        'banned.html',
        username=found_user,
        reason=ban_info.get('reason', 'Vi phạm điều khoản'),
        banned_at=banned_at or '—',
        banned_by=ban_info.get('by', 'System'),
        ban_id=ban_id
    )


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

    warnings = user.get('warnings', [])

    if not session.get('warnings_shown') and warnings:
        return render_template(
            'warned.html',
            username=session['username'],
            warnings=warnings
        )

    return redirect(url_for('index'))


@app.route('/api/acknowledge-warnings', methods=['POST'])
def acknowledge_warnings():
    if 'username' in session:
        session['warnings_shown'] = True
        users = load_users()
        if session['username'] in users:
            users[session['username']]['warnings_shown'] = True
            save_users(users)
    return jsonify({'success': True})


# ============================================================
# ROUTES CHÍNH
# ============================================================
@app.route('/')
@login_required
def index():
    users = load_users()
    user = users.get(session['username'], {})

    if user.get('status') == 'banned' and not is_super_admin(session['username']):
        uname = session.get('username', '')
        session.clear()
        return redirect(url_for('banned_page', user=uname))

    warnings = user.get('warnings', [])
    if warnings and not session.get('warnings_shown') and not is_super_admin(session['username']):
        return redirect(url_for('warned_page'))

    return render_template(
        'index.html',
        methods=METHODS,
        username=session.get('username'),
        role=user.get('role', 'user'),
        is_super_admin=is_super_admin(session['username'])
    )


@app.route('/api/process', methods=['POST'])
@login_required
def api_process():
    try:
        users = load_users()
        user = users.get(session['username'], {})

        if user.get('status') == 'banned' and not is_super_admin(session['username']):
            uname = session.get('username', '')
            session.clear()
            return jsonify({
                'success': False,
                'error': 'Tài khoản đã bị ban!',
                'banned': True,
                'redirect': f'/banned?user={uname}'
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
            return jsonify({
                'success': False,
                'error': f'Phương pháp "{METHODS[method]}" là mã hóa 1 chiều — không thể giải mã!'
            }), 400

        result = process(text, method, action, key)

        history = user.get('history', [])
        history.insert(0, {
            'method': method,
            'action': action,
            'input_preview': text[:50],
            'output_preview': result[:50],
            'time': datetime.now().isoformat()
        })
        users[session['username']]['history'] = history[:20]
        save_users(users)

        log_activity(session['username'], action, f'{method}: {text[:30]}')

        return jsonify({
            'success': True,
            'result': result,
            'method': method,
            'action': action,
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
# ADMIN PANEL
# ============================================================
@app.route('/admin')
@admin_required
def admin_panel():
    users = load_users()
    user = users.get(session['username'], {})
    return render_template(
        'admin.html',
        username=session['username'],
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
            'role': data.get('role', 'user'),
            'status': data.get('status', 'active'),
            'login_count': data.get('login_count', 0),
            'created_at': data.get('created_at'),
            'last_login': data.get('last_login'),
            'warnings_count': len(data.get('warnings', [])),
            'history_count': len(data.get('history', [])),
            'suspicious_score': data.get('suspicious_score', 0),
            'ban_info': data.get('ban_info'),
            'protected': data.get('protected', False),
            'is_super_admin': is_super_admin(username)
        })

    def sort_key(u):
        if u['is_super_admin']: return (0, 0, 0, u['username'].lower())
        if u['role'] == 'admin': return (1, 0, 0, u['username'].lower())
        if u['status'] == 'banned': return (2, 0, 0, u['username'].lower())
        if u['status'] == 'warned': return (2, 1, 0, u['username'].lower())
        return (2, 2, 0, u['username'].lower())

    result.sort(key=sort_key)
    return jsonify({'success': True, 'users': result})


# ============================================================
# ADMIN ACTIONS — CHỈ SUPER ADMIN + CHẶN TỰ BAN/WARN/XÓA
# ============================================================
@app.route('/api/admin/ban', methods=['POST'])
@super_admin_required
def admin_ban():
    """Ban user — 🚫 CHẶN tự ban chính mình"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Vi phạm điều khoản').strip() or 'Vi phạm điều khoản'

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400

        # 🚫 CHẶN TỰ BAN
        if target == session['username']:
            return jsonify({
                'success': False,
                'error': '🚫 KHÔNG THỂ TỰ BAN CHÍNH MÌNH!\n\n'
                         'Bạn là Super Admin duy nhất. Nếu tự ban, bạn sẽ mất '
                         'quyền truy cập và không ai có thể gỡ ban cho bạn.'
            }), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        # 🚫 CHẶN BAN SUPER ADMIN KHÁC
        if is_super_admin(target):
            return jsonify({
                'success': False,
                'error': '🚫 Không thể ban Super Admin khác!'
            }), 403

        users[target]['status'] = 'banned'
        users[target]['ban_info'] = {
            'reason': reason,
            'time': datetime.now().isoformat(),
            'by': session['username']
        }
        save_users(users)

        return jsonify({
            'success': True,
            'message': f'🚫 Đã ban {target}',
            'ban_info': users[target]['ban_info']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/unban', methods=['POST'])
@super_admin_required
def admin_unban():
    """Gỡ ban — CHỈ Super Admin"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        users[target]['status'] = 'active'
        users[target]['ban_info'] = None
        save_users(users)

        return jsonify({'success': True, 'message': f'✅ Đã gỡ ban {target}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/warn', methods=['POST'])
@super_admin_required
def admin_warn():
    """Cảnh báo user — 🚫 CHẶN tự warn chính mình"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Cảnh báo từ admin').strip() or 'Cảnh báo từ admin'

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400

        # 🚫 CHẶN TỰ WARN
        if target == session['username']:
            return jsonify({
                'success': False,
                'error': '🚫 KHÔNG THỂ TỰ CẢNH BÁO CHÍNH MÌNH!\n\n'
                         'Hãy cảnh báo user khác. Nếu tự cảnh báo, bạn sẽ bị '
                         'chuyển đến trang cảnh báo và phải xác nhận.'
            }), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        # 🚫 CHẶN WARN SUPER ADMIN KHÁC
        if is_super_admin(target):
            return jsonify({
                'success': False,
                'error': '🚫 Không thể cảnh báo Super Admin khác!'
            }), 403

        warnings = users[target].get('warnings', [])
        warnings.append({
            'reason': reason,
            'time': datetime.now().isoformat(),
            'by': session['username']
        })
        users[target]['warnings'] = warnings

        if users[target].get('status') == 'active':
            users[target]['status'] = 'warned'

        users[target]['warnings_shown'] = False
        save_users(users)

        return jsonify({
            'success': True,
            'message': f'⚠️ Đã cảnh báo {target} (tổng: {len(warnings)})',
            'total_warnings': len(warnings)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/reset-warnings', methods=['POST'])
@super_admin_required
def admin_reset_warnings():
    """Xóa cảnh báo — CHỈ Super Admin"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        users[target]['warnings'] = []
        users[target]['warnings_shown'] = True
        if users[target].get('status') == 'warned':
            users[target]['status'] = 'active'
        save_users(users)

        return jsonify({'success': True, 'message': f'🔄 Đã xóa cảnh báo của {target}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/user/<username>')
@admin_required
def admin_user_detail(username):
    """Chi tiết user — admin nào cũng xem được"""
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

    return jsonify({
        'success': True,
        'user': {
            'username': username,
            'role': user.get('role', 'user'),
            'status': user.get('status', 'active'),
            'created_at': user.get('created_at'),
            'last_login': user.get('last_login'),
            'login_count': user.get('login_count', 0),
            'warnings': user.get('warnings', []),
            'ban_info': user.get('ban_info'),
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
    admins = sum(1 for u in users.values() if u.get('role') in ('admin', 'super_admin'))
    suspicious = sum(1 for u in users.values() if u.get('suspicious_score', 0) >= WARN_THRESHOLD)

    return jsonify({
        'success': True,
        'stats': {
            'total': total,
            'active': active,
            'warned': warned,
            'banned': banned,
            'admins': admins,
            'suspicious': suspicious
        }
    })


@app.route('/api/admin/delete', methods=['POST'])
@super_admin_required
def admin_delete():
    """Xóa user — 🚫 CHẶN tự xóa chính mình"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400

        # 🚫 CHẶN TỰ XÓA
        if target == session['username']:
            return jsonify({
                'success': False,
                'error': '🚫 KHÔNG THỂ TỰ XÓA CHÍNH MÌNH!\n\n'
                         'Bạn là Super Admin duy nhất. Hãy để user khác xóa '
                         'hoặc xóa thủ công file users.json nếu muốn reset.'
            }), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        # 🚫 CHẶN XÓA SUPER ADMIN KHÁC
        if is_super_admin(target):
            return jsonify({
                'success': False,
                'error': '🚫 Không thể xóa Super Admin khác!'
            }), 403

        del users[target]
        save_users(users)

        return jsonify({'success': True, 'message': f'🗑️ Đã xóa {target}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/promote', methods=['POST'])
@super_admin_required
def admin_promote():
    """Nâng user lên admin — CHỈ Super Admin"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        if users[target].get('role') == 'super_admin':
            return jsonify({'success': False, 'error': 'Đã là Super Admin!'}), 400

        users[target]['role'] = 'admin'
        save_users(users)

        return jsonify({'success': True, 'message': f'👑 Đã nâng {target} lên Admin'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/demote', methods=['POST'])
@super_admin_required
def admin_demote():
    """Hạ admin xuống user — CHỈ Super Admin"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400

        if target == session['username']:
            return jsonify({'success': False, 'error': 'Không thể tự hạ cấp!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        if is_super_admin(target):
            return jsonify({'success': False, 'error': 'Không thể hạ Super Admin!'}), 403

        users[target]['role'] = 'user'
        save_users(users)

        return jsonify({'success': True, 'message': f'👤 Đã hạ {target} xuống User'})
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
        'total_methods': len(METHODS),
        'total_users': len(users),
        'super_admin': SUPER_ADMIN_USERNAME,
        'super_admin_exists': SUPER_ADMIN_USERNAME in users,
        'super_admin_role': users.get(SUPER_ADMIN_USERNAME, {}).get('role', 'none')
    })


# ============================================================
# KHỞI ĐỘNG
# ============================================================
init_super_admin()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
