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
ADMIN_USERNAME = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

# Ngưỡng phát hiện bất thường
SUSPICIOUS_THRESHOLD = 50   # >= 50 hành động / 5 phút → tự warn
WARN_THRESHOLD = 30         # >= 30 hành động / 5 phút → đánh dấu suspicious


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


def init_default_user():
    """Tạo tài khoản admin mặc định nếu chưa có"""
    users = load_users()
    if ADMIN_USERNAME not in users:
        users[ADMIN_USERNAME] = {
            'password': hash_password(ADMIN_PASSWORD),
            'role': 'admin',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'login_count': 0,
            'history': [],
            'status': 'active',
            'warnings': [],
            'ban_info': None,
            'activity_log': [],
            'suspicious_score': 0,
            'warnings_shown': False
        }
        save_users(users)
        print(f"✅ Đã tạo tài khoản admin: {ADMIN_USERNAME}")
    else:
        # Đảm bảo admin luôn có role = admin
        if users[ADMIN_USERNAME].get('role') != 'admin':
            users[ADMIN_USERNAME]['role'] = 'admin'
            save_users(users)


def log_activity(username, action, detail=''):
    """Ghi log hoạt động + tính điểm bất thường"""
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

    # Tính suspicious score
    try:
        five_min_ago = datetime.now() - timedelta(minutes=5)
        recent = [
            l for l in log
            if datetime.fromisoformat(l['time']) > five_min_ago
        ]
        users[username]['suspicious_score'] = len(recent)

        # Tự động warn nếu vượt ngưỡng
        if len(recent) >= SUSPICIOUS_THRESHOLD and users[username].get('status') == 'active':
            warnings = users[username].get('warnings', [])
            warnings.append({
                'reason': f'Hoạt động bất thường: {len(recent)} thao tác trong 5 phút',
                'time': datetime.now().isoformat(),
                'by': 'system'
            })
            users[username]['warnings'] = warnings
            users[username]['status'] = 'warned'
            print(f"⚠️ Auto-warn {username}: {len(recent)} actions/5min")
    except Exception as e:
        print(f"⚠️ Lỗi tính suspicious: {e}")

    save_users(users)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Chưa đăng nhập!',
                    'need_login': True
                }), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({
                    'success': False,
                    'error': 'Chưa đăng nhập!',
                    'need_login': True
                }), 401
            return redirect(url_for('login_page'))

        users = load_users()
        user = users.get(session['username'], {})
        if user.get('role') != 'admin':
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Không có quyền admin!'}), 403
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# AUTH ROUTES
# ============================================================
@app.route('/login')
def login_page():
    if 'username' in session:
        # Kiểm tra ban
        users = load_users()
        user = users.get(session['username'], {})
        if user.get('status') == 'banned':
            session.clear()
            return redirect(url_for('banned_page', user=session.get('username', '')))
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        # Validate
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Tên đăng nhập phải có ít nhất 3 ký tự!'}), 400
        if len(username) > 30:
            return jsonify({'success': False, 'error': 'Tên đăng nhập tối đa 30 ký tự!'}), 400
        if not username.replace('_', '').replace('.', '').isalnum():
            return jsonify({'success': False, 'error': 'Tên chỉ được chứa chữ, số, dấu _ và .'}), 400
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Mật khẩu phải có ít nhất 6 ký tự!'}), 400

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
            'warnings_shown': False
        }
        save_users(users)

        session.permanent = True
        session['username'] = username
        session['login_time'] = now
        session['warnings_shown'] = True  # user mới không cần xem warning

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

        # Tìm user không phân biệt hoa thường
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

        # ===== KIỂM TRA BAN =====
        if user.get('status') == 'banned':
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

        # Log
        log = users[found_user].get('activity_log', [])
        log.insert(0, {
            'action': 'login',
            'detail': f'Đăng nhập lần {users[found_user]["login_count"]}',
            'time': now
        })
        users[found_user]['activity_log'] = log[:50]

        # Reset cờ warnings_shown mỗi lần login
        users[found_user]['warnings_shown'] = False
        save_users(users)

        # Set session
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

    # Nếu bị ban giữa chừng
    if user.get('status') == 'banned':
        session.clear()
        return jsonify({
            'success': False,
            'banned': True,
            'error': 'Tài khoản đã bị ban!',
            'redirect': f'/banned?user={session.get("username", "")}'
        }), 403

    return jsonify({
        'success': True,
        'logged_in': True,
        'username': session['username'],
        'role': user.get('role', 'user'),
        'login_time': session.get('login_time'),
        'login_count': user.get('login_count', 0),
        'created_at': user.get('created_at'),
        'status': user.get('status', 'active'),
        'warnings': user.get('warnings', []),
        'history_count': len(user.get('history', []))
    })


# ============================================================
# ROUTES BAN & WARNING
# ============================================================
@app.route('/banned')
def banned_page():
    """Trang bị ban — kiểu Roblox"""
    username = request.args.get('user', '').strip()
    users = load_users()

    # Tìm user không phân biệt hoa thường
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

    # Tạo Ban ID
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
    """Trang cảnh báo — kiểu Roblox"""
    if 'username' not in session:
        return redirect(url_for('login_page'))

    users = load_users()
    user = users.get(session['username'])

    if not user:
        session.clear()
        return redirect(url_for('login_page'))

    # Nếu bị ban → chuyển trang ban
    if user.get('status') == 'banned':
        return redirect(url_for('banned_page', user=session['username']))

    warnings = user.get('warnings', [])

    # Chỉ hiển thị nếu CHƯA xem
    if not session.get('warnings_shown') and warnings:
        return render_template(
            'warned.html',
            username=session['username'],
            warnings=warnings
        )

    return redirect(url_for('index'))


@app.route('/api/acknowledge-warnings', methods=['POST'])
def acknowledge_warnings():
    """Đánh dấu đã đọc cảnh báo"""
    if 'username' in session:
        session['warnings_shown'] = True
        # Lưu vào user data
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

    # Kiểm tra ban
    if user.get('status') == 'banned':
        uname = session.get('username', '')
        session.clear()
        return redirect(url_for('banned_page', user=uname))

    # Kiểm tra warning → hiển thị trang cảnh báo 1 lần
    warnings = user.get('warnings', [])
    if warnings and not session.get('warnings_shown'):
        return redirect(url_for('warned_page'))

    return render_template(
        'index.html',
        methods=METHODS,
        username=session.get('username'),
        role=user.get('role', 'user')
    )


@app.route('/api/process', methods=['POST'])
@login_required
def api_process():
    try:
        # Kiểm tra ban
        users = load_users()
        user = users.get(session['username'], {})
        if user.get('status') == 'banned':
            session.clear()
            return jsonify({
                'success': False,
                'error': 'Tài khoản đã bị ban!',
                'banned': True,
                'redirect': f'/banned?user={session.get("username", "")}'
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

        # Lưu lịch sử
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

        # Log hoạt động
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
    return render_template('admin.html', username=session['username'])


@app.route('/api/admin/users')
@admin_required
def admin_users():
    """Danh sách tất cả user"""
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
            'ban_info': data.get('ban_info')
        })

    # Sắp xếp: admin trước, sau đó banned/warned, cuối cùng theo tên
    result.sort(key=lambda u: (
        0 if u['role'] == 'admin' else 1,
        0 if u['status'] == 'banned' else 1,
        0 if u['status'] == 'warned' else 2,
        u['username'].lower()
    ))
    return jsonify({'success': True, 'users': result})


@app.route('/api/admin/ban', methods=['POST'])
@admin_required
def admin_ban():
    """Ban user"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Vi phạm điều khoản').strip() or 'Vi phạm điều khoản'

        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400
        if target == session['username']:
            return jsonify({'success': False, 'error': 'Không thể tự ban chính mình!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if users[target].get('role') == 'admin':
            return jsonify({'success': False, 'error': 'Không thể ban admin khác!'}), 403

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
@admin_required
def admin_unban():
    """Unban user"""
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
@admin_required
def admin_warn():
    """Cảnh báo user"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()
        reason = data.get('reason', 'Cảnh báo từ admin').strip() or 'Cảnh báo từ admin'

        if target == session['username']:
            return jsonify({'success': False, 'error': 'Không thể tự cảnh báo mình!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

        warnings = users[target].get('warnings', [])
        warnings.append({
            'reason': reason,
            'time': datetime.now().isoformat(),
            'by': session['username']
        })
        users[target]['warnings'] = warnings

        if users[target].get('status') == 'active':
            users[target]['status'] = 'warned'

        # Reset cờ warnings_shown để user thấy lại cảnh báo khi vào
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
@admin_required
def admin_reset_warnings():
    """Xóa hết cảnh báo"""
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
    """Chi tiết 1 user"""
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
            'suspicious_score': user.get('suspicious_score', 0)
        }
    })


@app.route('/api/admin/user/<username>/warnings')
@admin_required
def admin_user_warnings(username):
    """Xem warnings của user"""
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

    return jsonify({
        'success': True,
        'username': username,
        'warnings': user.get('warnings', []),
        'status': user.get('status', 'active')
    })


@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    """Thống kê tổng quan"""
    users = load_users()
    total = len(users)
    active = sum(1 for u in users.values() if u.get('status') == 'active')
    warned = sum(1 for u in users.values() if u.get('status') == 'warned')
    banned = sum(1 for u in users.values() if u.get('status') == 'banned')
    admins = sum(1 for u in users.values() if u.get('role') == 'admin')
    suspicious = sum(
        1 for u in users.values()
        if u.get('suspicious_score', 0) >= WARN_THRESHOLD
    )

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
@admin_required
def admin_delete():
    """Xóa user vĩnh viễn"""
    try:
        data = request.get_json()
        target = data.get('username', '').strip()

        if target == session['username']:
            return jsonify({'success': False, 'error': 'Không thể tự xóa chính mình!'}), 400

        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if users[target].get('role') == 'admin':
            return jsonify({'success': False, 'error': 'Không thể xóa admin!'}), 403

        del users[target]
        save_users(users)

        return jsonify({'success': True, 'message': f'🗑️ Đã xóa {target}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/preview-ban/<username>')
@admin_required
def admin_preview_ban(username):
    """Xem trước trang ban của user (chỉ admin)"""
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

    return jsonify({
        'success': True,
        'preview_url': f'/banned?user={username}',
        'is_banned': user.get('status') == 'banned'
    })


@app.route('/api/admin/preview-warn/<username>')
@admin_required
def admin_preview_warn(username):
    """Xem trước trang cảnh báo"""
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404

    return jsonify({
        'success': True,
        'warnings': user.get('warnings', []),
        'has_warnings': len(user.get('warnings', [])) > 0
    })


# ============================================================
# HEALTH CHECK
# ============================================================
@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'total_methods': len(METHODS),
        'total_users': len(load_users())
    })


# ============================================================
# KHỞI ĐỘNG
# ============================================================
init_default_user()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
