from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from crypto_utils import process, METHODS, ONE_WAY_ONLY
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import unicodedata
import os
import json
import hashlib
import secrets

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-production')
app.permanent_session_lifetime = timedelta(days=7)

USERS_FILE = 'users.json'

# 👑 ADMIN MẶC ĐỊNH = "Hùng"
SUPER_ADMIN_USERNAME = os.getenv('ADMIN_USER', 'Hùng')
SUPER_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
SUPER_ADMIN_DISPLAY = 'Hùng'  # Tên hiển thị đẹp

SUSPICIOUS_THRESHOLD = 50
WARN_THRESHOLD = 30
MAX_WARN_BEFORE_BAN_OPTION = 3
PENDING_DELETE_DAYS = 7


# ============================================================
# XỬ LÝ USERNAME (HỖ TRỢ DẤU TIẾNG VIỆT)
# ============================================================
def normalize_username(username):
    """Chuẩn hóa username: NFC form, strip"""
    if not username:
        return ''
    return unicodedata.normalize('NFC', username.strip())


def remove_accents(s):
    """Bỏ dấu tiếng Việt: 'Hùng' → 'Hung'"""
    if not s:
        return ''
    nfd = unicodedata.normalize('NFD', s)
    return ''.join(c for c in nfd if unicodedata.category(c) != 'Mn')


def usernames_match(a, b):
    """So sánh username không phân biệt hoa thường + dấu"""
    if not a or not b:
        return False
    a_norm = normalize_username(a)
    b_norm = normalize_username(b)
    
    # So sánh chính xác (có dấu, không phân biệt hoa thường)
    if a_norm.lower() == b_norm.lower():
        return True
    
    # Fallback: so sánh không dấu
    return remove_accents(a_norm).lower() == remove_accents(b_norm).lower()


def is_super_admin(username):
    """Check xem có phải super admin không (hỗ trợ không dấu)"""
    return usernames_match(username, SUPER_ADMIN_USERNAME)


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


# ============================================================
# KHỞI TẠO SUPER ADMIN — TỰ ĐỘNG ĐỔI TÊN THÀNH "HÙNG"
# ============================================================
def init_super_admin():
    users = load_users()
    now = datetime.now().isoformat()
    
    # Tên admin chuẩn (đã normalize NFC)
    admin_name = normalize_username(SUPER_ADMIN_USERNAME)
    
    # Tìm user admin cũ (không phân biệt dấu)
    existing_admin = None
    for u in users.keys():
        if usernames_match(u, admin_name):
            existing_admin = u
            break
    
    # ===== CHƯA CÓ ADMIN → TẠO MỚI =====
    if existing_admin is None:
        users[admin_name] = {
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
            'activity_log': [{
                'action': 'system',
                'detail': 'Super Admin tạo tự động',
                'time': now
            }],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': True
        }
        save_users(users)
        print(f"👑 Đã tạo SUPER ADMIN: {admin_name} (display: {SUPER_ADMIN_DISPLAY})")
        return
    
    # ===== ĐÃ CÓ → NÂNG CẤP & ĐỔI TÊN =====
    changed = False
    user = users[existing_admin]
    
    # 1. Đổi tên nếu khác (VD: admin → Hùng)
    if existing_admin != admin_name:
        print(f"📝 Đổi tên admin: '{existing_admin}' → '{admin_name}'")
        users[admin_name] = user
        del users[existing_admin]
        existing_admin = admin_name
        changed = True
    
    # 2. Đảm bảo role = super_admin
    if user.get('role') != 'super_admin':
        user['role'] = 'super_admin'
        changed = True
    
    # 3. Đảm bảo display_name = "Hùng"
    if user.get('display_name') != SUPER_ADMIN_DISPLAY:
        user['display_name'] = SUPER_ADMIN_DISPLAY
        changed = True
    
    # 4. Gỡ ban / xóa nếu có
    if user.get('status') != 'active':
        user['status'] = 'active'
        user['ban_info'] = None
        user['delete_info'] = None
        changed = True
    
    # 5. Đồng bộ mật khẩu từ env
    if not verify_password(SUPER_ADMIN_PASSWORD, user.get('password', '')):
        user['password'] = hash_password(SUPER_ADMIN_PASSWORD)
        changed = True
        print(f"🔑 Đã đồng bộ mật khẩu admin từ ENV")
    
    # 6. Xóa warnings
    if user.get('warnings'):
        user['warnings'] = []
        user['warnings_shown'] = True
        changed = True
    
    # 7. Bảo vệ
    if not user.get('protected'):
        user['protected'] = True
        changed = True
    
    # 8. Bổ sung field thiếu
    defaults = {
        'created_at': now,
        'last_login': None,
        'login_count': 0,
        'history': [],
        'warnings': [],
        'ban_info': None,
        'delete_info': None,
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
        print(f"👑 Đã cập nhật SUPER ADMIN: {admin_name}")
    else:
        print(f"✓ Super Admin {admin_name} đã sẵn sàng")


# ============================================================
# AUTO UNBAN / AUTO DELETE
# ============================================================
def auto_unban_expired():
    users = load_users()
    changed = False
    now = datetime.now()
    
    for username, user in users.items():
        if user.get('status') != 'banned':
            continue
        ban_info = user.get('ban_info', {}) or {}
        if not ban_info.get('is_temp_ban'):
            continue
        ban_until = ban_info.get('ban_until')
        if not ban_until:
            continue
        try:
            ban_until_dt = datetime.fromisoformat(ban_until)
            if now >= ban_until_dt:
                user['status'] = 'warned' if user.get('warnings') else 'active'
                user['ban_info'] = None
                user['warnings_shown'] = False
                changed = True
                print(f"🔓 Auto-unban: {username}")
        except Exception as e:
            print(f"⚠️ Lỗi auto-unban {username}: {e}")
    
    if changed:
        save_users(users)


def auto_delete_expired():
    users = load_users()
    changed = False
    now = datetime.now()
    to_delete = []
    
    for username, user in users.items():
        if user.get('status') != 'pending_delete':
            continue
        delete_info = user.get('delete_info', {}) or {}
        expires_at = delete_info.get('expires_at')
        if not expires_at:
            continue
        try:
            expires_at_dt = datetime.fromisoformat(expires_at)
            if now >= expires_at_dt:
                to_delete.append(username)
                changed = True
        except Exception as e:
            print(f"⚠️ Lỗi expires_at {username}: {e}")
    
    for username in to_delete:
        del users[username]
        print(f"🗑️ Auto-delete: {username}")
    
    if changed:
        save_users(users)


def check_and_auto_unban(username):
    users = load_users()
    if username not in users:
        return {}
    user = users[username]
    if user.get('status') != 'banned':
        return user
    ban_info = user.get('ban_info', {}) or {}
    if not ban_info.get('is_temp_ban'):
        return user
    ban_until = ban_info.get('ban_until')
    if not ban_until:
        return user
    try:
        ban_until_dt = datetime.fromisoformat(ban_until)
        if datetime.now() >= ban_until_dt:
            user['status'] = 'warned' if user.get('warnings') else 'active'
            user['ban_info'] = None
            user['warnings_shown'] = False
            users[username] = user
            save_users(users)
            print(f"🔓 Auto-unban khi check: {username}")
    except Exception as e:
        print(f"⚠️ Lỗi auto-unban {username}: {e}")
    return user


def log_activity(username, action, detail=''):
    users = load_users()
    if username not in users:
        return
    log = users[username].get('activity_log', [])
    log.insert(0, {'action': action, 'detail': detail, 'time': datetime.now().isoformat()})
    users[username]['activity_log'] = log[:50]
    try:
        five_min_ago = datetime.now() - timedelta(minutes=5)
        recent = [l for l in log if datetime.fromisoformat(l['time']) > five_min_ago]
        users[username]['suspicious_score'] = len(recent)
        if (len(recent) >= SUSPICIOUS_THRESHOLD
            and users[username].get('status') == 'active'
            and users[username].get('role') != 'super_admin'):
            warnings = users[username].get('warnings', [])
            warnings.append({
                'reason': f'Hoạt động bất thường: {len(recent)} thao tác/5 phút',
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
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Chuẩn hóa
        username = normalize_username(username)
        
        if len(username) < 3:
            return jsonify({'success': False, 'error': 'Tên đăng nhập phải có ít nhất 3 ký tự!'}), 400
        if len(username) > 30:
            return jsonify({'success': False, 'error': 'Tên đăng nhập tối đa 30 ký tự!'}), 400
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Mật khẩu phải có ít nhất 6 ký tự!'}), 400
        
        # Chặn đăng ký trùng tên super admin
        if usernames_match(username, SUPER_ADMIN_USERNAME):
            return jsonify({'success': False, 'error': 'Tên này đã được bảo vệ!'}), 400
        
        users = load_users()
        
        # Check trùng (không phân biệt dấu)
        for u in users.keys():
            if usernames_match(u, username):
                return jsonify({'success': False, 'error': 'Tên đăng nhập đã tồn tại!'}), 400
        
        now = datetime.now().isoformat()
        users[username] = {
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
            'activity_log': [{'action': 'register', 'detail': 'Đăng ký mới', 'time': now}],
            'suspicious_score': 0,
            'warnings_shown': True,
            'protected': False
        }
        save_users(users)
        
        session.permanent = True
        session['username'] = username
        session['login_time'] = now
        
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
        
        # ===== CHECK SUPER ADMIN TRƯỚC =====
        if usernames_match(username, SUPER_ADMIN_USERNAME):
            # Tìm admin (không phân biệt dấu)
            found_admin = None
            for u in users.keys():
                if usernames_match(u, SUPER_ADMIN_USERNAME):
                    found_admin = u
                    break
            
            if not found_admin:
                # Chưa có → tạo mới
                init_super_admin()
                users = load_users()
                for u in users.keys():
                    if usernames_match(u, SUPER_ADMIN_USERNAME):
                        found_admin = u
                        break
            
            if not found_admin:
                return jsonify({'success': False, 'error': 'Lỗi tạo admin!'}), 500
            
            # Verify password
            if password != SUPER_ADMIN_PASSWORD and not verify_password(password, users[found_admin]['password']):
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
            
            found_user = found_admin
        else:
            # ===== USER THƯỜNG =====
            found_user = None
            for u in users.keys():
                if usernames_match(u, username):
                    found_user = u
                    break
            
            if not found_user:
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
            if not verify_password(password, users[found_user]['password']):
                return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
        
        # Auto-unban
        user = check_and_auto_unban(found_user)
        
        # Ban check
        if user.get('status') == 'banned' and not is_super_admin(found_user):
            ban_info = user.get('ban_info', {}) or {}
            return jsonify({
                'success': False,
                'error': 'Tài khoản đã bị BAN!',
                'banned': True,
                'ban_info': ban_info,
                'ban_until': ban_info.get('ban_until'),
                'redirect': f'/banned?user={found_user}'
            }), 403
        
        # Pending delete check
        if user.get('status') == 'pending_delete':
            delete_info = user.get('delete_info', {}) or {}
            return jsonify({
                'success': False,
                'error': 'Tài khoản đã bị đánh dấu xóa!',
                'pending_delete': True,
                'delete_info': delete_info,
                'redirect': '/deleted'
            }), 403
        
        # Cập nhật login info
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
        
        save_users(users)
        
        session.permanent = remember
        session['username'] = found_user
        session['login_time'] = now
        
        warnings = users[found_user].get('warnings', [])
        
        return jsonify({
            'success': True,
            'message': f'Chào mừng trở lại, {users[found_user].get("display_name", found_user)}!',
            'username': found_user,
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
    user = check_and_auto_unban(session['username'])
    
    # Ban
    if user.get('status') == 'banned' and not is_super_admin(session['username']):
        ban_info = user.get('ban_info', {}) or {}
        uname = session.get('username', '')
        return jsonify({
            'success': False, 'banned': True,
            'error': 'Tài khoản đã bị ban!',
            'ban_info': ban_info,
            'ban_until': ban_info.get('ban_until'),
            'redirect': f'/banned?user={uname}'
        }), 403
    
    # Pending delete
    if user.get('status') == 'pending_delete':
        delete_info = user.get('delete_info', {}) or {}
        return jsonify({
            'success': False,
            'pending_delete': True,
            'error': 'Tài khoản đã bị đánh dấu xóa!',
            'delete_info': delete_info,
            'redirect': '/deleted'
        }), 403
    
    return jsonify({
        'success': True, 'logged_in': True,
        'username': session['username'],
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
    
    return render_template(
        'banned.html',
        username=user.get('display_name', found_user),
        reason=ban_info.get('reason', 'Vi phạm điều khoản'),
        banned_at=banned_at or '—',
        banned_by=ban_info.get('by', 'System'),
        ban_id=ban_id,
        ban_until_display=ban_until_display,
        ban_until_iso=ban_until_iso,
        is_temp_ban=is_temp_ban
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
    del users[username]
    save_users(users)
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
        warnings=warnings
    )


@app.route('/api/acknowledge-warnings', methods=['POST'])
def acknowledge_warnings():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Chưa đăng nhập!'}), 401
    users = load_users()
    if session['username'] in users:
        users[session['username']]['warnings_shown'] = True
        save_users(users)
    return jsonify({'success': True, 'message': 'Đã ghi nhận'})


# ============================================================
# ROUTES CHÍNH
# ============================================================
@app.route('/')
@login_required
def index():
    user = check_and_auto_unban(session['username'])
    
    if user.get('status') == 'banned' and not is_super_admin(session['username']):
        uname = session.get('username', '')
        session.clear()
        return redirect(url_for('banned_page', user=uname))
    
    if user.get('status') == 'pending_delete':
        return redirect(url_for('deleted_page'))
    
    return render_template(
        'index.html',
        methods=METHODS,
        username=user.get('display_name', session.get('username')),
        real_username=session.get('username'),
        role=user.get('role', 'user'),
        is_super_admin=is_super_admin(session['username'])
    )


@app.route('/api/process', methods=['POST'])
@login_required
def api_process():
    try:
        user = check_and_auto_unban(session['username'])
        
        # Ban
        if user.get('status') == 'banned' and not is_super_admin(session['username']):
            ban_info = user.get('ban_info', {}) or {}
            return jsonify({
                'success': False, 'error': 'Tài khoản đã bị BAN!',
                'banned': True, 'blocked': True,
                'ban_info': ban_info, 'username': session['username']
            }), 403
        
        # Pending delete
        if user.get('status') == 'pending_delete':
            return jsonify({
                'success': False, 'error': 'Tài khoản đã bị đánh dấu xóa!',
                'pending_delete': True, 'blocked': True,
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
        
        users = load_users()
        history = user.get('history', [])
        history.insert(0, {
            'method': method, 'action': action,
            'input_preview': text[:50], 'output_preview': result[:50],
            'time': datetime.now().isoformat()
        })
        users[session['username']]['history'] = history[:20]
        save_users(users)
        
        log_activity(session['username'], action, f'{method}: {text[:30]}')
        
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
        
        if not target:
            return jsonify({'success': False, 'error': 'Thiếu username!'}), 400
        if usernames_match(target, session['username']):
            return jsonify({'success': False, 'error': '🚫 KHÔNG THỂ TỰ BAN!'}), 400
        
        users = load_users()
        if target not in users:
            return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
        if is_super_admin(target):
            return jsonify({'success': False, 'error': '🚫 Không thể ban Super Admin!'}), 403
        
        ban_info = {
            'reason': reason,
            'time': datetime.now().isoformat(),
            'by': session['username']
        }
        if duration == '1day':
            ban_info['ban_until'] = (datetime.now() + timedelta(days=1)).isoformat()
            ban_info['is_temp_ban'] = True
        else:
            ban_info['is_temp_ban'] = False
        
        users[target]['status'] = 'banned'
        users[target]['ban_info'] = ban_info
        save_users(users)
        
        msg = f'🚫 Đã ban {target}' + (' (1 ngày)' if duration == '1day' else ' (vĩnh viễn)')
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
        users[target]['status'] = 'warned' if users[target].get('warnings') else 'active'
        users[target]['ban_info'] = None
        users[target]['warnings_shown'] = False
        save_users(users)
        return jsonify({'success': True, 'message': f'✅ Đã gỡ ban {target}'})
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
        
        warnings = users[target].get('warnings', [])
        warnings.append({
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
                'reason': f'{reason} (Ban 1 ngày vì có {len(warnings)} cảnh báo)',
                'time': datetime.now().isoformat(),
                'by': session['username'],
                'ban_until': (datetime.now() + timedelta(days=1)).isoformat(),
                'is_temp_ban': True
            }
        
        save_users(users)
        
        if ban_1_day:
            return jsonify({
                'success': True,
                'message': f'⚠️🚫 Đã warn + ban 1 ngày {target}',
                'total_warnings': len(warnings),
                'banned': True
            })
        else:
            return jsonify({
                'success': True,
                'message': f'⚠️ Đã cảnh báo {target}',
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
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({'success': False, 'error': 'Không tìm thấy user!'}), 404
    return jsonify({
        'success': True,
        'user': {
            'username': username,
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
        
        users[target]['status'] = 'pending_delete'
        users[target]['delete_info'] = {
            'reason': reason,
            'time': datetime.now().isoformat(),
            'by': session['username'],
            'expires_at': (datetime.now() + timedelta(days=PENDING_DELETE_DAYS)).isoformat()
        }
        save_users(users)
        
        return jsonify({
            'success': True,
            'message': f'⚠️ Đã đánh dấu xóa {target}',
            'delete_info': users[target]['delete_info']
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
        users[target]['status'] = 'warned' if users[target].get('warnings') else 'active'
        users[target]['delete_info'] = None
        users[target]['warnings_shown'] = False
        save_users(users)
        return jsonify({'success': True, 'message': f'✅ Đã hủy xóa {target}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/admin/refresh-status', methods=['POST'])
@super_admin_required
def admin_refresh_status():
    """Reset toàn bộ trạng thái user về active"""
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
        old_status = user.get('status', 'active')
        old_warns = len(user.get('warnings', []))
        had_ban = user.get('ban_info') is not None
        had_delete = user.get('delete_info') is not None
        
        user['status'] = 'active'
        user['warnings'] = []
        user['ban_info'] = None
        user['delete_info'] = None
        user['suspicious_score'] = 0
        user['warnings_shown'] = True
        
        if not keep_history:
            user['history'] = []
        if not keep_log:
            user['activity_log'] = []
        
        log = user.get('activity_log', [])
        log.insert(0, {
            'action': 'refresh_status',
            'detail': f'Admin {session["username"]} đã làm mới trạng thái',
            'time': datetime.now().isoformat()
        })
        user['activity_log'] = log[:50]
        
        users[target] = user
        save_users(users)
        
        changes = []
        if old_status != 'active':
            changes.append(f'"{old_status}" → "active"')
        if old_warns > 0:
            changes.append(f'xóa {old_warns} warn')
        if had_ban:
            changes.append('gỡ ban')
        if had_delete:
            changes.append('hủy xóa')
        
        if not changes:
            changes.append('không có gì thay đổi')
        
        return jsonify({
            'success': True,
            'message': f'♻️ Đã làm mới {target}: ' + ', '.join(changes),
            'old_status': old_status
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
        'total_methods': len(METHODS),
        'total_users': len(users),
        'super_admin': SUPER_ADMIN_USERNAME,
        'super_admin_exists': any(usernames_match(u, SUPER_ADMIN_USERNAME) for u in users.keys())
    })


@app.route('/ping')
def ping():
    return 'pong', 200


# ============================================================
# KHỞI ĐỘNG
# ============================================================
init_super_admin()
auto_unban_expired()
auto_delete_expired()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
