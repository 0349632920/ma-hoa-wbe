from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from crypto_utils import process, METHODS, ONE_WAY_ONLY
from dotenv import load_dotenv
from functools import wraps
import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-production')
app.permanent_session_lifetime = timedelta(days=7)

USERS_FILE = 'users.json'


# ============================================================
# QUẢN LÝ USER
# ============================================================
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}


def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def hash_password(password, salt=None):
    """Băm mật khẩu với salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return f"{salt}${hashed}"


def verify_password(password, stored):
    """Kiểm tra mật khẩu"""
    try:
        salt, _ = stored.split('$', 1)
        return hash_password(password, salt) == stored
    except:
        return False


def login_required(f):
    """Decorator yêu cầu đăng nhập"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Chưa đăng nhập!', 'need_login': True}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# ROUTES AUTH
# ============================================================
@app.route('/login')
def login_page():
    if 'username' in session:
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

        # Tạo user mới
        users[username] = {
            'password': hash_password(password),
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'login_count': 0,
            'history': []
        }
        save_users(users)

        # Auto login
        session.permanent = True
        session['username'] = username
        session['login_time'] = datetime.now().isoformat()

        return jsonify({
            'success': True,
            'message': f'Chào mừng {username}!',
            'username': username
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

        # Tìm user (không phân biệt hoa thường)
        found_user = None
        for u in users.keys():
            if u.lower() == username.lower():
                found_user = u
                break

        if not found_user:
            return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

        if not verify_password(password, users[found_user]['password']):
            return jsonify({'success': False, 'error': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401

        # Cập nhật thông tin
        users[found_user]['last_login'] = datetime.now().isoformat()
        users[found_user]['login_count'] = users[found_user].get('login_count', 0) + 1
        save_users(users)

        # Set session
        session.permanent = remember
        session['username'] = found_user
        session['login_time'] = datetime.now().isoformat()

        return jsonify({
            'success': True,
            'message': f'Chào mừng trở lại, {found_user}!',
            'username': found_user
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Đã đăng xuất'})


@app.route('/api/me')
def me():
    if 'username' not in session:
        return jsonify({'success': False, 'logged_in': False}), 401

    users = load_users()
    user = users.get(session['username'], {})

    return jsonify({
        'success': True,
        'logged_in': True,
        'username': session['username'],
        'login_time': session.get('login_time'),
        'login_count': user.get('login_count', 0),
        'created_at': user.get('created_at'),
        'history_count': len(user.get('history', []))
    })


# ============================================================
# ROUTES CHÍNH
# ============================================================
@app.route('/')
@login_required
def index():
    return render_template('index.html', methods=METHODS, username=session.get('username'))


@app.route('/api/process', methods=['POST'])
@login_required
def api_process():
    try:
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

        # Lưu lịch sử (tối đa 20)
        users = load_users()
        if session['username'] in users:
            history = users[session['username']].get('history', [])
            history.insert(0, {
                'method': method,
                'action': action,
                'input_preview': text[:50],
                'output_preview': result[:50],
                'time': datetime.now().isoformat()
            })
            users[session['username']]['history'] = history[:20]
            save_users(users)

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


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'total_methods': len(METHODS)})


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
