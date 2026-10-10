from flask import Flask, render_template, request, jsonify
from crypto_utils import process, METHODS, ONE_WAY_ONLY
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me')


@app.route('/')
def index():
    return render_template('index.html', methods=METHODS)


@app.route('/api/process', methods=['POST'])
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

        result = process(text, method, action, key)
        return jsonify({
            'success': True,
            'result': result,
            'method': method,
            'action': action,
            'one_way': method in ONE_WAY_ONLY
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'total_methods': len(METHODS)})


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
