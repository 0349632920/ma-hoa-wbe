from flask import Flask, render_template, request, jsonify
from crypto_utils import (
    base64_encode, base64_decode,
    caesar_cipher, rot13,
    binary_encode, binary_decode,
    hex_encode, hex_decode,
    aes_encrypt, aes_decrypt
)
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key-change-me')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/process', methods=['POST'])
def process():
    """API xử lý mã hóa / giải mã"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        method = data.get('method', 'base64')
        action = data.get('action', 'encrypt')
        key = data.get('key', '')

        if not text:
            return jsonify({'success': False, 'error': 'Văn bản trống!'}), 400

        result = ''

        # Base64
        if method == 'base64':
            result = base64_encode(text) if action == 'encrypt' else base64_decode(text)

        # Caesar
        elif method == 'caesar':
            shift = int(key) if key else 3
            result = caesar_cipher(text, shift if action == 'encrypt' else -shift)

        # ROT13
        elif method == 'rot13':
            result = rot13(text)

        # Binary
        elif method == 'binary':
            result = binary_encode(text) if action == 'encrypt' else binary_decode(text)

        # Hex
        elif method == 'hex':
            result = hex_encode(text) if action == 'encrypt' else hex_decode(text)

        # AES
        elif method == 'aes':
            if not key:
                return jsonify({'success': False, 'error': 'Cần mật khẩu cho AES!'}), 400
            if action == 'encrypt':
                result = aes_encrypt(text, key)
            else:
                result = aes_decrypt(text, key)
        else:
            return jsonify({'success': False, 'error': 'Phương pháp không hợp lệ!'}), 400

        return jsonify({'success': True, 'result': result})

    except Exception as e:
        return jsonify({'success': False, 'error': f'Lỗi: {str(e)}'}), 500


@app.route('/health')
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
