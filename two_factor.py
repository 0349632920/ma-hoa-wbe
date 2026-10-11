"""
═══════════════════════════════════════════════════════════════════════════
  TWO_FACTOR.PY — Xác thực 2 lớp (TOTP) cho Admin
═══════════════════════════════════════════════════════════════════════════
"""

import base64
import io
import secrets
import time
from datetime import datetime
from typing import Optional

try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False
    print("⚠️ Chưa cài pyotp — chạy: pip install pyotp")

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False
    print("⚠️ Chưa cài qrcode — chạy: pip install qrcode[pil]")


# ═══════════════════════════════════════════════════════════════════════════
#  CẤU HÌNH
# ═══════════════════════════════════════════════════════════════════════════

ISSUER_NAME = "Mã Hóa Tool"       # Tên hiển thị trong app Authenticator
TOTP_DIGITS = 6                    # Số chữ số của mã OTP
TOTP_INTERVAL = 30                 # Chu kỳ đổi mã (giây)
TOTP_WINDOW = 1                    # Cho phép lệch 1 chu kỳ (30s trước/sau)
BACKUP_CODE_COUNT = 10             # Số mã dự phòng
BACKUP_CODE_LENGTH = 8             # Độ dài mã dự phòng


# ═══════════════════════════════════════════════════════════════════════════
#  1. SINH SECRET KEY
# ═══════════════════════════════════════════════════════════════════════════

def generate_secret() -> str:
    """Sinh secret key base32 (32 ký tự) để user scan vào app."""
    if HAS_PYOTP:
        return pyotp.random_base32()
    # Fallback nếu thiếu pyotp
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


# ═══════════════════════════════════════════════════════════════════════════
#  2. SINH URI ĐỂ SCAN QR CODE
# ═══════════════════════════════════════════════════════════════════════════

def get_totp_uri(secret: str, username: str, issuer: str = ISSUER_NAME) -> str:
    """
    Sinh URI otpauth:// để app Authenticator scan.
    Ví dụ: otpauth://totp/Mã Hóa Tool:admin?secret=ABC...&issuer=Mã Hóa Tool
    """
    if HAS_PYOTP:
        totp = pyotp.TOTP(
            secret,
            digits=TOTP_DIGITS,
            interval=TOTP_INTERVAL,
            issuer=issuer,
        )
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    # Fallback
    from urllib.parse import quote
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret}&issuer={quote(issuer)}"
        f"&digits={TOTP_DIGITS}&period={TOTP_INTERVAL}"
    )


# ═══════════════════════════════════════════════════════════════════════════
#  3. SINH QR CODE (dạng base64 image)
# ═══════════════════════════════════════════════════════════════════════════

def generate_qr_base64(uri: str) -> Optional[str]:
    """
    Sinh QR code từ URI, trả về chuỗi base64 dạng data URI.
    Frontend dùng: <img src="data:image/png;base64,...">
    """
    if not HAS_QRCODE:
        return None
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_bytes = buffer.getvalue()
        img_b64 = base64.b64encode(img_bytes).decode('ascii')
        return f"data:image/png;base64,{img_b64}"
    except Exception as e:
        print(f"⚠️ Lỗi sinh QR: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  4. VERIFY MÃ OTP
# ═══════════════════════════════════════════════════════════════════════════

def verify_code(secret: str, code: str, window: int = TOTP_WINDOW) -> bool:
    """
    Kiểm tra mã OTP user nhập có đúng không.
    window=1 → cho phép lệch 30s trước/sau.
    """
    if not secret or not code:
        return False
    code = str(code).strip().replace(' ', '')
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False

    if HAS_PYOTP:
        try:
            totp = pyotp.TOTP(
                secret,
                digits=TOTP_DIGITS,
                interval=TOTP_INTERVAL,
            )
            return totp.verify(code, valid_window=window)
        except Exception:
            return False

    # Fallback nếu thiếu pyotp: verify thủ công
    try:
        counter = int(time.time() // TOTP_INTERVAL)
        for offset in range(-window, window + 1):
            expected = _hotp(secret, counter + offset)
            if expected == code:
                return True
        return False
    except Exception:
        return False


def _hotp(secret: str, counter: int) -> str:
    """TOTP dùng HMAC-SHA1 chuẩn RFC 6238."""
    import hmac
    import hashlib
    import struct

    key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack('>I', digest[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


# ═══════════════════════════════════════════════════════════════════════════
#  5. SINH MÃ DỰ PHÒNG (BACKUP CODES)
# ═══════════════════════════════════════════════════════════════════════════

def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list:
    """
    Sinh danh sách mã dự phòng.
    User dùng khi mất điện thoại, mỗi mã dùng được 1 lần.
    """
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(BACKUP_CODE_LENGTH // 2).upper()
        # Format: XXXX-XXXX
        formatted = f"{raw[:4]}-{raw[4:8]}"
        codes.append(formatted)
    return codes


def hash_backup_code(code: str) -> str:
    """Hash backup code để lưu DB (không lưu plaintext)."""
    import hashlib
    return hashlib.sha256(code.upper().replace('-', '').encode()).hexdigest()


def verify_backup_code(code: str, hashed_codes: list) -> Optional[str]:
    """
    Kiểm tra backup code có hợp lệ không.
    Trả về hash nếu hợp lệ (để remove khỏi DB), None nếu không.
    """
    h = hash_backup_code(code)
    if h in hashed_codes:
        return h
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  6. TIỆN ÍCH
# ═══════════════════════════════════════════════════════════════════════════

def get_remaining_seconds() -> int:
    """Số giây còn lại của chu kỳ TOTP hiện tại."""
    return TOTP_INTERVAL - int(time.time() % TOTP_INTERVAL)


def get_current_code(secret: str) -> str:
    """Lấy mã OTP hiện tại (dùng debug, KHÔNG dùng trong production)."""
    if HAS_PYOTP:
        try:
            return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL).now()
        except Exception:
            return ""
    counter = int(time.time() // TOTP_INTERVAL)
    return _hotp(secret, counter)
