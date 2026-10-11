"""
═══════════════════════════════════════════════════════════════════════════
  TWO_FACTOR.PY — Xác thực 2 lớp (TOTP)
═══════════════════════════════════════════════════════════════════════════
"""

import base64
import io
import os
import secrets
import struct
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

os.environ['TZ'] = 'Asia/Ho_Chi_Minh'
try:
    time.tzset()
except Exception:
    pass

try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

ISSUER_NAME = "Mã Hóa Tool"
TOTP_DIGITS = 6
TOTP_INTERVAL = 30
TOTP_WINDOW = 3
BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 8
DEBUG_2FA = True


def generate_secret() -> str:
    if HAS_PYOTP:
        return pyotp.random_base32()
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def get_totp_uri(secret: str, username: str, issuer: str = ISSUER_NAME) -> str:
    if HAS_PYOTP:
        totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL, issuer=issuer)
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}"
            f"&digits={TOTP_DIGITS}&period={TOTP_INTERVAL}")


def generate_qr_base64(uri: str) -> Optional[str]:
    if not HAS_QRCODE:
        return None
    try:
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M,
                           box_size=8, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_b64 = base64.b64encode(buffer.getvalue()).decode('ascii')
        return f"data:image/png;base64,{img_b64}"
    except Exception:
        return None


def verify_code(secret: str, code: str, window: int = TOTP_WINDOW) -> bool:
    if not secret or not code:
        return False
    code = str(code).strip().replace(' ', '').replace('-', '')
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False

    if HAS_PYOTP:
        try:
            totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
            return totp.verify(code, valid_window=window)
        except Exception:
            pass

    try:
        counter = int(time.time() // TOTP_INTERVAL)
        for offset in range(-window, window + 1):
            if _hotp(secret, counter + offset) == code:
                return True
        return False
    except Exception:
        return False


def _hotp(secret: str, counter: int) -> str:
    import hmac
    import hashlib
    secret_upper = secret.upper().replace(' ', '')
    padding = '=' * ((8 - len(secret_upper) % 8) % 8)
    key = base64.b32decode(secret_upper + padding)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack('>I', digest[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list:
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(BACKUP_CODE_LENGTH // 2).upper()
        codes.append(f"{raw[:4]}-{raw[4:8]}")
    return codes


def hash_backup_code(code: str) -> str:
    import hashlib
    return hashlib.sha256(code.upper().replace('-', '').replace(' ', '').encode()).hexdigest()


def verify_backup_code(code: str, hashed_codes: list) -> Optional[str]:
    h = hash_backup_code(code)
    return h if h in hashed_codes else None


def get_remaining_seconds() -> int:
    return TOTP_INTERVAL - int(time.time() % TOTP_INTERVAL)


def get_current_code(secret: str) -> str:
    if HAS_PYOTP:
        try:
            return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL).now()
        except Exception:
            return ""
    return _hotp(secret, int(time.time() // TOTP_INTERVAL))
