"""
═══════════════════════════════════════════════════════════════════════════
  TWO_FACTOR.PY — Xác thực 2 lớp (TOTP) — FIXED
  - Hỗ trợ timezone VN (UTC+7)
  - Window rộng (chấp nhận lệch ±90 giây)
  - Debug mode để kiểm tra
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

# ═══════════════════════════════════════════════════════════════════════════
#  SET TIMEZONE VN
# ═══════════════════════════════════════════════════════════════════════════
os.environ['TZ'] = 'Asia/Ho_Chi_Minh'
try:
    time.tzset()
except Exception:
    pass  # Windows không có tzset

# ═══════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════════════════
try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False
    print("⚠️ Chưa cài pyotp")

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False
    print("⚠️ Chưa cài qrcode[pil]")


# ═══════════════════════════════════════════════════════════════════════════
#  CẤU HÌNH
# ═══════════════════════════════════════════════════════════════════════════
ISSUER_NAME = "Mã Hóa Tool"
TOTP_DIGITS = 6
TOTP_INTERVAL = 30
TOTP_WINDOW = 3              # ⭐ FIX: Cho phép lệch ±90 giây
BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 8
DEBUG_2FA = True             # ⭐ Bật để xem log trên Render


# ═══════════════════════════════════════════════════════════════════════════
#  SINH SECRET
# ═══════════════════════════════════════════════════════════════════════════
def generate_secret() -> str:
    if HAS_PYOTP:
        secret = pyotp.random_base32()
    else:
        secret = base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')
    if DEBUG_2FA:
        print(f"[2FA] Sinh secret: {secret}")
    return secret


# ═══════════════════════════════════════════════════════════════════════════
#  SINH URI CHO QR CODE
# ═══════════════════════════════════════════════════════════════════════════
def get_totp_uri(secret: str, username: str, issuer: str = ISSUER_NAME) -> str:
    if HAS_PYOTP:
        totp = pyotp.TOTP(
            secret,
            digits=TOTP_DIGITS,
            interval=TOTP_INTERVAL,
            issuer=issuer,
        )
        uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    else:
        from urllib.parse import quote
        uri = (
            f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}"
            f"&digits={TOTP_DIGITS}&period={TOTP_INTERVAL}"
        )
    if DEBUG_2FA:
        print(f"[2FA] URI: {uri}")
    return uri


# ═══════════════════════════════════════════════════════════════════════════
#  SINH QR CODE (Base64)
# ═══════════════════════════════════════════════════════════════════════════
def generate_qr_base64(uri: str) -> Optional[str]:
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
        print(f"[2FA] Lỗi QR: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  VERIFY MÃ OTP — FIX CHÍNH Ở ĐÂY
# ═══════════════════════════════════════════════════════════════════════════
def verify_code(secret: str, code: str, window: int = TOTP_WINDOW) -> bool:
    """
    Kiểm tra mã OTP.
    - window=3 → chấp nhận mã trong ±90 giây (lệch giờ giữa server và phone)
    - Dùng thời gian UTC tuyệt đối → không bị lệch múi giờ
    """
    if not secret or not code:
        return False

    code = str(code).strip().replace(' ', '').replace('-', '')
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False

    # ⭐ Dùng time.time() — LUÔN là UTC timestamp (không phụ thuộc timezone)
    current_ts = time.time()
    current_counter = int(current_ts // TOTP_INTERVAL)

    if DEBUG_2FA:
        vn_tz = timezone(timedelta(hours=7))
        vn_time = datetime.now(vn_tz).strftime('%H:%M:%S')
        utc_time = datetime.now(timezone.utc).strftime('%H:%M:%S')
        print(f"[2FA] Verify: secret={secret[:8]}... code={code}")
        print(f"[2FA] UTC: {utc_time} | VN: {vn_time} | counter={current_counter}")

    # Thử verify với pyotp
    if HAS_PYOTP:
        try:
            totp = pyotp.TOTP(
                secret,
                digits=TOTP_DIGITS,
                interval=TOTP_INTERVAL,
            )
            # ⭐ pyotp.verify() tự dùng time.time() → UTC → không bị lệch
            result = totp.verify(code, valid_window=window)

            if DEBUG_2FA:
                now_code = totp.now()
                print(f"[2FA] Mã đúng phải là: {now_code} (window=±{window*30}s)")

            return result
        except Exception as e:
            print(f"[2FA] Lỗi verify pyotp: {e}")
            # Fallback xuống manual

    # Fallback: tự verify bằng HOTP
    try:
        for offset in range(-window, window + 1):
            expected = _hotp(secret, current_counter + offset)
            if expected == code:
                if DEBUG_2FA:
                    print(f"[2FA] ✅ Match at offset {offset}")
                return True
        if DEBUG_2FA:
            print(f"[2FA] ❌ Không match. Mã đúng: {_hotp(secret, current_counter)}")
        return False
    except Exception as e:
        print(f"[2FA] Lỗi manual verify: {e}")
        return False


def _hotp(secret: str, counter: int) -> str:
    """TOTP dùng HMAC-SHA1 chuẩn RFC 6238."""
    import hmac
    import hashlib

    # Pad secret cho đủ bội số của 8
    secret_upper = secret.upper().replace(' ', '')
    padding = '=' * ((8 - len(secret_upper) % 8) % 8)
    key = base64.b32decode(secret_upper + padding)

    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack('>I', digest[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


# ═══════════════════════════════════════════════════════════════════════════
#  BACKUP CODES
# ═══════════════════════════════════════════════════════════════════════════
def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list:
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(BACKUP_CODE_LENGTH // 2).upper()
        formatted = f"{raw[:4]}-{raw[4:8]}"
        codes.append(formatted)
    return codes


def hash_backup_code(code: str) -> str:
    import hashlib
    return hashlib.sha256(code.upper().replace('-', '').replace(' ', '').encode()).hexdigest()


def verify_backup_code(code: str, hashed_codes: list) -> Optional[str]:
    h = hash_backup_code(code)
    if h in hashed_codes:
        return h
    return None


# ═══════════════════════════════════════════════════════════════════════════
#  TIỆN ÍCH
# ═══════════════════════════════════════════════════════════════════════════
def get_remaining_seconds() -> int:
    return TOTP_INTERVAL - int(time.time() % TOTP_INTERVAL)


def get_current_code(secret: str) -> str:
    """Lấy mã hiện tại (dùng cho debug)."""
    if HAS_PYOTP:
        try:
            return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL).now()
        except Exception:
            return ""
    counter = int(time.time() // TOTP_INTERVAL)
    return _hotp(secret, counter)


def debug_info(secret: str = None) -> dict:
    """Trả về thông tin debug."""
    vn_tz = timezone(timedelta(hours=7))
    info = {
        'utc_time': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'vn_time': datetime.now(vn_tz).strftime('%Y-%m-%d %H:%M:%S'),
        'timestamp': time.time(),
        'counter': int(time.time() // TOTP_INTERVAL),
        'remaining_seconds': get_remaining_seconds(),
        'window': TOTP_WINDOW,
    }
    if secret:
        info['current_code'] = get_current_code(secret)
    return info
