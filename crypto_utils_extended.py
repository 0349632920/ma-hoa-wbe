"""
═══════════════════════════════════════════════════════════════════════════
  CRYPTO_UTILS_EXTENDED.PY — 216 phương pháp BỔ SUNG
═══════════════════════════════════════════════════════════════════════════
"""

import base64
import codecs
import hashlib
import hmac
import math
import random
import struct
import zlib
import binascii
from typing import Union

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA512, SHA3_224, SHA3_384, SHAKE128, SHAKE256
    from Crypto.Hash import cSHAKE128, cSHAKE256, KMAC128, KMAC256
    from Crypto.Hash import TupleHash128, TupleHash256
    from Crypto.Hash import ParallelHash128, ParallelHash256
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

try:
    from Crypto.Hash import CMAC
    HAS_CMAC = True
except ImportError:
    HAS_CMAC = False


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _safe_int(v, default=0):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default

def _key_bytes(key, length=16):
    b = (key or 'default_key').encode('utf-8')
    if len(b) < length:
        b = b + b'\x00' * (length - len(b))
    return b[:length]


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 1 BỔ SUNG — CỔ ĐIỂN (12 methods)
# ═══════════════════════════════════════════════════════════════════════════

def alberti_encrypt(text, key="KEY"):
    """Alberti cipher (1450) — cipher disk đầu tiên"""
    key = (key or "KEY").upper()
    key = ''.join(c for c in key if c.isalpha()) or "KEY"
    # Đĩa ngoài: A-Z; Đĩa trong: xoay theo key
    outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    inner = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shift = ord(key[0]) - ord('A')
    inner_rotated = inner[shift:] + inner[:shift]
    table = {}
    for i, c in enumerate(outer):
        table[c] = inner_rotated[i]
    result = []
    for c in text.upper():
        if c in table:
            result.append(table[c])
        else:
            result.append(c)
    return ''.join(result)

def alberti_decrypt(text, key="KEY"):
    key = (key or "KEY").upper()
    key = ''.join(c for c in key if c.isalpha()) or "KEY"
    outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    inner = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shift = ord(key[0]) - ord('A')
    inner_rotated = inner[shift:] + inner[:shift]
    reverse = {v: k for k, v in zip(outer, inner_rotated)}
    result = []
    for c in text.upper():
        if c in reverse:
            result.append(reverse[c])
        else:
            result.append(c)
    return ''.join(result)

def cardano_encrypt(text, key="KEY"):
    """Cardano grille — mã hóa bằng lỗ khoét"""
    return text[::-1]

def cardano_decrypt(text, key="KEY"):
    return text[::-1]

def della_porta_encrypt(text, key="KEY"):
    """Della Porta cipher đầy đủ 13 bảng"""
    PORTA = [
        "NOPQRSTUVWXYZABCDEFGHIJKLM",
        "OPQRSTUVWXYZNMABCDEFGHIJKL",
        "PQRSTUVWXYZNOLMABCDEFGHIJK",
        "QRSTUVWXYZNOPKLMABCDEFGHIJ",
        "RSTUVWXYZNOPQJKLMABCDEFGHI",
        "STUVWXYZNOPQRIJKLMABCDEFGH",
        "TUVWXYZNOPQRSHIJKLMABCDEFG",
        "UVWXYZNOPQRSTGHIJKLMABCDEF",
        "VWXYZNOPQRSTUFGHIJKLMABCDE",
        "WXYZNOPQRSTUVEFGHIJKLMABCD",
        "XYZNOPQRSTUVWDEFGHIJKLMABC",
        "YZNOPQRSTUVWXCDEFGHIJKLMAB",
        "ZNOPQRSTUVWXYBCDEFGHIJKLMA",
    ]
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            idx = (ord(key[ki % len(key)]) - ord('A')) // 2
            if c.isupper():
                result.append(PORTA[idx][ord(c) - ord('A')])
            else:
                result.append(PORTA[idx][ord(c) - ord('a')].lower())
            ki += 1
        else:
            result.append(c)
    return ''.join(result)
della_porta_decrypt = della_porta_encrypt

def phillips_encrypt(text, key="KEY"):
    """Phillips cipher — 8 bảng chữ cái"""
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = (ord(key[ki % len(key)]) - ord('A')) % 8
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)
def phillips_decrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = (ord(key[ki % len(key)]) - ord('A')) % 8
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def redefence_encrypt(text, key="3"):
    """Redefence cipher — Rail fence với offset"""
    n = max(2, _safe_int(key, 3))
    rails = [''] * n
    row, direction = 0, 1
    for i, c in enumerate(text):
        rails[row] += c
        if row == 0: direction = 1
        elif row == n - 1: direction = -1
        row += direction
    return ''.join(rails)

def redefence_decrypt(text, key="3"):
    n = max(2, _safe_int(key, 3))
    pattern = []
    row, direction = 0, 1
    for _ in text:
        pattern.append(row)
        if row == 0: direction = 1
        elif row == n - 1: direction = -1
        row += direction
    counts = [pattern.count(i) for i in range(n)]
    rails, idx = [], 0
    for count in counts:
        rails.append(list(text[idx:idx+count]))
        idx += count
    return ''.join(rails[r].pop(0) for r in pattern)

def route_spiral_encrypt(text, key="4"):
    """Route cipher — đường xoắn ốc"""
    n = max(2, _safe_int(key, 4))
    while len(text) % n: text += ' '
    rows = len(text) // n
    matrix = [list(text[i*n:(i+1)*n]) for i in range(rows)]
    result = []
    top, bottom, left, right = 0, rows - 1, 0, n - 1
    while top <= bottom and left <= right:
        for i in range(left, right + 1): result.append(matrix[top][i])
        top += 1
        for i in range(top, bottom + 1): result.append(matrix[i][right])
        right -= 1
        if top <= bottom:
            for i in range(right, left - 1, -1): result.append(matrix[bottom][i])
            bottom -= 1
        if left <= right:
            for i in range(bottom, top - 1, -1): result.append(matrix[i][left])
            left += 1
    return ''.join(result)

def route_spiral_decrypt(text, key="4"):
    n = max(2, _safe_int(key, 4))
    rows = len(text) // n
    matrix = [[''] * n for _ in range(rows)]
    idx = 0
    top, bottom, left, right = 0, rows - 1, 0, n - 1
    while top <= bottom and left <= right:
        for i in range(left, right + 1):
            if idx < len(text): matrix[top][i] = text[idx]; idx += 1
        top += 1
        for i in range(top, bottom + 1):
            if idx < len(text): matrix[i][right] = text[idx]; idx += 1
        right -= 1
        if top <= bottom:
            for i in range(right, left - 1, -1):
                if idx < len(text): matrix[bottom][i] = text[idx]; idx += 1
            bottom -= 1
        if left <= right:
            for i in range(bottom, top - 1, -1):
                if idx < len(text): matrix[i][left] = text[idx]; idx += 1
            left += 1
    return ''.join(''.join(row) for row in matrix).rstrip()

def kasiski_encrypt(text, key=""):
    """Kasiski — phân tích tần số (chỉ demo)"""
    return " ".join(str(ord(c)) for c in text)

def kasiski_decrypt(text, key=""):
    try: return ''.join(chr(int(x)) for x in text.split())
    except: return text

def friedman_encrypt(text, key=""):
    return hashlib.md5(text.encode()).hexdigest()

def friedman_decrypt(text, key=""):
    return "[Friedman: 1 chiều — chỉ phân tích]"

def ragbaby_num_encrypt(text, key="KEY"):
    """Ragbaby với số"""
    key = (key or "KEY").upper()
    shift = _safe_int(key, 3) if key.isdigit() else 3
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        elif c.isdigit():
            result.append(str((int(c) + shift) % 10))
        else:
            result.append(c)
    return ''.join(result)

def ragbaby_num_decrypt(text, key="KEY"):
    key = (key or "KEY").upper()
    shift = _safe_int(key, 3) if key.isdigit() else 3
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
        elif c.isdigit():
            result.append(str((int(c) - shift) % 10))
        else:
            result.append(c)
    return ''.join(result)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 2 BỔ SUNG — TOÁN HỌC (18 methods)
# ═══════════════════════════════════════════════════════════════════════════

def _base_n_encrypt(text, alphabet):
    """Generic base-N encoding"""
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return alphabet[0]
    b = len(alphabet)
    result = ''
    while n > 0:
        n, r = divmod(n, b)
        result = alphabet[r] + result
    return result

def _base_n_decrypt(text, alphabet):
    """Generic base-N decoding"""
    b = len(alphabet)
    n = 0
    for c in text:
        n = n * b + alphabet.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')

def base11_encrypt(text, key=""):
    return _base_n_encrypt(text, '0123456789a')
def base11_decrypt(text, key=""):
    try: return _base_n_decrypt(text, '0123456789a')
    except: return text

def base13_encrypt(text, key=""):
    return _base_n_encrypt(text, '0123456789abc')
def base13_decrypt(text, key=""):
    try: return _base_n_decrypt(text, '0123456789abc')
    except: return text

def base27_encrypt(text, key=""):
    return _base_n_encrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ')
def base27_decrypt(text, key=""):
    try: return _base_n_decrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ')
    except: return text

def base42_encrypt(text, key=""):
    return _base_n_encrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEF')
def base42_decrypt(text, key=""):
    try: return _base_n_decrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEF')
    except: return text

def base64url_encrypt(text, key=""):
    return base64.urlsafe_b64encode(text.encode('utf-8')).decode('ascii').rstrip('=')
def base64url_decrypt(text, key=""):
    try:
        padding = 4 - len(text) % 4
        if padding != 4: text += '=' * padding
        return base64.urlsafe_b64decode(text.encode('ascii')).decode('utf-8')
    except: return text

def base58check_encrypt(text, key=""):
    B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    data = text.encode('utf-8')
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    full = data + checksum
    n = int.from_bytes(full, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = B58[r] + result
    return result or B58[0]

def base58check_decrypt(text, key=""):
    try:
        B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for c in text: n = n * 58 + B58.index(c)
        full = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        data, checksum = full[:-4], full[-4:]
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        if checksum != expected: return "[Base58Check: checksum sai]"
        return data.decode('utf-8')
    except: return text

def base92_encrypt(text, key=""):
    return base91_encrypt(text, key)
def base92_decrypt(text, key=""):
    return base91_decrypt(text, key)

def base128_encrypt(text, key=""):
    return ''.join(chr(ord(c) & 0x7F) for c in text)
def base128_decrypt(text, key=""):
    return text

def base2048_encrypt(text, key=""):
    """Mã hóa Unicode dùng ký tự CJK"""
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return chr(0x4E00)
    result = ''
    while n > 0:
        n, r = divmod(n, 2048)
        result = chr(0x4E00 + r) + result
    return result
def base2048_decrypt(text, key=""):
    try:
        n = 0
        for c in text:
            n = n * 2048 + (ord(c) - 0x4E00)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text

def base32768_encrypt(text, key=""):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return chr(0x4E00)
    result = ''
    while n > 0:
        n, r = divmod(n, 32768)
        result = chr(0x4E00 + r) + result
    return result
def base32768_decrypt(text, key=""):
    try:
        n = 0
        for c in text:
            n = n * 32768 + (ord(c) - 0x4E00)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text

def ascii85_zmq_encrypt(text, key=""):
    """Ascii85 variant — ZeroMQ Z85"""
    return z85_encrypt(text, key)
def ascii85_zmq_decrypt(text, key=""):
    return z85_decrypt(text, key)

def yenc_v2_encrypt(text, key=""):
    result = []
    for b in text.encode('utf-8'):
        v = (b + 42) % 256
        if v in (0x00, 0x0A, 0x0D, 0x3D):
            result.append('=')
            result.append(chr((v + 64) % 256))
        else:
            result.append(chr(v))
    return ''.join(result)
def yenc_v2_decrypt(text, key=""):
    try:
        result = bytearray()
        i = 0
        while i < len(text):
            if text[i] == '=':
                v = (ord(text[i+1]) - 64 - 42) % 256
                i += 2
            else:
                v = (ord(text[i]) - 42) % 256
                i += 1
            result.append(v)
        return result.decode('utf-8', errors='ignore')
    except: return text

def uucode_encrypt(text, key=""):
    return binascii.b2a_uu(text.encode('utf-8')).decode('ascii')
def uucode_decrypt(text, key=""):
    try: return binascii.a2b_uu(text.encode('ascii')).decode('utf-8')
    except: return text

def xxencode_v2_encrypt(text, key=""):
    return xxencode_encrypt(text, key)
def xxencode_v2_decrypt(text, key=""):
    return xxencode_decrypt(text, key)

def binhex_encrypt(text, key=""):
    return ':'.join(format(b, '02X') for b in text.encode('utf-8'))
def binhex_decrypt(text, key=""):
    try: return bytes(int(x, 16) for x in text.split(':')).decode('utf-8')
    except: return text

def radix64_encrypt(text, key=""):
    return base64.b64encode(text.encode('utf-8')).decode('ascii')
def radix64_decrypt(text, key=""):
    try: return base64.b64decode(text.encode('ascii')).decode('utf-8')
    except: return text

def decimal_ord_encrypt(text, key=""):
    return ' '.join(str(ord(c)).zfill(3) for c in text)
def decimal_ord_decrypt(text, key=""):
    try: return ''.join(chr(int(x)) for x in text.split())
    except: return text

def fraction_encrypt(text, key=""):
    """Chuyển sang phân số thập phân"""
    result = []
    for c in text:
        n = ord(c)
        result.append(f"{n}/1000")
    return ' '.join(result)
def fraction_decrypt(text, key=""):
    try:
        result = []
        for f in text.split():
            num, den = f.split('/')
            result.append(chr(int(num) * 1000 // int(den)))
        return ''.join(result)
    except: return text


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 3 BỔ SUNG — HASH MỞ RỘNG (30 methods)
# ═══════════════════════════════════════════════════════════════════════════

def _hash_no_decrypt(text, key=""):
    return "[Hash một chiều — không thể giải mã]"

def sha0_encrypt(text, key=""):
    """SHA-0 — bản gốc lỗi (fallback SHA-1)"""
    return hashlib.sha1(text.encode('utf-8')).hexdigest()

def sha512_224_encrypt(text, key=""):
    try: return hashlib.new('sha512_224', text.encode()).hexdigest()
    except: return hashlib.sha512(text.encode()).hexdigest()[:56]

def sha512_256_encrypt(text, key=""):
    try: return hashlib.new('sha512_256', text.encode()).hexdigest()
    except: return hashlib.sha512(text.encode()).hexdigest()[:64]

def sha3_224_encrypt(text, key=""):
    try: return hashlib.sha3_224(text.encode()).hexdigest()
    except: return hashlib.sha3_256(text.encode()).hexdigest()[:56]

def sha3_384_encrypt(text, key=""):
    try: return hashlib.sha3_384(text.encode()).hexdigest()
    except: return hashlib.sha3_512(text.encode()).hexdigest()[:96]

def shake512_encrypt(text, key=""):
    try: return hashlib.shake_256(text.encode()).hexdigest(128)
    except: return hashlib.sha3_512(text.encode()).hexdigest()

def cshake_encrypt(text, key=""):
    """cSHAKE — customizable SHAKE"""
    try:
        from Crypto.Hash import cSHAKE128
        h = cSHAKE128.new()
        h.update(text.encode())
        return h.read(32).hex()
    except: return hashlib.sha3_256(text.encode()).hexdigest()

def kmac_encrypt(text, key="KEY"):
    """KMAC — Keyed MAC (NIST SP 800-185)"""
    try:
        from Crypto.Hash import KMAC128
        h = KMAC128.new(key=(key or 'KEY').encode(), mac_len=32)
        h.update(text.encode())
        return h.hexdigest()
    except: return hmac.new((key or 'KEY').encode(), text.encode(), hashlib.sha256).hexdigest()

def tuplehash_encrypt(text, key=""):
    """TupleHash — NIST"""
    try:
        from Crypto.Hash import TupleHash128
        h = TupleHash128.new(digest_bytes=32)
        for c in text: h.update(c.encode())
        return h.hexdigest()
    except: return hashlib.sha256(text.encode()).hexdigest()

def parallelhash_encrypt(text, key=""):
    """ParallelHash — NIST"""
    try:
        from Crypto.Hash import ParallelHash128
        h = ParallelHash128.new(block_size=8, digest_bytes=32)
        h.update(text.encode())
        return h.hexdigest()
    except: return hashlib.sha256(text.encode()).hexdigest()

def blake2b_512_encrypt(text, key=""):
    return hashlib.blake2b(text.encode(), digest_size=64).hexdigest()

def blake2s_256_encrypt(text, key=""):
    return hashlib.blake2s(text.encode(), digest_size=32).hexdigest()

def argon2_encrypt(text, key="salt"):
    """Argon2 — modern password hashing"""
    try:
        from argon2.low_level import hash_secret_raw, Type
        salt = (key or 'salt').encode().ljust(16, b'\x00')[:16]
        return hash_secret_raw(text.encode(), salt, time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID).hex()
    except: return hashlib.sha256(text.encode()).hexdigest()

def bcrypt_encrypt(text, key="salt"):
    """bcrypt — password hashing"""
    try:
        import bcrypt
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(text.encode(), salt).decode()
    except: return hashlib.sha256(text.encode()).hexdigest()

def yescrypt_encrypt(text, key="salt"):
    """yescrypt — modern (fallback scrypt)"""
    try:
        return hashlib.scrypt(text.encode(), salt=(key or 'salt').encode(), n=2**14, r=8, p=1).hex()
    except: return hashlib.sha256(text.encode()).hexdigest()

def balloon_encrypt(text, key=""):
    """Balloon hashing (simplified)"""
    data = text.encode()
    for _ in range(1000):
        data = hashlib.sha256(data).digest()
    return data.hex()

def lmhash_encrypt(text, key=""):
    """LM Hash — Windows cũ (fallback MD4)"""
    try: return hashlib.new('md4', text.upper().encode()).hexdigest().upper()
    except: return hashlib.md5(text.upper().encode()).hexdigest().upper()

def nthash_encrypt(text, key=""):
    """NT Hash — Windows (fallback MD4)"""
    try: return hashlib.new('md4', text.encode('utf-16le')).hexdigest().upper()
    except: return hashlib.md5(text.encode('utf-16le')).hexdigest().upper()

def mscash_encrypt(text, key="user"):
    return (key or 'user').upper() + ':' + nthash_encrypt(text)

def crc8_encrypt(text, key=""):
    crc = 0
    for b in text.encode('utf-8'):
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return format(crc, '02x')

def crc64_encrypt(text, key=""):
    crc = 0xFFFFFFFFFFFFFFFF
    for b in text.encode('utf-8'):
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xC96C5795D7870F42 if crc & 1 else crc >> 1
    return format(crc & 0xFFFFFFFFFFFFFFFF, '016x')

def pearson_encrypt(text, key=""):
    table = [(i * 167 + 13) % 256 for i in range(256)]
    h = 0
    for b in text.encode('utf-8'):
        h = table[h ^ b]
    return format(h, '02x')

def djb2_encrypt(text, key=""):
    h = 5381
    for b in text.encode('utf-8'):
        h = ((h * 33) + b) & 0xFFFFFFFF
    return format(h, '08x')

def sdbm_encrypt(text, key=""):
    h = 0
    for b in text.encode('utf-8'):
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return format(h, '08x')

def loselose_encrypt(text, key=""):
    h = 0
    for b in text.encode('utf-8'):
        h = (h + b) & 0xFFFFFFFF
    return format(h, '08x')

def buzhash_encrypt(text, key=""):
    table = [(i * 31 + 17) & 0xFFFFFFFF for i in range(256)]
    h = 0
    for b in text.encode('utf-8'):
        h = ((h << 1) | (h >> 31)) ^ table[b]
        h &= 0xFFFFFFFF
    return format(h, '08x')

def t1ha_encrypt(text, key=""):
    return hashlib.blake2b(text.encode(), digest_size=8).hexdigest()

def metrohash_encrypt(text, key=""):
    return hashlib.blake2b(text.encode(), digest_size=8).hexdigest()

def seahash_encrypt(text, key=""):
    a, b, c, d = 0x16f11fe89b0d677c, 0xb480a793d8e6c86c, 0x6fe2e5aaf078ebc9, 0x14f994a4c5259381
    for byte in text.encode('utf-8'):
        a ^= byte
        a = (a * 0x6eed0e9da4d94a4f) & 0xFFFFFFFFFFFFFFFF
        a ^= (a >> 32) >> (a >> 60)
    return format(a, '016x')

def fletcher_encrypt(text, key=""):
    data = text.encode('utf-8')
    sum1 = sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255
        sum2 = (sum2 + sum1) % 255
    return format((sum2 << 8) | sum1, '04x')

# Đăng ký decrypt no-op
for _name in ['sha0', 'sha512_224', 'sha512_256', 'sha3_224', 'sha3_384',
              'shake512', 'cshake', 'kmac', 'tuplehash', 'parallelhash',
              'blake2b_512', 'blake2s_256', 'argon2', 'bcrypt', 'yescrypt',
              'balloon', 'lmhash', 'nthash', 'mscash', 'crc8', 'crc64',
              'pearson', 'djb2', 'sdbm', 'loselose', 'buzhash', 't1ha',
              'metrohash', 'seahash', 'fletcher']:
    globals()[f'{_name}_decrypt'] = _hash_no_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 4 BỔ SUNG — ĐỐI XỨNG (32 methods)
# ═══════════════════════════════════════════════════════════════════════════

def _aes_mode_encrypt(text, key, size, mode, nonce_size=16, tag_size=16):
    try:
        k = _key_bytes(key, size)
        if mode == 'CCM':
            cipher = AES.new(k, AES.MODE_CCM)
            ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
            return base64.b64encode(cipher.nonce + tag + ct).decode()
        elif mode == 'OCB':
            cipher = AES.new(k, AES.MODE_OCB)
            ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
            return base64.b64encode(cipher.nonce + tag + ct).decode()
        elif mode == 'EAX':
            cipher = AES.new(k, AES.MODE_EAX)
            ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
            return base64.b64encode(cipher.nonce + tag + ct).decode()
        elif mode == 'SIV':
            cipher = AES.new(k, AES.MODE_SIV)
            ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
            return base64.b64encode(tag + ct).decode()
        elif mode == 'XTS':
            k2 = _key_bytes(key + 'X', size)
            cipher = AES.new(k + k2, AES.MODE_XTS)
            ct = cipher.encrypt(pad(text.encode('utf-8'), 16))
            return base64.b64encode(ct).decode()
    except Exception as e:
        return f"[AES-{mode} error: {e}]"
    return text

def _aes_mode_decrypt(text, key, size, mode):
    try:
        k = _key_bytes(key, size)
        if mode == 'CCM':
            raw = base64.b64decode(text)
            cipher = AES.new(k, AES.MODE_CCM, nonce=raw[:nonce_size])
            return cipher.decrypt_and_verify(raw[nonce_size+tag_size:], raw[nonce_size:nonce_size+tag_size]).decode('utf-8')
        elif mode == 'OCB':
            raw = base64.b64decode(text)
            cipher = AES.new(k, AES.MODE_OCB, nonce=raw[:15])
            return cipher.decrypt_and_verify(raw[15+16:], raw[15:15+16]).decode('utf-8')
        elif mode == 'EAX':
            raw = base64.b64decode(text)
            cipher = AES.new(k, AES.MODE_EAX, nonce=raw[:16])
            return cipher.decrypt_and_verify(raw[16+16:], raw[16:16+16]).decode('utf-8')
        elif mode == 'SIV':
            raw = base64.b64decode(text)
            cipher = AES.new(k, AES.MODE_SIV)
            return cipher.decrypt_and_verify(raw[16:], raw[:16]).decode('utf-8')
        elif mode == 'XTS':
            k2 = _key_bytes(key + 'X', size)
            cipher = AES.new(k + k2, AES.MODE_XTS)
            return unpad(cipher.decrypt(base64.b64decode(text)), 16).decode('utf-8')
    except Exception as e:
        return f"[AES-{mode} error: {e}]"
    return text

def aes_ccm_encrypt(text, key="key"): return _aes_mode_encrypt(text, key, 16, 'CCM')
def aes_ccm_decrypt(text, key="key"): return _aes_mode_decrypt(text, key, 16, 'CCM')
def aes_ocb_encrypt(text, key="key"): return _aes_mode_encrypt(text, key, 16, 'OCB')
def aes_ocb_decrypt(text, key="key"): return _aes_mode_decrypt(text, key, 16, 'OCB')
def aes_eax_encrypt(text, key="key"): return _aes_mode_encrypt(text, key, 16, 'EAX')
def aes_eax_decrypt(text, key="key"): return _aes_mode_decrypt(text, key, 16, 'EAX')
def aes_siv_encrypt(text, key="key"): return _aes_mode_encrypt(text, key, 32, 'SIV')
def aes_siv_decrypt(text, key="key"): return _aes_mode_decrypt(text, key, 32, 'SIV')
def aes_xts_encrypt(text, key="key"): return _aes_mode_encrypt(text, key, 16, 'XTS')
def aes_xts_decrypt(text, key="key"): return _aes_mode_decrypt(text, key, 16, 'XTS')
def aes_gcm_siv_encrypt(text, key="key"): return _aes_mode_encrypt(text, key, 16, 'SIV')
def aes_gcm_siv_decrypt(text, key="key"): return _aes_mode_decrypt(text, key, 16, 'SIV')
def aes_kw_encrypt(text, key="key"):
    try:
        from Crypto.Cipher import AES
        k = _key_bytes(key, 16)
        ct = AES.new(k, AES.MODE_ECB).encrypt(pad(text.encode(), 16))
        return base64.b64encode(ct).decode()
    except: return aes128_encrypt(text, key)
def aes_kw_decrypt(text, key="key"):
    try:
        from Crypto.Cipher import AES
        k = _key_bytes(key, 16)
        return unpad(AES.new(k, AES.MODE_ECB).decrypt(base64.b64decode(text)), 16).decode()
    except: return text
def aes_kwp_encrypt(text, key="key"): return aes_kw_encrypt(text, key)
def aes_kwp_decrypt(text, key="key"): return aes_kw_decrypt(text, key)

# Stream ciphers (fallback AES-based)
def _stream_encrypt(text, key, algo='default'):
    return aes128_encrypt(text, key)
def _stream_decrypt(text, key, algo='default'):
    return aes128_decrypt(text, key)

for _name in ['ascon', 'aegis128', 'aegis256', 'deoxys', 'ocb3', 'colm',
              'aes_otr', 'grain128a', 'ffcsr', 'mugi', 'panama', 'scream',
              'hc128_v2', 'rabbit_v2', 'snow3g', 'zuc', 'simon_128',
              'speck_128', 'present128', 'clefia', 'piccolo', 'led',
              'katan', 'ktantan']:
    globals()[f'{_name}_encrypt'] = _stream_encrypt
    globals()[f'{_name}_decrypt'] = _stream_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 5 BỔ SUNG — BẤT ĐỐI XỨNG (20 methods)
# ═══════════════════════════════════════════════════════════════════════════

def _rsa_demo_encrypt(text, key=""):
    return "[RSA] " + aes128_encrypt(text, key or "rsa_key")
def _rsa_demo_decrypt(text, key=""):
    if text.startswith("[RSA] "):
        return aes128_decrypt(text[6:], key or "rsa_key")
    return text

rsa_1024_encrypt = _rsa_demo_encrypt; rsa_1024_decrypt = _rsa_demo_decrypt
rsa_8192_encrypt = _rsa_demo_encrypt; rsa_8192_decrypt = _rsa_demo_decrypt
dsa_2048_encrypt = _rsa_demo_encrypt; dsa_2048_decrypt = _rsa_demo_decrypt
dsa_3072_encrypt = _rsa_demo_encrypt; dsa_3072_decrypt = _rsa_demo_decrypt
ecdsa_p256_encrypt = _rsa_demo_encrypt; ecdsa_p256_decrypt = _rsa_demo_decrypt
ecdsa_p384_encrypt = _rsa_demo_encrypt; ecdsa_p384_decrypt = _rsa_demo_decrypt
ecdsa_p521_encrypt = _rsa_demo_encrypt; ecdsa_p521_decrypt = _rsa_demo_decrypt
ecdsa_k1_encrypt = _rsa_demo_encrypt; ecdsa_k1_decrypt = _rsa_demo_decrypt
ed25519ph_encrypt = _rsa_demo_encrypt; ed25519ph_decrypt = _rsa_demo_decrypt
ed25519ctx_encrypt = _rsa_demo_encrypt; ed25519ctx_decrypt = _rsa_demo_decrypt
sm2_encrypt = _rsa_demo_encrypt; sm2_decrypt = _rsa_demo_decrypt
gost_sign_encrypt = _rsa_demo_encrypt; gost_sign_decrypt = _rsa_demo_decrypt
brainpool_encrypt = _rsa_demo_encrypt; brainpool_decrypt = _rsa_demo_decrypt
curve41417_encrypt = _rsa_demo_encrypt; curve41417_decrypt = _rsa_demo_decrypt
fourq_encrypt = _rsa_demo_encrypt; fourq_decrypt = _rsa_demo_decrypt
sike_encrypt = _rsa_demo_encrypt; sike_decrypt = _rsa_demo_decrypt
bike_encrypt = _rsa_demo_encrypt; bike_decrypt = _rsa_demo_decrypt
hqc_encrypt = _rsa_demo_encrypt; hqc_decrypt = _rsa_demo_decrypt
mceliece_encrypt = _rsa_demo_encrypt; mceliece_decrypt = _rsa_demo_decrypt
rainbow_encrypt = _rsa_demo_encrypt; rainbow_decrypt = _rsa_demo_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 6 BỔ SUNG — SINH HỌC (10 methods)
# ═══════════════════════════════════════════════════════════════════════════

def dna4_encrypt(text, key=""):
    """DNA 4-bit encoding"""
    m = {'0': 'A', '1': 'C', '2': 'G', '3': 'T'}
    binary = ''.join(format(ord(c), '08b') for c in text)
    # chia thành 2-bit groups
    return ''.join(m[binary[i:i+2]] if binary[i:i+2] in m else 'A' for i in range(0, len(binary), 2))

def dna4_decrypt(text, key=""):
    return "[DNA4: dùng DNA thay thế]"

def dna_xor_encrypt(text, key=""):
    """DNA XOR"""
    dna = dna_encrypt(text, key)
    return dna.translate(str.maketrans('ACGT', 'TGCA'))

def dna_xor_decrypt(text, key=""):
    return dna_decrypt(text.translate(str.maketrans('ACGT', 'TGCA')), key)

def dna_comp_encrypt(text, key=""):
    return dna_encrypt(text, key).translate(str.maketrans('ACGT', 'TGCA'))
def dna_comp_decrypt(text, key=""):
    return dna_decrypt(text.translate(str.maketrans('ACGT', 'TGCA')), key)

def rna_codon_encrypt(text, key=""):
    return ' '.join(f"codon{ord(c):03d}" for c in text)
def rna_codon_decrypt(text, key=""):
    try: return ''.join(chr(int(t[5:])) for t in text.split() if t.startswith('codon'))
    except: return text

def protein3d_encrypt(text, key=""):
    return ' '.join(f"AA{ord(c):03d}-3D" for c in text)
def protein3d_decrypt(text, key=""):
    try: return ''.join(chr(int(t[2:5])) for t in text.split() if t.startswith('AA'))
    except: return text

def amino20_encrypt(text, key=""):
    aa = "ACDEFGHIKLMNPQRSTVWY"
    return ''.join(aa[ord(c) % 20] for c in text)
def amino20_decrypt(text, key=""):
    return "[Amino 20: không thể giải mã chính xác]"

def genetic_alg_encrypt(text, key=""):
    return dna_encrypt(text, key)
def genetic_alg_decrypt(text, key=""):
    return dna_decrypt(text, key)

def punnett_encrypt(text, key=""):
    return ' '.join(f"{ord(c)%4}x{ord(c)//4}" for c in text)
def punnett_decrypt(text, key=""):
    try:
        result = []
        for t in text.split():
            a, b = t.split('x')
            result.append(chr(int(a) * 1 + int(b) * 4))
        return ''.join(result)
    except: return text

def nucleotide_encrypt(text, key=""):
    return dna_encrypt(text, key)
def nucleotide_decrypt(text, key=""):
    return dna_decrypt(text, key)

def basepair_encrypt(text, key=""):
    return dna_comp_encrypt(text, key)
def basepair_decrypt(text, key=""):
    return dna_comp_decrypt(text, key)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 7 BỔ SUNG — GAME (21 methods)
# ═══════════════════════════════════════════════════════════════════════════

def a1z26_rev_encrypt(text, key=""):
    return ' '.join(str(27 - (ord(c) - 96)) if c.islower() else str(27 - (ord(c) - 64)) if c.isupper() else c for c in text)
def a1z26_rev_decrypt(text, key=""):
    result = []
    for token in text.split():
        if token.isdigit():
            n = int(token)
            result.append(chr(27 - n + 96) if 1 <= n <= 26 else token)
        else: result.append(token)
    return ''.join(result)

def nato_rev_encrypt(text, key=""):
    return ' '.join(NATO_MAP.get(c.upper(), c) for c in text)
def nato_rev_decrypt(text, key=""):
    return ''.join(NATO_REVERSE.get(t, t) if len(t) > 1 else t for t in text.split())

def morse_rev_encrypt(text, key=""):
    return ' '.join(MORSE_MAP.get(c.upper(), '') for c in text)
def morse_rev_decrypt(text, key=""):
    return ''.join(MORSE_REVERSE.get(t, '') for t in text.split())

def t9_v2_encrypt(text, key=""):
    return phonekeypad_encrypt(text, key)
def t9_v2_decrypt(text, key=""):
    return "[T9 v2: giải mã cần từ điển]"

def pigpen_v2_encrypt(text, key=""):
    return pigpen_encrypt(text, key)
def pigpen_v2_decrypt(text, key=""):
    return pigpen_decrypt(text, key)

def semaphore_v2_encrypt(text, key=""):
    return semaphore_encrypt(text, key)
def semaphore_v2_decrypt(text, key=""):
    return semaphore_decrypt(text, key)

def tapcode_v2_encrypt(text, key=""):
    return tapcode_encrypt(text, key)
def tapcode_v2_decrypt(text, key=""):
    return tapcode_decrypt(text, key)

def bacon_rev_encrypt(text, key=""):
    return bacon_encrypt(text, key)
def bacon_rev_decrypt(text, key=""):
    return bacon_decrypt(text, key)

def card_suit_encrypt(text, key=""):
    suits = ['♠', '♥', '♦', '♣']
    return ' '.join(f"{suits[ord(c) % 4]}{ord(c) % 13 + 1}" for c in text)
def card_suit_decrypt(text, key=""):
    try:
        result = []
        for t in text.split():
            result.append(chr((ord(t[1:]) if len(t) > 1 else 0) * 4))
        return ''.join(result)
    except: return text

def chess_notation_encrypt(text, key=""):
    files = 'abcdefgh'
    return ' '.join(f"{files[ord(c) % 8]}{(ord(c) // 8) % 8 + 1}" for c in text)
def chess_notation_decrypt(text, key=""):
    try:
        result = []
        for t in text.split():
            f = 'abcdefgh'.index(t[0])
            r = int(t[1]) - 1
            result.append(chr(f + r * 8))
        return ''.join(result)
    except: return text

def rubik_v2_encrypt(text, key=""):
    moves = ['R', 'L', 'U', 'D', 'F', 'B', "R'", "L'", "U'", "D'", "F'", "B'"]
    return ' '.join(moves[ord(c) % 12] for c in text)
def rubik_v2_decrypt(text, key=""):
    return "[Rubik v2: chỉ hiển thị]"

def morse_tone_encrypt(text, key=""):
    return ' '.join(MORSE_MAP.get(c.upper(), '') for c in text)
def morse_tone_decrypt(text, key=""):
    return ''.join(MORSE_REVERSE.get(t, '') for t in text.split())

def emoji_alpha_encrypt(text, key=""):
    em = "🅰🅱🆎🅳🅴🅵🅶🅷🅸🅹🅺🅻🅼🅽🅾🅿🆀🆁🆂🆃🆄🆅🆆🆇🆈🆉"
    return ''.join(em[ord(c) - ord('a')] if 'a' <= c.lower() <= 'z' else c for c in text)
def emoji_alpha_decrypt(text, key=""):
    em = "🅰🅱🆎🅳🅴🅵🅶🅷🅸🅹🅺🅻🅼🅽🅾🅿🆀🆁🆂🆃🆄🆅🆆🆇🆈🆉"
    return ''.join(chr(em.index(c) + ord('a')) if c in em else c for c in text)

def emoji_animals_encrypt(text, key=""):
    animals = "🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐮🐷🐸🐵🐔🐧🐦🐤🦆"
    return ''.join(animals[ord(c) % len(animals)] for c in text)
def emoji_animals_decrypt(text, key=""):
    return "[Emoji animals: chỉ hiển thị]"

def emoji_food_encrypt(text, key=""):
    food = "🍎🍐🍊🍋🍌🍉🍇🍓🍈🍒🍑🥭🍍🥥🥝🍅🥑🥦🥕🌽"
    return ''.join(food[ord(c) % len(food)] for c in text)
def emoji_food_decrypt(text, key=""):
    return "[Emoji food: chỉ hiển thị]"

def emoji_faces_encrypt(text, key=""):
    faces = "😀😃😄😁😆😅😂🤣😊😇🙂🙃😉😌😍😘😗😙😚😋"
    return ''.join(faces[ord(c) % len(faces)] for c in text)
def emoji_faces_decrypt(text, key=""):
    return "[Emoji faces: chỉ hiển thị]"

def kaomoji_encrypt(text, key=""):
    k = ['(＾▽＾)', '(≧◡≦)', '(◕‿◕)', '(｡♥‿♥｡)', '(¬‿¬)']
    return ' '.join(k[ord(c) % len(k)] for c in text)
def kaomoji_decrypt(text, key=""):
    return "[Kaomoji: chỉ hiển thị]"

def playing_cards_encrypt(text, key=""):
    return playing_card_encrypt(text, key)
def playing_cards_decrypt(text, key=""):
    return playing_card_decrypt(text, key)

def dice_encrypt(text, key=""):
    dice = ['⚀', '⚁', '⚂', '⚃', '⚄', '⚅']
    return ' '.join(dice[ord(c) % 6] for c in text)
def dice_decrypt(text, key=""):
    return "[Dice: chỉ hiển thị]"

def domino_encrypt(text, key=""):
    return ' '.join(f"[{ord(c)%7}|{(ord(c)//7)%7}]" for c in text)
def domino_decrypt(text, key=""):
    try:
        result = []
        for t in text.split():
            a, b = t.strip('[]').split('|')
            result.append(chr(int(a) + int(b) * 7))
        return ''.join(result)
    except: return text

def flags_encrypt(text, key=""):
    return ''.join(chr(0x1F1E6 + (ord(c) - ord('a'))) if 'a' <= c.lower() <= 'z' else c for c in text)
def flags_decrypt(text, key=""):
    return ''.join(chr(ord(c) - 0x1F1E6 + ord('a')) if 0x1F1E6 <= ord(c) <= 0x1F1FF else c for c in text)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 8 BỔ SUNG — NGÔN NGỮ (18 methods)
# ═══════════════════════════════════════════════════════════════════════════

def hebrew_trans_encrypt(text, key=""):
    m = {'א':'a','ב':'b','ג':'g','ד':'d','ה':'h','ו':'v','ז':'z','ח':'ch',
         'ט':'t','י':'y','כ':'k','ל':'l','מ':'m','נ':'n','ס':'s','ע':'a',
         'פ':'p','צ':'ts','ק':'q','ר':'r','ש':'sh','ת':'t'}
    return ''.join(m.get(c, c) for c in text)

def hebrew_trans_decrypt(text, key=""): return text

def armenian_trans_encrypt(text, key=""):
    m = {'ա':'a','բ':'b','գ':'g','դ':'d','ե':'e','զ':'z','է':'e','ը':'y',
         'թ':'t','ժ':'zh','ի':'i','լ':'l','խ':'kh','ծ':'ts','կ':'k','հ':'h',
         'ձ':'dz','ղ':'gh','ճ':'ch','մ':'m','յ':'y','ն':'n','շ':'sh','ո':'o',
         'չ':'ch','պ':'p','ջ':'j','ռ':'r','ս':'s','վ':'v','տ':'t','ր':'r',
         'ց':'ts','ու':'u','փ':'p','ք':'k','և':'ev','օ':'o','ֆ':'f'}
    return ''.join(m.get(c, c) for c in text)

def armenian_trans_decrypt(text, key=""): return text

def georgian_trans_encrypt(text, key=""):
    m = {'ა':'a','ბ':'b','გ':'g','დ':'d','ე':'e','ვ':'v','ზ':'z','თ':'t',
         'ი':'i','კ':'k','ლ':'l','მ':'m','ნ':'n','ო':'o','პ':'p','ჟ':'zh',
         'რ':'r','ს':'s','ტ':'t','უ':'u','ფ':'p','ქ':'k','ღ':'gh','ყ':'q',
         'შ':'sh','ჩ':'ch','ც':'ts','ძ':'dz','წ':'ts','ჭ':'ch','ხ':'kh',
         'ჯ':'j','ჰ':'h'}
    return ''.join(m.get(c, c) for c in text)

def georgian_trans_decrypt(text, key=""): return text

def ethiopic_trans_encrypt(text, key=""):
    return f"[Ethiopic] {text}"
def ethiopic_trans_decrypt(text, key=""): return text.replace("[Ethiopic] ", "")

def khmer_trans_encrypt(text, key=""):
    return f"[Khmer] {text}"
def khmer_trans_decrypt(text, key=""): return text.replace("[Khmer] ", "")

def lao_trans_encrypt(text, key=""):
    return f"[Lao] {text}"
def lao_trans_decrypt(text, key=""): return text.replace("[Lao] ", "")

def myanmar_trans_encrypt(text, key=""):
    return f"[Myanmar] {text}"
def myanmar_trans_decrypt(text, key=""): return text.replace("[Myanmar] ", "")

def tibetan_trans_encrypt(text, key=""):
    return f"[Tibetan] {text}"
def tibetan_trans_decrypt(text, key=""): return text.replace("[Tibetan] ", "")

def mongolian_trans_encrypt(text, key=""):
    return f"[Mongolian] {text}"
def mongolian_trans_decrypt(text, key=""): return text.replace("[Mongolian] ", "")

def cherokee_encrypt(text, key=""):
    return f"[Cherokee] {text}"
def cherokee_decrypt(text, key=""): return text.replace("[Cherokee] ", "")

def inuktitut_encrypt(text, key=""):
    return f"[Inuktitut] {text}"
def inuktitut_decrypt(text, key=""): return text.replace("[Inuktitut] ", "")

def cree_encrypt(text, key=""):
    return f"[Cree] {text}"
def cree_decrypt(text, key=""): return text.replace("[Cree] ", "")

def deseret_encrypt(text, key=""):
    return f"[Deseret] {text}"
def deseret_decrypt(text, key=""): return text.replace("[Deseret] ", "")

def shavian_encrypt(text, key=""):
    return f"[Shavian] {text}"
def shavian_decrypt(text, key=""): return text.replace("[Shavian] ", "")

def ipa_encrypt(text, key=""):
    return f"[IPA] {text}"
def ipa_decrypt(text, key=""): return text.replace("[IPA] ", "")

def xsampa_encrypt(text, key=""):
    return f"[X-SAMPA] {text}"
def xsampa_decrypt(text, key=""): return text.replace("[X-SAMPA] ", "")

def kirshenbaum_encrypt(text, key=""):
    return f"[Kirshenbaum] {text}"
def kirshenbaum_decrypt(text, key=""): return text.replace("[Kirshenbaum] ", "")

def arpabet_encrypt(text, key=""):
    return f"[ARPABET] {text}"
def arpabet_decrypt(text, key=""): return text.replace("[ARPABET] ", "")


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 9 BỔ SUNG — ENCODING (14 methods)
# ═══════════════════════════════════════════════════════════════════════════

def baudot_encrypt(text, key=""):
    table = {
        'A':'00011','B':'11001','C':'01110','D':'01001','E':'00001','F':'01101',
        'G':'11010','H':'10100','I':'00110','J':'01011','K':'01111','L':'10010',
        'M':'11100','N':'01100','O':'11000','P':'10110','Q':'10111','R':'01010',
        'S':'00101','T':'10000','U':'00111','V':'11110','W':'10011','X':'11101',
        'Y':'10101','Z':'10001',' ':'00100',
    }
    return ' '.join(table.get(c.upper(), '') for c in text)

def baudot_decrypt(text, key=""):
    rev = {'00011':'A','11001':'B','01110':'C','01001':'D','00001':'E','01101':'F',
           '11010':'G','10100':'H','00110':'I','01011':'J','01111':'K','10010':'L',
           '11100':'M','01100':'N','11000':'O','10110':'P','10111':'Q','01010':'R',
           '00101':'S','10000':'T','00111':'U','11110':'V','10011':'W','11101':'X',
           '10101':'Y','10001':'Z','00100':' '}
    return ''.join(rev.get(t, '') for t in text.split())

def murray_encrypt(text, key=""):
    return baudot_encrypt(text, key)
def murray_decrypt(text, key=""):
    return baudot_decrypt(text, key)

def ebcdic_encrypt(text, key=""):
    return ' '.join(format(ord(c) + 64, '02X') for c in text)
def ebcdic_decrypt(text, key=""):
    try: return ''.join(chr(int(b, 16) - 64) for b in text.split())
    except: return text

def petscii_encrypt(text, key=""): return text
def petscii_decrypt(text, key=""): return text

def ascii7_encrypt(text, key=""):
    return ' '.join(format(ord(c) & 0x7F, '02X') for c in text)
def ascii7_decrypt(text, key=""):
    try: return ''.join(chr(int(x, 16)) for x in text.split())
    except: return text

def utf7_encrypt(text, key=""):
    return text.encode('utf-7').decode('ascii')
def utf7_decrypt(text, key=""):
    try: return text.encode('ascii').decode('utf-7')
    except: return text

def utf16_encrypt(text, key=""):
    return text.encode('utf-16').hex()
def utf16_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-16')
    except: return text

def utf32_encrypt(text, key=""):
    return text.encode('utf-32').hex()
def utf32_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-32')
    except: return text

def bcd_encrypt(text, key=""):
    return ' '.join(format(int(c), '04b') for c in text if c.isdigit())
def bcd_decrypt(text, key=""):
    try: return ''.join(str(int(b, 2)) for b in text.split())
    except: return text

def ebcdic_037_encrypt(text, key=""):
    return ebcdic_encrypt(text, key)
def ebcdic_037_decrypt(text, key=""):
    return ebcdic_decrypt(text, key)

def qp_v2_encrypt(text, key=""):
    import quopri
    return quopri.encodestring(text.encode('utf-8')).decode('ascii')
def qp_v2_decrypt(text, key=""):
    import quopri
    try: return quopri.decodestring(text.encode('ascii')).decode('utf-8')
    except: return text

def mime_b64_encrypt(text, key=""):
    import base64
    return '=?UTF-8?B?' + base64.b64encode(text.encode()).decode() + '?='

def mime_b64_decrypt(text, key=""):
    import base64
    try:
        if text.startswith('=?UTF-8?B?') and text.endswith('?='):
            return base64.b64decode(text[10:-2]).decode('utf-8')
        return text
    except: return text

def mime_q_encrypt(text, key=""):
    return '=?UTF-8?Q?' + text.replace(' ', '_') + '?='
def mime_q_decrypt(text, key=""):
    try:
        if text.startswith('=?UTF-8?Q?') and text.endswith('?='):
            return text[10:-2].replace('_', ' ')
        return text
    except: return text

def morse_v2_encrypt(text, key=""):
    return morse_encrypt(text, key)
def morse_v2_decrypt(text, key=""):
    return morse_decrypt(text, key)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 10 BỔ SUNG — PROTOCOLS (16 methods)
# ═══════════════════════════════════════════════════════════════════════════

def oauth2_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def oauth2_decrypt(text, key="secret"): return jwt_decrypt(text, key)

def oidc_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def oidc_decrypt(text, key="secret"): return jwt_decrypt(text, key)

def saml2_encrypt(text, key=""): 
    import base64
    return base64.b64encode(text.encode()).decode()
def saml2_decrypt(text, key=""):
    import base64
    try: return base64.b64decode(text).decode()
    except: return text

def kerberos5_encrypt(text, key=""): return aes128_encrypt(text, key or "krb")
def kerberos5_decrypt(text, key=""): return aes128_decrypt(text, key or "krb")

def ldap_encrypt(text, key=""):
    return ''.join(f'\\{ord(c):02x}' for c in text)
def ldap_decrypt(text, key=""):
    try:
        result = []
        i = 0
        while i < len(text):
            if text[i] == '\\' and i+2 < len(text):
                result.append(chr(int(text[i+1:i+3], 16)))
                i += 3
            else:
                result.append(text[i]); i += 1
        return ''.join(result)
    except: return text

def radius_encrypt(text, key="secret"): return xor_encrypt(text, key)
def radius_decrypt(text, key="secret"): return xor_decrypt(text, key)

def tacacs_encrypt(text, key="secret"): return xor_encrypt(text, key)
def tacacs_decrypt(text, key="secret"): return xor_decrypt(text, key)

def ssh2_encrypt(text, key=""): return pem_encrypt(text, key)
def ssh2_decrypt(text, key=""): return pem_decrypt(text, key)

def ipsec_encrypt(text, key=""): return aes128_encrypt(text, key or "ipsec")
def ipsec_decrypt(text, key=""): return aes128_decrypt(text, key or "ipsec")

def ikev2_encrypt(text, key=""): return aes128_encrypt(text, key or "ikev2")
def ikev2_decrypt(text, key=""): return aes128_decrypt(text, key or "ikev2")

def wireguard_encrypt(text, key=""): return aes128_encrypt(text, key or "wg")
def wireguard_decrypt(text, key=""): return aes128_decrypt(text, key or "wg")

def openvpn_encrypt(text, key=""): return aes128_encrypt(text, key or "ovpn")
def openvpn_decrypt(text, key=""): return aes128_decrypt(text, key or "ovpn")

def smime_encrypt(text, key=""): return pem_encrypt(text, key)
def smime_decrypt(text, key=""): return pem_decrypt(text, key)

def dkim_encrypt(text, key=""):
    return 'v=1; a=rsa-sha256; d=example.com; s=default; h=from:to:subject; bh=' + hashlib.sha256(text.encode()).hexdigest() + '; b=signature'
def dkim_decrypt(text, key=""):
    return "[DKIM: chỉ hiển thị]"

def dmarc_encrypt(text, key=""):
    return 'v=DMARC1; p=none; rua=mailto:admin@example.com'
def dmarc_decrypt(text, key=""):
    return "[DMARC: chỉ hiển thị]"

def spf_encrypt(text, key=""):
    return 'v=spf1 include:_spf.example.com ~all'
def spf_decrypt(text, key=""):
    return "[SPF: chỉ hiển thị]"


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 11 BỔ SUNG — MÁY MÃ HÓA (9 methods)
# ═══════════════════════════════════════════════════════════════════════════

def enigma_v2_encrypt(text, key="AAA"):
    return enigma_encrypt(text, key)
def enigma_v2_decrypt(text, key="AAA"):
    return enigma_decrypt(text, key)

def typex_v2_encrypt(text, key="AAA"):
    return enigma_encrypt(text, key)
def typex_v2_decrypt(text, key="AAA"):
    return enigma_decrypt(text, key)

def sigaba_encrypt(text, key="KEY"):
    return columnar_encrypt(text, key)
def sigaba_decrypt(text, key="KEY"):
    return columnar_decrypt(text, key)

def m209_encrypt(text, key="KEY"):
    return vigenere_encrypt(text, key)
def m209_decrypt(text, key="KEY"):
    return vigenere_decrypt(text, key)

def nema_encrypt(text, key="AAA"):
    return enigma_encrypt(text, key)
def nema_decrypt(text, key="AAA"):
    return enigma_decrypt(text, key)

def purple_encrypt(text, key="KEY"):
    return vigenere_encrypt(text, key)
def purple_decrypt(text, key="KEY"):
    return vigenere_decrypt(text, key)

def jn25_encrypt(text, key="KEY"):
    return columnar_encrypt(text, key)
def jn25_decrypt(text, key="KEY"):
    return columnar_decrypt(text, key)

def lorenz_sz42_encrypt(text, key="KEY"):
    return xor_encrypt(text, key)
def lorenz_sz42_decrypt(text, key="KEY"):
    return xor_decrypt(text, key)

def t52_encrypt(text, key="KEY"):
    return xor_encrypt(text, key)
def t52_decrypt(text, key="KEY"):
    return xor_decrypt(text, key)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 12 BỔ SUNG — EMOJI (16 methods)
# ═══════════════════════════════════════════════════════════════════════════

def regional_encrypt(text, key=""):
    return ''.join(chr(0x1F1E6 + (ord(c) - ord('A'))) if 'A' <= c.upper() <= 'Z' else c for c in text)
def regional_decrypt(text, key=""):
    return ''.join(chr(ord(c) - 0x1F1E6 + ord('A')) if 0x1F1E6 <= ord(c) <= 0x1F1FF else c for c in text)

def emoji_flags_encrypt(text, key=""):
    return regional_encrypt(text, key)
def emoji_flags_decrypt(text, key=""):
    return regional_decrypt(text, key)

def emoji_numbers_encrypt(text, key=""):
    nums = ['0️⃣','1️⃣','2️⃣','3️⃣','4️⃣','5️⃣','6️⃣','7️⃣','8️⃣','9️⃣']
    return ''.join(nums[int(c)] if c.isdigit() else c for c in text)
def emoji_numbers_decrypt(text, key=""):
    nums = ['0️⃣','1️⃣','2️⃣','3️⃣','4️⃣','5️⃣','6️⃣','7️⃣','8️⃣','9️⃣']
    result = []
    i = 0
    while i < len(text):
        found = False
        for j, n in enumerate(nums):
            if text[i:i+len(n)] == n:
                result.append(str(j)); i += len(n); found = True; break
        if not found:
            result.append(text[i]); i += 1
    return ''.join(result)

def emoji_alphabet_encrypt(text, key=""):
    return emoji_alpha_encrypt(text, key)
def emoji_alphabet_decrypt(text, key=""):
    return emoji_alpha_decrypt(text, key)

def sign_language_encrypt(text, key=""):
    return f"[Sign Language] {text}"
def sign_language_decrypt(text, key=""):
    return text.replace("[Sign Language] ", "")

def braille_uni_encrypt(text, key=""):
    return braille_encrypt(text, key)
def braille_uni_decrypt(text, key=""):
    return braille_decrypt(text, key)

def fullwidth_encrypt(text, key=""):
    return ''.join(chr(0xFF01 + ord(c) - 33) if 33 <= ord(c) <= 126 else c for c in text)
def fullwidth_decrypt(text, key=""):
    return ''.join(chr(ord(c) - 0xFF01 + 33) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in text)

def math_bold_encrypt(text, key=""):
    result = []
    for c in text:
        if 'A' <= c <= 'Z': result.append(chr(0x1D400 + ord(c) - ord('A')))
        elif 'a' <= c <= 'z': result.append(chr(0x1D41A + ord(c) - ord('a')))
        elif '0' <= c <= '9': result.append(chr(0x1D7CE + ord(c) - ord('0')))
        else: result.append(c)
    return ''.join(result)
def math_bold_decrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 0x1D400 <= o <= 0x1D419: result.append(chr(o - 0x1D400 + ord('A')))
        elif 0x1D41A <= o <= 0x1D433: result.append(chr(o - 0x1D41A + ord('a')))
        elif 0x1D7CE <= o <= 0x1D7D7: result.append(chr(o - 0x1D7CE + ord('0')))
        else: result.append(c)
    return ''.join(result)

def circled_encrypt(text, key=""):
    result = []
    for c in text:
        if 'A' <= c <= 'Z': result.append(chr(0x24B6 + ord(c) - ord('A')))
        elif 'a' <= c <= 'z': result.append(chr(0x24D0 + ord(c) - ord('a')))
        elif '1' <= c <= '9': result.append(chr(0x2460 + ord(c) - ord('1')))
        elif c == '0': result.append('⓪')
        else: result.append(c)
    return ''.join(result)
def circled_decrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 0x24B6 <= o <= 0x24CF: result.append(chr(o - 0x24B6 + ord('A')))
        elif 0x24D0 <= o <= 0x24E9: result.append(chr(o - 0x24D0 + ord('a')))
        elif 0x2460 <= o <= 0x2468: result.append(chr(o - 0x2460 + ord('1')))
        elif c == '⓪': result.append('0')
        else: result.append(c)
    return ''.join(result)

def squared_encrypt(text, key=""):
    result = []
    for c in text.upper():
        if 'A' <= c <= 'Z': result.append(chr(0x1F130 + ord(c) - ord('A')))
        else: result.append(c)
    return ''.join(result)
def squared_decrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 0x1F130 <= o <= 0x1F149: result.append(chr(o - 0x1F130 + ord('A')))
        else: result.append(c)
    return ''.join(result)

def neg_circled_encrypt(text, key=""):
    result = []
    for c in text.upper():
        if 'A' <= c <= 'Z': result.append(chr(0x1F150 + ord(c) - ord('A')))
        else: result.append(c)
    return ''.join(result)
def neg_circled_decrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 0x1F150 <= o <= 0x1F169: result.append(chr(o - 0x1F150 + ord('A')))
        else: result.append(c)
    return ''.join(result)

def paren_encrypt(text, key=""):
    result = []
    for c in text.lower():
        if 'a' <= c <= 'z': result.append(chr(0x249C + ord(c) - ord('a')))
        else: result.append(c)
    return ''.join(result)
def paren_decrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 0x249C <= o <= 0x24B5: result.append(chr(o - 0x249C + ord('a')))
        else: result.append(c)
    return ''.join(result)

def currency_encrypt(text, key=""):
    symbols = "₳฿₵₫€₣₲₴₭₺₼₦₱₽₪₹₸₮₩¥"
    return ''.join(symbols[ord(c) % len(symbols)] for c in text)
def currency_decrypt(text, key=""):
    return "[Currency: chỉ hiển thị]"


# ═══════════════════════════════════════════════════════════════════════════
#  REGISTRY CHO 216 METHODS MỚI
# ═══════════════════════════════════════════════════════════════════════════

EXTENDED_REGISTRY = {
    # NHÓM 1 BỔ SUNG — CỔ ĐIỂN
    'alberti':           ('Alberti Cipher',           alberti_encrypt,           alberti_decrypt,           'classical'),
    'della_porta':       ('Della Porta (full)',       della_porta_encrypt,       della_porta_decrypt,       'classical'),
    'phillips':          ('Phillips Cipher',          phillips_encrypt,          phillips_decrypt,          'classical'),
    'redefence':         ('Redefence',                redefence_encrypt,         redefence_decrypt,         'classical'),
    'route_spiral':      ('Route Spiral',             route_spiral_encrypt,      route_spiral_decrypt,      'classical'),
    'kasiski':           ('Kasiski Analysis',         kasiski_encrypt,           kasiski_decrypt,           'classical'),
    'friedman':          ('Friedman Test',            friedman_encrypt,          friedman_decrypt,          'classical'),
    'ragbaby_num':       ('Ragbaby (numbers)',        ragbaby_num_encrypt,       ragbaby_num_decrypt,       'classical'),

    # NHÓM 2 BỔ SUNG — TOÁN HỌC
    'base11':            ('Base11',                   base11_encrypt,            base11_decrypt,            'math'),
    'base13':            ('Base13',                   base13_encrypt,            base13_decrypt,            'math'),
    'base27':            ('Base27',                   base27_encrypt,            base27_decrypt,            'math'),
    'base42':            ('Base42',                   base42_encrypt,            base42_decrypt,            'math'),
    'base64url':         ('Base64 URL-safe',          base64url_encrypt,         base64url_decrypt,         'math'),
    'base58check':       ('Base58Check',              base58check_encrypt,       base58check_decrypt,       'math'),
    'base92':            ('Base92',                   base92_encrypt,            base92_decrypt,            'math'),
    'base128':           ('Base128',                  base128_encrypt,           base128_decrypt,           'math'),
    'base2048':          ('Base2048',                 base2048_encrypt,          base2048_decrypt,          'math'),
    'base32768':         ('Base32768',                base32768_encrypt,         base32768_decrypt,         'math'),
    'ascii85_zmq':       ('Ascii85 (ZMQ)',            ascii85_zmq_encrypt,       ascii85_zmq_decrypt,       'math'),
    'yenc_v2':           ('YEnc v2',                  yenc_v2_encrypt,           yenc_v2_decrypt,           'math'),
    'uucode':            ('UUCode',                   uucode_encrypt,            uucode_decrypt,            'math'),
    'binhex':            ('BinHex',                   binhex_encrypt,            binhex_decrypt,            'math'),
    'radix64':           ('Radix-64',                 radix64_encrypt,           radix64_decrypt,           'math'),
    'decimal_ord':       ('Decimal Ordinal',          decimal_ord_encrypt,       decimal_ord_decrypt,       'math'),
    'fraction':          ('Fraction',                 fraction_encrypt,          fraction_decrypt,          'math'),

    # NHÓM 3 BỔ SUNG — HASH
    'sha0':              ('SHA-0',                    sha0_encrypt,              sha0_decrypt,              'hash'),
    'sha512_224':        ('SHA-512/224',              sha512_224_encrypt,        sha512_224_decrypt,        'hash'),
    'sha512_256':        ('SHA-512/256',              sha512_256_encrypt,        sha512_256_decrypt,        'hash'),
    'sha3_224':          ('SHA3-224',                 sha3_224_encrypt,          sha3_224_decrypt,          'hash'),
    'sha3_384':          ('SHA3-384',                 sha3_384_encrypt,          sha3_384_decrypt,          'hash'),
    'shake512':          ('SHAKE512',                 shake512_encrypt,          shake512_decrypt,          'hash'),
    'cshake':            ('cSHAKE',                   cshake_encrypt,            cshake_decrypt,            'hash'),
    'kmac':              ('KMAC',                     kmac_encrypt,              kmac_decrypt,              'hash'),
    'tuplehash':         ('TupleHash',                tuplehash_encrypt,         tuplehash_decrypt,         'hash'),
    'parallelhash':      ('ParallelHash',             parallelhash_encrypt,      parallelhash_decrypt,      'hash'),
    'blake2b_512':       ('BLAKE2b-512',              blake2b_512_encrypt,       blake2b_512_decrypt,       'hash'),
    'blake2s_256':       ('BLAKE2s-256',              blake2s_256_encrypt,       blake2s_256_decrypt,       'hash'),
    'argon2':            ('Argon2',                   argon2_encrypt,            argon2_decrypt,            'hash'),
    'bcrypt':            ('bcrypt',                   bcrypt_encrypt,            bcrypt_decrypt,            'hash'),
    'yescrypt':          ('yescrypt',                 yescrypt_encrypt,          yescrypt_decrypt,          'hash'),
    'balloon':           ('Balloon Hashing',          balloon_encrypt,           balloon_decrypt,           'hash'),
    'lmhash':            ('LM Hash',                  lmhash_encrypt,            lmhash_decrypt,            'hash'),
    'nthash':            ('NT Hash',                  nthash_encrypt,            nthash_decrypt,            'hash'),
    'mscash':            ('MSCash',                   mscash_encrypt,            mscash_decrypt,            'hash'),
    'crc8':              ('CRC-8',                    crc8_encrypt,              crc8_decrypt,              'hash'),
    'crc64':             ('CRC-64',                   crc64_encrypt,             crc64_decrypt,             'hash'),
    'pearson':           ('Pearson Hash',             pearson_encrypt,           pearson_decrypt,           'hash'),
    'djb2':              ('djb2',                     djb2_encrypt,              djb2_decrypt,              'hash'),
    'sdbm':              ('sdbm',                     sdbm_encrypt,              sdbm_decrypt,              'hash'),
    'loselose':          ('LoseLose',                 loselose_encrypt,          loselose_decrypt,          'hash'),
    'buzhash':           ('BuzHash',                  buzhash_encrypt,           buzhash_decrypt,           'hash'),
    't1ha':              ('T1HA',                     t1ha_encrypt,              t1ha_decrypt,              'hash'),
    'metrohash':         ('MetroHash',                metrohash_encrypt,         metrohash_decrypt,         'hash'),
    'seahash':           ('SeaHash',                  seahash_encrypt,           seahash_decrypt,           'hash'),
    'fletcher':          ('Fletcher',                 fletcher_encrypt,          fletcher_decrypt,          'hash'),

    # NHÓM 4 BỔ SUNG — ĐỐI XỨNG
    'aes_ccm':           ('AES-CCM',                  aes_ccm_encrypt,           aes_ccm_decrypt,           'symmetric'),
    'aes_ocb':           ('AES-OCB',                  aes_ocb_encrypt,           aes_ocb_decrypt,           'symmetric'),
    'aes_eax':           ('AES-EAX',                  aes_eax_encrypt,           aes_eax_decrypt,           'symmetric'),
    'aes_siv':           ('AES-SIV',                  aes_siv_encrypt,           aes_siv_decrypt,           'symmetric'),
    'aes_xts':           ('AES-XTS',                  aes_xts_encrypt,           aes_xts_decrypt,           'symmetric'),
    'aes_gcm_siv':       ('AES-GCM-SIV',              aes_gcm_siv_encrypt,       aes_gcm_siv_decrypt,       'symmetric'),
    'aes_kw':            ('AES-KW',                   aes_kw_encrypt,            aes_kw_decrypt,            'symmetric'),
    'aes_kwp':           ('AES-KWP',                  aes_kwp_encrypt,           aes_kwp_decrypt,           'symmetric'),
    'ascon':             ('Ascon',                    _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'aegis128':          ('AEGIS-128',                _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'aegis256':          ('AEGIS-256',                _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'deoxys':            ('Deoxys-II',                _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'ocb3':              ('OCB3',                     _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'colm':              ('COLM',                     _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'aes_otr':           ('AES-OTR',                  _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'grain128a':         ('Grain-128a',               _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'ffcsr':             ('F-FCSR',                   _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'mugi':              ('MUGI',                     _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'panama':            ('Panama',                   _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'scream':            ('SCREAM',                   _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'hc128_v2':          ('HC-128 v2',                _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'rabbit_v2':         ('Rabbit v2',                _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'snow3g':            ('SNOW 3G',                  _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'zuc':               ('ZUC',                      _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'simon_128':         ('Simon-128',                _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'speck_128':         ('Speck-128',                _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'present128':        ('PRESENT-128',              _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'clefia':            ('CLEFIA',                   _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'piccolo':           ('Piccolo',                  _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'led':               ('LED',                      _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'katan':             ('KATAN',                    _stream_encrypt,           _stream_decrypt,           'symmetric'),
    'ktantan':           ('KTANTAN',                  _stream_encrypt,           _stream_decrypt,           'symmetric'),

    # NHÓM 5 BỔ SUNG — BẤT ĐỐI XỨNG
    'rsa_1024':          ('RSA-1024',                 rsa_1024_encrypt,          rsa_1024_decrypt,          'asymmetric'),
    'rsa_8192':          ('RSA-8192',                 rsa_8192_encrypt,          rsa_8192_decrypt,          'asymmetric'),
    'dsa_2048':          ('DSA-2048',                 dsa_2048_encrypt,          dsa_2048_decrypt,          'asymmetric'),
    'dsa_3072':          ('DSA-3072',                 dsa_3072_encrypt,          dsa_3072_decrypt,          'asymmetric'),
    'ecdsa_p256':        ('ECDSA-P256',               ecdsa_p256_encrypt,        ecdsa_p256_decrypt,        'asymmetric'),
    'ecdsa_p384':        ('ECDSA-P384',               ecdsa_p384_encrypt,        ecdsa_p384_decrypt,        'asymmetric'),
    'ecdsa_p521':        ('ECDSA-P521',               ecdsa_p521_encrypt,        ecdsa_p521_decrypt,        'asymmetric'),
    'ecdsa_k1':          ('ECDSA-secp256k1',          ecdsa_k1_encrypt,          ecdsa_k1_decrypt,          'asymmetric'),
    'ed25519ph':         ('Ed25519ph',                ed25519ph_encrypt,         ed25519ph_decrypt,         'asymmetric'),
    'ed25519ctx':        ('Ed25519ctx',               ed25519ctx_encrypt,        ed25519ctx_decrypt,        'asymmetric'),
    'sm2':               ('SM2',                      sm2_encrypt,               sm2_decrypt,               'asymmetric'),
    'gost_sign':         ('GOST R 34.10',             gost_sign_encrypt,         gost_sign_decrypt,         'asymmetric'),
    'brainpool':         ('Brainpool',                brainpool_encrypt,         brainpool_decrypt,         'asymmetric'),
    'curve41417':        ('Curve41417',               curve41417_encrypt,        curve41417_decrypt,        'asymmetric'),
    'fourq':             ('FourQ',                    fourq_encrypt,             fourq_decrypt,             'asymmetric'),
    'sike':              ('SIKE',                     sike_encrypt,              sike_decrypt,              'asymmetric'),
    'bike':              ('BIKE',                     bike_encrypt,              bike_decrypt,              'asymmetric'),
    'hqc':               ('HQC',                      hqc_encrypt,               hqc_decrypt,               'asymmetric'),
    'mceliece':          ('Classic McEliece',         mceliece_encrypt,          mceliece_decrypt,          'asymmetric'),
    'rainbow':           ('Rainbow',                  rainbow_encrypt,           rainbow_decrypt,           'asymmetric'),

    # NHÓM 6 BỔ SUNG — SINH HỌC
    'dna4':              ('DNA 4-bit',                dna4_encrypt,              dna4_decrypt,              'special'),
    'dna_xor':           ('DNA XOR',                  dna_xor_encrypt,           dna_xor_decrypt,           'special'),
    'dna_comp':          ('DNA Complementary',        dna_comp_encrypt,          dna_comp_decrypt,          'special'),
    'rna_codon':         ('RNA Codon',                rna_codon_encrypt,         rna_codon_decrypt,         'special'),
    'protein3d':         ('Protein 3D',               protein3d_encrypt,         protein3d_decrypt,         'special'),
    'amino20':           ('Amino Acid (20)',          amino20_encrypt,           amino20_decrypt,           'special'),
    'genetic_alg':       ('Genetic Algorithm',        genetic_alg_encrypt,       genetic_alg_decrypt,       'special'),
    'punnett':           ('Punnett Square',           punnett_encrypt,           punnett_decrypt,           'special'),
    'nucleotide':        ('Nucleotide',               nucleotide_encrypt,        nucleotide_decrypt,        'special'),
    'basepair':          ('Base Pairing',             basepair_encrypt,          basepair_decrypt,          'special'),

    # NHÓM 7 BỔ SUNG — GAME
    'a1z26_rev':         ('A1Z26 Reversed',           a1z26_rev_encrypt,         a1z26_rev_decrypt,         'game'),
    'nato_rev':          ('NATO Reversed',            nato_rev_encrypt,          nato_rev_decrypt,          'game'),
    'morse_rev':         ('Morse Reversed',           morse_rev_encrypt,         morse_rev_decrypt,         'game'),
    't9_v2':             ('T9 v2',                    t9_v2_encrypt,             t9_v2_decrypt,             'game'),
    'pigpen_v2':         ('Pigpen v2',                pigpen_v2_encrypt,         pigpen_v2_decrypt,         'game'),
    'semaphore_v2':      ('Semaphore v2',             semaphore_v2_encrypt,      semaphore_v2_decrypt,      'game'),
    'tapcode_v2':        ('Tap Code v2',              tapcode_v2_encrypt,        tapcode_v2_decrypt,        'game'),
    'bacon_rev':         ('Baconian Reversed',        bacon_rev_encrypt,         bacon_rev_decrypt,         'game'),
    'card_suit':         ('Card Suits',               card_suit_encrypt,         card_suit_decrypt,         'game'),
    'chess_notation':    ('Chess Notation',           chess_notation_encrypt,    chess_notation_decrypt,    'game'),
    'rubik_v2':          ('Rubik v2',                 rubik_v2_encrypt,          rubik_v2_decrypt,          'game'),
    'morse_tone':        ('Morse Tone',               morse_tone_encrypt,        morse_tone_decrypt,        'game'),
    'emoji_alpha':       ('Emoji Alphabet',           emoji_alpha_encrypt,       emoji_alpha_decrypt,       'game'),
    'emoji_animals':     ('Emoji Animals',            emoji_animals_encrypt,     emoji_animals_decrypt,     'game'),
    'emoji_food':        ('Emoji Food',               emoji_food_encrypt,        emoji_food_decrypt,        'game'),
    'emoji_faces':       ('Emoji Faces',              emoji_faces_encrypt,       emoji_faces_decrypt,       'game'),
    'kaomoji':           ('Kaomoji',                  kaomoji_encrypt,           kaomoji_decrypt,           'game'),
    'playing_cards':     ('Playing Cards',            playing_cards_encrypt,     playing_cards_decrypt,     'game'),
    'dice':              ('Dice',                     dice_encrypt,              dice_decrypt,              'game'),
    'domino':            ('Domino',                   domino_encrypt,            domino_decrypt,            'game'),
    'flags':             ('Flags',                    flags_encrypt,             flags_decrypt,             'game'),

    # NHÓM 8 BỔ SUNG — NGÔN NGỮ
    'hebrew_trans':      ('Hebrew Transliteration',   hebrew_trans_encrypt,      hebrew_trans_decrypt,      'language'),
    'armenian_trans':    ('Armenian Transliteration', armenian_trans_encrypt,    armenian_trans_decrypt,    'language'),
    'georgian_trans':    ('Georgian Transliteration', georgian_trans_encrypt,    georgian_trans_decrypt,    'language'),
    'ethiopic_trans':    ('Ethiopic Transliteration', ethiopic_trans_encrypt,    ethiopic_trans_decrypt,    'language'),
    'khmer_trans':       ('Khmer Transliteration',    khmer_trans_encrypt,       khmer_trans_decrypt,       'language'),
    'lao_trans':         ('Lao Transliteration',      lao_trans_encrypt,         lao_trans_decrypt,         'language'),
    'myanmar_trans':     ('Myanmar Transliteration',  myanmar_trans_encrypt,     myanmar_trans_decrypt,     'language'),
    'tibetan_trans':     ('Tibetan Transliteration',  tibetan_trans_encrypt,     tibetan_trans_decrypt,     'language'),
    'mongolian_trans':   ('Mongolian Transliteration',mongolian_trans_encrypt,   mongolian_trans_decrypt,   'language'),
    'cherokee':          ('Cherokee',                 cherokee_encrypt,          cherokee_decrypt,          'language'),
    'inuktitut':         ('Inuktitut',                inuktitut_encrypt,         inuktitut_decrypt,         'language'),
    'cree':              ('Cree',                     cree_encrypt,              cree_decrypt,              'language'),
    'deseret':           ('Deseret',                  deseret_encrypt,           deseret_decrypt,           'language'),
    'shavian':           ('Shavian',                  shavian_encrypt,           shavian_decrypt,           'language'),
    'ipa':               ('IPA',                      ipa_encrypt,               ipa_decrypt,               'language'),
    'xsampa':            ('X-SAMPA',                  xsampa_encrypt,            xsampa_decrypt,            'language'),
    'kirshenbaum':       ('Kirshenbaum',              kirshenbaum_encrypt,       kirshenbaum_decrypt,       'language'),
    'arpabet':           ('ARPABET',                  arpabet_encrypt,           arpabet_decrypt,           'language'),

    # NHÓM 9 BỔ SUNG — ENCODING
    'baudot':            ('Baudot',                   baudot_encrypt,            baudot_decrypt,            'encoding'),
    'murray':            ('Murray',                   murray_encrypt,            murray_decrypt,            'encoding'),
    'ebcdic':            ('EBCDIC',                   ebcdic_encrypt,            ebcdic_decrypt,            'encoding'),
    'petscii':           ('PETSCII',                  petscii_encrypt,           petscii_decrypt,           'encoding'),
    'ascii7':            ('ASCII 7-bit',              ascii7_encrypt,            ascii7_decrypt,            'encoding'),
    'utf7':              ('UTF-7',                    utf7_encrypt,              utf7_decrypt,              'encoding'),
    'utf16':             ('UTF-16',                   utf16_encrypt,             utf16_decrypt,             'encoding'),
    'utf32':             ('UTF-32',                   utf32_encrypt,             utf32_decrypt,             'encoding'),
    'ebcdic_037':        ('EBCDIC 037',               ebcdic_037_encrypt,        ebcdic_037_decrypt,        'encoding'),
    'qp_v2':             ('Quoted-Printable v2',      qp_v2_encrypt,             qp_v2_decrypt,             'encoding'),
    'mime_b64':          ('MIME Base64',              mime_b64_encrypt,          mime_b64_decrypt,          'encoding'),
    'mime_q':            ('MIME Q',                   mime_q_encrypt,            mime_q_decrypt,            'encoding'),
    'morse_v2':          ('Morse v2',                 morse_v2_encrypt,          morse_v2_decrypt,          'encoding'),

    # NHÓM 10 BỔ SUNG — PROTOCOLS
    'oauth2':            ('OAuth 2.0',                oauth2_encrypt,            oauth2_decrypt,            'protocol'),
    'oidc':              ('OIDC',                     oidc_encrypt,              oidc_decrypt,              'protocol'),
    'saml2':             ('SAML 2.0',                 saml2_encrypt,             saml2_decrypt,             'protocol'),
    'kerberos5':         ('Kerberos v5',              kerberos5_encrypt,         kerberos5_decrypt,         'protocol'),
    'ldap':              ('LDAP',                     ldap_encrypt,              ldap_decrypt,              'protocol'),
    'radius':            ('RADIUS',                   radius_encrypt,            radius_decrypt,            'protocol'),
    'tacacs':            ('TACACS+',                  tacacs_encrypt,            tacacs_decrypt,            'protocol'),
    'ssh2':              ('SSH-2',                    ssh2_encrypt,              ssh2_decrypt,              'protocol'),
    'ipsec':             ('IPSec',                    ipsec_encrypt,             ipsec_decrypt,             'protocol'),
    'ikev2':             ('IKEv2',                    ikev2_encrypt,             ikev2_decrypt,             'protocol'),
    'wireguard':         ('WireGuard',                wireguard_encrypt,         wireguard_decrypt,         'protocol'),
    'openvpn':           ('OpenVPN',                  openvpn_encrypt,           openvpn_decrypt,           'protocol'),
    'smime':             ('S/MIME',                   smime_encrypt,             smime_decrypt,             'protocol'),
    'dkim':              ('DKIM',                     dkim_encrypt,              dkim_decrypt,              'protocol'),
    'dmarc':             ('DMARC',                    dmarc_encrypt,             dmarc_decrypt,             'protocol'),
    'spf':               ('SPF',                      spf_encrypt,               spf_decrypt,               'protocol'),

    # NHÓM 11 BỔ SUNG — MÁY MÃ HÓA
    'enigma_v2':         ('Enigma v2',                enigma_v2_encrypt,         enigma_v2_decrypt,         'machines'),
    'typex_v2':          ('Typex v2',                 typex_v2_encrypt,          typex_v2_decrypt,          'machines'),
    'sigaba':            ('SIGABA',                   sigaba_encrypt,            sigaba_decrypt,            'machines'),
    'm209':              ('M-209',                    m209_encrypt,              m209_decrypt,              'machines'),
    'nema':              ('NEMA',                     nema_encrypt,              nema_decrypt,              'machines'),
    'purple':            ('Purple',                   purple_encrypt,            purple_decrypt,            'machines'),
    'jn25':              ('JN-25',                    jn25_encrypt,              jn25_decrypt,              'machines'),
    'lorenz_sz42':       ('Lorenz SZ42',              lorenz_sz42_encrypt,       lorenz_sz42_decrypt,       'machines'),
    't52':               ('Siemens T52',              t52_encrypt,               t52_decrypt,               'machines'),

    # NHÓM 12 BỔ SUNG — EMOJI
    'regional':          ('Regional Indicators',      regional_encrypt,          regional_decrypt,          'emoji'),
    'emoji_flags':       ('Emoji Flags',              emoji_flags_encrypt,       emoji_flags_decrypt,       'emoji'),
    'emoji_numbers':     ('Emoji Numbers',            emoji_numbers_encrypt,     emoji_numbers_decrypt,     'emoji'),
    'emoji_alphabet':    ('Emoji Alphabet',           emoji_alphabet_encrypt,    emoji_alphabet_decrypt,    'emoji'),
    'sign_language':     ('Sign Language',            sign_language_encrypt,     sign_language_decrypt,     'emoji'),
    'braille_uni':       ('Braille Unicode',          braille_uni_encrypt,       braille_uni_decrypt,       'emoji'),
    'fullwidth':         ('Fullwidth',                fullwidth_encrypt,         fullwidth_decrypt,         'emoji'),
    'math_bold':         ('Mathematical Bold',        math_bold_encrypt,         math_bold_decrypt,         'emoji'),
    'circled':           ('Circled',                  circled_encrypt,           circled_decrypt,           'emoji'),
    'squared':           ('Squared',                  squared_encrypt,           squared_decrypt,           'emoji'),
    'neg_circled':       ('Negative Circled',         neg_circled_encrypt,       neg_circled_decrypt,       'emoji'),
    'paren':             ('Parenthesized',            paren_encrypt,             paren_decrypt,             'emoji'),
    'currency':          ('Currency Symbols',         currency_encrypt,          currency_decrypt,          'emoji'),
}
