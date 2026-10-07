# -*- coding: utf-8 -*-
"""
Crypto utilities - tập hợp 40+ hàm mã hóa
"""
import base64, codecs, unicodedata, urllib.parse, html, hashlib, os
import zlib, gzip

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

try:
    import bcrypt
    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False

try:
    from Crypto.Cipher import DES, DES3, Blowfish, ARC4, ChaCha20
    PYCRYPTO_OK = True
except ImportError:
    PYCRYPTO_OK = False

# ===== Bảng mã =====
MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
    "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
    '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
    ' ': '/'
}
MORSE_REVERSE = {v: k for k, v in MORSE_CODE.items()}

TELEX_MAP = {
    'ă': 'aw', 'â': 'aa', 'ê': 'ee', 'ô': 'oo', 'ơ': 'ow', 'ư': 'uw', 'đ': 'dd',
    'á': 'as', 'à': 'af', 'ả': 'ar', 'ã': 'ax', 'ạ': 'aj',
    'ấ': 'aas', 'ầ': 'aaf', 'ẩ': 'aar', 'ẫ': 'aax', 'ậ': 'aaj',
    'ắ': 'aws', 'ằ': 'awf', 'ẳ': 'awr', 'ẵ': 'awx', 'ặ': 'awj',
    'é': 'es', 'è': 'ef', 'ẻ': 'er', 'ẽ': 'ex', 'ẹ': 'ej',
    'ế': 'ees', 'ề': 'eef', 'ể': 'eer', 'ễ': 'eex', 'ệ': 'eej',
    'í': 'is', 'ì': 'if', 'ỉ': 'ir', 'ĩ': 'ix', 'ị': 'ij',
    'ó': 'os', 'ò': 'of', 'ỏ': 'or', 'õ': 'ox', 'ọ': 'oj',
    'ố': 'oos', 'ồ': 'oof', 'ổ': 'oor', 'ỗ': 'oox', 'ộ': 'ooj',
    'ớ': 'ows', 'ờ': 'owf', 'ở': 'owr', 'ỡ': 'owx', 'ợ': 'owj',
    'ú': 'us', 'ù': 'uf', 'ủ': 'ur', 'ũ': 'ux', 'ụ': 'uj',
    'ứ': 'uws', 'ừ': 'uwf', 'ử': 'uwr', 'ữ': 'uwx', 'ự': 'uwj',
    'ý': 'ys', 'ỳ': 'yf', 'ỷ': 'yr', 'ỹ': 'yx', 'ỵ': 'yj',
    'Ă': 'Aw', 'Â': 'Aa', 'Ê': 'Ee', 'Ô': 'Oo', 'Ơ': 'Ow', 'Ư': 'Uw', 'Đ': 'Dd',
}
TELEX_REVERSE = {v: k for k, v in TELEX_MAP.items()}

VNI_MAP = {
    'ă': 'a8', 'â': 'a6', 'ê': 'e6', 'ô': 'o6', 'ơ': 'o7', 'ư': 'u7', 'đ': 'd9',
    'á': 'a1', 'à': 'a2', 'ả': 'a3', 'ã': 'a4', 'ạ': 'a5',
    'ấ': 'a61', 'ầ': 'a62', 'ẩ': 'a63', 'ẫ': 'a64', 'ậ': 'a65',
    'ắ': 'a81', 'ằ': 'a82', 'ẳ': 'a83', 'ẵ': 'a84', 'ặ': 'a85',
    'é': 'e1', 'è': 'e2', 'ẻ': 'e3', 'ẽ': 'e4', 'ẹ': 'e5',
    'ế': 'e61', 'ề': 'e62', 'ể': 'e63', 'ễ': 'e64', 'ệ': 'e65',
    'í': 'i1', 'ì': 'i2', 'ỉ': 'i3', 'ĩ': 'i4', 'ị': 'i5',
    'ó': 'o1', 'ò': 'o2', 'ỏ': 'o3', 'õ': 'o4', 'ọ': 'o5',
    'ố': 'o61', 'ồ': 'o62', 'ổ': 'o63', 'ỗ': 'o64', 'ộ': 'o65',
    'ớ': 'o71', 'ờ': 'o72', 'ở': 'o73', 'ỡ': 'o74', 'ợ': 'o75',
    'ú': 'u1', 'ù': 'u2', 'ủ': 'u3', 'ũ': 'u4', 'ụ': 'u5',
    'ứ': 'u71', 'ừ': 'u72', 'ử': 'u73', 'ữ': 'u74', 'ự': 'u75',
    'ý': 'y1', 'ỳ': 'y2', 'ỷ': 'y3', 'ỹ': 'y4', 'ỵ': 'y5',
}
VNI_REVERSE = {v: k for k, v in VNI_MAP.items()}

VIQR_MAP = {
    'ă': 'a(', 'â': 'a^', 'ê': 'e^', 'ô': 'o^', 'ơ': 'o+', 'ư': 'u+', 'đ': 'dd',
    'á': "a'", 'à': 'a`', 'ả': 'a?', 'ã': 'a~', 'ạ': 'a.',
    'ấ': "a^'", 'ầ': 'a^`', 'ẩ': 'a^?', 'ẫ': 'a^~', 'ậ': 'a^.',
    'ắ': "a('", 'ằ': 'a(`', 'ẳ': 'a(?', 'ẵ': 'a(~', 'ặ': 'a(.',
    'é': "e'", 'è': 'e`', 'ẻ': 'e?', 'ẽ': 'e~', 'ẹ': 'e.',
    'ế': "e^'", 'ề': 'e^`', 'ể': 'e^?', 'ễ': 'e^~', 'ệ': 'e^.',
    'í': "i'", 'ì': 'i`', 'ỉ': 'i?', 'ĩ': 'i~', 'ị': 'i.',
    'ó': "o'", 'ò': 'o`', 'ỏ': 'o?', 'õ': 'o~', 'ọ': 'o.',
    'ố': "o^'", 'ồ': 'o^`', 'ổ': 'o^?', 'ỗ': 'o^~', 'ộ': 'o^.',
    'ớ': "o+'", 'ờ': 'o+`', 'ở': 'o+?', 'ỡ': 'o+~', 'ợ': 'o+.',
    'ú': "u'", 'ù': 'u`', 'ủ': 'u?', 'ũ': 'u~', 'ụ': 'u.',
    'ứ': "u+'", 'ừ': 'u+`', 'ử': 'u+?', 'ữ': 'u+~', 'ự': 'u+.',
    'ý': "y'", 'ỳ': 'y`', 'ỷ': 'y?', 'ỹ': 'y~', 'ỵ': 'y.',
}
VIQR_REVERSE = {v: k for k, v in VIQR_MAP.items()}

# ===== Hàm helper =====
def strip_viet(t):
    t = t.replace('đ', 'd').replace('Đ', 'D')
    return ''.join(c for c in unicodedata.normalize('NFD', t)
                   if unicodedata.category(c) != 'Mn')

def no_encrypt(t, k): return t
def no_decrypt(t, k): return t

# ===== Base =====
def to_binary(t, k): return " ".join(f"{b:08b}" for b in t.encode("utf-8"))
def from_binary(d, k):
    d = d.replace(" ", "").replace("\n", "")
    if len(d) % 8 != 0: raise ValueError("Độ dài nhị phân phải chia hết cho 8.")
    return bytes(int(d[i:i+8], 2) for i in range(0, len(d), 8)).decode("utf-8")

def to_base64(t, k): return base64.b64encode(t.encode("utf-8")).decode("ascii")
def from_base64(d, k): return base64.b64decode(d.strip().replace("\n","").replace(" ","")).decode("utf-8")
def to_base32(t, k): return base64.b32encode(t.encode("utf-8")).decode("ascii")
def from_base32(d, k): return base64.b32decode(d.strip().replace("\n","").replace(" ","")).decode("utf-8")
def to_base85(t, k): return base64.b85encode(t.encode("utf-8")).decode("ascii")
def from_base85(d, k): return base64.b85decode(d.strip().encode("ascii")).decode("utf-8")
def to_a85(t, k): return base64.a85encode(t.encode("utf-8")).decode("ascii")
def from_a85(d, k): return base64.a85decode(d.strip()).decode("utf-8")
def to_base16(t, k): return base64.b16encode(t.encode("utf-8")).decode("ascii")
def from_base16(d, k): return base64.b16decode(d.strip()).decode("utf-8")
def to_hex(t, k): return " ".join(f"{b:02X}" for b in t.encode("utf-8"))
def from_hex(d, k):
    d = d.replace(" ","").replace("\n","").replace("0x","").replace("0X","")
    return bytes.fromhex(d).decode("utf-8")

# ===== Cổ điển =====
def rot13_fn(t, k=None): return codecs.encode(t, 'rot_13')
def rot47(t, k=None):
    out = []
    for c in t:
        o = ord(c)
        if 33 <= o <= 126: out.append(chr(33 + ((o - 33 + 47) % 94)))
        else: out.append(c)
    return ''.join(out)
def atbash(t, k=None):
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            if c.islower(): out.append(chr(ord('z') - (ord(c) - ord('a'))))
            else: out.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else: out.append(c)
    return ''.join(out)

def caesar_enc(t, k):
    try: shift = int(k) if k else 3
    except ValueError: shift = 3
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - b + shift) % 26 + b))
        else: out.append(c)
    return ''.join(out)

def caesar_dec(t, k):
    try: shift = int(k) if k else 3
    except ValueError: shift = 3
    return caesar_enc(t, -shift)

def vigenere_enc(t, k):
    if not k: raise ValueError("Nhập khóa!")
    k = ''.join(c for c in k.upper() if c.isalpha())
    if not k: raise ValueError("Khóa phải có chữ cái!")
    out = []; ki = 0
    for c in t:
        if c.isalpha() and ord(c) < 128:
            shift = ord(k[ki % len(k)]) - ord('A')
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - b + shift) % 26 + b)); ki += 1
        else: out.append(c)
    return ''.join(out)

def vigenere_dec(t, k):
    if not k: raise ValueError("Nhập khóa!")
    k = ''.join(c for c in k.upper() if c.isalpha())
    if not k: raise ValueError("Khóa phải có chữ cái!")
    out = []; ki = 0
    for c in t:
        if c.isalpha() and ord(c) < 128:
            shift = ord(k[ki % len(k)]) - ord('A')
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - b - shift) % 26 + b)); ki += 1
        else: out.append(c)
    return ''.join(out)

def affine_enc(t, k):
    try:
        parts = k.split(",") if k else ["5", "8"]
        a = int(parts[0]) % 26; b = int(parts[1]) % 26 if len(parts) > 1 else 8
    except Exception: a, b = 5, 8
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((a * (ord(c) - base) + b) % 26 + base))
        else: out.append(c)
    return ''.join(out)

def affine_dec(t, k):
    try:
        parts = k.split(",") if k else ["5", "8"]
        a = int(parts[0]) % 26; b = int(parts[1]) % 26 if len(parts) > 1 else 8
    except Exception: a, b = 5, 8
    try: a_inv = pow(a, -1, 26)
    except ValueError: raise ValueError(f"a={a} không hợp lệ!")
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((a_inv * (ord(c) - base - b)) % 26 + base))
        else: out.append(c)
    return ''.join(out)

def rail_fence_enc(t, k):
    try: rails = max(2, int(k) if k else 3)
    except ValueError: rails = 3
    fence = [[] for _ in range(rails)]
    rail = 0; d = 1
    for c in t:
        fence[rail].append(c)
        if rail == 0: d = 1
        elif rail == rails - 1: d = -1
        rail += d
    return ''.join(''.join(r) for r in fence)

def rail_fence_dec(t, k):
    try: rails = max(2, int(k) if k else 3)
    except ValueError: rails = 3
    pattern = []; rail = 0; d = 1
    for _ in t:
        pattern.append(rail)
        if rail == 0: d = 1
        elif rail == rails - 1: d = -1
        rail += d
    counts = [pattern.count(r) for r in range(rails)]
    chunks = []; idx = 0
    for cnt in counts:
        chunks.append(list(t[idx:idx+cnt])); idx += cnt
    out = []; pos = [0] * rails
    for r in pattern:
        out.append(chunks[r][pos[r]]); pos[r] += 1
    return ''.join(out)

def columnar_enc(t, k):
    if not k: raise ValueError("Nhập khóa!")
    key = k.upper(); n = len(key)
    pad = (-len(t)) % n
    t = t + " " * pad
    rows = [t[i:i+n] for i in range(0, len(t), n)]
    order = sorted(range(n), key=lambda i: key[i])
    result = []
    for col in order:
        for row in rows: result.append(row[col])
    return ''.join(result)

def columnar_dec(t, k):
    if not k: raise ValueError("Nhập khóa!")
    key = k.upper(); n = len(key)
    if len(t) % n != 0: raise ValueError("Độ dài không chia hết cho khóa!")
    rows_count = len(t) // n
    order = sorted(range(n), key=lambda i: key[i])
    cols = {}; idx = 0
    for col in order:
        cols[col] = list(t[idx:idx+rows_count]); idx += rows_count
    result = []
    for r in range(rows_count):
        for c in range(n): result.append(cols[c][r])
    return ''.join(result).rstrip()

# ===== Ký tự =====
def to_unicode(t, k): return " ".join(f"U+{ord(c):04X}" for c in t)
def from_unicode(d, k):
    return "".join(chr(int(p.replace("U+","").replace("u+",""), 16))
                   for p in d.replace(","," ").split())
def to_ascii(t, k): return " ".join(str(ord(c)) for c in t)
def from_ascii(d, k): return "".join(chr(int(p)) for p in d.replace(","," ").split())
def to_morse(t, k):
    return " ".join(MORSE_CODE.get(c, '?') for c in strip_viet(t).upper())
def from_morse(d, k):
    return " ".join("".join(MORSE_REVERSE.get(c, '?') for c in w.split())
                    for w in d.strip().split(" / "))

# ===== Web =====
def to_url(t, k): return urllib.parse.quote(t, safe="")
def from_url(d, k): return urllib.parse.unquote(d)
def to_html_fn(t, k): return html.escape(t)
def from_html_fn(d, k): return html.unescape(d)

# ===== Tiếng Việt =====
def _to_syl(t, m): return "".join(m.get(c, c) for c in t)
def _from_syl(t, rm):
    keys = sorted(rm.keys(), key=len, reverse=True)
    out, i = [], 0
    while i < len(t):
        matched = False
        for kk in keys:
            if t[i:i+len(kk)].lower() == kk.lower():
                orig = t[i:i+len(kk)]
                v = rm[kk]
                if orig[0].isupper() and v:
                    v = v.upper() if len(v) == 1 else v[0].upper() + v[1:]
                out.append(v); i += len(kk); matched = True; break
        if not matched: out.append(t[i]); i += 1
    return "".join(out)

def to_telex(t, k): return _to_syl(t, TELEX_MAP)
def from_telex(t, k): return _from_syl(t, TELEX_REVERSE)
def to_vni(t, k): return _to_syl(t, VNI_MAP)
def from_vni(t, k): return _from_syl(t, VNI_REVERSE)
def to_viqr(t, k): return _to_syl(t, VIQR_MAP)
def from_viqr(t, k): return _from_syl(t, VIQR_REVERSE)
def to_no_accent(t, k): return strip_viet(t)
def from_no_accent(d, k): raise ValueError("Không thể giải mã 'không dấu'!")

# ===== Hash =====
def hash_md5(t, k): return hashlib.md5(t.encode("utf-8")).hexdigest()
def hash_sha1(t, k): return hashlib.sha1(t.encode("utf-8")).hexdigest()
def hash_sha256(t, k): return hashlib.sha256(t.encode("utf-8")).hexdigest()
def hash_sha512(t, k): return hashlib.sha512(t.encode("utf-8")).hexdigest()
def hash_err(d, k): raise ValueError("Hash một chiều!")

def bcrypt_hash(t, k):
    if not BCRYPT_OK: raise ValueError("Cần bcrypt!")
    return bcrypt.hashpw(t.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def bcrypt_verify(t, k):
    if not BCRYPT_OK: raise ValueError("Cần bcrypt!")
    try:
        return "✅ Đúng" if bcrypt.checkpw(k.encode("utf-8"), t.strip().encode("utf-8")) else "❌ Sai"
    except Exception as e: raise ValueError(f"Hash sai: {e}")

def pbkdf2_hash(t, k):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', t.encode("utf-8"), salt, 100000)
    return base64.b64encode(salt + dk).decode("ascii")
def pbkdf2_err(d, k): raise ValueError("PBKDF2 một chiều!")

# ===== Nén =====
def gzip_encode(t, k):
    return base64.b64encode(gzip.compress(t.encode("utf-8"))).decode("ascii")
def gzip_decode(d, k):
    return gzip.decompress(base64.b64decode(d.strip())).decode("utf-8")
def zlib_encode(t, k):
    return base64.b64encode(zlib.compress(t.encode("utf-8"))).decode("ascii")
def zlib_decode(d, k):
    return zlib.decompress(base64.b64decode(d.strip())).decode("utf-8")

# ===== AES =====
def aes_encrypt(text, key):
    if not CRYPTO_OK: raise ValueError("Cần cryptography!")
    if not key: raise ValueError("Nhập khóa!")
    k = hashlib.sha256(key.encode("utf-8")).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode("utf-8")) + padder.finalize()
    c = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).encryptor()
    return base64.b64encode(iv + c.update(padded) + c.finalize()).decode("ascii")

def aes_decrypt(data, key):
    if not CRYPTO_OK: raise ValueError("Cần cryptography!")
    if not key: raise ValueError("Nhập khóa!")
    k = hashlib.sha256(key.encode("utf-8")).digest()
    raw = base64.b64decode(data.strip())
    iv, ct = raw[:16], raw[16:]
    c = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = c.update(ct) + c.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
    except Exception: raise ValueError("Khóa sai!")

# ===== DES / 3DES / Blowfish / RC4 / ChaCha20 =====
def _mk8(key): return hashlib.sha256(key.encode("utf-8")).digest()[:8]
def _mk16(key): return hashlib.sha256(key.encode("utf-8")).digest()[:16]
def _mk24(key): return hashlib.sha256(key.encode("utf-8")).digest()[:24]
def _pad8(d):
    p = 8 - (len(d) % 8); return d + bytes([p]*p)
def _unpad8(d): return d[:-d[-1]]

def des_encrypt(text, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = _mk8(key); iv = os.urandom(8)
    c = DES.new(k, DES.MODE_CBC, iv)
    return base64.b64encode(iv + c.encrypt(_pad8(text.encode("utf-8")))).decode("ascii")
def des_decrypt(data, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = _mk8(key)
    raw = base64.b64decode(data.strip()); iv, ct = raw[:8], raw[8:]
    c = DES.new(k, DES.MODE_CBC, iv)
    return _unpad8(c.decrypt(ct)).decode("utf-8")

def des3_encrypt(text, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = _mk24(key)
    try:
        k = DES3.adjust_key_parity(k); c = DES3.new(k, DES3.MODE_CBC)
    except Exception:
        k = _mk16(key); c = DES3.new(k, DES3.MODE_CBC)
    return base64.b64encode(c.iv + c.encrypt(_pad8(text.encode("utf-8")))).decode("ascii")
def des3_decrypt(data, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = _mk24(key)
    try: k = DES3.adjust_key_parity(k)
    except Exception: k = _mk16(key)
    raw = base64.b64decode(data.strip()); iv, ct = raw[:8], raw[8:]
    c = DES3.new(k, DES3.MODE_CBC, iv)
    return _unpad8(c.decrypt(ct)).decode("utf-8")

def blowfish_encrypt(text, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = _mk16(key); iv = os.urandom(8)
    c = Blowfish.new(k, Blowfish.MODE_CBC, iv)
    return base64.b64encode(iv + c.encrypt(_pad8(text.encode("utf-8")))).decode("ascii")
def blowfish_decrypt(data, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = _mk16(key)
    raw = base64.b64decode(data.strip()); iv, ct = raw[:8], raw[8:]
    c = Blowfish.new(k, Blowfish.MODE_CBC, iv)
    return _unpad8(c.decrypt(ct)).decode("utf-8")

def rc4_encrypt(text, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    return base64.b64encode(ARC4.new(_mk16(key)).encrypt(text.encode("utf-8"))).decode("ascii")
def rc4_decrypt(data, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    return ARC4.new(_mk16(key)).decrypt(base64.b64decode(data.strip())).decode("utf-8")

def chacha_encrypt(text, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = hashlib.sha256(key.encode("utf-8")).digest(); nonce = os.urandom(8)
    c = ChaCha20.new(key=k, nonce=nonce)
    return base64.b64encode(nonce + c.encrypt(text.encode("utf-8"))).decode("ascii")
def chacha_decrypt(data, key):
    if not PYCRYPTO_OK: raise ValueError("Cần pycryptodome!")
    if not key: raise ValueError("Nhập khóa!")
    k = hashlib.sha256(key.encode("utf-8")).digest()
    raw = base64.b64decode(data.strip()); nonce, ct = raw[:8], raw[8:]
    c = ChaCha20.new(key=k, nonce=nonce)
    return c.decrypt(ct).decode("utf-8")

# ===== RSA =====
_RSA = {"priv": None, "pub": None}
def rsa_gen():
    if not CRYPTO_OK: raise ValueError("Cần cryptography!")
    p = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    _RSA["priv"] = p; _RSA["pub"] = p.public_key()

def rsa_encrypt(text, key):
    if not CRYPTO_OK: raise ValueError("Cần cryptography!")
    if _RSA["pub"] is None: rsa_gen()
    ct = _RSA["pub"].encrypt(text.encode("utf-8"),
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(ct).decode("ascii")
def rsa_decrypt(data, key):
    if not CRYPTO_OK: raise ValueError("Cần cryptography!")
    if _RSA["priv"] is None: raise ValueError("Chưa có khóa riêng!")
    pt = _RSA["priv"].decrypt(base64.b64decode(data.strip()),
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))
    return pt.decode("utf-8")

# ===== XOR & PWD =====
def xor_encrypt(text, key):
    if not key: raise ValueError("Nhập khóa!")
    kb = key.encode("utf-8"); tb = text.encode("utf-8")
    return base64.b64encode(bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb)))).decode("ascii")
def xor_decrypt(data, key):
    if not key: raise ValueError("Nhập khóa!")
    kb = key.encode("utf-8"); tb = base64.b64decode(data.strip())
    return bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb))).decode("utf-8")

def pwd_encrypt(text, key): return "PWD1:" + aes_encrypt(text, key)
def pwd_decrypt(data, key):
    if not data.startswith("PWD1:"): raise ValueError("Không phải PWD1!")
    return aes_decrypt(data[5:], key)

# ============================================================
# ENCODERS MAP
# ============================================================
ENCODERS = {
    "none":     ("⭕ Không mã hóa",  "Không mã hóa", no_encrypt,    no_decrypt),
    "binary":   ("🔢 Nhị phân",      "Cơ bản",     to_binary,     from_binary),
    "base64":   ("📦 Base64",        "Cơ bản",     to_base64,     from_base64),
    "base32":   ("🗜 Base32",        "Cơ bản",     to_base32,     from_base32),
    "base85":   ("🔷 Base85",        "Cơ bản",     to_base85,     from_base85),
    "a85":      ("🔶 Ascii85",       "Cơ bản",     to_a85,        from_a85),
    "base16":   ("🔡 Base16",        "Cơ bản",     to_base16,     from_base16),
    "hex":      ("#️⃣ Hex",           "Cơ bản",     to_hex,        from_hex),
    "rot13":    ("🔄 ROT13",         "Cổ điển",    rot13_fn,      rot13_fn),
    "rot47":    ("🔃 ROT47",         "Cổ điển",    rot47,         rot47),
    "atbash":   ("🔤 Atbash",        "Cổ điển",    atbash,        atbash),
    "caesar":   ("🏛 Caesar",        "Cổ điển",    caesar_enc,    caesar_dec),
    "vigenere": ("🔐 Vigenère",      "Cổ điển",    vigenere_enc,  vigenere_dec),
    "affine":   ("🎯 Affine",        "Cổ điển",    affine_enc,    affine_dec),
    "railfence":("🚂 Rail Fence",    "Cổ điển",    rail_fence_enc, rail_fence_dec),
    "columnar": ("📊 Columnar",      "Cổ điển",    columnar_enc,  columnar_dec),
    "unicode":  ("🌐 Unicode",       "Ký tự",      to_unicode,    from_unicode),
    "ascii":    ("🔤 ASCII",         "Ký tự",      to_ascii,      from_ascii),
    "morse":    ("📡 Morse",         "Ký tự",      to_morse,      from_morse),
    "url":      ("🔗 URL Encode",    "Web",        to_url,        from_url),
    "html":     ("🌍 HTML Entity",   "Web",        to_html_fn,    from_html_fn),
    "telex":    ("🚫 Không dấu",     "Tiếng Việt", to_telex,      from_telex),
    "vni":      ("🇻🇳 VNI",          "Tiếng Việt", to_vni,        from_vni),
    "viqr":     ("🇻🇳 VIQR",         "Tiếng Việt", to_viqr,       from_viqr),
    "noaccent": ("🚫 Bỏ dấu",        "Tiếng Việt", to_no_accent,  from_no_accent),
    "md5":      ("🔒 MD5",           "Hash",       hash_md5,      hash_err),
    "sha1":     ("🔒 SHA-1",         "Hash",       hash_sha1,     hash_err),
    "sha256":   ("🔒 SHA-256",       "Hash",       hash_sha256,   hash_err),
    "sha512":   ("🔒 SHA-512",       "Hash",       hash_sha512,   hash_err),
    "pbkdf2":   ("🔐 PBKDF2",        "Hash",       pbkdf2_hash,   pbkdf2_err),
    "aes":      ("🔐 AES-256",       "Bảo mật",    aes_encrypt,   aes_decrypt),
    "rsa":      ("🔑 RSA-2048",      "Bảo mật",    rsa_encrypt,   rsa_decrypt),
    "xor":      ("🧮 XOR",           "Bảo mật",    xor_encrypt,   xor_decrypt),
    "pwd":      ("🔐 Mật khẩu",      "Bảo mật",    pwd_encrypt,   pwd_decrypt),
    "gzip":     ("🗜 Gzip + B64",    "Nén",        gzip_encode,   gzip_decode),
    "zlib":     ("🗜 Zlib + B64",    "Nén",        zlib_encode,   zlib_decode),
}
if CRYPTO_OK:
    ENCODERS["bcrypt"] = ("🔒 Bcrypt", "Bảo mật", bcrypt_hash, bcrypt_verify)
if PYCRYPTO_OK:
    ENCODERS["des"] = ("🔐 DES", "Bảo mật", des_encrypt, des_decrypt)
    ENCODERS["des3"] = ("🔐 3DES", "Bảo mật", des3_encrypt, des3_decrypt)
    ENCODERS["blowfish"] = ("🐡 Blowfish", "Bảo mật", blowfish_encrypt, blowfish_decrypt)
    ENCODERS["rc4"] = ("📻 RC4", "Bảo mật", rc4_encrypt, rc4_decrypt)
    ENCODERS["chacha"] = ("🌊 ChaCha20", "Bảo mật", chacha_encrypt, chacha_decrypt)

GROUP_ORDER = ["Không mã hóa", "Cơ bản", "Cổ điển", "Ký tự", "Web",
               "Tiếng Việt", "Hash", "Bảo mật", "Nén"]

def get_grouped():
    """Trả về dict nhóm → list thuật toán cho frontend."""
    result = {}
    for key, (label, group, _, _) in ENCODERS.items():
        if group not in result:
            result[group] = []
        result[group].append({"key": key, "label": label})
    return result