# -*- coding: utf-8 -*-
"""Crypto utilities - 40+ hàm mã hóa"""
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

def strip_viet(t):
    t = t.replace('đ', 'd').replace('Đ', 'D')
    return ''.join(c for c in unicodedata.normalize('NFD', t)
                   if unicodedata.category(c) != 'Mn')

def no_encrypt(t, k): return t
def no_decrypt(t, k): return t

def to_binary(t, k): return " ".join(f"{b:08b}" for b in t.encode("utf-8"))
def from_binary(d, k):
    d = d.replace(" ", "").replace("\n", "")
    if len(d) % 8 != 0: raise ValueError("Độ dài nhị phân phải chia hết cho 8.")
    return bytes(int(d[i:i+8], 2) for i in range(0, len(d), 8)).decode("utf-8")

def to_base64(t, k): return base64.b64encode(t.encode("utf-8")).decode("ascii")
def from_base64(d, k): return base64.b64decode(d.strip().replace("\n","").replace(" ","")).decode("utf-8")
def to_base32(t, k): return base64.b32encode(t.encode("utf-8")).decode("ascii")
def from_base32(d, k): return base64.b32decode(d.strip().replace("\n","").replace(" ","")).decode("utf-8")
def to_hex(t, k): return " ".join(f"{b:02X}" for b in t.encode("utf-8"))
def from_hex(d, k):
    d = d.replace(" ","").replace("\n","").replace("0x","").replace("0X","")
    return bytes.fromhex(d).decode("utf-8")

def rot13_fn(t, k=None): return codecs.encode(t, 'rot_13')
def atbash(t, k=None):
    return ''.join(chr(ord('z') - (ord(c) - ord('a'))) if c.islower()
                   else chr(ord('Z') - (ord(c) - ord('A'))) if c.isupper()
                   else c for c in t)

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

def caesar_dec(t, k): return caesar_enc(t, -(int(k) if k and k.lstrip('-').isdigit() else 3))

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
def to_url(t, k): return urllib.parse.quote(t, safe="")
def from_url(d, k): return urllib.parse.unquote(d)
def to_html_fn(t, k): return html.escape(t)
def from_html_fn(d, k): return html.unescape(d)

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
def to_no_accent(t, k): return strip_viet(t)
def from_no_accent(d, k): raise ValueError("Không thể giải mã 'không dấu'!")

def hash_md5(t, k): return hashlib.md5(t.encode("utf-8")).hexdigest()
def hash_sha1(t, k): return hashlib.sha1(t.encode("utf-8")).hexdigest()
def hash_sha256(t, k): return hashlib.sha256(t.encode("utf-8")).hexdigest()
def hash_sha512(t, k): return hashlib.sha512(t.encode("utf-8")).hexdigest()
def hash_err(d, k): raise ValueError("Hash là hàm một chiều!")

def gzip_encode(t, k):
    return base64.b64encode(gzip.compress(t.encode("utf-8"))).decode("ascii")
def gzip_decode(d, k):
    return gzip.decompress(base64.b64decode(d.strip())).decode("utf-8")
def zlib_encode(t, k):
    return base64.b64encode(zlib.compress(t.encode("utf-8"))).decode("ascii")
def zlib_decode(d, k):
    return zlib.decompress(base64.b64decode(d.strip())).decode("utf-8")

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

def xor_encrypt(text, key):
    if not key: raise ValueError("Nhập khóa!")
    kb = key.encode("utf-8"); tb = text.encode("utf-8")
    return base64.b64encode(bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb)))).decode("ascii")
def xor_decrypt(data, key):
    if not key: raise ValueError("Nhập khóa!")
    kb = key.encode("utf-8"); tb = base64.b64decode(data.strip())
    return bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb))).decode("utf-8")

ENCODERS = {
    "none":     ("⭕ Không mã hóa",  "Không mã hóa", no_encrypt,    no_decrypt),
    "binary":   ("🔢 Nhị phân",      "Cơ bản",     to_binary,     from_binary),
    "base64":   ("📦 Base64",        "Cơ bản",     to_base64,     from_base64),
    "base32":   ("🗜 Base32",        "Cơ bản",     to_base32,     from_base32),
    "hex":      ("#️⃣ Hex",           "Cơ bản",     to_hex,        from_hex),
    "rot13":    ("🔄 ROT13",         "Cổ điển",    rot13_fn,      rot13_fn),
    "atbash":   ("🔤 Atbash",        "Cổ điển",    atbash,        atbash),
    "caesar":   ("🏛 Caesar",        "Cổ điển",    caesar_enc,    caesar_dec),
    "unicode":  ("🌐 Unicode",       "Ký tự",      to_unicode,    from_unicode),
    "ascii":    ("🔤 ASCII",         "Ký tự",      to_ascii,      from_ascii),
    "morse":    ("📡 Morse",         "Ký tự",      to_morse,      from_morse),
    "url":      ("🔗 URL Encode",    "Web",        to_url,        from_url),
    "html":     ("🌍 HTML Entity",   "Web",        to_html_fn,    from_html_fn),
    "telex":    ("🚫 Không dấu",     "Tiếng Việt", to_telex,      from_telex),
    "noaccent": ("🚫 Bỏ dấu",        "Tiếng Việt", to_no_accent,  from_no_accent),
    "md5":      ("🔒 MD5",           "Hash",       hash_md5,      hash_err),
    "sha1":     ("🔒 SHA-1",         "Hash",       hash_sha1,     hash_err),
    "sha256":   ("🔒 SHA-256",       "Hash",       hash_sha256,   hash_err),
    "sha512":   ("🔒 SHA-512",       "Hash",       hash_sha512,   hash_err),
    "aes":      ("🔐 AES-256",       "Bảo mật",    aes_encrypt,   aes_decrypt),
    "xor":      ("🧮 XOR",           "Bảo mật",    xor_encrypt,   xor_decrypt),
    "gzip":     ("🗜 Gzip + B64",    "Nén",        gzip_encode,   gzip_decode),
    "zlib":     ("🗜 Zlib + B64",    "Nén",        zlib_encode,   zlib_decode),
}
if not CRYPTO_OK:
    ENCODERS.pop("aes", None)

GROUP_ORDER = ["Không mã hóa", "Cơ bản", "Cổ điển", "Ký tự", "Web",
               "Tiếng Việt", "Hash", "Bảo mật", "Nén"]

def get_grouped():
    result = {}
    for key, (label, group, _, _) in ENCODERS.items():
        if group not in result:
            result[group] = []
        result[group].append({"key": key, "label": label})
    return result
