# -*- coding: utf-8 -*-
"""Crypto utilities - 70+ hàm mã hóa"""
import base64, codecs, unicodedata, urllib.parse, html, hashlib, os
import zlib, gzip, binascii, struct, json, string

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

try:
    import bcrypt
    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False


# ==================== BẢNG MÃ ====================
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

BACON_MAP = {chr(65 + i): format(i, '05b').replace('0', 'A').replace('1', 'B') for i in range(26)}
BACON_REVERSE = {v: k for k, v in BACON_MAP.items()}

POLYBIUS_MAP = {}
for i, c in enumerate("ABCDEFGHIKLMNOPQRSTUVWXYZ"):  # Bỏ J
    POLYBIUS_MAP[c] = f"{i // 5 + 1}{i % 5 + 1}"
POLYBIUS_REVERSE = {v: k for k, v in POLYBIUS_MAP.items()}

NATO_MAP = {
    'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
    'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliett',
    'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
    'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray', 'Y': 'Yankee',
    'Z': 'Zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three',
    '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine'
}
NATO_REVERSE = {v.upper(): k for k, v in NATO_MAP.items()}

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase


# ==================== HÀM TIỆN ÍCH ====================
def strip_viet(t):
    t = t.replace('đ', 'd').replace('Đ', 'D')
    return ''.join(c for c in unicodedata.normalize('NFD', t)
                   if unicodedata.category(c) != 'Mn')


# ==================== NHÓM KHÔNG MÃ HÓA ====================
def no_encrypt(t, k): return t
def no_decrypt(t, k): return t


# ==================== NHÓM CƠ BẢN ====================
def to_binary(t, k):
    return " ".join(f"{b:08b}" for b in t.encode("utf-8"))

def from_binary(d, k):
    d = d.replace(" ", "").replace("\n", "")
    if len(d) % 8 != 0:
        raise ValueError("Độ dài nhị phân phải chia hết cho 8.")
    return bytes(int(d[i:i+8], 2) for i in range(0, len(d), 8)).decode("utf-8")


def to_octal(t, k):
    return " ".join(f"{b:03o}" for b in t.encode("utf-8"))

def from_octal(d, k):
    d = d.replace(" ", "").replace("\n", "")
    if len(d) % 3 != 0:
        raise ValueError("Độ dài octal phải chia hết cho 3.")
    return bytes(int(d[i:i+3], 8) for i in range(0, len(d), 3)).decode("utf-8")


def to_decimal(t, k):
    return " ".join(str(b) for b in t.encode("utf-8"))

def from_decimal(d, k):
    return bytes(int(p) for p in d.split()).decode("utf-8")


def to_base64(t, k):
    return base64.b64encode(t.encode("utf-8")).decode("ascii")

def from_base64(d, k):
    return base64.b64decode(d.strip().replace("\n", "").replace(" ", "")).decode("utf-8")


def to_base64url(t, k):
    return base64.urlsafe_b64encode(t.encode("utf-8")).decode("ascii").rstrip("=")

def from_base64url(d, k):
    d = d.strip()
    d += "=" * (4 - len(d) % 4)
    return base64.urlsafe_b64decode(d).decode("utf-8")


def to_base32(t, k):
    return base64.b32encode(t.encode("utf-8")).decode("ascii")

def from_base32(d, k):
    return base64.b32decode(d.strip().replace("\n", "").replace(" ", "")).decode("utf-8")


def to_base58(t, k):
    data = t.encode("utf-8")
    n = int.from_bytes(data, 'big')
    result = ""
    while n > 0:
        n, r = divmod(n, 58)
        result = BASE58_ALPHABET[r] + result
    for byte in data:
        if byte == 0:
            result = BASE58_ALPHABET[0] + result
        else:
            break
    return result or BASE58_ALPHABET[0]

def from_base58(d, k):
    d = d.strip()
    n = 0
    for char in d:
        n = n * 58 + BASE58_ALPHABET.index(char)
    data = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n > 0 else b''
    pad = 0
    for char in d:
        if char == BASE58_ALPHABET[0]:
            pad += 1
        else:
            break
    return (b'\x00' * pad + data).decode("utf-8")


def to_base62(t, k):
    data = t.encode("utf-8")
    n = int.from_bytes(data, 'big')
    result = ""
    while n > 0:
        n, r = divmod(n, 62)
        result = BASE62_ALPHABET[r] + result
    return result or "0"

def from_base62(d, k):
    d = d.strip()
    n = 0
    for char in d:
        n = n * 62 + BASE62_ALPHABET.index(char)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode("utf-8")


def to_base85(t, k):
    return base64.b85encode(t.encode("utf-8")).decode("ascii")

def from_base85(d, k):
    return base64.b85decode(d.strip().encode("ascii")).decode("utf-8")


def to_ascii85(t, k):
    return base64.a85encode(t.encode("utf-8")).decode("ascii")

def from_ascii85(d, k):
    return base64.a85decode(d.strip().encode("ascii")).decode("utf-8")


def to_hex(t, k):
    return " ".join(f"{b:02X}" for b in t.encode("utf-8"))

def from_hex(d, k):
    d = d.replace(" ", "").replace("\n", "").replace("0x", "").replace("0X", "")
    return bytes.fromhex(d).decode("utf-8")


# ==================== NHÓM CỔ ĐIỂN ====================
def rot13_fn(t, k=None):
    return codecs.encode(t, 'rot_13')


def atbash(t, k=None):
    return ''.join(
        chr(ord('z') - (ord(c) - ord('a'))) if c.islower()
        else chr(ord('Z') - (ord(c) - ord('A'))) if c.isupper()
        else c
        for c in t
    )


def caesar_enc(t, k):
    try:
        shift = int(k) if k else 3
    except ValueError:
        shift = 3
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - b + shift) % 26 + b))
        else:
            out.append(c)
    return ''.join(out)


def caesar_dec(t, k):
    try:
        shift = -int(k) if k else -3
    except ValueError:
        shift = -3
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - b + shift) % 26 + b))
        else:
            out.append(c)
    return ''.join(out)


def vigenere_enc(t, k):
    if not k:
        k = "KEY"
    k = k.upper()
    out, ki = [], 0
    for c in t:
        if c.isalpha():
            shift = ord(k[ki % len(k)]) - ord('A')
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - b + shift) % 26 + b))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)


def vigenere_dec(t, k):
    if not k:
        k = "KEY"
    k = k.upper()
    out, ki = [], 0
    for c in t:
        if c.isalpha():
            shift = ord(k[ki % len(k)]) - ord('A')
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - b - shift) % 26 + b))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)


def affine_enc(t, k):
    try:
        parts = k.split(",") if k else ["5", "8"]
        a, b = int(parts[0]), int(parts[1])
    except Exception:
        a, b = 5, 8
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((a * (ord(c) - base) + b) % 26 + base))
        else:
            out.append(c)
    return ''.join(out)


def affine_dec(t, k):
    try:
        parts = k.split(",") if k else ["5", "8"]
        a, b = int(parts[0]), int(parts[1])
    except Exception:
        a, b = 5, 8
    a_inv = next((i for i in range(26) if (a * i) % 26 == 1), None)
    if a_inv is None:
        raise ValueError("Khóa a phải nguyên tố cùng nhau với 26")
    out = []
    for c in t:
        if c.isalpha() and ord(c) < 128:
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((a_inv * (ord(c) - base - b)) % 26 + base))
        else:
            out.append(c)
    return ''.join(out)


def railfence_enc(t, k):
    try:
        rails = int(k) if k else 3
    except Exception:
        rails = 3
    if rails < 2:
        rails = 2
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for c in t:
        fence[rail].append(c)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return ''.join(''.join(r) for r in fence)


def railfence_dec(t, k):
    try:
        rails = int(k) if k else 3
    except Exception:
        rails = 3
    if rails < 2:
        rails = 2
    n = len(t)
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    counts = [pattern.count(r) for r in range(rails)]
    chunks, idx = [], 0
    for cnt in counts:
        chunks.append(list(t[idx:idx+cnt]))
        idx += cnt
    result, pointers = [], [0] * rails
    for r in pattern:
        result.append(chunks[r][pointers[r]])
        pointers[r] += 1
    return ''.join(result)


def columnar_enc(t, k):
    if not k:
        k = "KEY"
    key = k.upper()
    key_order = sorted(range(len(key)), key=lambda i: key[i])
    cols = [''] * len(key)
    for i, c in enumerate(t):
        cols[i % len(key)] += c
    return ''.join(cols[i] for i in key_order)


def columnar_dec(t, k):
    if not k:
        k = "KEY"
    key = k.upper()
    n = len(key)
    key_order = sorted(range(n), key=lambda i: key[i])
    col_lengths = [len(t) // n + (1 if i < len(t) % n else 0) for i in range(n)]
    sorted_lengths = [col_lengths[i] for i in key_order]
    cols, idx = {}, 0
    for i, ki in enumerate(key_order):
        cols[ki] = t[idx:idx+sorted_lengths[i]]
        idx += sorted_lengths[i]
    result = []
    for i in range(len(t)):
        result.append(cols[i % n][i // n])
    return ''.join(result)


def bacon_enc(t, k):
    return ' '.join(BACON_MAP.get(c.upper(), '?????') for c in t if c.upper() in BACON_MAP)


def bacon_dec(d, k):
    return ''.join(BACON_REVERSE.get(w.upper(), '?') for w in d.split())


def polybius_enc(t, k):
    return ' '.join(POLYBIUS_MAP.get(c.upper(), '??') for c in t if c.upper() in POLYBIUS_MAP)


def polybius_dec(d, k):
    return ''.join(POLYBIUS_REVERSE.get(w, '?') for w in d.split())


# ==================== NHÓM KÝ TỰ ====================
def to_unicode(t, k):
    return " ".join(f"U+{ord(c):04X}" for c in t)


def from_unicode(d, k):
    return "".join(
        chr(int(p.replace("U+", "").replace("u+", ""), 16))
        for p in d.replace(",", " ").split()
    )


def to_ascii(t, k):
    return " ".join(str(ord(c)) for c in t)


def from_ascii(d, k):
    return "".join(chr(int(p)) for p in d.replace(",", " ").split())


def to_morse(t, k):
    return " ".join(MORSE_CODE.get(c, '?') for c in strip_viet(t).upper())


def from_morse(d, k):
    return " ".join(
        "".join(MORSE_REVERSE.get(c, '?') for c in w.split())
        for w in d.strip().split(" / ")
    )


def to_leet(t, k):
    m = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7',
         'b': '8', 'g': '9', 'l': '1', 'z': '2'}
    return ''.join(m.get(c.lower(), c) for c in t)


def from_leet(d, k):
    m = {'4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't',
         '8': 'b', '9': 'g', '2': 'z'}
    return ''.join(m.get(c, c) for c in d)


UPSIDE_MAP = {
    'a': 'ɐ', 'b': 'q', 'c': 'ɔ', 'd': 'p', 'e': 'ǝ', 'f': 'ɟ', 'g': 'ƃ', 'h': 'ɥ',
    'i': 'ᴉ', 'j': 'ɾ', 'k': 'ʞ', 'l': 'l', 'm': 'ɯ', 'n': 'u', 'o': 'o', 'p': 'd',
    'q': 'b', 'r': 'ɹ', 's': 's', 't': 'ʇ', 'u': 'n', 'v': 'ʌ', 'w': 'ʍ', 'x': 'x',
    'y': 'ʎ', 'z': 'z', 'A': '∀', 'B': '𐐒', 'C': 'Ɔ', 'D': '◖', 'E': 'Ǝ', 'F': 'Ⅎ',
    'G': '⅁', 'H': 'H', 'I': 'I', 'J': 'ſ', 'K': '⋊', 'L': '˥', 'M': 'W', 'N': 'N',
    'O': 'O', 'P': 'Ԁ', 'Q': 'Ό', 'R': 'ᴚ', 'S': 'S', 'T': '⊥', 'U': '∩', 'V': 'Λ',
    'W': 'M', 'X': 'X', 'Y': '⅄', 'Z': 'Z', '0': '0', '1': 'Ɩ', '2': 'ᄅ', '3': 'Ɛ',
    '4': 'ㄣ', '5': 'ϛ', '6': '9', '7': 'ㄥ', '8': '8', '9': '6',
    '.': '˙', ',': "'", '?': '¿', '!': '¡', "'": ',', '"': '„',
    '(': ')', ')': '(', '[': ']', ']': '[', '{': '}', '}': '{',
    '<': '>', '>': '<', '&': '⅋', '_': '‾'
}
UPSIDE_REVERSE = {v: k for k, v in UPSIDE_MAP.items()}


def to_upside_down(t, k):
    return ''.join(UPSIDE_MAP.get(c, c) for c in reversed(t))


def from_upside_down(d, k):
    return ''.join(UPSIDE_REVERSE.get(c, c) for c in reversed(d))


def to_nato(t, k):
    return ' '.join(NATO_MAP.get(c.upper(), c) for c in t)


def from_nato(d, k):
    return ''.join(NATO_REVERSE.get(w.upper(), w) for w in d.split())


def to_reverse(t, k):
    return t[::-1]


def from_reverse(d, k):
    return d[::-1]


def to_double(t, k):
    return ''.join(c * 2 for c in t)


def from_double(d, k):
    return ''.join(d[i] for i in range(0, len(d), 2))


def to_number_replace(t, k):
    return ' '.join(str(ord(c.upper()) - 64) if c.isalpha() and ord(c) < 128 else c for c in t)


def from_number_replace(d, k):
    result = []
    for part in d.split():
        if part.isdigit() and 1 <= int(part) <= 26:
            result.append(chr(ord('A') + int(part) - 1))
        else:
            result.append(part)
    return ''.join(result)


# ==================== NHÓM WEB ====================
def to_url(t, k):
    return urllib.parse.quote(t, safe="")


def from_url(d, k):
    return urllib.parse.unquote(d)


def to_html_fn(t, k):
    return html.escape(t)


def from_html_fn(d, k):
    return html.unescape(d)


def to_jwt_like(t, k):
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"data": t}).encode()
    ).decode().rstrip("=")
    return f"{header}.{payload}."


def from_jwt_like(d, k):
    parts = d.split(".")
    if len(parts) < 2:
        raise ValueError("JWT-like không hợp lệ")
    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode()).get("data", "")


# ==================== NHÓM TIẾNG VIỆT ====================
def _to_syl(t, m):
    return "".join(m.get(c, c) for c in t)


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
                out.append(v)
                i += len(kk)
                matched = True
                break
        if not matched:
            out.append(t[i])
            i += 1
    return "".join(out)


def to_telex(t, k):
    return _to_syl(t, TELEX_MAP)


def from_telex(t, k):
    return _from_syl(t, TELEX_REVERSE)


def to_vni(t, k):
    return _to_syl(t, VNI_MAP)


def from_vni(t, k):
    return _from_syl(t, VNI_REVERSE)


def to_viqr(t, k):
    return _to_syl(t, VIQR_MAP)


def from_viqr(t, k):
    return _from_syl(t, VIQR_REVERSE)


def to_no_accent(t, k):
    return strip_viet(t)


def from_no_accent(d, k):
    raise ValueError("Không thể giải mã 'không dấu'!")


# ==================== NHÓM HASH ====================
def hash_md5(t, k):
    return hashlib.md5(t.encode("utf-8")).hexdigest()


def hash_sha1(t, k):
    return hashlib.sha1(t.encode("utf-8")).hexdigest()


def hash_sha256(t, k):
    return hashlib.sha256(t.encode("utf-8")).hexdigest()


def hash_sha512(t, k):
    return hashlib.sha512(t.encode("utf-8")).hexdigest()


def hash_sha3_256(t, k):
    return hashlib.sha3_256(t.encode("utf-8")).hexdigest()


def hash_sha3_512(t, k):
    return hashlib.sha3_512(t.encode("utf-8")).hexdigest()


def hash_blake2b(t, k):
    return hashlib.blake2b(t.encode("utf-8")).hexdigest()


def hash_blake2s(t, k):
    return hashlib.blake2s(t.encode("utf-8")).hexdigest()


def hash_crc32(t, k):
    return format(binascii.crc32(t.encode("utf-8")) & 0xFFFFFFFF, '08x')


def to_hmac_sha256(t, k):
    import hmac
    if not k:
        k = "secret"
    return hmac.new(k.encode("utf-8"), t.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_err(d, k):
    raise ValueError("Hash là hàm một chiều!")


# ==================== NHÓM NÉN ====================
def gzip_encode(t, k):
    return base64.b64encode(gzip.compress(t.encode("utf-8"))).decode("ascii")


def gzip_decode(d, k):
    return gzip.decompress(base64.b64decode(d.strip())).decode("utf-8")


def zlib_encode(t, k):
    return base64.b64encode(zlib.compress(t.encode("utf-8"))).decode("ascii")


def zlib_decode(d, k):
    return zlib.decompress(base64.b64decode(d.strip())).decode("utf-8")


def bz2_encode(t, k):
    import bz2
    return base64.b64encode(bz2.compress(t.encode("utf-8"))).decode("ascii")


def bz2_decode(d, k):
    import bz2
    return bz2.decompress(base64.b64decode(d.strip())).decode("utf-8")


def lzma_encode(t, k):
    import lzma
    return base64.b64encode(lzma.compress(t.encode("utf-8"))).decode("ascii")


def lzma_decode(d, k):
    import lzma
    return lzma.decompress(base64.b64decode(d.strip())).decode("utf-8")


# ==================== NHÓM BẢO MẬT ====================
def aes_encrypt(text, key):
    if not CRYPTO_OK:
        raise ValueError("Cần cài cryptography!")
    if not key:
        raise ValueError("Nhập khóa!")
    k = hashlib.sha256(key.encode("utf-8")).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode("utf-8")) + padder.finalize()
    c = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).encryptor()
    return base64.b64encode(iv + c.update(padded) + c.finalize()).decode("ascii")


def aes_decrypt(data, key):
    if not CRYPTO_OK:
        raise ValueError("Cần cài cryptography!")
    if not key:
        raise ValueError("Nhập khóa!")
    k = hashlib.sha256(key.encode("utf-8")).digest()
    raw = base64.b64decode(data.strip())
    iv, ct = raw[:16], raw[16:]
    c = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = c.update(ct) + c.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
    except Exception:
        raise ValueError("Khóa sai!")


def xor_encrypt(text, key):
    if not key:
        raise ValueError("Nhập khóa!")
    kb = key.encode("utf-8")
    tb = text.encode("utf-8")
    return base64.b64encode(
        bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb)))
    ).decode("ascii")


def xor_decrypt(data, key):
    if not key:
        raise ValueError("Nhập khóa!")
    kb = key.encode("utf-8")
    tb = base64.b64decode(data.strip())
    return bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb))).decode("utf-8")


def _rc4_crypt(data, key):
    kb = key.encode("utf-8")
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + kb[i % len(kb)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(char ^ K)
    return bytes(result)


def rc4_encrypt(text, key):
    if not key:
        raise ValueError("Nhập khóa!")
    return base64.b64encode(_rc4_crypt(text.encode("utf-8"), key)).decode("ascii")


def rc4_decrypt(data, key):
    if not key:
        raise ValueError("Nhập khóa!")
    return _rc4_crypt(base64.b64decode(data.strip()), key).decode("utf-8")


def to_bcrypt(t, k):
    if not BCRYPT_OK:
        raise ValueError("Cần cài bcrypt!")
    return bcrypt.hashpw(t.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def from_bcrypt(d, k):
    raise ValueError("Bcrypt là hàm một chiều!")


# ==================== NHÓM ĐẶC BIỆT ====================
QWERTY = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"
QWERTY_SHIFTED = "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?"


def to_qwerty_shift(t, k):
    return ''.join(QWERTY_SHIFTED[QWERTY.index(c)] if c in QWERTY else c for c in t.lower())


def from_qwerty_shift(d, k):
    return ''.join(QWERTY[QWERTY_SHIFTED.index(c)] if c in QWERTY_SHIFTED else c for c in d)


DVORAK = "`1234567890[]',.pyfgcrl/=\\aoeuidhtns-;qjkxbmwvz"


def to_dvorak(t, k):
    return ''.join(DVORAK[QWERTY.index(c)] if c in QWERTY else c for c in t.lower())


def from_dvorak(d, k):
    return ''.join(QWERTY[DVORAK.index(c)] if c in DVORAK else c for c in d)


# ==================== ĐỊNH NGHĨA ENCODERS ====================
ENCODERS = {
    # Nhóm không mã hóa
    "none":      ("⭕ Không mã hóa",   "Không mã hóa", no_encrypt, no_decrypt),

    # Nhóm cơ bản
    "binary":    ("🔢 Nhị phân",       "Cơ bản", to_binary, from_binary),
    "octal":     ("🔢 Bát phân",       "Cơ bản", to_octal, from_octal),
    "decimal":   ("🔢 Thập phân",      "Cơ bản", to_decimal, from_decimal),
    "base64":    ("📦 Base64",         "Cơ bản", to_base64, from_base64),
    "base64url": ("📦 Base64 URL",     "Cơ bản", to_base64url, from_base64url),
    "base32":    ("🗜 Base32",          "Cơ bản", to_base32, from_base32),
    "base58":    ("🪙 Base58",         "Cơ bản", to_base58, from_base58),
    "base62":    ("🔢 Base62",         "Cơ bản", to_base62, from_base62),
    "base85":    ("🗜 Base85",          "Cơ bản", to_base85, from_base85),
    "ascii85":   ("📦 ASCII85",        "Cơ bản", to_ascii85, from_ascii85),
    "hex":       ("#️⃣ Hex",            "Cơ bản", to_hex, from_hex),

    # Nhóm cổ điển
    "rot13":     ("🔄 ROT13",          "Cổ điển", rot13_fn, rot13_fn),
    "atbash":    ("🔤 Atbash",         "Cổ điển", atbash, atbash),
    "caesar":    ("🏛 Caesar",         "Cổ điển", caesar_enc, caesar_dec),
    "vigenere":  ("🔑 Vigenère",       "Cổ điển", vigenere_enc, vigenere_dec),
    "affine":    ("📐 Affine",         "Cổ điển", affine_enc, affine_dec),
    "railfence": ("🚂 Rail Fence",     "Cổ điển", railfence_enc, railfence_dec),
    "columnar":  ("📊 Columnar",       "Cổ điển", columnar_enc, columnar_dec),
    "bacon":     ("🥓 Bacon",          "Cổ điển", bacon_enc, bacon_dec),
    "polybius":  ("🔲 Polybius",       "Cổ điển", polybius_enc, polybius_dec),

    # Nhóm ký tự
    "unicode":   ("🌐 Unicode",        "Ký tự", to_unicode, from_unicode),
    "ascii":     ("🔤 ASCII",          "Ký tự", to_ascii, from_ascii),
    "morse":     ("📡 Morse",          "Ký tự", to_morse, from_morse),
    "leet":      ("💻 Leet Speak",     "Ký tự", to_leet, from_leet),
    "upside":    ("🙃 Lật ngược",      "Ký tự", to_upside_down, from_upside_down),
    "nato":      ("🎖 NATO",           "Ký tự", to_nato, from_nato),
    "reverse":   ("🔃 Đảo ngược",      "Ký tự", to_reverse, from_reverse),
    "double":    ("✌ Nhân đôi",        "Ký tự", to_double, from_double),
    "number":    ("🔢 Thay số",        "Ký tự", to_number_replace, from_number_replace),

    # Nhóm web
    "url":       ("🔗 URL Encode",     "Web", to_url, from_url),
    "html":      ("🌍 HTML Entity",    "Web", to_html_fn, from_html_fn),
    "jwt":       ("🎫 JWT-like",       "Web", to_jwt_like, from_jwt_like),

    # Nhóm tiếng Việt
    "telex":     ("🚫 Telex",          "Tiếng Việt", to_telex, from_telex),
    "vni":       ("🇻🇳 VNI",            "Tiếng Việt", to_vni, from_vni),
    "viqr":      ("🇻🇳 VIQR",           "Tiếng Việt", to_viqr, from_viqr),
    "noaccent":  ("🚫 Bỏ dấu",         "Tiếng Việt", to_no_accent, from_no_accent),

    # Nhóm hash
    "md5":       ("🔒 MD5",            "Hash", hash_md5, hash_err),
    "sha1":      ("🔒 SHA-1",          "Hash", hash_sha1, hash_err),
    "sha256":    ("🔒 SHA-256",        "Hash", hash_sha256, hash_err),
    "sha512":    ("🔒 SHA-512",        "Hash", hash_sha512, hash_err),
    "sha3_256":  ("🔒 SHA3-256",       "Hash", hash_sha3_256, hash_err),
    "sha3_512":  ("🔒 SHA3-512",       "Hash", hash_sha3_512, hash_err),
    "blake2b":   ("🔒 Blake2b",        "Hash", hash_blake2b, hash_err),
    "blake2s":   ("🔒 Blake2s",        "Hash", hash_blake2s, hash_err),
    "crc32":     ("🔒 CRC32",          "Hash", hash_crc32, hash_err),
    "hmac":      ("🔑 HMAC-SHA256",    "Hash", to_hmac_sha256, hash_err),

    # Nhóm bảo mật
    "aes":       ("🔐 AES-256",        "Bảo mật", aes_encrypt, aes_decrypt),
    "xor":       ("🧮 XOR",            "Bảo mật", xor_encrypt, xor_decrypt),
    "rc4":       ("🔐 RC4",            "Bảo mật", rc4_encrypt, rc4_decrypt),
    "bcrypt":    ("🔐 Bcrypt",         "Bảo mật", to_bcrypt, from_bcrypt),

    # Nhóm nén
    "gzip":      ("🗜 Gzip + B64",     "Nén", gzip_encode, gzip_decode),
    "zlib":      ("🗜 Zlib + B64",     "Nén", zlib_encode, zlib_decode),
    "bz2":       ("🗜 Bzip2 + B64",    "Nén", bz2_encode, bz2_decode),
    "lzma":      ("🗜 LZMA + B64",     "Nén", lzma_encode, lzma_decode),

    # Nhóm đặc biệt
    "qwerty":    ("⌨ QWERTY Shift",   "Đặc biệt", to_qwerty_shift, from_qwerty_shift),
    "dvorak":    ("⌨ Dvorak",         "Đặc biệt", to_dvorak, from_dvorak),
}

# Loại bỏ thuật toán nếu thiếu thư viện
if not CRYPTO_OK:
    ENCODERS.pop("aes", None)
if not BCRYPT_OK:
    ENCODERS.pop("bcrypt", None)

GROUP_ORDER = ["Không mã hóa", "Cơ bản", "Cổ điển", "Ký tự", "Web",
               "Tiếng Việt", "Hash", "Bảo mật", "Nén", "Đặc biệt"]


def get_grouped():
    """Trả về dict các nhóm thuật toán theo thứ tự GROUP_ORDER"""
    result = {}
    for key, (label, group, _, _) in ENCODERS.items():
        result.setdefault(group, []).append({"key": key, "label": label})
    return {g: result[g] for g in GROUP_ORDER if g in result}


# ==================== SELF-TEST ====================
if __name__ == "__main__":
    print(f"✅ Đã load {len(ENCODERS)} thuật toán")
    print(f"📦 Nhóm: {', '.join(GROUP_ORDER)}")
    for g, algos in get_grouped().items():
        print(f"  {g}: {len(algos)} thuật toán")
