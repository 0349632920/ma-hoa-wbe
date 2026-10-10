"""
Module chứa hơn 70 kiểu mã hóa / giải mã
"""
import base64
import codecs
import hashlib
import html
import json
import quopri
import urllib.parse
import uuid
import zlib
import gzip
import bz2
import lzma
import string
import random
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============================================================
# DANH SÁCH PHƯƠNG PHÁP
# ============================================================
METHODS = {
    # Encoding cơ bản
    "base64": "Base64",
    "base64url": "Base64 URL-safe",
    "base32": "Base32",
    "base85": "Base85 (Ascii85)",
    "base16": "Base16 (Hex)",
    "base58": "Base58",
    "hex": "Hexadecimal",
    "binary": "Binary (Nhị phân)",
    "octal": "Octal (Bát phân)",
    "decimal": "Decimal (Thập phân)",
    "ascii_codes": "Mã ASCII",

    # Mật mã cổ điển
    "caesar": "Caesar Cipher",
    "rot13": "ROT13",
    "rot5": "ROT5 (số)",
    "rot18": "ROT18",
    "rot47": "ROT47",
    "atbash": "Atbash",
    "affine": "Affine Cipher",
    "vigenere": "Vigenère",
    "beaufort": "Beaufort",
    "autokey": "Autokey Cipher",
    "playfair": "Playfair",
    "hill": "Hill Cipher (2x2)",
    "railfence": "Rail Fence",
    "columnar": "Columnar Transposition",
    "bacon": "Bacon Cipher",
    "polybius": "Polybius Square",
    "morse": "Mã Morse",
    "tap_code": "Tap Code",
    "nato": "NATO Phonetic",
    "pigpen": "Pigpen Cipher",

    # Hiện đại
    "aes": "AES (Fernet)",
    "xor": "XOR Cipher",
    "reverse": "Đảo ngược chuỗi",
    "reverse_words": "Đảo ngược từ",
    "swap_case": "Đổi hoa/thường",
    "leet": "Leet Speak (1337)",

    # Hash (1 chiều)
    "md5": "MD5 (không giải mã)",
    "sha1": "SHA-1 (không giải mã)",
    "sha224": "SHA-224 (không giải mã)",
    "sha256": "SHA-256 (không giải mã)",
    "sha384": "SHA-384 (không giải mã)",
    "sha512": "SHA-512 (không giải mã)",
    "sha3_256": "SHA3-256 (không giải mã)",
    "sha3_512": "SHA3-512 (không giải mã)",
    "blake2b": "BLAKE2b (không giải mã)",
    "blake2s": "BLAKE2s (không giải mã)",
    "crc32": "CRC32 (không giải mã)",

    # URL / Web
    "url": "URL Encode",
    "url_plus": "URL Encode (dấu +)",
    "html_entities": "HTML Entities",
    "html_decimal": "HTML Decimal",
    "html_hex": "HTML Hex",
    "js_escape": "JavaScript Escape",
    "unicode_escape": "Unicode Escape",
    "punycode": "Punycode",

    # Quoted-Printable
    "quoted_printable": "Quoted-Printable",
    "uuencode": "UUencode",
    "xxencode": "XXencode",

    # Nén
    "zlib": "Zlib (Base64)",
    "gzip": "Gzip (Base64)",
    "bz2": "BZip2 (Base64)",
    "lzma": "LZMA (Base64)",

    # Định danh
    "uuid": "UUID v4 (ngẫu nhiên)",
    "random_hex": "Random Hex",

    # Đặc biệt
    "json_escape": "JSON Escape",
    "backslash_escape": "Backslash Escape",
    "unicode_full": "Unicode Full-width",
    "zalgo": "Zalgo Text",
    "upside_down": "Upside Down",
    "mirror": "Mirror Text",
    "small_caps": "Small Caps",
    "bubble": "Bubble Text",
    "strikethrough": "Strikethrough",
    "superscript": "Superscript",
    "subscript": "Subscript",
    "invisible": "Invisible Text",
}

HASH_METHODS = {'md5','sha1','sha224','sha256','sha384','sha512',
                'sha3_256','sha3_512','blake2b','blake2s','crc32'}
ONE_WAY_ONLY = HASH_METHODS | {'uuid','random_hex'}


# ============================================================
# BASE FAMILY
# ============================================================
def base64_encode(t): return base64.b64encode(t.encode()).decode()
def base64_decode(t): return base64.b64decode(t.encode()).decode()

def base64url_encode(t): return base64.urlsafe_b64encode(t.encode()).decode()
def base64url_decode(t): return base64.urlsafe_b64decode(t.encode()).decode()

def base32_encode(t): return base64.b32encode(t.encode()).decode()
def base32_decode(t): return base64.b32decode(t.encode()).decode()

def base85_encode(t): return base64.b85encode(t.encode()).decode()
def base85_decode(t): return base64.b85decode(t.encode()).decode()

def base16_encode(t): return base64.b16encode(t.encode()).decode()
def base16_decode(t): return base64.b16decode(t.encode()).decode()

B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58_encode(t):
    n = int.from_bytes(t.encode(), 'big')
    res = ''
    while n > 0:
        n, r = divmod(n, 58)
        res = B58_ALPHABET[r] + res
    for b in t.encode():
        if b == 0: res = '1' + res
        else: break
    return res or '1'

def base58_decode(t):
    n = 0
    for c in t:
        n = n * 58 + B58_ALPHABET.index(c)
    res = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    pad = 0
    for c in t:
        if c == '1': pad += 1
        else: break
    return (b'\x00' * pad + res).decode()


# ============================================================
# HEX / BINARY / OCTAL / DECIMAL
# ============================================================
def hex_encode(t): return ' '.join(format(ord(c), '02x') for c in t)
def hex_decode(t): return ''.join(chr(int(h, 16)) for h in t.strip().split())

def binary_encode(t): return ' '.join(format(ord(c), '08b') for c in t)
def binary_decode(t): return ''.join(chr(int(b, 2)) for b in t.strip().split())

def octal_encode(t): return ' '.join(format(ord(c), 'o') for c in t)
def octal_decode(t): return ''.join(chr(int(o, 8)) for o in t.strip().split())

def decimal_encode(t): return ' '.join(str(ord(c)) for c in t)
def decimal_decode(t): return ''.join(chr(int(d)) for d in t.strip().split())

def ascii_codes_encode(t): return ' '.join(str(ord(c)) for c in t)
def ascii_codes_decode(t): return ''.join(chr(int(d)) for d in t.strip().split())


# ============================================================
# CAESAR FAMILY
# ============================================================
def caesar_cipher(t, shift):
    r = []
    for ch in t:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            r.append(chr((ord(ch) - base + shift) % 26 + base))
        else: r.append(ch)
    return ''.join(r)

def rot13(t): return caesar_cipher(t, 13)

def rot5(t):
    return ''.join(str((int(c) + 5) % 10) if c.isdigit() else c for c in t)

def rot18(t): return rot5(rot13(t))

def rot47(t):
    return ''.join(chr(33 + ((ord(c) - 33 + 14) % 94)) if 33 <= ord(c) <= 126 else c for c in t)


# ============================================================
# ATBASH / AFFINE / VIGENERE
# ============================================================
def atbash(t):
    r = []
    for ch in t:
        if ch.isupper():
            r.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        elif ch.islower():
            r.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else: r.append(ch)
    return ''.join(r)

def affine_encrypt(t, a=5, b=8):
    r = []
    for ch in t:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            r.append(chr((a * x + b) % 26 + base))
        else: r.append(ch)
    return ''.join(r)

def affine_decrypt(t, a=5, b=8):
    a_inv = pow(a, -1, 26)
    r = []
    for ch in t:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            y = ord(ch) - base
            r.append(chr((a_inv * (y - b)) % 26 + base))
        else: r.append(ch)
    return ''.join(r)

def vigenere_encrypt(t, key):
    if not key: key = 'KEY'
    key = key.upper()
    r, ki = [], 0
    for ch in t:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('A')
            r.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else: r.append(ch)
    return ''.join(r)

def vigenere_decrypt(t, key):
    if not key: key = 'KEY'
    key = key.upper()
    r, ki = [], 0
    for ch in t:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('A')
            r.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else: r.append(ch)
    return ''.join(r)

def beaufort_encrypt(t, key):
    if not key: key = 'KEY'
    key = key.upper()
    r, ki = [], 0
    for ch in t:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('A')
            r.append(chr((shift - (ord(ch) - base)) % 26 + base))
            ki += 1
        else: r.append(ch)
    return ''.join(r)
beaufort_decrypt = beaufort_encrypt

def autokey_encrypt(t, key):
    if not key: key = 'KEY'
    key = key.upper()
    r = []
    full_key = (key + t.upper().replace(' ', ''))[:len(t)]
    for i, ch in enumerate(t):
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(full_key[i]) - ord('A')
            r.append(chr((ord(ch) - base + shift) % 26 + base))
        else: r.append(ch)
    return ''.join(r)

def autokey_decrypt(t, key):
    if not key: key = 'KEY'
    key = key.upper()
    r = []
    full_key = list(key)
    for i, ch in enumerate(t):
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(full_key[i]) - ord('A')
            plain = chr((ord(ch) - base - shift) % 26 + base)
            r.append(plain)
            full_key.append(plain.upper())
        else:
            r.append(ch)
    return ''.join(r)


# ============================================================
# PLAYFAIR / HILL / RAILFENCE / COLUMNAR
# ============================================================
def _playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    seen, matrix = set(), []
    for c in key + string.ascii_uppercase:
        if c == 'J': continue
        if c not in seen:
            seen.add(c)
            matrix.append(c)
    return [matrix[i*5:(i+1)*5] for i in range(5)]

def _playfair_pos(matrix, ch):
    for i, row in enumerate(matrix):
        if ch in row: return i, row.index(ch)
    return -1, -1

def playfair_encrypt(t, key):
    if not key: key = 'KEY'
    matrix = _playfair_matrix(key)
    text = re.sub(r'[^A-Z]', '', t.upper().replace('J', 'I'))
    if len(text) % 2: text += 'X'
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        if a == b: b = 'X'
        ra, ca = _playfair_pos(matrix, a)
        rb, cb = _playfair_pos(matrix, b)
        if ra == rb:
            result.append(matrix[ra][(ca+1) % 5])
            result.append(matrix[rb][(cb+1) % 5])
        elif ca == cb:
            result.append(matrix[(ra+1) % 5][ca])
            result.append(matrix[(rb+1) % 5][cb])
        else:
            result.append(matrix[ra][cb])
            result.append(matrix[rb][ca])
    return ''.join(result)

def playfair_decrypt(t, key):
    if not key: key = 'KEY'
    matrix = _playfair_matrix(key)
    text = re.sub(r'[^A-Z]', '', t.upper())
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        ra, ca = _playfair_pos(matrix, a)
        rb, cb = _playfair_pos(matrix, b)
        if ra == rb:
            result.append(matrix[ra][(ca-1) % 5])
            result.append(matrix[rb][(cb-1) % 5])
        elif ca == cb:
            result.append(matrix[(ra-1) % 5][ca])
            result.append(matrix[(rb-1) % 5][cb])
        else:
            result.append(matrix[ra][cb])
            result.append(matrix[rb][ca])
    return ''.join(result)

def hill_encrypt(t, key='3,3,2,5'):
    try: k = [int(x) for x in key.split(',')]
    except: k = [3,3,2,5]
    if len(k) != 4: k = [3,3,2,5]
    text = re.sub(r'[^A-Z]', '', t.upper())
    if len(text) % 2: text += 'X'
    result = []
    for i in range(0, len(text), 2):
        x, y = ord(text[i])-65, ord(text[i+1])-65
        result.append(chr((k[0]*x + k[1]*y) % 26 + 65))
        result.append(chr((k[2]*x + k[3]*y) % 26 + 65))
    return ''.join(result)

def hill_decrypt(t, key='3,3,2,5'):
    try: k = [int(x) for x in key.split(',')]
    except: k = [3,3,2,5]
    if len(k) != 4: k = [3,3,2,5]
    det = (k[0]*k[3] - k[1]*k[2]) % 26
    det_inv = pow(det, -1, 26)
    inv = [(k[3]*det_inv) % 26, (-k[1]*det_inv) % 26,
           (-k[2]*det_inv) % 26, (k[0]*det_inv) % 26]
    text = re.sub(r'[^A-Z]', '', t.upper())
    if len(text) % 2: text += 'X'
    result = []
    for i in range(0, len(text), 2):
        x, y = ord(text[i])-65, ord(text[i+1])-65
        result.append(chr((inv[0]*x + inv[1]*y) % 26 + 65))
        result.append(chr((inv[2]*x + inv[3]*y) % 26 + 65))
    return ''.join(result)

def railfence_encrypt(t, rails=3):
    try: rails = int(rails)
    except: rails = 3
    if rails < 2: rails = 2
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in t:
        fence[rail].append(ch)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    return ''.join(''.join(r) for r in fence)

def railfence_decrypt(t, rails=3):
    try: rails = int(rails)
    except: rails = 3
    if rails < 2: rails = 2
    n = len(t)
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    counts = [pattern.count(i) for i in range(rails)]
    fence = []
    idx = 0
    for c in counts:
        fence.append(list(t[idx:idx+c]))
        idx += c
    pointers = [0] * rails
    result = []
    for r in pattern:
        result.append(fence[r][pointers[r]])
        pointers[r] += 1
    return ''.join(result)

def columnar_encrypt(t, key='KEY'):
    if not key: key = 'KEY'
    key = key.upper()
    order = sorted(range(len(key)), key=lambda i: key[i])
    cols = [[] for _ in key]
    for i, ch in enumerate(t):
        cols[i % len(key)].append(ch)
    result = []
    for i in order:
        result.extend(cols[i])
    return ''.join(result)

def columnar_decrypt(t, key='KEY'):
    if not key: key = 'KEY'
    key = key.upper()
    n = len(key)
    order = sorted(range(n), key=lambda i: key[i])
    col_len = [len(t) // n] * n
    for i in range(len(t) % n):
        col_len[i] += 1
    cols = [''] * n
    idx = 0
    for i in order:
        cols[i] = t[idx:idx+col_len[i]]
        idx += col_len[i]
    result = []
    for i in range(len(t)):
        result.append(cols[i % n][i // n])
    return ''.join(result)


# ============================================================
# BACON / POLYBIUS / MORSE / TAP / NATO / PIGPEN
# ============================================================
def bacon_encode(t):
    result = []
    for ch in t.upper():
        if ch.isalpha():
            n = ord(ch) - 65
            result.append(format(n, '05b').replace('0', 'A').replace('1', 'B'))
        else: result.append(ch)
    return ' '.join(result)

def bacon_decode(t):
    result = []
    for code in t.split():
        if len(code) == 5:
            bits = code.upper().replace('A', '0').replace('B', '1')
            try: result.append(chr(int(bits, 2) + 65))
            except: result.append('?')
    return ''.join(result)

def polybius_encode(t):
    matrix = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    result = []
    for ch in t.upper():
        if ch == 'J': ch = 'I'
        if ch in matrix:
            i = matrix.index(ch)
            result.append(f'{i//5+1}{i%5+1}')
        else: result.append(ch)
    return ' '.join(result)

def polybius_decode(t):
    matrix = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    result = []
    for code in t.split():
        if len(code) == 2 and code.isdigit():
            i = (int(code[0])-1) * 5 + (int(code[1])-1)
            result.append(matrix[i])
    return ''.join(result)

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', ' ': '/'
}
MORSE_REV = {v: k for k, v in MORSE.items()}

def morse_encode(t):
    return ' '.join(MORSE.get(c.upper(), c) for c in t)
def morse_decode(t):
    return ''.join(MORSE_REV.get(c, '') for c in t.split())

def tap_encode(t):
    matrix = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    result = []
    for ch in t.upper():
        if ch == 'J': ch = 'I'
        if ch in matrix:
            i = matrix.index(ch)
            row, col = i//5+1, i%5+1
            result.append('.'*row + ' ' + '.'*col)
        else: result.append(ch)
    return ' / '.join(result)

def tap_decode(t):
    matrix = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    result = []
    for code in t.split(' / '):
        parts = code.strip().split()
        if len(parts) == 2:
            row, col = len(parts[0]), len(parts[1])
            i = (row-1)*5 + (col-1)
            if 0 <= i < 25: result.append(matrix[i])
    return ''.join(result)

NATO = {'A':'Alfa','B':'Bravo','C':'Charlie','D':'Delta','E':'Echo','F':'Foxtrot',
        'G':'Golf','H':'Hotel','I':'India','J':'Juliett','K':'Kilo','L':'Lima',
        'M':'Mike','N':'November','O':'Oscar','P':'Papa','Q':'Quebec','R':'Romeo',
        'S':'Sierra','T':'Tango','U':'Uniform','V':'Victor','W':'Whiskey',
        'X':'X-ray','Y':'Yankee','Z':'Zulu'}
NATO_REV = {v.upper(): k for k, v in NATO.items()}

def nato_encode(t):
    return ' '.join(NATO.get(c.upper(), c) for c in t)
def nato_decode(t):
    return ''.join(NATO_REV.get(w.upper(), '') for w in t.split())

def pigpen_encode(t):
    result = []
    for ch in t.upper():
        if ch.isalpha():
            n = ord(ch) - 65
            result.append(f'[{n//9+1},{n%9+1}]')
        else: result.append(ch)
    return ' '.join(result)

def pigpen_decode(t):
    result = []
    for code in t.split():
        m = re.match(r'\[(\d),(\d)\]', code)
        if m:
            n = (int(m.group(1))-1)*9 + (int(m.group(2))-1)
            if 0 <= n < 26: result.append(chr(n+65))
    return ''.join(result)


# ============================================================
# XOR / REVERSE / LEET
# ============================================================
def xor_cipher(t, key):
    if not key: key = 'KEY'
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(t))

def reverse_str(t): return t[::-1]
def reverse_words(t): return ' '.join(t.split()[::-1])
def swap_case(t): return t.swapcase()

LEET = {'a':'4','b':'8','e':'3','g':'6','i':'1','l':'1','o':'0','s':'5','t':'7','z':'2'}
LEET_REV = {v:k for k,v in LEET.items()}
def leet_encode(t):
    return ''.join(LEET.get(c.lower(), c) for c in t)
def leet_decode(t):
    return ''.join(LEET_REV.get(c, c) for c in t)


# ============================================================
# HASH
# ============================================================
def hash_md5(t): return hashlib.md5(t.encode()).hexdigest()
def hash_sha1(t): return hashlib.sha1(t.encode()).hexdigest()
def hash_sha224(t): return hashlib.sha224(t.encode()).hexdigest()
def hash_sha256(t): return hashlib.sha256(t.encode()).hexdigest()
def hash_sha384(t): return hashlib.sha384(t.encode()).hexdigest()
def hash_sha512(t): return hashlib.sha512(t.encode()).hexdigest()
def hash_sha3_256(t): return hashlib.sha3_256(t.encode()).hexdigest()
def hash_sha3_512(t): return hashlib.sha3_512(t.encode()).hexdigest()
def hash_blake2b(t): return hashlib.blake2b(t.encode()).hexdigest()
def hash_blake2s(t): return hashlib.blake2s(t.encode()).hexdigest()
def hash_crc32(t): return format(zlib.crc32(t.encode()) & 0xffffffff, '08x')


# ============================================================
# URL / HTML
# ============================================================
def url_encode(t): return urllib.parse.quote(t, safe='')
def url_decode(t): return urllib.parse.unquote(t)
def url_plus_encode(t): return urllib.parse.quote_plus(t)
def url_plus_decode(t): return urllib.parse.unquote_plus(t)

def html_entities_encode(t): return html.escape(t)
def html_entities_decode(t): return html.unescape(t)
def html_decimal_encode(t): return ''.join(f'&#{ord(c)};' for c in t)
def html_decimal_decode(t): return re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), t)
def html_hex_encode(t): return ''.join(f'&#x{ord(c):x};' for c in t)
def html_hex_decode(t): return re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1),16)), t)


# ============================================================
# JS / UNICODE ESCAPE / PUNYCODE
# ============================================================
def js_escape_encode(t):
    return ''.join(f'\\x{ord(c):02x}' if ord(c) < 256 else f'\\u{ord(c):04x}' for c in t)
def js_escape_decode(t):
    return re.sub(r'\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})',
                  lambda m: chr(int(m.group(1),16) if m.group(1) else int(m.group(2),16)), t)

def unicode_escape_encode(t):
    return ''.join(f'\\u{ord(c):04x}' for c in t)
def unicode_escape_decode(t):
    return re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1),16)), t)

def punycode_encode(t): return t.encode('punycode').decode()
def punycode_decode(t): return t.encode().decode('punycode')


# ============================================================
# QUOTED-PRINTABLE / UUENCODE
# ============================================================
def quoted_printable_encode(t): return quopri.encodestring(t.encode()).decode()
def quoted_printable_decode(t): return quopri.decodestring(t.encode()).decode()

def uuencode_encode(t): return codecs.encode(t.encode(), 'uu').decode()
def uuencode_decode(t): return codecs.decode(t.encode(), 'uu').decode()

def xxencode_encode(t): return codecs.encode(t.encode(), 'uu').decode()
def xxencode_decode(t): return codecs.decode(t.encode(), 'uu').decode()


# ============================================================
# COMPRESSION
# ============================================================
def zlib_encode(t): return base64.b64encode(zlib.compress(t.encode())).decode()
def zlib_decode(t): return zlib.decompress(base64.b64decode(t)).decode()

def gzip_encode(t): return base64.b64encode(gzip.compress(t.encode())).decode()
def gzip_decode(t): return gzip.decompress(base64.b64decode(t)).decode()

def bz2_encode(t): return base64.b64encode(bz2.compress(t.encode())).decode()
def bz2_decode(t): return bz2.decompress(base64.b64decode(t)).decode()

def lzma_encode(t): return base64.b64encode(lzma.compress(t.encode())).decode()
def lzma_decode(t): return lzma.decompress(base64.b64decode(t)).decode()


# ============================================================
# UUID / RANDOM
# ============================================================
def uuid_gen(t): return str(uuid.uuid4())
def random_hex(t): return ''.join(random.choices('0123456789abcdef', k=32))


# ============================================================
# AES
# ============================================================
def _derive_key(password, salt=b'ma-hoa-salt-2024'):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def aes_encrypt(t, password):
    if not password: password = 'default'
    f = Fernet(_derive_key(password))
    return f.encrypt(t.encode()).decode()

def aes_decrypt(t, password):
    if not password: password = 'default'
    f = Fernet(_derive_key(password))
    return f.decrypt(t.encode()).decode()


# ============================================================
# JSON / BACKSLASH / UNICODE STYLE
# ============================================================
def json_escape_encode(t): return json.dumps(t)[1:-1]
def json_escape_decode(t): return json.loads(f'"{t}"')

def backslash_escape_encode(t):
    return t.replace('\\', '\\\\').replace('\n', '\\n').replace('\t', '\\t').replace('"', '\\"')
def backslash_escape_decode(t):
    return t.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')

def unicode_full_encode(t):
    return ''.join(chr(ord(c) + 0xFEE0) if 33 <= ord(c) <= 126 else c for c in t)
def unicode_full_decode(t):
    return ''.join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in t)

def zalgo_encode(t):
    marks = [chr(c) for c in range(0x0300, 0x036F)]
    return ''.join(c + ''.join(random.choices(marks, k=3)) if c.isalpha() else c for c in t)
zalgo_decode = lambda t: ''.join(c for c in t if ord(c) < 0x0300)

UPS
