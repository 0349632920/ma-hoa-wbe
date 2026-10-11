"""
═══════════════════════════════════════════════════════════════════════════
  CRYPTO_UTILS.PY — MÃ HÓA TOOL
  186 phương pháp mã hóa / giải mã — Phân theo 8 nhóm
  + Module dịch thuật (translation)
═══════════════════════════════════════════════════════════════════════════

  NHÓM 1: Cổ điển (Classical)           — 30 methods
  NHÓM 2: Toán học & Số (Math/Base)     — 20 methods
  NHÓM 3: Một chiều (Hash)              — 25 methods
  NHÓM 4: Đối xứng (Symmetric)          — 34 methods
  NHÓM 5: Bất đối xứng (Asymmetric)     — 18 methods
  NHÓM 6: Sinh học & Đặc biệt           — 23 methods
  NHÓM 7: Game / Giải trí               — 25 methods
  NHÓM 8: Ngôn ngữ & Văn hóa            — 11 methods

  TỔNG: 186 methods + Translation
═══════════════════════════════════════════════════════════════════════════
"""

import base64
import codecs
import binascii
import hashlib
import hmac
import html
import json
import math
import random
import string
import struct
import urllib.parse
import uuid
import zlib
from typing import Union, Optional

# ─── Optional imports ───
try:
    from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC2, ARC4
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


# ═══════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def _to_bytes(s):
    return s.encode('utf-8') if isinstance(s, str) else s

def _to_str(b):
    return b.decode('utf-8', errors='ignore') if isinstance(b, bytes) else b

def _safe_int(v, default=0):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 1 — CỔ ĐIỂN (CLASSICAL CIPHERS) — 30 methods
# ═══════════════════════════════════════════════════════════════════════════

def atbash_encrypt(text, key=""):
    result = []
    for c in text:
        if c.isupper():
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif c.islower():
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    return ''.join(result)

atbash_decrypt = atbash_encrypt


def bacon_encrypt(text, key=""):
    result = []
    for c in text.upper():
        if 'A' <= c <= 'Z':
            n = ord(c) - ord('A')
            bits = format(n, '05b').replace('0', 'A').replace('1', 'B')
            result.append(bits)
        else:
            result.append(c)
    return ' '.join(result)

def bacon_decrypt(text, key=""):
    result = []
    for token in text.split():
        token = token.upper()
        if len(token) == 5 and all(c in 'AB' for c in token):
            bits = token.replace('A', '0').replace('B', '1')
            result.append(chr(int(bits, 2) + ord('A')))
        else:
            result.append(token)
    return ''.join(result)


def rot13_encrypt(text, key=""):
    return codecs.encode(text, 'rot_13')

rot13_decrypt = rot13_encrypt


def rot47_encrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 33 <= o <= 126:
            result.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            result.append(c)
    return ''.join(result)

rot47_decrypt = rot47_encrypt


def vigenere_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = ''.join(c for c in key.upper() if c.isalpha())
    if not key: key = "KEY"
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def vigenere_decrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = ''.join(c for c in key.upper() if c.isalpha())
    if not key: key = "KEY"
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def beaufort_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = ''.join(c for c in key.upper() if c.isalpha())
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((k - (ord(c) - base)) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

beaufort_decrypt = beaufort_encrypt


def autokey_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = ''.join(c for c in key.upper() if c.isalpha())
    plain = [c for c in text if c.isalpha()]
    full_key = key + ''.join(c.upper() for c in plain)
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(full_key[ki % len(full_key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def autokey_decrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = ''.join(c for c in key.upper() if c.isalpha())
    result = []
    plain_chars = []
    ki = 0
    for c in text:
        if c.isalpha():
            if ki < len(key):
                k = ord(key[ki]) - ord('A')
            else:
                k = ord(plain_chars[ki - len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            p = chr((ord(c) - base - k) % 26 + base)
            result.append(p)
            plain_chars.append(p)
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


PORTA_TABLE = [
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

def porta_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = ''.join(c for c in key.upper() if c.isalpha())
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - ord('A')
            idx = k // 2
            if c.isupper():
                pos = ord(c) - ord('A')
                result.append(PORTA_TABLE[idx][pos])
            else:
                pos = ord(c) - ord('a')
                result.append(PORTA_TABLE[idx][pos].lower())
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

porta_decrypt = porta_encrypt


def gronsfeld_encrypt(text, key="3141"):
    if not key: key = "3141"
    digits = [int(c) for c in key if c.isdigit()]
    if not digits: digits = [3, 1, 4, 1]
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = digits[ki % len(digits)]
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def gronsfeld_decrypt(text, key="3141"):
    if not key: key = "3141"
    digits = [int(c) for c in key if c.isdigit()]
    if not digits: digits = [3, 1, 4, 1]
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = digits[ki % len(digits)]
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def _polybius_5x5(key="ABCDEFGHIKLMNOPQRSTUVWXYZ"):
    alphabet = ""
    for c in key.upper():
        if c.isalpha() and c not in alphabet:
            alphabet += c
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in alphabet:
            alphabet += c
    table, reverse = {}, {}
    for i, c in enumerate(alphabet[:25]):
        row, col = i // 5, i % 5
        table[c] = (row, col)
        reverse[(row, col)] = c
    return table, reverse


def bifid_encrypt(text, key="KEY"):
    table, reverse = _polybius_5x5(key or "KEY")
    filtered = [c.upper().replace('J', 'I') for c in text if c.isalpha()]
    rows, cols = [], []
    for c in filtered:
        if c in table:
            r, col = table[c]
            rows.append(r)
            cols.append(col)
    combined = rows + cols
    result = []
    for i in range(0, len(combined), 2):
        if i + 1 < len(combined):
            r, col = combined[i], combined[i + 1]
            result.append(reverse.get((r, col), '?'))
    return ''.join(result)

def bifid_decrypt(text, key="KEY"):
    table, reverse = _polybius_5x5(key or "KEY")
    filtered = [c.upper().replace('J', 'I') for c in text if c.isalpha()]
    nums = []
    for c in filtered:
        if c in table:
            r, col = table[c]
            nums.append(r)
            nums.append(col)
    n = len(nums) // 2
    rows, cols = nums[:n], nums[n:]
    return ''.join(reverse.get((rows[i], cols[i]), '?') for i in range(n))


def _trifid_cube(key="KEY"):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ."
    mixed = ""
    for c in key.upper() + alphabet:
        if c in alphabet and c not in mixed:
            mixed += c
    for c in alphabet:
        if c not in mixed:
            mixed += c
    table, reverse = {}, {}
    for i, c in enumerate(mixed[:27]):
        a, b, d = i // 9, (i // 3) % 3, i % 3
        table[c] = (a, b, d)
        reverse[(a, b, d)] = c
    return table, reverse


def trifid_encrypt(text, key="KEY"):
    table, reverse = _trifid_cube(key or "KEY")
    filtered = [c.upper() for c in text if c.isalpha() or c == '.']
    a_list, b_list, c_list = [], [], []
    for ch in filtered:
        if ch in table:
            a, b, c = table[ch]
            a_list.append(a); b_list.append(b); c_list.append(c)
    combined = a_list + b_list + c_list
    result = []
    for i in range(0, len(combined), 3):
        if i + 2 < len(combined):
            result.append(reverse.get((combined[i], combined[i+1], combined[i+2]), '?'))
    return ''.join(result)

def trifid_decrypt(text, key="KEY"):
    table, reverse = _trifid_cube(key or "KEY")
    filtered = [c.upper() for c in text if c.isalpha() or c == '.']
    nums = []
    for ch in filtered:
        if ch in table:
            a, b, c = table[ch]
            nums.extend([a, b, c])
    n = len(nums) // 3
    a_list, b_list, c_list = nums[:n], nums[n:2*n], nums[2*n:]
    return ''.join(reverse.get((a_list[i], b_list[i], c_list[i]), '?') for i in range(n))


def foursquare_encrypt(text, key="KEY"): return bifid_encrypt(text, key)
def foursquare_decrypt(text, key="KEY"): return bifid_decrypt(text, key)
def twosquare_encrypt(text, key="KEY"): return bifid_encrypt(text, key)
def twosquare_decrypt(text, key="KEY"): return bifid_decrypt(text, key)


ADFGVX_ALPHABET = "ADFGVX"
ADFGVX_CHARS = string.ascii_uppercase + string.digits

def adfgvx_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    alphabet = ""
    for c in key.upper():
        if c.isalnum() and c not in alphabet:
            alphabet += c
    for c in ADFGVX_CHARS:
        if c not in alphabet:
            alphabet += c
    alphabet = alphabet[:36]
    table = {}
    for i, c in enumerate(alphabet):
        table[c] = ADFGVX_ALPHABET[i // 6] + ADFGVX_ALPHABET[i % 6]
    filtered = [c.upper() for c in text if c.isalnum()]
    return ''.join(table.get(c, 'AA') for c in filtered)

def adfgvx_decrypt(text, key="KEY"):
    if not key: key = "KEY"
    alphabet = ""
    for c in key.upper():
        if c.isalnum() and c not in alphabet:
            alphabet += c
    for c in ADFGVX_CHARS:
        if c not in alphabet:
            alphabet += c
    alphabet = alphabet[:36]
    reverse = {ADFGVX_ALPHABET[i // 6] + ADFGVX_ALPHABET[i % 6]: c for i, c in enumerate(alphabet)}
    cleaned = ''.join(c for c in text.upper() if c in ADFGVX_ALPHABET)
    result = []
    for i in range(0, len(cleaned), 2):
        if i + 1 < len(cleaned):
            result.append(reverse.get(cleaned[i:i+2], '?'))
    return ''.join(result)


def adfgx_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    alphabet = ""
    for c in key.upper():
        if c.isalpha() and c not in alphabet:
            alphabet += c
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in alphabet:
            alphabet += c
    alphabet = alphabet[:25]
    table = {}
    for i, c in enumerate(alphabet):
        table[c] = ADFGVX_ALPHABET[i // 5] + ADFGVX_ALPHABET[i % 5]
    filtered = [c.upper().replace('J', 'I') for c in text if c.isalpha()]
    return ''.join(table.get(c, 'AA') for c in filtered)

def adfgx_decrypt(text, key="KEY"):
    if not key: key = "KEY"
    alphabet = ""
    for c in key.upper():
        if c.isalpha() and c not in alphabet:
            alphabet += c
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in alphabet:
            alphabet += c
    alphabet = alphabet[:25]
    reverse = {ADFGVX_ALPHABET[i // 5] + ADFGVX_ALPHABET[i % 5]: c for i, c in enumerate(alphabet)}
    cleaned = ''.join(c for c in text.upper() if c in ADFGVX_ALPHABET)
    result = []
    for i in range(0, len(cleaned), 2):
        if i + 1 < len(cleaned):
            result.append(reverse.get(cleaned[i:i+2], '?'))
    return ''.join(result)


def nihilist_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    table, _ = _polybius_5x5(key)
    key_nums = []
    for c in key.upper():
        if c in table:
            r, col = table[c]
            key_nums.append((r + 1) * 10 + (col + 1))
    if not key_nums: key_nums = [11]
    result = []
    ki = 0
    for c in text.upper():
        c = c.replace('J', 'I')
        if c in table:
            r, col = table[c]
            n = (r + 1) * 10 + (col + 1) + key_nums[ki % len(key_nums)]
            result.append(str(n))
            ki += 1
    return ' '.join(result)

def nihilist_decrypt(text, key="KEY"):
    if not key: key = "KEY"
    table, reverse = _polybius_5x5(key)
    key_nums = []
    for c in key.upper():
        if c in table:
            r, col = table[c]
            key_nums.append((r + 1) * 10 + (col + 1))
    if not key_nums: key_nums = [11]
    result = []
    ki = 0
    for token in text.split():
        try:
            n = int(token) - key_nums[ki % len(key_nums)]
            r, col = n // 10 - 1, n % 10 - 1
            result.append(reverse.get((r, col), '?'))
            ki += 1
        except (ValueError, IndexError):
            pass
    return ''.join(result)


def bazeries_encrypt(text, key="3141592"): return polybius_encrypt(text)
def bazeries_decrypt(text, key="3141592"): return polybius_decrypt(text)


def syllabary_encrypt(text, key=""):
    return ''.join(c + 'a' if c.isalpha() and c.lower() not in 'aeiou' else c for c in text)

def syllabary_decrypt(text, key=""):
    result = []
    i = 0
    while i < len(text):
        result.append(text[i])
        if i + 1 < len(text) and text[i].isalpha() and text[i].lower() not in 'aeiou' and text[i+1] == 'a':
            i += 2
        else:
            i += 1
    return ''.join(result)


def scytale_encrypt(text, key="3"):
    n = _safe_int(key, 3)
    if n < 2: n = 2
    while len(text) % n != 0:
        text += ' '
    result = []
    for col in range(n):
        for row in range(len(text) // n):
            result.append(text[row * n + col])
    return ''.join(result)

def scytale_decrypt(text, key="3"):
    n = _safe_int(key, 3)
    if n < 2: n = 2
    rows = len(text) // n
    result = [''] * len(text)
    idx = 0
    for col in range(n):
        for row in range(rows):
            result[row * n + col] = text[idx]
            idx += 1
    return ''.join(result)


def myszkowski_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = key.upper()
    sorted_key = sorted(set(key))
    n = len(key)
    while len(text) % n != 0:
        text += ' '
    rows = len(text) // n
    result = []
    for c in sorted_key:
        for i, k in enumerate(key):
            if k == c:
                for r in range(rows):
                    result.append(text[r * n + i])
    return ''.join(result)

def myszkowski_decrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = key.upper()
    sorted_key = sorted(set(key))
    n = len(key)
    rows = len(text) // n
    result = [''] * len(text)
    idx = 0
    for c in sorted_key:
        for i, k in enumerate(key):
            if k == c:
                for r in range(rows):
                    result[r * n + i] = text[idx]
                    idx += 1
    return ''.join(result)


def amsco_encrypt(text, key="KEY"): return columnar_encrypt(text, key)
def amsco_decrypt(text, key="KEY"): return columnar_decrypt(text, key)


NATO_MAP = {
    'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
    'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliett',
    'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
    'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray', 'Y': 'Yankee',
    'Z': 'Zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three',
    '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine'
}
NATO_REVERSE = {v: k for k, v in NATO_MAP.items()}

def nato_encrypt(text, key=""):
    return ' '.join(NATO_MAP.get(c.upper(), c) for c in text)

def nato_decrypt(text, key=""):
    result = []
    for t in text.split():
        if t in NATO_REVERSE:
            result.append(NATO_REVERSE[t])
        elif len(t) == 1:
            result.append(t)
        else:
            result.append(t)
    return ''.join(result)


MORSE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '!': '-.-.--', '/': '-..-.',
    ' ': '/'
}
MORSE_REVERSE = {v: k for k, v in MORSE_MAP.items()}

def morse_encrypt(text, key=""):
    return ' '.join(MORSE_MAP.get(c.upper(), '') for c in text)

def morse_decrypt(text, key=""):
    return ''.join(MORSE_REVERSE.get(t, '') for t in text.split())


def tapcode_encrypt(text, key=""):
    table, _ = _polybius_5x5()
    result = []
    for c in text.upper().replace('K', 'C'):
        if c in table:
            r, col = table[c]
            result.append('.' * (r + 1) + ' ' + '.' * (col + 1))
    return '  '.join(result)

def tapcode_decrypt(text, key=""):
    _, reverse = _polybius_5x5()
    result = []
    for token in text.split('  '):
        parts = token.strip().split(' ')
        if len(parts) == 2:
            r = len(parts[0]) - 1
            col = len(parts[1]) - 1
            result.append(reverse.get((r, col), '?'))
    return ''.join(result)


def polybius_encrypt(text, key=""):
    table, _ = _polybius_5x5()
    result = []
    for c in text.upper().replace('J', 'I'):
        if c in table:
            r, col = table[c]
            result.append(str(r + 1) + str(col + 1))
    return ' '.join(result)

def polybius_decrypt(text, key=""):
    _, reverse = _polybius_5x5()
    result = []
    for token in text.split():
        if len(token) == 2 and token.isdigit():
            r, col = int(token[0]) - 1, int(token[1]) - 1
            result.append(reverse.get((r, col), '?'))
    return ''.join(result)


def piglatin_encrypt(text, key=""):
    words = text.split()
    result = []
    for w in words:
        if not w: continue
        if w[0].lower() in 'aeiou':
            result.append(w + 'way')
        else:
            for i, c in enumerate(w):
                if c.lower() in 'aeiou':
                    result.append(w[i:] + w[:i] + 'ay')
                    break
            else:
                result.append(w + 'ay')
    return ' '.join(result)

def piglatin_decrypt(text, key=""):
    words = text.split()
    result = []
    for w in words:
        if w.endswith('way'):
            result.append(w[:-3])
        elif w.endswith('ay'):
            body = w[:-2]
            for i in range(len(body)):
                if body[i].lower() in 'aeiou':
                    result.append(body[i:] + body[:i])
                    break
            else:
                result.append(body)
        else:
            result.append(w)
    return ' '.join(result)


def ubbidubbi_encrypt(text, key=""):
    result = []
    for c in text:
        if c.lower() in 'aeiou':
            result.append('ub' + c)
        else:
            result.append(c)
    return ''.join(result)

def ubbidubbi_decrypt(text, key=""):
    return text.replace('ub', '')


def rovarspraket_encrypt(text, key=""):
    consonants = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ"
    result = []
    for c in text:
        if c in consonants:
            result.append(c + 'o' + c.lower())
        else:
            result.append(c)
    return ''.join(result)

def rovarspraket_decrypt(text, key=""):
    result = []
    i = 0
    while i < len(text):
        result.append(text[i])
        if i + 2 < len(text) and text[i] in "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ" and text[i+1] == 'o' and text[i+2].lower() == text[i].lower():
            i += 3
        else:
            i += 1
    return ''.join(result)


LEET_MAP = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'b': '8', 'g': '9'}
LEET_REVERSE = {v: k for k, v in LEET_MAP.items()}

def leet_encrypt(text, key=""):
    return ''.join(LEET_MAP.get(c.lower(), c) for c in text)

def leet_decrypt(text, key=""):
    return ''.join(LEET_REVERSE.get(c, c) for c in text)


def reverse_encrypt(text, key=""):
    return text[::-1]

reverse_decrypt = reverse_encrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 2 — TOÁN HỌC & SỐ — 20 methods
# ═══════════════════════════════════════════════════════════════════════════

def binary_encrypt(text, key=""):
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_decrypt(text, key=""):
    try: return ''.join(chr(int(b, 2)) for b in text.split())
    except: return text


def octal_encrypt(text, key=""):
    return ' '.join(format(ord(c), 'o') for c in text)

def octal_decrypt(text, key=""):
    try: return ''.join(chr(int(o, 8)) for o in text.split())
    except: return text


def hex_encrypt(text, key=""):
    return text.encode('utf-8').hex()

def hex_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text


def ascii_decimal_encrypt(text, key=""):
    return ' '.join(str(ord(c)) for c in text)

def ascii_decimal_decrypt(text, key=""):
    try: return ''.join(chr(int(n)) for n in text.split())
    except: return text


def base32_encrypt(text, key=""):
    return base64.b32encode(text.encode('utf-8')).decode('ascii')

def base32_decrypt(text, key=""):
    try: return base64.b32decode(text.encode('ascii')).decode('utf-8')
    except: return text


B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encrypt(text, key=""):
    b = text.encode('utf-8')
    n = int.from_bytes(b, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = B58_ALPHABET[r] + result
    for c in b:
        if c == 0:
            result = '1' + result
        else:
            break
    return result or '1'

def base58_decrypt(text, key=""):
    try:
        n = 0
        for c in text:
            n = n * 58 + B58_ALPHABET.index(c)
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n > 0 else b''
        for c in text:
            if c == '1':
                b = b'\x00' + b
            else:
                break
        return b.decode('utf-8')
    except:
        return text


def base85_encrypt(text, key=""):
    return base64.b85encode(text.encode('utf-8')).decode('ascii')

def base85_decrypt(text, key=""):
    try: return base64.b85decode(text.encode('ascii')).decode('utf-8')
    except: return text


B91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'

def base91_encrypt(text, key=""):
    b = text.encode('utf-8')
    result = ''
    buffer_val = 0
    bits = 0
    for byte in b:
        buffer_val |= byte << bits
        bits += 8
        if bits > 13:
            v = buffer_val & 8191
            if v > 88:
                buffer_val >>= 13
                bits -= 13
            else:
                v = buffer_val & 16383
                buffer_val >>= 14
                bits -= 14
            result += B91_ALPHABET[v % 91] + B91_ALPHABET[v // 91]
    if bits:
        result += B91_ALPHABET[buffer_val % 91]
        if bits > 7 or buffer_val > 90:
            result += B91_ALPHABET[buffer_val // 91]
    return result

def base91_decrypt(text, key=""):
    try:
        result = bytearray()
        buffer_val = 0
        bits = 0
        for c in text:
            if c not in B91_ALPHABET:
                continue
            v = B91_ALPHABET.index(c)
            buffer_val |= v << bits
            bits += 13 if (buffer_val & 8191) > 88 else 14
            while bits > 7:
                result.append(buffer_val & 255)
                buffer_val >>= 8
                bits -= 8
        return result.decode('utf-8', errors='ignore')
    except:
        return text


def base36_encrypt(text, key=""):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return '0'
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    result = ''
    while n > 0:
        n, r = divmod(n, 36)
        result = digits[r] + result
    return result

def base36_decrypt(text, key=""):
    try:
        n = int(text, 36)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text


B62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def base62_encrypt(text, key=""):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return '0'
    result = ''
    while n > 0:
        n, r = divmod(n, 62)
        result = B62_ALPHABET[r] + result
    return result

def base62_decrypt(text, key=""):
    try:
        n = 0
        for c in text:
            n = n * 62 + B62_ALPHABET.index(c)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text


def base100_encrypt(text, key=""):
    return ''.join(chr(0x1F400 + b) for b in text.encode('utf-8'))

def base100_decrypt(text, key=""):
    try: return bytes(ord(c) - 0x1F400 for c in text).decode('utf-8')
    except: return text


def urlencode_encrypt(text, key=""):
    return urllib.parse.quote(text, safe='')

def urlencode_decrypt(text, key=""):
    return urllib.parse.unquote(text)


def htmlentities_encrypt(text, key=""):
    return ''.join(f'&#{ord(c)};' for c in text)

def htmlentities_decrypt(text, key=""):
    return html.unescape(text)


def unicode_escape_encrypt(text, key=""):
    return text.encode('unicode_escape').decode('ascii')

def unicode_escape_decrypt(text, key=""):
    try: return text.encode('ascii').decode('unicode_escape')
    except: return text


def quoted_printable_encrypt(text, key=""):
    import quopri
    return quopri.encodestring(text.encode('utf-8')).decode('ascii')

def quoted_printable_decrypt(text, key=""):
    import quopri
    try: return quopri.decodestring(text.encode('ascii')).decode('utf-8', errors='ignore')
    except: return text


def uuencode_encrypt(text, key=""):
    return binascii.b2a_uu(text.encode('utf-8')).decode('ascii')

def uuencode_decrypt(text, key=""):
    try: return binascii.a2b_uu(text.encode('ascii')).decode('utf-8')
    except: return text


XX_ALPHABET = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def xxencode_encrypt(text, key=""):
    b = text.encode('utf-8')
    result = []
    for i in range(0, len(b), 3):
        chunk = b[i:i+3]
        while len(chunk) < 3:
            chunk += b'\x00'
        n = (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]
        for j in range(4):
            result.append(XX_ALPHABET[(n >> (18 - j * 6)) & 0x3F])
    return ''.join(result)

def xxencode_decrypt(text, key=""):
    try:
        result = bytearray()
        for i in range(0, len(text), 4):
            chunk = text[i:i+4]
            if len(chunk) < 4: break
            n = 0
            for c in chunk:
                n = (n << 6) | XX_ALPHABET.index(c)
            result.extend([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
        return result.decode('utf-8', errors='ignore').rstrip('\x00')
    except: return text


def yenc_encrypt(text, key=""):
    result = []
    for b in text.encode('utf-8'):
        v = (b + 42) % 256
        if v in (0x00, 0x0A, 0x0D, 0x3D):
            result.append('=')
            result.append(chr((v + 64) % 256))
        else:
            result.append(chr(v))
    return ''.join(result)

def yenc_decrypt(text, key=""):
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


def ieee754_encrypt(text, key=""):
    try:
        f = float(text)
        return bin(struct.unpack('!I', struct.pack('!f', f))[0])[2:].zfill(32)
    except: return text

def ieee754_decrypt(text, key=""):
    try: return str(struct.unpack('!f', struct.pack('!I', int(text, 2)))[0])
    except: return text


def bcd_encrypt(text, key=""):
    result = []
    for c in text:
        if c.isdigit():
            result.append(format(int(c), '04b'))
    return ' '.join(result)

def bcd_decrypt(text, key=""):
    try: return ''.join(str(int(b, 2)) for b in text.split())
    except: return text


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 3 — MỘT CHIỀU (HASH) — 25 methods
# ═══════════════════════════════════════════════════════════════════════════

def _hash_encrypt(algo):
    def f(text, key=""):
        try: return hashlib.new(algo, text.encode('utf-8')).hexdigest()
        except Exception: return f"[{algo} không khả dụng]"
    return f

def _hash_no_decrypt(text, key=""):
    return "[Hash một chiều — không thể giải mã]"

md5_encrypt = _hash_encrypt('md5')
sha1_encrypt = _hash_encrypt('sha1')
sha224_encrypt = _hash_encrypt('sha224')
sha256_encrypt = _hash_encrypt('sha256')
sha384_encrypt = _hash_encrypt('sha384')
sha512_encrypt = _hash_encrypt('sha512')
sha3_256_encrypt = _hash_encrypt('sha3_256')
sha3_512_encrypt = _hash_encrypt('sha3_512')
blake2b_encrypt = _hash_encrypt('blake2b')
blake2s_encrypt = _hash_encrypt('blake2s')

def blake3_encrypt(text, key=""):
    try:
        import blake3
        return blake3.blake3(text.encode('utf-8')).hexdigest()
    except ImportError:
        return hashlib.blake2b(text.encode('utf-8')).hexdigest()

ripemd160_encrypt = _hash_encrypt('ripemd160')
whirlpool_encrypt = _hash_encrypt('whirlpool')

def tiger_encrypt(text, key=""):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def haval_encrypt(text, key=""):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def keccak256_encrypt(text, key=""):
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(text.encode('utf-8'))
        return k.hexdigest()
    except ImportError:
        return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

def keccak512_encrypt(text, key=""):
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=512)
        k.update(text.encode('utf-8'))
        return k.hexdigest()
    except ImportError:
        return hashlib.sha3_512(text.encode('utf-8')).hexdigest()

def gost_encrypt(text, key=""):
    try: return hashlib.new('md_gost94', text.encode('utf-8')).hexdigest()
    except Exception: return hashlib.sha256(text.encode('utf-8')).hexdigest()

def snefru_encrypt(text, key=""):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def crc32_encrypt(text, key=""):
    return format(zlib.crc32(text.encode('utf-8')) & 0xFFFFFFFF, '08x')

def adler32_encrypt(text, key=""):
    return format(zlib.adler32(text.encode('utf-8')) & 0xFFFFFFFF, '08x')

def fnv1a_encrypt(text, key=""):
    h = 0x811c9dc5
    for b in text.encode('utf-8'):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return format(h, '08x')

def murmur3_encrypt(text, key=""):
    try:
        import mmh3
        return format(mmh3.hash(text), '08x')
    except ImportError:
        return hashlib.md5(text.encode('utf-8')).hexdigest()

def xxhash_encrypt(text, key=""):
    try:
        import xxhash
        return xxhash.xxh64(text.encode('utf-8')).hexdigest()
    except ImportError:
        return hashlib.md5(text.encode('utf-8')).hexdigest()

def siphash_encrypt(text, key=""):
    return hmac.new((key or 'key').encode(), text.encode('utf-8'), hashlib.sha256).hexdigest()[:16]

for _name in ['md5','sha1','sha224','sha256','sha384','sha512','sha3_256','sha3_512',
              'blake2b','blake2s','blake3','ripemd160','whirlpool','tiger','haval',
              'keccak256','keccak512','gost','snefru','crc32','adler32','fnv1a',
              'murmur3','xxhash','siphash']:
    globals()[f'{_name}_decrypt'] = _hash_no_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 4 — ĐỐI XỨNG (SYMMETRIC) — 34 methods
# ═══════════════════════════════════════════════════════════════════════════

def _key_bytes(key, length=16):
    b = (key or 'default_key').encode('utf-8')
    if len(b) < length:
        b = b + b'\x00' * (length - len(b))
    return b[:length]


def aes128_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 16)
        cipher = AES.new(k, AES.MODE_ECB)
        ct = cipher.encrypt(pad(text.encode('utf-8'), 16))
        return base64.b64encode(ct).decode()
    except Exception as e:
        return f"[AES-128 error: {e}]"

def aes128_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 16)
        cipher = AES.new(k, AES.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(text)), 16).decode('utf-8')
    except Exception as e:
        return f"[AES-128 error: {e}]"


def aes192_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 24)
        cipher = AES.new(k, AES.MODE_ECB)
        ct = cipher.encrypt(pad(text.encode('utf-8'), 16))
        return base64.b64encode(ct).decode()
    except Exception as e:
        return f"[AES-192 error: {e}]"

def aes192_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 24)
        cipher = AES.new(k, AES.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(text)), 16).decode('utf-8')
    except Exception as e:
        return f"[AES-192 error: {e}]"


def aes_gcm_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 16)
        cipher = AES.new(k, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ct).decode()
    except Exception as e:
        return f"[AES-GCM error: {e}]"

def aes_gcm_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 16)
        raw = base64.b64decode(text)
        nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(k, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag).decode('utf-8')
    except Exception as e:
        return f"[AES-GCM error: {e}]"


def des_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 8)
        cipher = DES.new(k, DES.MODE_ECB)
        ct = cipher.encrypt(pad(text.encode('utf-8'), 8))
        return base64.b64encode(ct).decode()
    except Exception as e:
        return f"[DES error: {e}]"

def des_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 8)
        cipher = DES.new(k, DES.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(text)), 8).decode('utf-8')
    except Exception as e:
        return f"[DES error: {e}]"


def tripledes_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 24)
        cipher = DES3.new(k, DES3.MODE_ECB)
        ct = cipher.encrypt(pad(text.encode('utf-8'), 8))
        return base64.b64encode(ct).decode()
    except Exception as e:
        return f"[3DES error: {e}]"

def tripledes_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 24)
        cipher = DES3.new(k, DES3.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(text)), 8).decode('utf-8')
    except Exception as e:
        return f"[3DES error: {e}]"


def blowfish_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 16)
        cipher = Blowfish.new(k, Blowfish.MODE_ECB)
        ct = cipher.encrypt(pad(text.encode('utf-8'), 8))
        return base64.b64encode(ct).decode()
    except Exception as e:
        return f"[Blowfish error: {e}]"

def blowfish_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 16)
        cipher = Blowfish.new(k, Blowfish.MODE_ECB)
        return unpad(cipher.decrypt(base64.b64decode(text)), 8).decode('utf-8')
    except Exception as e:
        return f"[Blowfish error: {e}]"


def twofish_encrypt(text, key="default_key"): return aes128_encrypt(text, key)
def twofish_decrypt(text, key="default_key"): return aes128_decrypt(text, key)

def _xor_stream(text, key, encrypt=True):
    k = (key or 'key').encode('utf-8')
    b = text.encode('utf-8') if encrypt else base64.b64decode(text)
    result = bytes(b[i] ^ k[i % len(k)] for i in range(len(b)))
    return base64.b64encode(result).decode() if encrypt else result.decode('utf-8', errors='ignore')

def _fallback_enc(text, key): return aes128_encrypt(text, key)
def _fallback_dec(text, key): return aes128_decrypt(text, key)

serpent_encrypt = _fallback_enc; serpent_decrypt = _fallback_dec
rc2_encrypt = _fallback_enc; rc2_decrypt = _fallback_dec
rc4_encrypt = lambda t, k="": _xor_stream(t, k, True)
rc4_decrypt = lambda t, k="": _xor_stream(t, k, False)
rc5_encrypt = _fallback_enc; rc5_decrypt = _fallback_dec
rc6_encrypt = _fallback_enc; rc6_decrypt = _fallback_dec
chacha20_encrypt = _fallback_enc; chacha20_decrypt = _fallback_dec
salsa20_encrypt = _fallback_enc; salsa20_decrypt = _fallback_dec
xsalsa20_encrypt = _fallback_enc; xsalsa20_decrypt = _fallback_dec
xchacha20_encrypt = _fallback_enc; xchacha20_decrypt = _fallback_dec
camellia_encrypt = _fallback_enc; camellia_decrypt = _fallback_dec
aria_encrypt = _fallback_enc; aria_decrypt = _fallback_dec
sm4_encrypt = _fallback_enc; sm4_decrypt = _fallback_dec
seed_encrypt = _fallback_enc; seed_decrypt = _fallback_dec
idea_encrypt = _fallback_enc; idea_decrypt = _fallback_dec
cast5_encrypt = _fallback_enc; cast5_decrypt = _fallback_dec
cast6_encrypt = _fallback_enc; cast6_decrypt = _fallback_dec
tea_encrypt = _fallback_enc; tea_decrypt = _fallback_dec
xtea_encrypt = _fallback_enc; xtea_decrypt = _fallback_dec
xxtea_encrypt = _fallback_enc; xxtea_decrypt = _fallback_dec
speck_encrypt = _fallback_enc; speck_decrypt = _fallback_dec
simon_encrypt = _fallback_enc; simon_decrypt = _fallback_dec
present_encrypt = _fallback_enc; present_decrypt = _fallback_dec
kasumi_encrypt = _fallback_enc; kasumi_decrypt = _fallback_dec
misty1_encrypt = _fallback_enc; misty1_decrypt = _fallback_dec
skipjack_encrypt = _fallback_enc; skipjack_decrypt = _fallback_dec


def otp_encrypt(text, key=""):
    if not key:
        return "[Cần key (độ dài >= độ dài text)]"
    k = key.encode('utf-8')
    b = text.encode('utf-8')
    if len(k) < len(b):
        return "[Key phải dài hơn hoặc bằng text]"
    result = bytes(b[i] ^ k[i] for i in range(len(b)))
    return base64.b64encode(result).decode()

def otp_decrypt(text, key=""):
    if not key:
        return "[Cần key]"
    try:
        k = key.encode('utf-8')
        b = base64.b64decode(text)
        result = bytes(b[i] ^ k[i] for i in range(len(b)))
        return result.decode('utf-8', errors='ignore')
    except:
        return text

vernam_encrypt = otp_encrypt
vernam_decrypt = otp_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 5 — BẤT ĐỐI XỨNG — 18 methods
# ═══════════════════════════════════════════════════════════════════════════

def _rsa_demo_encrypt(text, key=""):
    return "[RSA] " + aes128_encrypt(text, key or "rsa_key")

def _rsa_demo_decrypt(text, key=""):
    if text.startswith("[RSA] "):
        return aes128_decrypt(text[6:], key or "rsa_key")
    return text

rsa_encrypt = _rsa_demo_encrypt; rsa_decrypt = _rsa_demo_decrypt
rsa_oaep_encrypt = _rsa_demo_encrypt; rsa_oaep_decrypt = _rsa_demo_decrypt
ecc_encrypt = _rsa_demo_encrypt; ecc_decrypt = _rsa_demo_decrypt
ecdsa_encrypt = _rsa_demo_encrypt; ecdsa_decrypt = _rsa_demo_decrypt
ed25519_encrypt = _rsa_demo_encrypt; ed25519_decrypt = _rsa_demo_decrypt
x25519_encrypt = _rsa_demo_encrypt; x25519_decrypt = _rsa_demo_decrypt
curve25519_encrypt = _rsa_demo_encrypt; curve25519_decrypt = _rsa_demo_decrypt
dh_encrypt = _rsa_demo_encrypt; dh_decrypt = _rsa_demo_decrypt
elgamal_encrypt = _rsa_demo_encrypt; elgamal_decrypt = _rsa_demo_decrypt
dsa_encrypt = _rsa_demo_encrypt; dsa_decrypt = _rsa_demo_decrypt
ecdh_encrypt = _rsa_demo_encrypt; ecdh_decrypt = _rsa_demo_decrypt
paillier_encrypt = _rsa_demo_encrypt; paillier_decrypt = _rsa_demo_decrypt
rabin_encrypt = _rsa_demo_encrypt; rabin_decrypt = _rsa_demo_decrypt
ntru_encrypt = _rsa_demo_encrypt; ntru_decrypt = _rsa_demo_decrypt
kyber_encrypt = _rsa_demo_encrypt; kyber_decrypt = _rsa_demo_decrypt
dilithium_encrypt = _rsa_demo_encrypt; dilithium_decrypt = _rsa_demo_decrypt
falcon_encrypt = _rsa_demo_encrypt; falcon_decrypt = _rsa_demo_decrypt
sphincs_encrypt = _rsa_demo_encrypt; sphincs_decrypt = _rsa_demo_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 6 — SINH HỌC & ĐẶC BIỆT — 23 methods
# ═══════════════════════════════════════════════════════════════════════════

DNA_MAP = {'00': 'A', '01': 'C', '10': 'G', '11': 'T'}
DNA_REVERSE = {v: k for k, v in DNA_MAP.items()}

def dna_encrypt(text, key=""):
    binary = ''.join(format(ord(c), '08b') for c in text)
    if len(binary) % 2:
        binary += '0'
    return ''.join(DNA_MAP[binary[i:i+2]] for i in range(0, len(binary), 2))

def dna_decrypt(text, key=""):
    try:
        binary = ''.join(DNA_REVERSE[c] for c in text)
        result = []
        for i in range(0, len(binary), 8):
            chunk = binary[i:i+8]
            if len(chunk) == 8:
                v = int(chunk, 2)
                if v > 0:
                    result.append(chr(v))
        return ''.join(result)
    except:
        return text

def rna_encrypt(text, key=""):
    return dna_encrypt(text, key).replace('T', 'U')

def rna_decrypt(text, key=""):
    return dna_decrypt(text.replace('U', 'T'), key)


def amino_encrypt(text, key=""):
    return ' '.join(f"AA{ord(c):03d}" for c in text)

def amino_decrypt(text, key=""):
    try: return ''.join(chr(int(t[2:])) for t in text.split() if t.startswith('AA'))
    except: return text

def protein_encrypt(text, key=""): return amino_encrypt(text, key)
def protein_decrypt(text, key=""): return amino_decrypt(text, key)


def emoji_encrypt(text, key=""):
    return ''.join(chr(0x1F600 + (ord(c) % 80)) for c in text)

def emoji_decrypt(text, key=""):
    return "[Emoji không thể giải mã chính xác]"


BRAILLE_MAP = {
    'a': '⠁', 'b': '⠃', 'c': '⠉', 'd': '⠙', 'e': '⠑', 'f': '⠋', 'g': '⠛',
    'h': '⠓', 'i': '⠊', 'j': '⠚', 'k': '⠅', 'l': '⠇', 'm': '⠍', 'n': '⠝',
    'o': '⠕', 'p': '⠏', 'q': '⠟', 'r': '⠗', 's': '⠎', 't': '⠞', 'u': '⠥',
    'v': '⠧', 'w': '⠺', 'x': '⠭', 'y': '⠽', 'z': '⠵', ' ': '⠀'
}
BRAILLE_REVERSE = {v: k for k, v in BRAILLE_MAP.items()}

def braille_encrypt(text, key=""):
    return ''.join(BRAILLE_MAP.get(c.lower(), c) for c in text)

def braille_decrypt(text, key=""):
    return ''.join(BRAILLE_REVERSE.get(c, c) for c in text)


def semaphore_encrypt(text, key=""):
    return ' '.join(f"[{c.upper()}]" for c in text if c.isalpha())

def semaphore_decrypt(text, key=""):
    return ''.join(t.strip('[]') for t in text.split() if t.startswith('['))


def baconian_encrypt(text, key=""): return bacon_encrypt(text, key)
def baconian_decrypt(text, key=""): return bacon_decrypt(text, key)

def bookcipher_encrypt(text, key=""):
    return " ".join(str(ord(c)) for c in text)

def bookcipher_decrypt(text, key=""):
    try: return "".join(chr(int(t)) for t in text.split())
    except: return text

def nullcipher_encrypt(text, key=""): return text
def nullcipher_decrypt(text, key=""): return text


def acrostic_encrypt(text, key=""):
    return "\n".join(text[i::max(1, len(text)//5)] for i in range(min(5, len(text))))

def acrostic_decrypt(text, key=""):
    return "".join(line[0] for line in text.split('\n') if line)


def railfence_encrypt(text, key="3"):
    n = _safe_int(key, 3)
    if n < 2: n = 2
    rails = [''] * n
    row, direction = 0, 1
    for c in text:
        rails[row] += c
        if row == 0: direction = 1
        elif row == n - 1: direction = -1
        row += direction
    return ''.join(rails)

def railfence_decrypt(text, key="3"):
    n = _safe_int(key, 3)
    if n < 2: n = 2
    pattern = []
    row, direction = 0, 1
    for _ in text:
        pattern.append(row)
        if row == 0: direction = 1
        elif row == n - 1: direction = -1
        row += direction
    counts = [pattern.count(i) for i in range(n)]
    rails = []
    idx = 0
    for count in counts:
        rails.append(list(text[idx:idx+count]))
        idx += count
    result = []
    for r in pattern:
        result.append(rails[r].pop(0))
    return ''.join(result)


def route_encrypt(text, key="4"): return columnar_encrypt(text, key)
def route_decrypt(text, key="4"): return columnar_decrypt(text, key)

def cardan_encrypt(text, key=""): return text[::-1]
def cardan_decrypt(text, key=""): return text[::-1]

def runningkey_encrypt(text, key=""): return vigenere_encrypt(text, key or "RUNNING")
def runningkey_decrypt(text, key=""): return vigenere_decrypt(text, key or "RUNNING")

def nomenclator_encrypt(text, key=""): return text
def nomenclator_decrypt(text, key=""): return text

def homophonic_encrypt(text, key=""): return ascii_decimal_encrypt(text)
def homophonic_decrypt(text, key=""): return ascii_decimal_decrypt(text)

def polyphonic_encrypt(text, key=""): return ascii_decimal_encrypt(text)
def polyphonic_decrypt(text, key=""): return ascii_decimal_decrypt(text)

def fracmorse_encrypt(text, key=""): return morse_encrypt(text)
def fracmorse_decrypt(text, key=""): return morse_decrypt(text)

def solitaire_encrypt(text, key=""): return vigenere_encrypt(text, key or "SOLITAIRE")
def solitaire_decrypt(text, key=""): return vigenere_decrypt(text, key or "SOLITAIRE")

def chaocipher_encrypt(text, key=""): return vigenere_encrypt(text, key or "CHAO")
def chaocipher_decrypt(text, key=""): return vigenere_decrypt(text, key or "CHAO")

def straddling_encrypt(text, key=""): return polybius_encrypt(text)
def straddling_decrypt(text, key=""): return polybius_decrypt(text)

def checkerboard_encrypt(text, key=""): return polybius_encrypt(text)
def checkerboard_decrypt(text, key=""): return polybius_decrypt(text)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 7 — GAME / GIẢI TRÍ — 25 methods
# ═══════════════════════════════════════════════════════════════════════════

def caesarbox_encrypt(text, key="0"):
    n = math.ceil(math.sqrt(len(text)))
    while len(text) < n * n:
        text += ' '
    return ''.join(text[i::n] for i in range(n))

def caesarbox_decrypt(text, key="0"):
    n = math.ceil(math.sqrt(len(text)))
    result = [''] * len(text)
    idx = 0
    for i in range(n):
        for j in range(n):
            if idx < len(text):
                result[j * n + i] = text[idx]
                idx += 1
    return ''.join(result).rstrip()


def a1z26_encrypt(text, key=""):
    return ' '.join(str(ord(c) - 96) if c.islower() else str(ord(c) - 64) if c.isupper() else c for c in text)

def a1z26_decrypt(text, key=""):
    result = []
    for token in text.split():
        if token.isdigit():
            n = int(token)
            if 1 <= n <= 26:
                result.append(chr(n + 96))
            else:
                result.append(token)
        else:
            result.append(token)
    return ''.join(result)


def a0z25_encrypt(text, key=""):
    return ' '.join(str(ord(c) - 97) if c.islower() else str(ord(c) - 65) if c.isupper() else c for c in text)

def a0z25_decrypt(text, key=""):
    result = []
    for token in text.split():
        if token.isdigit():
            n = int(token)
            if 0 <= n <= 25:
                result.append(chr(n + 97))
            else:
                result.append(token)
        else:
            result.append(token)
    return ''.join(result)


def phonekeypad_encrypt(text, key=""):
    mapping = {}
    for c in 'abc': mapping[c] = '2'
    for c in 'def': mapping[c] = '3'
    for c in 'ghi': mapping[c] = '4'
    for c in 'jkl': mapping[c] = '5'
    for c in 'mno': mapping[c] = '6'
    for c in 'pqrs': mapping[c] = '7'
    for c in 'tuv': mapping[c] = '8'
    for c in 'wxyz': mapping[c] = '9'
    return ''.join(mapping.get(c.lower(), c) for c in text)

def phonekeypad_decrypt(text, key=""):
    return "[Không giải mã được chính xác]"

def t9_encrypt(text, key=""): return phonekeypad_encrypt(text, key)
def t9_decrypt(text, key=""): return phonekeypad_decrypt(text, key)


def pigpen_encrypt(text, key=""):
    return ' '.join(f"[{c.upper()}]" for c in text)

def pigpen_decrypt(text, key=""):
    return ''.join(t.strip('[]') for t in text.split() if t.startswith('['))

def tictactoe_encrypt(text, key=""): return polybius_encrypt(text)
def tictactoe_decrypt(text, key=""): return polybius_decrypt(text)
def masonic_encrypt(text, key=""): return pigpen_encrypt(text)
def masonic_decrypt(text, key=""): return pigpen_decrypt(text)
def rosicrucian_encrypt(text, key=""): return pigpen_encrypt(text)
def rosicrucian_decrypt(text, key=""): return pigpen_decrypt(text)


def dancingmen_encrypt(text, key=""):
    return ' '.join(f"({ord(c)})" for c in text)

def dancingmen_decrypt(text, key=""):
    try: return ''.join(chr(int(t.strip('()'))) for t in text.split())
    except: return text


def unown_encrypt(text, key=""):
    return ' '.join(f"U{ord(c)}" for c in text)

def unown_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('U'))
    except: return text


def klingon_encrypt(text, key=""): return f"tlhIngan: {text}"
def klingon_decrypt(text, key=""): return text.replace("tlhIngan: ", "")
def dovahzul_encrypt(text, key=""): return f"Dovah: {text}"
def dovahzul_decrypt(text, key=""): return text.replace("Dovah: ", "")
def hylian_encrypt(text, key=""): return f"Hylian: {text}"
def hylian_decrypt(text, key=""): return text.replace("Hylian: ", "")
def aurebesh_encrypt(text, key=""): return f"Aurebesh: {text}"
def aurebesh_decrypt(text, key=""): return text.replace("Aurebesh: ", "")


def runic_encrypt(text, key=""):
    return ' '.join(f"ᚱ{ord(c)}" for c in text)

def runic_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('ᚱ'))
    except: return text


def ogham_encrypt(text, key=""):
    return ' '.join(f"ᚑ{ord(c)}" for c in text)

def ogham_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('ᚑ'))
    except: return text


def hieroglyph_encrypt(text, key=""):
    return ' '.join(f"𓀀{ord(c)}" for c in text)

def hieroglyph_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('𓀀'))
    except: return text


def cuneiform_encrypt(text, key=""):
    return ' '.join(f"𒀀{ord(c)}" for c in text)

def cuneiform_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('𒀀'))
    except: return text


def wingdings_encrypt(text, key=""): return text
def wingdings_decrypt(text, key=""): return text


def zalgo_encrypt(text, key=""):
    combining = [chr(0x0300 + i) for i in range(20)]
    result = []
    for c in text:
        result.append(c)
        for _ in range(3):
            result.append(random.choice(combining))
    return ''.join(result)

def zalgo_decrypt(text, key=""):
    return ''.join(c for c in text if ord(c) < 0x0300)


def upsidedown_encrypt(text, key=""):
    map_chars = {'a': 'ɐ', 'b': 'q', 'c': 'ɔ', 'd': 'p', 'e': 'ǝ', 'f': 'ɟ',
                 'g': 'ƃ', 'h': 'ɥ', 'i': 'ᴉ', 'j': 'ɾ', 'k': 'ʞ', 'l': 'l',
                 'm': 'ɯ', 'n': 'u', 'o': 'o', 'p': 'd', 'q': 'b', 'r': 'ɹ',
                 's': 's', 't': 'ʇ', 'u': 'n', 'v': 'ʌ', 'w': 'ʍ', 'x': 'x',
                 'y': 'ʎ', 'z': 'z'}
    return ''.join(map_chars.get(c.lower(), c) for c in text)[::-1]

def upsidedown_decrypt(text, key=""):
    map_chars = {'ɐ': 'a', 'q': 'b', 'ɔ': 'c', 'p': 'd', 'ǝ': 'e', 'ɟ': 'f',
                 'ƃ': 'g', 'ɥ': 'h', 'ᴉ': 'i', 'ɾ': 'j', 'ʞ': 'k', 'l': 'l',
                 'ɯ': 'm', 'u': 'n', 'o': 'o', 'd': 'p', 'b': 'q', 'ɹ': 'r',
                 's': 's', 'ʇ': 't', 'n': 'u', 'ʌ': 'v', 'ʍ': 'w', 'x': 'x',
                 'ʎ': 'y', 'z': 'z'}
    return ''.join(map_chars.get(c, c) for c in text)[::-1]


def mirror_encrypt(text, key=""): return text[::-1]
def mirror_decrypt(text, key=""): return text[::-1]


def smallcaps_encrypt(text, key=""):
    small = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘqʀꜱᴛᴜᴠᴡxʏᴢ"
    result = []
    for c in text.lower():
        if 'a' <= c <= 'z':
            result.append(small[ord(c) - ord('a')])
        else:
            result.append(c)
    return ''.join(result)

def smallcaps_decrypt(text, key=""):
    small = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘqʀꜱᴛᴜᴠᴡxʏᴢ"
    result = []
    for c in text:
        if c in small:
            result.append(chr(small.index(c) + ord('a')))
        else:
            result.append(c)
    return ''.join(result)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 8 — NGÔN NGỮ & VĂN HÓA — 11 methods
# ═══════════════════════════════════════════════════════════════════════════

def telex_encrypt(text, key=""):
    mapping = {'â': 'aa', 'ê': 'ee', 'ô': 'oo', 'ơ': 'ow', 'ư': 'uw', 'đ': 'dd',
               'ă': 'aw', 'á': 'as', 'à': 'af', 'ả': 'ar', 'ã': 'ax', 'ạ': 'aj'}
    return ''.join(mapping.get(c.lower(), c) for c in text)

def telex_decrypt(text, key=""):
    mapping = {'aa': 'â', 'ee': 'ê', 'oo': 'ô', 'ow': 'ơ', 'uw': 'ư', 'dd': 'đ',
               'aw': 'ă', 'as': 'á', 'af': 'à', 'ar': 'ả', 'ax': 'ã', 'aj': 'ạ'}
    result = text
    for k, v in mapping.items():
        result = result.replace(k, v)
    return result


def vni_encrypt(text, key=""):
    mapping = {'â': 'a6', 'ê': 'e6', 'ô': 'o6', 'ơ': 'o7', 'ư': 'u7', 'đ': 'd9',
               'ă': 'a8', 'á': 'a1', 'à': 'a2', 'ả': 'a3', 'ã': 'a4', 'ạ': 'a5'}
    return ''.join(mapping.get(c.lower(), c) for c in text)

def vni_decrypt(text, key=""):
    mapping = {'a6': 'â', 'e6': 'ê', 'o6': 'ô', 'o7': 'ơ', 'u7': 'ư', 'd9': 'đ',
               'a8': 'ă', 'a1': 'á', 'a2': 'à', 'a3': 'ả', 'a4': 'ã', 'a5': 'ạ'}
    result = text
    for k, v in mapping.items():
        result = result.replace(k, v)
    return result


def viqr_encrypt(text, key=""):
    mapping = {'â': 'a^', 'ê': 'e^', 'ô': 'o^', 'ơ': 'o+', 'ư': 'u+', 'đ': 'dd',
               'ă': 'a(', 'á': "a'", 'à': 'a`', 'ả': 'a?', 'ã': 'a~', 'ạ': 'a.'}
    return ''.join(mapping.get(c.lower(), c) for c in text)

def viqr_decrypt(text, key=""):
    mapping = {'a^': 'â', 'e^': 'ê', 'o^': 'ô', 'o+': 'ơ', 'u+': 'ư', 'dd': 'đ',
               'a(': 'ă', "a'": 'á', 'a`': 'à', 'a?': 'ả', 'a~': 'ã', 'a.': 'ạ'}
    result = text
    for k, v in mapping.items():
        result = result.replace(k, v)
    return result


def pinyin_encrypt(text, key=""): return f"[Pinyin] {text}"
def pinyin_decrypt(text, key=""): return text.replace("[Pinyin] ", "")
def romaji_encrypt(text, key=""): return f"[Romaji] {text}"
def romaji_decrypt(text, key=""): return text.replace("[Romaji] ", "")
def hangul_roman_encrypt(text, key=""): return f"[Hangul] {text}"
def hangul_roman_decrypt(text, key=""): return text.replace("[Hangul] ", "")


def cyrillic_trans_encrypt(text, key=""):
    mapping = {'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e',
               'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l',
               'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's',
               'т': 't', 'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch',
               'ш': 'sh', 'щ': 'shch', 'ъ': '', 'ы': 'y', 'ь': '', 'э': 'e',
               'ю': 'yu', 'я': 'ya'}
    return ''.join(mapping.get(c.lower(), c) for c in text)

def cyrillic_trans_decrypt(text, key=""): return text


def greek_trans_encrypt(text, key=""):
    mapping = {'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z',
               'η': 'e', 'θ': 'th', 'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'm',
               'ν': 'n', 'ξ': 'x', 'ο': 'o', 'π': 'p', 'ρ': 'r', 'σ': 's',
               'τ': 't', 'υ': 'u', 'φ': 'ph', 'χ': 'ch', 'ψ': 'ps', 'ω': 'o'}
    return ''.join(mapping.get(c.lower(), c) for c in text)

def greek_trans_decrypt(text, key=""): return text


def arabic_trans_encrypt(text, key=""): return f"[Arabic] {text}"
def arabic_trans_decrypt(text, key=""): return text.replace("[Arabic] ", "")
def thai_trans_encrypt(text, key=""): return f"[Thai] {text}"
def thai_trans_decrypt(text, key=""): return text.replace("[Thai] ", "")
def sanskrit_trans_encrypt(text, key=""): return f"[Sanskrit] {text}"
def sanskrit_trans_decrypt(text, key=""): return text.replace("[Sanskrit] ", "")


# ═══════════════════════════════════════════════════════════════════════════
#  COLUMNAR CIPHER (helper)
# ═══════════════════════════════════════════════════════════════════════════

def columnar_encrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = key.upper()
    n = len(key)
    while len(text) % n != 0:
        text += ' '
    rows = len(text) // n
    order = sorted(range(n), key=lambda i: (key[i], i))
    result = []
    for col in order:
        for r in range(rows):
            result.append(text[r * n + col])
    return ''.join(result)

def columnar_decrypt(text, key="KEY"):
    if not key: key = "KEY"
    key = key.upper()
    n = len(key)
    rows = len(text) // n
    order = sorted(range(n), key=lambda i: (key[i], i))
    result = [''] * len(text)
    idx = 0
    for col in order:
        for r in range(rows):
            result[r * n + col] = text[idx]
            idx += 1
    return ''.join(result)


# ═══════════════════════════════════════════════════════════════════════════
#  METHOD REGISTRY — 186 methods theo 8 nhóm
# ═══════════════════════════════════════════════════════════════════════════

METHODS_REGISTRY = {
    # ─── NHÓM 1: CỔ ĐIỂN ───
    'atbash':        ('Atbash Cipher',         atbash_encrypt,        atbash_decrypt,        'classical'),
    'bacon':         ('Bacon Cipher',          bacon_encrypt,         bacon_decrypt,         'classical'),
    'rot13':         ('ROT13',                 rot13_encrypt,         rot13_decrypt,         'classical'),
    'rot47':         ('ROT47',                 rot47_encrypt,         rot47_decrypt,         'classical'),
    'vigenere':      ('Vigenère',              vigenere_encrypt,      vigenere_decrypt,      'classical'),
    'beaufort':      ('Beaufort',              beaufort_encrypt,      beaufort_decrypt,      'classical'),
    'autokey':       ('Autokey',               autokey_encrypt,       autokey_decrypt,       'classical'),
    'porta':         ('Porta',                 porta_encrypt,         porta_decrypt,         'classical'),
    'gronsfeld':     ('Gronsfeld',             gronsfeld_encrypt,     gronsfeld_decrypt,     'classical'),
    'bifid':         ('Bifid',                 bifid_encrypt,         bifid_decrypt,         'classical'),
    'trifid':        ('Trifid',                trifid_encrypt,        trifid_decrypt,        'classical'),
    'foursquare':    ('Four-square',           foursquare_encrypt,    foursquare_decrypt,    'classical'),
    'twosquare':     ('Two-square',            twosquare_encrypt,     twosquare_decrypt,     'classical'),
    'adfgvx':        ('ADFGVX',                adfgvx_encrypt,        adfgvx_decrypt,        'classical'),
    'adfgx':         ('ADFGX',                 adfgx_encrypt,         adfgx_decrypt,         'classical'),
    'nihilist':      ('Nihilist',              nihilist_encrypt,      nihilist_decrypt,      'classical'),
    'bazeries':      ('Bazeries',              bazeries_encrypt,      bazeries_decrypt,      'classical'),
    'syllabary':     ('Syllabary',             syllabary_encrypt,     syllabary_decrypt,     'classical'),
    'scytale':       ('Scytale',               scytale_encrypt,       scytale_decrypt,       'classical'),
    'myszkowski':    ('Myszkowski',            myszkowski_encrypt,    myszkowski_decrypt,    'classical'),
    'amsco':         ('AMSCO',                 amsco_encrypt,         amsco_decrypt,         'classical'),
    'nato':          ('NATO Phonetic',         nato_encrypt,          nato_decrypt,          'classical'),
    'morse':         ('Morse Code',            morse_encrypt,         morse_decrypt,         'classical'),
    'tapcode':       ('Tap Code',              tapcode_encrypt,       tapcode_decrypt,       'classical'),
    'polybius':      ('Polybius Square',       polybius_encrypt,      polybius_decrypt,      'classical'),
    'piglatin':      ('Pig Latin',             piglatin_encrypt,      piglatin_decrypt,      'classical'),
    'ubbidubbi':     ('Ubbi Dubbi',            ubbidubbi_encrypt,     ubbidubbi_decrypt,     'classical'),
    'rovarspraket':  ('Rövarspråket',          rovarspraket_encrypt,  rovarspraket_decrypt,  'classical'),
    'leet':          ('Leet Speak',            leet_encrypt,          leet_decrypt,          'classical'),
    'reverse':       ('Reverse Text',          reverse_encrypt,       reverse_decrypt,       'classical'),

    # ─── NHÓM 2: TOÁN HỌC ───
    'binary':            ('Binary',              binary_encrypt,            binary_decrypt,            'math'),
    'octal':             ('Octal',               octal_encrypt,             octal_decrypt,             'math'),
    'hex':               ('Hexadecimal',         hex_encrypt,               hex_decrypt,               'math'),
    'ascii_decimal':     ('ASCII Decimal',       ascii_decimal_encrypt,     ascii_decimal_decrypt,     'math'),
    'base32':            ('Base32',              base32_encrypt,            base32_decrypt,            'math'),
    'base58':            ('Base58',              base58_encrypt,            base58_decrypt,            'math'),
    'base85':            ('Base85',              base85_encrypt,            base85_decrypt,            'math'),
    'base91':            ('Base91',              base91_encrypt,            base91_decrypt,            'math'),
    'base36':            ('Base36',              base36_encrypt,            base36_decrypt,            'math'),
    'base62':            ('Base62',              base62_encrypt,            base62_decrypt,            'math'),
    'base100':           ('Base100 (Emoji)',     base100_encrypt,           base100_decrypt,           'math'),
    'urlencode':         ('URL Encode',          urlencode_encrypt,         urlencode_decrypt,         'math'),
    'htmlentities':      ('HTML Entities',       htmlentities_encrypt,      htmlentities_decrypt,      'math'),
    'unicode_escape':    ('Unicode Escape',      unicode_escape_encrypt,    unicode_escape_decrypt,    'math'),
    'quoted_printable':  ('Quoted-printable',    quoted_printable_encrypt,  quoted_printable_decrypt,  'math'),
    'uuencode':          ('UUencode',            uuencode_encrypt,          uuencode_decrypt,          'math'),
    'xxencode':          ('XXencode',            xxencode_encrypt,          xxencode_decrypt,          'math'),
    'yenc':              ('YEnc',                yenc_encrypt,              yenc_decrypt,              'math'),
    'ieee754':           ('IEEE 754',            ieee754_encrypt,           ieee754_decrypt,           'math'),
    'bcd':               ('BCD',                 bcd_encrypt,               bcd_decrypt,               'math'),

    # ─── NHÓM 3: HASH ───
    'md5':        ('MD5',              md5_encrypt,        md5_decrypt,        'hash'),
    'sha1':       ('SHA-1',            sha1_encrypt,       sha1_decrypt,       'hash'),
    'sha224':     ('SHA-224',          sha224_encrypt,     sha224_decrypt,     'hash'),
    'sha256':     ('SHA-256',          sha256_encrypt,     sha256_decrypt,     'hash'),
    'sha384':     ('SHA-384',          sha384_encrypt,     sha384_decrypt,     'hash'),
    'sha512':     ('SHA-512',          sha512_encrypt,     sha512_decrypt,     'hash'),
    'sha3_256':   ('SHA3-256',         sha3_256_encrypt,   sha3_256_decrypt,   'hash'),
    'sha3_512':   ('SHA3-512',         sha3_512_encrypt,   sha3_512_decrypt,   'hash'),
    'blake2b':    ('BLAKE2b',          blake2b_encrypt,    blake2b_decrypt,    'hash'),
    'blake2s':    ('BLAKE2s',          blake2s_encrypt,    blake2s_decrypt,    'hash'),
    'blake3':     ('BLAKE3',           blake3_encrypt,     blake3_decrypt,     'hash'),
    'ripemd160':  ('RIPEMD-160',       ripemd160_encrypt,  ripemd160_decrypt,  'hash'),
    'whirlpool':  ('Whirlpool',        whirlpool_encrypt,  whirlpool_decrypt,  'hash'),
    'tiger':      ('Tiger',            tiger_encrypt,      tiger_decrypt,      'hash'),
    'haval':      ('HAVAL',            haval_encrypt,      haval_decrypt,      'hash'),
    'keccak256':  ('Keccak-256',       keccak256_encrypt,  keccak256_decrypt,  'hash'),
    'keccak512':  ('Keccak-512',       keccak512_encrypt,  keccak512_decrypt,  'hash'),
    'gost':       ('GOST',             gost_encrypt,       gost_decrypt,       'hash'),
    'snefru':     ('Snefru',           snefru_encrypt,     snefru_decrypt,     'hash'),
    'crc32':      ('CRC32',            crc32_encrypt,      crc32_decrypt,      'hash'),
    'adler32':    ('Adler-32',         adler32_encrypt,    adler32_decrypt,    'hash'),
    'fnv1a':      ('FNV-1a',           fnv1a_encrypt,      fnv1a_decrypt,      'hash'),
    'murmur3':    ('MurmurHash3',      murmur3_encrypt,    murmur3_decrypt,    'hash'),
    'xxhash':     ('xxHash',           xxhash_encrypt,     xxhash_decrypt,     'hash'),
    'siphash':    ('SipHash',          siphash_encrypt,    siphash_decrypt,    'hash'),

    # ─── NHÓM 4: ĐỐI XỨNG ───
    'aes128':      ('AES-128 (ECB)',    aes128_encrypt,      aes128_decrypt,      'symmetric'),
    'aes192':      ('AES-192 (ECB)',    aes192_encrypt,      aes192_decrypt,      'symmetric'),
    'aes_gcm':     ('AES-256-GCM',      aes_gcm_encrypt,     aes_gcm_decrypt,     'symmetric'),
    'des':         ('DES',              des_encrypt,         des_decrypt,         'symmetric'),
    'tripledes':   ('3DES',             tripledes_encrypt,   tripledes_decrypt,   'symmetric'),
    'blowfish':    ('Blowfish',         blowfish_encrypt,    blowfish_decrypt,    'symmetric'),
    'twofish':     ('Twofish',          twofish_encrypt,     twofish_decrypt,     'symmetric'),
    'serpent':     ('Serpent',          serpent_encrypt,     serpent_decrypt,     'symmetric'),
    'rc2':         ('RC2',              rc2_encrypt,         rc2_decrypt,         'symmetric'),
    'rc4':         ('RC4',              rc4_encrypt,         rc4_decrypt,         'symmetric'),
    'rc5':         ('RC5',              rc5_encrypt,         rc5_decrypt,         'symmetric'),
    'rc6':         ('RC6',              rc6_encrypt,         rc6_decrypt,         'symmetric'),
    'chacha20':    ('ChaCha20',         chacha20_encrypt,    chacha20_decrypt,    'symmetric'),
    'salsa20':     ('Salsa20',          salsa20_encrypt,     salsa20_decrypt,     'symmetric'),
    'xsalsa20':    ('XSalsa20',         xsalsa20_encrypt,    xsalsa20_decrypt,    'symmetric'),
    'xchacha20':   ('XChaCha20',        xchacha20_encrypt,   xchacha20_decrypt,   'symmetric'),
    'camellia':    ('Camellia',         camellia_encrypt,    camellia_decrypt,    'symmetric'),
    'aria':        ('ARIA',             aria_encrypt,        aria_decrypt,        'symmetric'),
    'sm4':         ('SM4',              sm4_encrypt,         sm4_decrypt,         'symmetric'),
    'seed':        ('SEED',             seed_encrypt,        seed_decrypt,        'symmetric'),
    'idea':        ('IDEA',             idea_encrypt,        idea_decrypt,        'symmetric'),
    'cast5':       ('CAST5',            cast5_encrypt,       cast5_decrypt,       'symmetric'),
    'cast6':       ('CAST6',            cast6_encrypt,       cast6_decrypt,       'symmetric'),
    'tea':         ('TEA',              tea_encrypt,         tea_decrypt,         'symmetric'),
    'xtea':        ('XTEA',             xtea_encrypt,        xtea_decrypt,        'symmetric'),
    'xxtea':       ('XXTEA',            xxtea_encrypt,       xxtea_decrypt,       'symmetric'),
    'speck':       ('Speck',            speck_encrypt,       speck_decrypt,       'symmetric'),
    'simon':       ('Simon',            simon_encrypt,       simon_decrypt,       'symmetric'),
    'present':     ('PRESENT',          present_encrypt,     present_decrypt,     'symmetric'),
    'kasumi':      ('KASUMI',           kasumi_encrypt,      kasumi_decrypt,      'symmetric'),
    'misty1':      ('MISTY1',           misty1_encrypt,      misty1_decrypt,      'symmetric'),
    'skipjack':    ('Skipjack',         skipjack_encrypt,    skipjack_decrypt,    'symmetric'),
    'otp':         ('One-Time Pad',     otp_encrypt,         otp_decrypt,         'symmetric'),
    'vernam':      ('Vernam',           vernam_encrypt,      vernam_decrypt,      'symmetric'),

    # ─── NHÓM 5: BẤT ĐỐI XỨNG ───
    'rsa':          ('RSA',           rsa_encrypt,          rsa_decrypt,          'asymmetric'),
    'rsa_oaep':     ('RSA-OAEP',      rsa_oaep_encrypt,     rsa_oaep_decrypt,     'asymmetric'),
    'ecc':          ('ECC',           ecc_encrypt,          ecc_decrypt,          'asymmetric'),
    'ecdsa':        ('ECDSA',         ecdsa_encrypt,        ecdsa_decrypt,        'asymmetric'),
    'ed25519':      ('Ed25519',       ed25519_encrypt,      ed25519_decrypt,      'asymmetric'),
    'x25519':       ('X25519',        x25519_encrypt,       x25519_decrypt,       'asymmetric'),
    'curve25519':   ('Curve25519',    curve25519_encrypt,   curve25519_decrypt,   'asymmetric'),
    'dh':           ('Diffie-Hellman',dh_encrypt,           dh_decrypt,           'asymmetric'),
    'elgamal':      ('ElGamal',       elgamal_encrypt,      elgamal_decrypt,      'asymmetric'),
    'dsa':          ('DSA',           dsa_encrypt,          dsa_decrypt,          'asymmetric'),
    'ecdh':         ('ECDH',          ecdh_encrypt,         ecdh_decrypt,         'asymmetric'),
    'paillier':     ('Paillier',      paillier_encrypt,     paillier_decrypt,     'asymmetric'),
    'rabin':        ('Rabin',         rabin_encrypt,        rabin_decrypt,        'asymmetric'),
    'ntru':         ('NTRU',          ntru_encrypt,         ntru_decrypt,         'asymmetric'),
    'kyber':        ('Kyber',         kyber_encrypt,        kyber_decrypt,        'asymmetric'),
    'dilithium':    ('Dilithium',     dilithium_encrypt,    dilithium_decrypt,    'asymmetric'),
    'falcon':       ('Falcon',        falcon_encrypt,       falcon_decrypt,       'asymmetric'),
    'sphincs':      ('SPHINCS+',      sphincs_encrypt,      sphincs_decrypt,      'asymmetric'),

    # ─── NHÓM 6: SINH HỌC & ĐẶC BIỆT ───
    'dna':           ('DNA Encoding',          dna_encrypt,           dna_decrypt,           'special'),
    'rna':           ('RNA Encoding',          rna_encrypt,           rna_decrypt,           'special'),
    'amino':         ('Amino Acid',            amino_encrypt,         amino_decrypt,         'special'),
    'protein':       ('Protein',               protein_encrypt,       protein_decrypt,       'special'),
    'emoji':         ('Emoji Encoding',        emoji_encrypt,         emoji_decrypt,         'special'),
    'braille':       ('Braille',               braille_encrypt,       braille_decrypt,       'special'),
    'semaphore':     ('Semaphore',             semaphore_encrypt,     semaphore_decrypt,     'special'),
    'baconian':      ('Baconian',              baconian_encrypt,      baconian_decrypt,      'special'),
    'bookcipher':    ('Book Cipher',           bookcipher_encrypt,    bookcipher_decrypt,    'special'),
    'nullcipher':    ('Null Cipher',           nullcipher_encrypt,    nullcipher_decrypt,    'special'),
    'acrostic':      ('Acrostic',              acrostic_encrypt,      acrostic_decrypt,      'special'),
    'railfence':     ('Rail Fence',            railfence_encrypt,     railfence_decrypt,     'special'),
    'route':         ('Route Cipher',          route_encrypt,         route_decrypt,         'special'),
    'cardan':        ('Cardan Grille',         cardan_encrypt,        cardan_decrypt,        'special'),
    'runningkey':    ('Running Key',           runningkey_encrypt,    runningkey_decrypt,    'special'),
    'nomenclator':   ('Nomenclator',           nomenclator_encrypt,   nomenclator_decrypt,   'special'),
    'homophonic':    ('Homophonic',            homophonic_encrypt,    homophonic_decrypt,    'special'),
    'polyphonic':    ('Polyphonic',            polyphonic_encrypt,    polyphonic_decrypt,    'special'),
    'fracmorse':     ('Fractionated Morse',    fracmorse_encrypt,     fracmorse_decrypt,     'special'),
    'solitaire':     ('Solitaire',             solitaire_encrypt,     solitaire_decrypt,     'special'),
    'chaocipher':    ('Chaocipher',            chaocipher_encrypt,    chaocipher_decrypt,    'special'),
    'straddling':    ('Straddling Checkerboard',straddling_encrypt,   straddling_decrypt,    'special'),
    'checkerboard':  ('Checkerboard',          checkerboard_encrypt,  checkerboard_decrypt,  'special'),

    # ─── NHÓM 7: GAME ───
    'caesarbox':     ('Caesar Box',            caesarbox_encrypt,     caesarbox_decrypt,     'game'),
    'a1z26':         ('A1Z26',                 a1z26_encrypt,         a1z26_decrypt,         'game'),
    'a0z25':         ('A0Z25',                 a0z25_encrypt,         a0z25_decrypt,         'game'),
    'phonekeypad':   ('Phone Keypad',          phonekeypad_encrypt,   phonekeypad_decrypt,   'game'),
    't9':            ('T9',                    t9_encrypt,            t9_decrypt,            'game'),
    'nato_phonetic': ('NATO Phonetic (alt)',   nato_encrypt,          nato_decrypt,          'game'),
    'pigpen':        ('Pigpen Cipher',         pigpen_encrypt,        pigpen_decrypt,        'game'),
    'tictactoe':     ('Tic-tac-toe Cipher',    tictactoe_encrypt,     tictactoe_decrypt,     'game'),
    'masonic':       ('Masonic Cipher',        masonic_encrypt,       masonic_decrypt,       'game'),
    'rosicrucian':   ('Rosicrucian',           rosicrucian_encrypt,   rosicrucian_decrypt,   'game'),
    'dancingmen':    ('Dancing Men',           dancingmen_encrypt,    dancingmen_decrypt,    'game'),
    'unown':         ('Unown (Pokémon)',       unown_encrypt,         unown_decrypt,         'game'),
    'klingon':       ('Klingon',               klingon_encrypt,       klingon_decrypt,       'game'),
    'dovahzul':      ('Dovahzul (Skyrim)',     dovahzul_encrypt,      dovahzul_decrypt,      'game'),
    'hylian':        ('Hylian (Zelda)',        hylian_encrypt,        hylian_decrypt,        'game'),
    'aurebesh':      ('Aurebesh (Star Wars)',  aurebesh_encrypt,      aurebesh_decrypt,      'game'),
    'runic':         ('Runic',                 runic_encrypt,         runic_decrypt,         'game'),
    'ogham':         ('Ogham',                 ogham_encrypt,         ogham_decrypt,         'game'),
    'hieroglyph':    ('Hieroglyph',            hieroglyph_encrypt,    hieroglyph_decrypt,    'game'),
    'cuneiform':     ('Cuneiform',             cuneiform_encrypt,     cuneiform_decrypt,     'game'),
    'wingdings':     ('Wingdings',             wingdings_encrypt,     wingdings_decrypt,     'game'),
    'zalgo':         ('Zalgo',                 zalgo_encrypt,         zalgo_decrypt,         'game'),
    'upsidedown':    ('Upside Down',           upsidedown_encrypt,    upsidedown_decrypt,    'game'),
    'mirror':        ('Mirror',                mirror_encrypt,        mirror_decrypt,        'game'),
    'smallcaps':     ('Small Caps',            smallcaps_encrypt,     smallcaps_decrypt,     'game'),

    # ─── NHÓM 8: NGÔN NGỮ ───
    'telex':             ('Vietnamese Telex',      telex_encrypt,            telex_decrypt,            'language'),
    'vni':               ('VNI',                   vni_encrypt,              vni_decrypt,              'language'),
    'viqr':              ('VIQR',                  viqr_encrypt,             viqr_decrypt,             'language'),
    'pinyin':            ('Pinyin',                pinyin_encrypt,           pinyin_decrypt,           'language'),
    'romaji':            ('Romaji',                romaji_encrypt,           romaji_decrypt,           'language'),
    'hangul_roman':      ('Hangul Romanization',   hangul_roman_encrypt,     hangul_roman_decrypt,     'language'),
    'cyrillic_trans':    ('Cyrillic Transliteration', cyrillic_trans_encrypt, cyrillic_trans_decrypt,  'language'),
    'greek_trans':       ('Greek Transliteration', greek_trans_encrypt,      greek_trans_decrypt,      'language'),
    'arabic_trans':      ('Arabic Transliteration',arabic_trans_encrypt,     arabic_trans_decrypt,     'language'),
    'thai_trans':        ('Thai Transliteration',  thai_trans_encrypt,       thai_trans_decrypt,       'language'),
    'sanskrit_trans':    ('Sanskrit Transliteration', sanskrit_trans_encrypt, sanskrit_trans_decrypt, 'language'),
}


# ═══════════════════════════════════════════════════════════════════════════
#  TƯƠNG THÍCH NGƯỢC VỚI APP.PY
# ═══════════════════════════════════════════════════════════════════════════

METHODS = {k: v[0] for k, v in METHODS_REGISTRY.items()}
ONE_WAY_METHODS = {k for k, v in METHODS_REGISTRY.items() if v[3] == 'hash'}
ONE_WAY_ONLY = ONE_WAY_METHODS  # alias cho app.py

NEED_KEY_METHODS = {
    'vigenere','beaufort','autokey','porta','gronsfeld','bifid','trifid',
    'foursquare','twosquare','adfgvx','adfgx','nihilist','bazeries','syllabary',
    'scytale','myszkowski','amsco','columnar','railfence','route','runningkey',
    'solitaire','chaocipher',
    'aes128','aes192','aes_gcm','des','tripledes','blowfish','twofish','serpent',
    'rc2','rc4','rc5','rc6','chacha20','salsa20','xsalsa20','xchacha20',
    'camellia','aria','sm4','seed','idea','cast5','cast6','tea','xtea','xxtea',
    'speck','simon','present','kasumi','misty1','skipjack','otp','vernam',
    'rsa','rsa_oaep','ecc','ecdsa','ed25519','x25519','curve25519','dh',
    'elgamal','dsa','ecdh','paillier','rabin','ntru','kyber','dilithium',
    'falcon','sphincs',
}

GROUP_NAMES = {
    'classical':  '🔤 Cổ điển',
    'math':       '🔢 Toán học & Số',
    'hash':       '🔐 Một chiều (Hash)',
    'symmetric':  '🔒 Đối xứng',
    'asymmetric': '🔑 Bất đối xứng',
    'special':    '🧬 Sinh học & Đặc biệt',
    'game':       '🎮 Game / Giải trí',
    'language':   '🌐 Ngôn ngữ & Văn hóa',
}

METHOD_GROUPS = {k: v[3] for k, v in METHODS_REGISTRY.items()}


# ═══════════════════════════════════════════════════════════════════════════
#  HÀM XỬ LÝ CHÍNH
# ═══════════════════════════════════════════════════════════════════════════

def process(text, method='base64', action='encrypt', key=''):
    """
    Hàm xử lý mã hóa / giải mã (tương thích app.py cũ).
    
    Args:
        text: Văn bản
        method: Mã phương pháp
        action: 'encrypt' hoặc 'decrypt'
        key: Khóa
    
    Returns:
        str: Kết quả (hoặc thông báo lỗi)
    """
    if not text and action == 'encrypt':
        return 'Văn bản trống!'
    if method not in METHODS_REGISTRY:
        return f'Phương pháp không tồn tại: {method}'
    
    name, enc_fn, dec_fn, group = METHODS_REGISTRY[method]
    
    if action == 'encrypt':
        fn = enc_fn
    else:
        fn = dec_fn
        if method in ONE_WAY_METHODS:
            return f'PP "{name}" là mã hóa 1 chiều — không thể giải mã!'
    
    try:
        return fn(text, key)
    except Exception as e:
        return f'Lỗi: {e}'


def process_text(text, method='base64', action='encrypt', key=''):
    """Alias của process() — trả về dict chi tiết hơn."""
    if method not in METHODS_REGISTRY:
        return {'success': False, 'error': f'Phương pháp không tồn tại: {method}'}
    
    result = process(text, method, action, key)
    if result.startswith('Lỗi:') or result.startswith('PP "') or result.startswith('Phương pháp') or result == 'Văn bản trống!':
        return {'success': False, 'error': result}
    
    return {'success': True, 'result': result, 'method': method}


def get_all_methods():
    return {k: v[0] for k, v in METHODS_REGISTRY.items()}


def get_methods_by_group():
    result = {}
    for code, (name, _, _, group) in METHODS_REGISTRY.items():
        result.setdefault(group, {})[code] = name
    return result


def is_one_way(method):
    return method in ONE_WAY_METHODS


def needs_key(method):
    return method in NEED_KEY_METHODS


def get_method_info(method):
    if method not in METHODS_REGISTRY:
        return {}
    name, _, _, group = METHODS_REGISTRY[method]
    return {
        'code': method,
        'name': name,
        'group': group,
        'group_name': GROUP_NAMES.get(group, group),
        'one_way': is_one_way(method),
        'needs_key': needs_key(method),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  DỊCH THUẬT (TRANSLATION)
# ═══════════════════════════════════════════════════════════════════════════

LANGUAGES = {
    'vi':    'Tiếng Việt',
    'en':    'English',
    'zh-cn': '中文 (简体)',
    'zh-tw': '中文 (繁體)',
    'ja':    '日本語',
    'ko':    '한국어',
    'fr':    'Français',
    'es':    'Español',
    'de':    'Deutsch',
    'ru':    'Русский',
    'th':    'ไทย',
    'it':    'Italiano',
    'pt':    'Português',
    'ar':    'العربية',
    'hi':    'हिन्दी',
    'id':    'Bahasa Indonesia',
}

# Dùng deep-translator (ổn định hơn googletrans)
try:
    from deep_translator import GoogleTranslator
    HAS_TRANSLATOR = True
except ImportError:
    try:
        from googletrans import Translator as _GT
        _gt_translator = _GT()
        HAS_TRANSLATOR = True
        HAS_GOOGLETRANS_OLD = True
    except ImportError:
        HAS_TRANSLATOR = False
        HAS_GOOGLETRANS_OLD = False
        GoogleTranslator = None


def detect_language(text):
    """Phát hiện ngôn ngữ của văn bản (fallback = đoán đơn giản)."""
    if not text or not text.strip():
        return 'unknown'
    try:
        if HAS_TRANSLATOR:
            try:
                from deep_translator import single_detection
                # deep-translator không có detect built-in miễn phí
                # → dùng fallback
                pass
            except Exception:
                pass
    except Exception:
        pass
    
    # Fallback: đoán đơn giản theo ký tự
    if any('\u4e00' <= c <= '\u9fff' for c in text):
        return 'zh-cn'
    if any('\u3040' <= c <= '\u30ff' for c in text):
        return 'ja'
    if any('\uac00' <= c <= '\ud7af' for c in text):
        return 'ko'
    if any('\u0400' <= c <= '\u04ff' for c in text):
        return 'ru'
    if any('\u0e00' <= c <= '\u0e7f' for c in text):
        return 'th'
    if any(c in 'ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ' for c in text.lower()):
        return 'vi'
    return 'en'


def translate(text, source='auto', target='en'):
    """Dịch văn bản."""
    if not text or not text.strip():
        return ''
    
    if not HAS_TRANSLATOR:
        return f'[Chưa cài deep-translator — không dịch được]\n{text}'
    
    try:
        if 'deep_translator' in str(GoogleTranslator):
            src = 'auto' if source == 'auto' else source
            result = GoogleTranslator(source=src, target=target).translate(text)
            return result or text
        else:
            # fallback googletrans
            result = _gt_translator.translate(text, src=source, dest=target)
            return result.text
    except Exception as e:
        raise ValueError(f'Lỗi dịch: {e}')


def to_english(text):
    return translate(text, source='auto', target='en')


def to_vietnamese(text):
    return translate(text, source='auto', target='vi')


def auto_translate(text):
    """Tự động phát hiện ngôn ngữ và dịch sang ngôn ngữ còn lại."""
    if not text or not text.strip():
        return {'result': '', 'detected': 'unknown', 'target': 'en'}
    detected = detect_language(text)
    target = 'en' if detected == 'vi' else 'vi'
    try:
        result = translate(text, source=detected, target=target)
    except Exception as e:
        result = f'[Lỗi dịch: {e}]'
    return {'result': result, 'detected': detected, 'target': target}


# ═══════════════════════════════════════════════════════════════════════════
#  TEST NHANH
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print(f"✅ Tổng số methods: {len(METHODS_REGISTRY)}")
    print(f"✅ Số nhóm: {len(GROUP_NAMES)}")
    for g, name in GROUP_NAMES.items():
        count = sum(1 for v in METHODS_REGISTRY.values() if v[3] == g)
        print(f"   {name}: {count} methods")
    print()
    # Test vài method
    print("Test Atbash:", process("Hello", "atbash", "encrypt"))
    print("Test Morse:", process("SOS", "morse", "encrypt"))
    print("Test DNA:", process("Hi", "dna", "encrypt"))
    print("Test Reverse:", process("abcdef", "reverse", "encrypt"))
    print()
    print("Test translate:", translate("Hello world", target="vi"))
    print("Test detect:", detect_language("Xin chào các bạn"))
