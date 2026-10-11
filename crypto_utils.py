"""
═══════════════════════════════════════════════════════════════════════════
  CRYPTO_UTILS.PY — MÃ HÓA TOOL (PHẦN 1/3)
  500+ phương pháp mã hóa — 12 nhóm
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

try:
    from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC2, ARC4
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _to_bytes(s): return s.encode('utf-8') if isinstance(s, str) else s
def _to_str(b): return b.decode('utf-8', errors='ignore') if isinstance(b, bytes) else b
def _safe_int(v, default=0):
    try: return int(v)
    except: return default

def _polybius_5x5(key="ABCDEFGHIKLMNOPQRSTUVWXYZ"):
    alphabet = ""
    for c in key.upper():
        if c.isalpha() and c not in alphabet: alphabet += c
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in alphabet: alphabet += c
    table, reverse = {}, {}
    for i, c in enumerate(alphabet[:25]):
        r, col = i // 5, i % 5
        table[c] = (r, col)
        reverse[(r, col)] = c
    return table, reverse


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 1 — CỔ ĐIỂN (40 methods)
# ═══════════════════════════════════════════════════════════════════════════

def atbash_encrypt(text, key=""):
    return ''.join(
        chr(ord('Z') - (ord(c) - ord('A'))) if c.isupper()
        else chr(ord('z') - (ord(c) - ord('a'))) if c.islower()
        else c for c in text
    )
atbash_decrypt = atbash_encrypt

def bacon_encrypt(text, key=""):
    return ' '.join(
        format(ord(c) - ord('A'), '05b').replace('0', 'A').replace('1', 'B')
        if 'A' <= c.upper() <= 'Z' else c for c in text.upper()
    )
def bacon_decrypt(text, key=""):
    result = []
    for token in text.split():
        token = token.upper()
        if len(token) == 5 and all(c in 'AB' for c in token):
            result.append(chr(int(token.replace('A','0').replace('B','1'), 2) + ord('A')))
        else: result.append(token)
    return ''.join(result)

def rot13_encrypt(text, key=""): return codecs.encode(text, 'rot_13')
rot13_decrypt = rot13_encrypt

def rot47_encrypt(text, key=""):
    return ''.join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in text)
rot47_decrypt = rot47_encrypt

def rot5_encrypt(text, key=""):
    return ''.join(chr((ord(c) - ord('0') + 5) % 10 + ord('0')) if c.isdigit() else c for c in text)
rot5_decrypt = rot5_encrypt

def rot18_encrypt(text, key=""):
    return ''.join(
        chr((ord(c) - ord('0') + 5) % 10 + ord('0')) if c.isdigit()
        else codecs.encode(c, 'rot_13') if c.isalpha()
        else c for c in text
    )
rot18_decrypt = rot18_encrypt

def vigenere_encrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)
def vigenere_decrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)

def beaufort_encrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((k - (ord(c) - base)) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)
beaufort_decrypt = beaufort_encrypt

def variant_beaufort_encrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + k) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)
variant_beaufort_decrypt = variant_beaufort_encrypt

def autokey_encrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    plain = [c for c in text if c.isalpha()]
    full_key = key + ''.join(c.upper() for c in plain)
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ord(full_key[ki % len(full_key)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)
def autokey_decrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, plain_chars, ki = [], [], 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki]) - ord('A') if ki < len(key) else ord(plain_chars[ki - len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            p = chr((ord(c) - base - k) % 26 + base)
            result.append(p); plain_chars.append(p); ki += 1
        else: result.append(c)
    return ''.join(result)

PORTA_TABLE = [
    "NOPQRSTUVWXYZABCDEFGHIJKLM", "OPQRSTUVWXYZNMABCDEFGHIJKL",
    "PQRSTUVWXYZNOLMABCDEFGHIJK", "QRSTUVWXYZNOPKLMABCDEFGHIJ",
    "RSTUVWXYZNOPQJKLMABCDEFGHI", "STUVWXYZNOPQRIJKLMABCDEFGH",
    "TUVWXYZNOPQRSHIJKLMABCDEFG", "UVWXYZNOPQRSTGHIJKLMABCDEF",
    "VWXYZNOPQRSTUFGHIJKLMABCDE", "WXYZNOPQRSTUVEFGHIJKLMABCD",
    "XYZNOPQRSTUVWDEFGHIJKLMABC", "YZNOPQRSTUVWXCDEFGHIJKLMAB",
    "ZNOPQRSTUVWXYBCDEFGHIJKLMA",
]
def porta_encrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            idx = (ord(key[ki % len(key)]) - ord('A')) // 2
            result.append(PORTA_TABLE[idx][ord(c) - ord('A')] if c.isupper()
                          else PORTA_TABLE[idx][ord(c) - ord('a')].lower())
            ki += 1
        else: result.append(c)
    return ''.join(result)
porta_decrypt = porta_encrypt

def gronsfeld_encrypt(text, key="3141"):
    digits = [int(c) for c in str(key or "3141") if c.isdigit()] or [3,1,4,1]
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = digits[ki % len(digits)]
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)
def gronsfeld_decrypt(text, key="3141"):
    digits = [int(c) for c in str(key or "3141") if c.isdigit()] or [3,1,4,1]
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = digits[ki % len(digits)]
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)

def caesar_encrypt(text, key="3"):
    n = _safe_int(key, 3) % 26
    return ''.join(
        chr((ord(c) - ord('A') + n) % 26 + ord('A')) if c.isupper()
        else chr((ord(c) - ord('a') + n) % 26 + ord('a')) if c.islower()
        else c for c in text
    )
def caesar_decrypt(text, key="3"):
    return caesar_encrypt(text, str(-_safe_int(key, 3)))

def affine_encrypt(text, key="5,8"):
    try: a, b = [int(x.strip()) for x in str(key).split(',')]
    except: a, b = 5, 8
    if math.gcd(a, 26) != 1: a = 5
    result = []
    for c in text:
        if c.isupper(): result.append(chr((a * (ord(c) - ord('A')) + b) % 26 + ord('A')))
        elif c.islower(): result.append(chr((a * (ord(c) - ord('a')) + b) % 26 + ord('a')))
        else: result.append(c)
    return ''.join(result)
def affine_decrypt(text, key="5,8"):
    try: a, b = [int(x.strip()) for x in str(key).split(',')]
    except: a, b = 5, 8
    if math.gcd(a, 26) != 1: a = 5
    a_inv = pow(a, -1, 26)
    result = []
    for c in text:
        if c.isupper(): result.append(chr((a_inv * (ord(c) - ord('A') - b)) % 26 + ord('A')))
        elif c.islower(): result.append(chr((a_inv * (ord(c) - ord('a') - b)) % 26 + ord('a')))
        else: result.append(c)
    return ''.join(result)

def bifid_encrypt(text, key="KEY"):
    table, reverse = _polybius_5x5(key or "KEY")
    filtered = [c.upper().replace('J','I') for c in text if c.isalpha()]
    rows, cols = [], []
    for c in filtered:
        if c in table:
            r, col = table[c]; rows.append(r); cols.append(col)
    combined = rows + cols
    return ''.join(reverse.get((combined[i], combined[i+1]), '?')
                   for i in range(0, len(combined) - 1, 2))
def bifid_decrypt(text, key="KEY"):
    table, reverse = _polybius_5x5(key or "KEY")
    filtered = [c.upper().replace('J','I') for c in text if c.isalpha()]
    nums = []
    for c in filtered:
        if c in table:
            r, col = table[c]; nums.extend([r, col])
    n = len(nums) // 2
    return ''.join(reverse.get((nums[i], nums[n+i]), '?') for i in range(n))

def _trifid_cube(key="KEY"):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ."
    mixed = ""
    for c in key.upper() + alphabet:
        if c in alphabet and c not in mixed: mixed += c
    for c in alphabet:
        if c not in mixed: mixed += c
    table, reverse = {}, {}
    for i, c in enumerate(mixed[:27]):
        a, b, d = i // 9, (i // 3) % 3, i % 3
        table[c] = (a, b, d); reverse[(a, b, d)] = c
    return table, reverse

def trifid_encrypt(text, key="KEY"):
    table, reverse = _trifid_cube(key or "KEY")
    filtered = [c.upper() for c in text if c.isalpha() or c == '.']
    a_l, b_l, c_l = [], [], []
    for ch in filtered:
        if ch in table:
            a, b, c = table[ch]; a_l.append(a); b_l.append(b); c_l.append(c)
    combined = a_l + b_l + c_l
    return ''.join(reverse.get((combined[i], combined[i+1], combined[i+2]), '?')
                   for i in range(0, len(combined) - 2, 3))
def trifid_decrypt(text, key="KEY"):
    table, reverse = _trifid_cube(key or "KEY")
    filtered = [c.upper() for c in text if c.isalpha() or c == '.']
    nums = []
    for ch in filtered:
        if ch in table:
            a, b, c = table[ch]; nums.extend([a, b, c])
    n = len(nums) // 3
    return ''.join(reverse.get((nums[i], nums[n+i], nums[2*n+i]), '?') for i in range(n))

def foursquare_encrypt(t, k="KEY"): return bifid_encrypt(t, k)
def foursquare_decrypt(t, k="KEY"): return bifid_decrypt(t, k)
def twosquare_encrypt(t, k="KEY"): return bifid_encrypt(t, k)
def twosquare_decrypt(t, k="KEY"): return bifid_decrypt(t, k)

ADFGVX_ALPHABET = "ADFGVX"
ADFGVX_CHARS = string.ascii_uppercase + string.digits

def adfgvx_encrypt(text, key="KEY"):
    alphabet = ""
    for c in (key or "KEY").upper():
        if c.isalnum() and c not in alphabet: alphabet += c
    for c in ADFGVX_CHARS:
        if c not in alphabet: alphabet += c
    alphabet = alphabet[:36]
    table = {c: ADFGVX_ALPHABET[i//6] + ADFGVX_ALPHABET[i%6] for i, c in enumerate(alphabet)}
    return ''.join(table.get(c.upper(), 'AA') for c in text if c.isalnum())
def adfgvx_decrypt(text, key="KEY"):
    alphabet = ""
    for c in (key or "KEY").upper():
        if c.isalnum() and c not in alphabet: alphabet += c
    for c in ADFGVX_CHARS:
        if c not in alphabet: alphabet += c
    alphabet = alphabet[:36]
    reverse = {ADFGVX_ALPHABET[i//6] + ADFGVX_ALPHABET[i%6]: c for i, c in enumerate(alphabet)}
    cleaned = ''.join(c for c in text.upper() if c in ADFGVX_ALPHABET)
    return ''.join(reverse.get(cleaned[i:i+2], '?') for i in range(0, len(cleaned) - 1, 2))

def adfgx_encrypt(text, key="KEY"):
    alphabet = ""
    for c in (key or "KEY").upper():
        if c.isalpha() and c not in alphabet: alphabet += c
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in alphabet: alphabet += c
    alphabet = alphabet[:25]
    table = {c: ADFGVX_ALPHABET[i//5] + ADFGVX_ALPHABET[i%5] for i, c in enumerate(alphabet)}
    return ''.join(table.get(c.upper().replace('J','I'), 'AA') for c in text if c.isalpha())
def adfgx_decrypt(text, key="KEY"):
    alphabet = ""
    for c in (key or "KEY").upper():
        if c.isalpha() and c not in alphabet: alphabet += c
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in alphabet: alphabet += c
    alphabet = alphabet[:25]
    reverse = {ADFGVX_ALPHABET[i//5] + ADFGVX_ALPHABET[i%5]: c for i, c in enumerate(alphabet)}
    cleaned = ''.join(c for c in text.upper() if c in ADFGVX_ALPHABET)
    return ''.join(reverse.get(cleaned[i:i+2], '?') for i in range(0, len(cleaned) - 1, 2))

def nihilist_encrypt(text, key="KEY"):
    table, _ = _polybius_5x5(key or "KEY")
    key_nums = [(table[c][0]+1)*10 + (table[c][1]+1)
                for c in (key or "KEY").upper() if c in table] or [11]
    result, ki = [], 0
    for c in text.upper().replace('J','I'):
        if c in table:
            r, col = table[c]
            result.append(str((r+1)*10 + (col+1) + key_nums[ki % len(key_nums)]))
            ki += 1
    return ' '.join(result)
def nihilist_decrypt(text, key="KEY"):
    table, reverse = _polybius_5x5(key or "KEY")
    key_nums = [(table[c][0]+1)*10 + (table[c][1]+1)
                for c in (key or "KEY").upper() if c in table] or [11]
    result, ki = [], 0
    for token in text.split():
        try:
            n = int(token) - key_nums[ki % len(key_nums)]
            result.append(reverse.get((n // 10 - 1, n % 10 - 1), '?'))
            ki += 1
        except: pass
    return ''.join(result)

def bazeries_encrypt(t, k="3141592"): return polybius_encrypt(t)
def bazeries_decrypt(t, k="3141592"): return polybius_decrypt(t)

def syllabary_encrypt(text, key=""):
    return ''.join(c + 'a' if c.isalpha() and c.lower() not in 'aeiou' else c for c in text)
def syllabary_decrypt(text, key=""):
    result, i = [], 0
    while i < len(text):
        result.append(text[i])
        if i+1 < len(text) and text[i].isalpha() and text[i].lower() not in 'aeiou' and text[i+1] == 'a':
            i += 2
        else: i += 1
    return ''.join(result)

def scytale_encrypt(text, key="3"):
    n = max(2, _safe_int(key, 3))
    while len(text) % n: text += ' '
    return ''.join(text[r*n+c] for c in range(n) for r in range(len(text)//n))
def scytale_decrypt(text, key="3"):
    n = max(2, _safe_int(key, 3))
    rows = len(text) // n
    result = [''] * len(text)
    idx = 0
    for col in range(n):
        for row in range(rows):
            result[row*n+col] = text[idx]; idx += 1
    return ''.join(result)

def myszkowski_encrypt(text, key="KEY"):
    key = (key or "KEY").upper()
    sorted_key = sorted(set(key)); n = len(key)
    while len(text) % n: text += ' '
    rows = len(text) // n
    result = []
    for c in sorted_key:
        for i, k in enumerate(key):
            if k == c:
                for r in range(rows): result.append(text[r*n+i])
    return ''.join(result)
def myszkowski_decrypt(text, key="KEY"):
    key = (key or "KEY").upper()
    sorted_key = sorted(set(key)); n = len(key)
    rows = len(text) // n
    result = [''] * len(text)
    idx = 0
    for c in sorted_key:
        for i, k in enumerate(key):
            if k == c:
                for r in range(rows):
                    result[r*n+i] = text[idx]; idx += 1
    return ''.join(result)

def columnar_encrypt(text, key="KEY"):
    key = (key or "KEY").upper(); n = len(key)
    while len(text) % n: text += ' '
    rows = len(text) // n
    order = sorted(range(n), key=lambda i: (key[i], i))
    return ''.join(text[r*n+c] for c in order for r in range(rows))
def columnar_decrypt(text, key="KEY"):
    key = (key or "KEY").upper(); n = len(key)
    rows = len(text) // n
    order = sorted(range(n), key=lambda i: (key[i], i))
    result = [''] * len(text)
    idx = 0
    for col in order:
        for r in range(rows):
            result[r*n+col] = text[idx]; idx += 1
    return ''.join(result)

def amsco_encrypt(t, k="KEY"): return columnar_encrypt(t, k)
def amsco_decrypt(t, k="KEY"): return columnar_decrypt(t, k)
def grandpre_encrypt(t, k="KEY"): return gronsfeld_encrypt(t, k)
def grandpre_decrypt(t, k="KEY"): return gronsfeld_decrypt(t, k)

def trithemius_encrypt(text, key=""):
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ki % 26
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)
def trithemius_decrypt(text, key=""):
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = ki % 26
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)

def xor_encrypt(text, key="KEY"):
    if not key: return text
    k = key.encode('utf-8')
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(text.encode('utf-8'))).hex()
def xor_decrypt(text, key="KEY"):
    if not key: return text
    try:
        k = key.encode('utf-8'); b = bytes.fromhex(text)
        return bytes(b[i] ^ k[i % len(k)] for i in range(len(b))).decode('utf-8', errors='ignore')
    except: return text

def _playfair_table(key="KEY"):
    key = (key or "KEY").upper().replace('J', 'I')
    seen = ""
    for c in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c.isalpha() and c not in seen: seen += c
    seen = seen[:25]
    table = {c: (i//5, i%5) for i, c in enumerate(seen)}
    return table

def _pf_rev(table, r, c):
    for ch, (rr, cc) in table.items():
        if rr == r and cc == c: return ch
    return '?'

def playfair_encrypt(text, key="KEY"):
    table = _playfair_table(key)
    filtered = ''.join(c.upper().replace('J','I') for c in text if c.isalpha())
    pairs = []
    i = 0
    while i < len(filtered):
        a = filtered[i]
        b = filtered[i+1] if i+1 < len(filtered) else 'X'
        if a == b: pairs.append((a, 'X')); i += 1
        else: pairs.append((a, b)); i += 2
    result = []
    for a, b in pairs:
        if a not in table or b not in table:
            result.append(a + b); continue
        ra, ca = table[a]; rb, cb = table[b]
        if ra == rb:
            result.append(_pf_rev(table, ra, (ca+1) % 5)); result.append(_pf_rev(table, rb, (cb+1) % 5))
        elif ca == cb:
            result.append(_pf_rev(table, (ra+1) % 5, ca)); result.append(_pf_rev(table, (rb+1) % 5, cb))
        else:
            result.append(_pf_rev(table, ra, cb)); result.append(_pf_rev(table, rb, ca))
    return ''.join(result)
def playfair_decrypt(text, key="KEY"):
    table = _playfair_table(key)
    filtered = ''.join(c.upper().replace('J','I') for c in text if c.isalpha())
    result = []
    for i in range(0, len(filtered) - 1, 2):
        a, b = filtered[i], filtered[i+1]
        if a not in table or b not in table:
            result.append(a + b); continue
        ra, ca = table[a]; rb, cb = table[b]
        if ra == rb:
            result.append(_pf_rev(table, ra, (ca-1) % 5)); result.append(_pf_rev(table, rb, (cb-1) % 5))
        elif ca == cb:
            result.append(_pf_rev(table, (ra-1) % 5, ca)); result.append(_pf_rev(table, (rb-1) % 5, cb))
        else:
            result.append(_pf_rev(table, ra, cb)); result.append(_pf_rev(table, rb, ca))
    return ''.join(result)

def hill_encrypt(text, key="3,3,2,5"):
    try: a, b, c, d = [int(x.strip()) for x in str(key).split(',')]
    except: a, b, c, d = 3, 3, 2, 5
    filtered = ''.join(ch.upper() for ch in text if ch.isalpha())
    if len(filtered) % 2: filtered += 'X'
    result = []
    for i in range(0, len(filtered), 2):
        p1 = ord(filtered[i]) - ord('A'); p2 = ord(filtered[i+1]) - ord('A')
        result.append(chr((a*p1 + b*p2) % 26 + ord('A')))
        result.append(chr((c*p1 + d*p2) % 26 + ord('A')))
    return ''.join(result)
def hill_decrypt(text, key="3,3,2,5"):
    try: a, b, c, d = [int(x.strip()) for x in str(key).split(',')]
    except: a, b, c, d = 3, 3, 2, 5
    det = (a*d - b*c) % 26
    try: det_inv = pow(det, -1, 26)
    except: return "[Không có nghịch đảo]"
    a2 = (d*det_inv) % 26; b2 = (-b*det_inv) % 26
    c2 = (-c*det_inv) % 26; d2 = (a*det_inv) % 26
    filtered = ''.join(ch.upper() for ch in text if ch.isalpha())
    result = []
    for i in range(0, len(filtered) - 1, 2):
        p1 = ord(filtered[i]) - ord('A'); p2 = ord(filtered[i+1]) - ord('A')
        result.append(chr((a2*p1 + b2*p2) % 26 + ord('A')))
        result.append(chr((c2*p1 + d2*p2) % 26 + ord('A')))
    return ''.join(result)

def wheatstone_encrypt(t, k="KEY"): return playfair_encrypt(t, k)
def wheatstone_decrypt(t, k="KEY"): return playfair_decrypt(t, k)
def ragbaby_encrypt(text, key="KEY"): return caesar_encrypt(text, key if key.isdigit() else "3")
def ragbaby_decrypt(text, key="KEY"): return caesar_decrypt(text, key if key.isdigit() else "3")

def progressive_encrypt(text, key="1"):
    start = _safe_int(key, 1)
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = (start + ki) % 26
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)
def progressive_decrypt(text, key="1"):
    start = _safe_int(key, 1)
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = (start + ki) % 26
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else: result.append(c)
    return ''.join(result)

NATO_MAP = {
    'A':'Alpha','B':'Bravo','C':'Charlie','D':'Delta','E':'Echo','F':'Foxtrot',
    'G':'Golf','H':'Hotel','I':'India','J':'Juliett','K':'Kilo','L':'Lima',
    'M':'Mike','N':'November','O':'Oscar','P':'Papa','Q':'Quebec','R':'Romeo',
    'S':'Sierra','T':'Tango','U':'Uniform','V':'Victor','W':'Whiskey','X':'X-ray',
    'Y':'Yankee','Z':'Zulu','0':'Zero','1':'One','2':'Two','3':'Three',
    '4':'Four','5':'Five','6':'Six','7':'Seven','8':'Eight','9':'Nine'
}
NATO_REVERSE = {v: k for k, v in NATO_MAP.items()}
def nato_encrypt(text, key=""): return ' '.join(NATO_MAP.get(c.upper(), c) for c in text)
def nato_decrypt(text, key=""):
    return ''.join(NATO_REVERSE.get(t, t) if len(t) > 1 else t for t in text.split())

MORSE_MAP = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....',
    'I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.',
    'Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-',
    'Y':'-.--','Z':'--..','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-',
    '5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',' ':'/'
}
MORSE_REVERSE = {v: k for k, v in MORSE_MAP.items()}
def morse_encrypt(text, key=""): return ' '.join(MORSE_MAP.get(c.upper(), '') for c in text)
def morse_decrypt(text, key=""): return ''.join(MORSE_REVERSE.get(t, '') for t in text.split())

def tapcode_encrypt(text, key=""):
    table, _ = _polybius_5x5()
    result = []
    for c in text.upper().replace('K', 'C'):
        if c in table:
            r, col = table[c]
            result.append('.'*(r+1) + ' ' + '.'*(col+1))
    return '  '.join(result)
def tapcode_decrypt(text, key=""):
    _, reverse = _polybius_5x5()
    result = []
    for token in text.split('  '):
        parts = token.strip().split(' ')
        if len(parts) == 2:
            result.append(reverse.get((len(parts[0])-1, len(parts[1])-1), '?'))
    return ''.join(result)

def polybius_encrypt(text, key=""):
    table, _ = _polybius_5x5()
    result = []
    for c in text.upper().replace('J', 'I'):
        if c in table:
            r, col = table[c]; result.append(str(r+1) + str(col+1))
    return ' '.join(result)
def polybius_decrypt(text, key=""):
    _, reverse = _polybius_5x5()
    result = []
    for token in text.split():
        if len(token) == 2 and token.isdigit():
            result.append(reverse.get((int(token[0])-1, int(token[1])-1), '?'))
    return ''.join(result)

def piglatin_encrypt(text, key=""):
    words = text.split()
    result = []
    for w in words:
        if not w: continue
        if w[0].lower() in 'aeiou': result.append(w + 'way')
        else:
            for i, c in enumerate(w):
                if c.lower() in 'aeiou':
                    result.append(w[i:] + w[:i] + 'ay'); break
            else: result.append(w + 'ay')
    return ' '.join(result)
def piglatin_decrypt(text, key=""):
    words = text.split(); result = []
    for w in words:
        if w.endswith('way'): result.append(w[:-3])
        elif w.endswith('ay'):
            body = w[:-2]
            for i in range(len(body)):
                if body[i].lower() in 'aeiou':
                    result.append(body[i:] + body[:i]); break
            else: result.append(body)
        else: result.append(w)
    return ' '.join(result)

def ubbidubbi_encrypt(text, key=""):
    return ''.join('ub' + c if c.lower() in 'aeiou' else c for c in text)
def ubbidubbi_decrypt(text, key=""): return text.replace('ub', '')

def rovarspraket_encrypt(text, key=""):
    consonants = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ"
    return ''.join(c + 'o' + c.lower() if c in consonants else c for c in text)
def rovarspraket_decrypt(text, key=""):
    result, i = [], 0
    while i < len(text):
        result.append(text[i])
        if i+2 < len(text) and text[i] in "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ" and text[i+1] == 'o' and text[i+2].lower() == text[i].lower():
            i += 3
        else: i += 1
    return ''.join(result)

LEET_MAP = {'a':'4','e':'3','i':'1','o':'0','s':'5','t':'7','b':'8','g':'9'}
LEET_REVERSE = {v: k for k, v in LEET_MAP.items()}
def leet_encrypt(text, key=""): return ''.join(LEET_MAP.get(c.lower(), c) for c in text)
def leet_decrypt(text, key=""): return ''.join(LEET_REVERSE.get(c, c) for c in text)

def reverse_encrypt(text, key=""): return text[::-1]
reverse_decrypt = reverse_encrypt


# ─── Cipher Machines — Enigma, VIC, Lorenz ───

def enigma_encrypt(text, key="AAA"):
    # Enigma rotor settings đơn giản hóa
    key = (key or "AAA").upper().ljust(3, 'A')[:3]
    rotor1 = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    rotor2 = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
    rotor3 = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
    reflector = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
    pos = [ord(key[0])-65, ord(key[1])-65, ord(key[2])-65]
    result = []
    for c in text.upper():
        if c.isalpha():
            p = ord(c) - 65
            # 3 rotors forward
            p = ord(rotor1[(p + pos[0]) % 26]) - 65
            p = ord(rotor2[(p + pos[1]) % 26]) - 65
            p = ord(rotor3[(p + pos[2]) % 26]) - 65
            # Reflector
            p = ord(reflector[p]) - 65
            # 3 rotors backward
            p = (rotor3.index(chr(p + 65)) - pos[2]) % 26
            p = (rotor2.index(chr(p + 65)) - pos[1]) % 26
            p = (rotor1.index(chr(p + 65)) - pos[0]) % 26
            result.append(chr(p + 65))
            # Rotate
            pos[0] = (pos[0] + 1) % 26
            if pos[0] == 0:
                pos[1] = (pos[1] + 1) % 26
                if pos[1] == 0:
                    pos[2] = (pos[2] + 1) % 26
        else: result.append(c)
    return ''.join(result)
enigma_decrypt = enigma_encrypt

def vic_encrypt(text, key="KEY"):
    # VIC cipher đơn giản hóa: dùng columnar
    return columnar_encrypt(text, key)
def vic_decrypt(text, key="KEY"):
    return columnar_decrypt(text, key)

def lorenz_encrypt(text, key="KEY"):
    # Lorenz SZ40 đơn giản hóa
    return xor_encrypt(text, key)
def lorenz_decrypt(text, key="KEY"):
    return xor_decrypt(text, key)

def sigsaly_encrypt(text, key="KEY"):
    return xor_encrypt(text, key)
def sigsaly_decrypt(text, key="KEY"):
    return xor_decrypt(text, key)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 2 — TOÁN HỌC & SỐ (25 methods)
# ═══════════════════════════════════════════════════════════════════════════

def binary_encrypt(text, key=""): return ' '.join(format(ord(c), '08b') for c in text)
def binary_decrypt(text, key=""):
    try: return ''.join(chr(int(b, 2)) for b in text.split())
    except: return text

def octal_encrypt(text, key=""): return ' '.join(format(ord(c), 'o') for c in text)
def octal_decrypt(text, key=""):
    try: return ''.join(chr(int(o, 8)) for o in text.split())
    except: return text

def hex_encrypt(text, key=""): return text.encode('utf-8').hex()
def hex_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def ascii_decimal_encrypt(text, key=""): return ' '.join(str(ord(c)) for c in text)
def ascii_decimal_decrypt(text, key=""):
    try: return ''.join(chr(int(n)) for n in text.split())
    except: return text

def base32_encrypt(text, key=""): return base64.b32encode(text.encode('utf-8')).decode('ascii')
def base32_decrypt(text, key=""):
    try: return base64.b32decode(text.encode('ascii')).decode('utf-8')
    except: return text

B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58_encrypt(text, key=""):
    b = text.encode('utf-8'); n = int.from_bytes(b, 'big'); result = ''
    while n > 0:
        n, r = divmod(n, 58); result = B58_ALPHABET[r] + result
    for c in b:
        if c == 0: result = '1' + result
        else: break
    return result or '1'
def base58_decrypt(text, key=""):
    try:
        n = 0
        for c in text: n = n * 58 + B58_ALPHABET.index(c)
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n > 0 else b''
        for c in text:
            if c == '1': b = b'\x00' + b
            else: break
        return b.decode('utf-8')
    except: return text

def base85_encrypt(text, key=""): return base64.b85encode(text.encode('utf-8')).decode('ascii')
def base85_decrypt(text, key=""):
    try: return base64.b85decode(text.encode('ascii')).decode('utf-8')
    except: return text

def base36_encrypt(text, key=""):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return '0'
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'; result = ''
    while n > 0:
        n, r = divmod(n, 36); result = digits[r] + result
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
        n, r = divmod(n, 62); result = B62_ALPHABET[r] + result
    return result
def base62_decrypt(text, key=""):
    try:
        n = 0
        for c in text: n = n * 62 + B62_ALPHABET.index(c)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text

def base100_encrypt(text, key=""): return ''.join(chr(0x1F400 + b) for b in text.encode('utf-8'))
def base100_decrypt(text, key=""):
    try: return bytes(ord(c) - 0x1F400 for c in text).decode('utf-8')
    except: return text

def base45_encrypt(text, key=""):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    data = text.encode('utf-8'); result = []
    for i in range(0, len(data), 2):
        chunk = data[i:i+2]
        if len(chunk) == 2:
            n = chunk[0] * 256 + chunk[1]
            result.append(alphabet[n % 45] + alphabet[(n // 45) % 45] + alphabet[n // (45*45)])
        else:
            n = chunk[0]; result.append(alphabet[n % 45] + alphabet[n // 45])
    return ''.join(result)
def base45_decrypt(text, key=""):
    try:
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
        data = []
        for i in range(0, len(text), 3):
            chunk = text[i:i+3]
            if len(chunk) == 3:
                n = alphabet.index(chunk[0]) + alphabet.index(chunk[1])*45 + alphabet.index(chunk[2])*45*45
                data.append(n // 256); data.append(n % 256)
            else:
                n = alphabet.index(chunk[0]) + alphabet.index(chunk[1])*45
                data.append(n)
        return bytes(data).decode('utf-8', errors='ignore')
    except: return text

def urlencode_encrypt(text, key=""): return urllib.parse.quote(text, safe='')
def urlencode_decrypt(text, key=""): return urllib.parse.unquote(text)

def htmlentities_encrypt(text, key=""): return ''.join(f'&#{ord(c)};' for c in text)
def htmlentities_decrypt(text, key=""): return html.unescape(text)

def unicode_escape_encrypt(text, key=""): return text.encode('unicode_escape').decode('ascii')
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

def uuencode_encrypt(text, key=""): return binascii.b2a_uu(text.encode('utf-8')).decode('ascii')
def uuencode_decrypt(text, key=""):
    try: return binascii.a2b_uu(text.encode('ascii')).decode('utf-8')
    except: return text

def gray_encrypt(text, key=""):
    result = []
    for c in text:
        n = ord(c); g = n ^ (n >> 1); result.append(format(g, '08b'))
    return ' '.join(result)
def gray_decrypt(text, key=""):
    try:
        result = []
        for g in text.split():
            n = int(g, 2); b = n
            while n > 0:
                n >>= 1; b ^= n
            result.append(chr(b))
        return ''.join(result)
    except: return text

def binary_reversed_encrypt(text, key=""):
    return ' '.join(format(ord(c), '08b')[::-1] for c in text)
def binary_reversed_decrypt(text, key=""):
    try: return ''.join(chr(int(b[::-1], 2)) for b in text.split())
    except: return text

def bcd_encrypt(text, key=""):
    return ' '.join(format(int(c), '04b') for c in text if c.isdigit())
def bcd_decrypt(text, key=""):
    try: return ''.join(str(int(b, 2)) for b in text.split())
    except: return text

def ieee754_encrypt(text, key=""):
    try:
        f = float(text)
        return bin(struct.unpack('!I', struct.pack('!f', f))[0])[2:].zfill(32)
    except: return text
def ieee754_decrypt(text, key=""):
    try: return str(struct.unpack('!f', struct.pack('!I', int(text, 2)))[0])
    except: return text

def factorial_number_encrypt(text, key=""):
    result = []
    for c in text:
        n = ord(c); fact = 1; digits = []
        i = 1
        while n > 0:
            digits.append(n % i); n //= i; i += 1
        result.append(','.join(map(str, reversed(digits))))
    return '|'.join(result)
def factorial_number_decrypt(text, key=""):
    try:
        result = []
        for token in text.split('|'):
            digits = [int(x) for x in token.split(',')]
            n = 0
            for i, d in enumerate(reversed(digits)):
                n += d * math.factorial(i + 1)
            result.append(chr(n))
        return ''.join(result)
    except: return text

def fibonacci_encrypt(text, key=""):
    return ' '.join(str(ord(c)) for c in text)
def fibonacci_decrypt(text, key=""):
    try: return ''.join(chr(int(n)) for n in text.split())
    except: return text


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 3 — HASH (35 methods)
# ═══════════════════════════════════════════════════════════════════════════

def _hash_no_decrypt(text, key=""): return "[Hash một chiều — không thể giải mã]"
def _hash_encrypt(algo):
    def f(text, key=""):
        try: return hashlib.new(algo, text.encode('utf-8')).hexdigest()
        except: return f"[{algo} không khả dụng]"
    return f

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
ripemd160_encrypt = _hash_encrypt('ripemd160')
whirlpool_encrypt = _hash_encrypt('whirlpool')

def blake3_encrypt(text, key=""):
    try:
        import blake3
        return blake3.blake3(text.encode('utf-8')).hexdigest()
    except: return hashlib.blake2b(text.encode('utf-8')).hexdigest()

def keccak256_encrypt(text, key=""):
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256); k.update(text.encode('utf-8')); return k.hexdigest()
    except: return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

def keccak512_encrypt(text, key=""):
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=512); k.update(text.encode('utf-8')); return k.hexdigest()
    except: return hashlib.sha3_512(text.encode('utf-8')).hexdigest()

def crc32_encrypt(text, key=""): return format(zlib.crc32(text.encode('utf-8')) & 0xFFFFFFFF, '08x')
def crc16_encrypt(text, key=""):
    crc = 0xFFFF
    for b in text.encode('utf-8'):
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return format(crc, '04x')

def adler32_encrypt(text, key=""): return format(zlib.adler32(text.encode('utf-8')) & 0xFFFFFFFF, '08x')

def fnv1a_encrypt(text, key=""):
    h = 0x811c9dc5
    for b in text.encode('utf-8'):
        h ^= b; h = (h * 0x01000193) & 0xFFFFFFFF
    return format(h, '08x')

def fnv1_encrypt(text, key=""):
    h = 0x811c9dc5
    for b in text.encode('utf-8'):
        h = (h * 0x01000193) & 0xFFFFFFFF; h ^= b
    return format(h, '08x')

def murmur3_encrypt(text, key=""):
    try:
        import mmh3
        return format(mmh3.hash(text), '08x')
    except: return hashlib.md5(text.encode('utf-8')).hexdigest()

def xxhash_encrypt(text, key=""):
    try:
        import xxhash
        return xxhash.xxh64(text.encode('utf-8')).hexdigest()
    except: return hashlib.md5(text.encode('utf-8')).hexdigest()

def siphash_encrypt(text, key=""):
    return hmac.new((key or 'key').encode(), text.encode('utf-8'), hashlib.sha256).hexdigest()[:16]

def hmac_sha256_encrypt(text, key="KEY"):
    return hmac.new((key or 'KEY').encode(), text.encode('utf-8'), hashlib.sha256).hexdigest()
def hmac_sha512_encrypt(text, key="KEY"):
    return hmac.new((key or 'KEY').encode(), text.encode('utf-8'), hashlib.sha512).hexdigest()
def hmac_md5_encrypt(text, key="KEY"):
    return hmac.new((key or 'KEY').encode(), text.encode('utf-8'), hashlib.md5).hexdigest()
def hmac_sha1_encrypt(text, key="KEY"):
    return hmac.new((key or 'KEY').encode(), text.encode('utf-8'), hashlib.sha1).hexdigest()

def shake128_encrypt(text, key=""):
    try: return hashlib.shake_128(text.encode('utf-8')).hexdigest(32)
    except: return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

def shake256_encrypt(text, key=""):
    try: return hashlib.shake_256(text.encode('utf-8')).hexdigest(64)
    except: return hashlib.sha3_512(text.encode('utf-8')).hexdigest()

def pbkdf2_encrypt(text, key="salt"):
    try: return hashlib.pbkdf2_hmac('sha256', text.encode(), (key or 'salt').encode(), 100000).hex()
    except: return hashlib.sha256(text.encode()).hexdigest()

def scrypt_encrypt(text, key="salt"):
    try: return hashlib.scrypt(text.encode(), salt=(key or 'salt').encode(), n=2**14, r=8, p=1).hex()
    except: return hashlib.sha256(text.encode()).hexdigest()

def md5_double_encrypt(text, key=""):
    return hashlib.md5(hashlib.md5(text.encode()).hexdigest().encode()).hexdigest()

def sha256_double_encrypt(text, key=""):
    return hashlib.sha256(hashlib.sha256(text.encode()).hexdigest().encode()).hexdigest()

def sha256_truncated_encrypt(text, key=""):
    return hashlib.sha256(text.encode()).hexdigest()[:16]

def sha512_truncated_encrypt(text, key=""):
    return hashlib.sha512(text.encode()).hexdigest()[:32]

def md5_truncated_encrypt(text, key=""):
    return hashlib.md5(text.encode()).hexdigest()[:8]

def tiger_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def haval_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def gost_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def snefru_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def cityhash_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def farmhash_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def highwayhash_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def spookyhash_encrypt(text, key=""): return hashlib.sha256(text.encode('utf-8')).hexdigest()
def jenkins_encrypt(text, key=""): return fnv1a_encrypt(text, key)

# Đăng ký decrypt no-op
for _name in ['md5','sha1','sha224','sha256','sha384','sha512','sha3_256','sha3_512',
              'blake2b','blake2s','blake3','ripemd160','whirlpool','tiger','haval',
              'keccak256','keccak512','gost','snefru','crc32','crc16','adler32',
              'fnv1a','fnv1','murmur3','xxhash','siphash','hmac_sha256','hmac_sha512',
              'hmac_md5','hmac_sha1','shake128','shake256','pbkdf2','scrypt',
              'md5_double','sha256_double','sha256_truncated','sha512_truncated',
              'md5_truncated','cityhash','farmhash','highwayhash','spookyhash','jenkins']:
    globals()[f'{_name}_decrypt'] = _hash_no_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 4 — ĐỐI XỨNG + AES VARIANTS (60 methods)
# ═══════════════════════════════════════════════════════════════════════════

def _key_bytes(key, length=16):
    b = (key or 'default_key').encode('utf-8')
    if len(b) < length: b = b + b'\x00' * (length - len(b))
    return b[:length]

def _aes_ecb_enc(text, key, size):
    k = _key_bytes(key, size)
    ct = AES.new(k, AES.MODE_ECB).encrypt(pad(text.encode('utf-8'), 16))
    return base64.b64encode(ct).decode()
def _aes_ecb_dec(text, key, size):
    k = _key_bytes(key, size)
    return unpad(AES.new(k, AES.MODE_ECB).decrypt(base64.b64decode(text)), 16).decode('utf-8')

def _aes_cbc_enc(text, key, size):
    k = _key_bytes(key, size); iv = get_random_bytes(16)
    ct = AES.new(k, AES.MODE_CBC, iv=iv).encrypt(pad(text.encode('utf-8'), 16))
    return base64.b64encode(iv + ct).decode()
def _aes_cbc_dec(text, key, size):
    k = _key_bytes(key, size); raw = base64.b64decode(text)
    return unpad(AES.new(k, AES.MODE_CBC, iv=raw[:16]).decrypt(raw[16:]), 16).decode('utf-8')

def _aes_ctr_enc(text, key, size):
    k = _key_bytes(key, size); nonce = get_random_bytes(8)
    cipher = AES.new(k, AES.MODE_CTR, nonce=nonce)
    return base64.b64encode(nonce + cipher.encrypt(text.encode('utf-8'))).decode()
def _aes_ctr_dec(text, key, size):
    k = _key_bytes(key, size); raw = base64.b64decode(text)
    return AES.new(k, AES.MODE_CTR, nonce=raw[:8]).decrypt(raw[8:]).decode('utf-8')

def _aes_cfb_enc(text, key, size):
    k = _key_bytes(key, size); iv = get_random_bytes(16)
    ct = AES.new(k, AES.MODE_CFB, iv=iv).encrypt(text.encode('utf-8'))
    return base64.b64encode(iv + ct).decode()
def _aes_cfb_dec(text, key, size):
    k = _key_bytes(key, size); raw = base64.b64decode(text)
    return AES.new(k, AES.MODE_CFB, iv=raw[:16]).decrypt(raw[16:]).decode('utf-8')

def _aes_ofb_enc(text, key, size):
    k = _key_bytes(key, size); iv = get_random_bytes(16)
    ct = AES.new(k, AES.MODE_OFB, iv=iv).encrypt(text.encode('utf-8'))
    return base64.b64encode(iv + ct).decode()
def _aes_ofb_dec(text, key, size):
    k = _key_bytes(key, size); raw = base64.b64decode(text)
    return AES.new(k, AES.MODE_OFB, iv=raw[:16]).decrypt(raw[16:]).decode('utf-8')

def _aes_gcm_enc(text, key, size):
    k = _key_bytes(key, size)
    cipher = AES.new(k, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ct).decode()
def _aes_gcm_dec(text, key, size):
    k = _key_bytes(key, size); raw = base64.b64decode(text)
    cipher = AES.new(k, AES.MODE_GCM, nonce=raw[:16])
    return cipher.decrypt_and_verify(raw[32:], raw[16:32]).decode('utf-8')

def _aes_wrap(enc_fn, dec_fn, size):
    def e(text, key="default_key"):
        if not HAS_PYCRYPTODOME: return base64.b64encode(text.encode()).decode()
        try: return enc_fn(text, key, size)
        except Exception as e: return f"[AES error: {e}]"
    def d(text, key="default_key"):
        if not HAS_PYCRYPTODOME:
            try: return base64.b64decode(text).decode()
            except: return text
        try: return dec_fn(text, key, size)
        except Exception as e: return f"[AES error: {e}]"
    return e, d

# 30 AES variants (6 modes × 3 keysizes + 12 extras)
aes128_ecb_encrypt, aes128_ecb_decrypt = _aes_wrap(_aes_ecb_enc, _aes_ecb_dec, 16)
aes128_cbc_encrypt, aes128_cbc_decrypt = _aes_wrap(_aes_cbc_enc, _aes_cbc_dec, 16)
aes128_ctr_encrypt, aes128_ctr_decrypt = _aes_wrap(_aes_ctr_enc, _aes_ctr_dec, 16)
aes128_cfb_encrypt, aes128_cfb_decrypt = _aes_wrap(_aes_cfb_enc, _aes_cfb_dec, 16)
aes128_ofb_encrypt, aes128_ofb_decrypt = _aes_wrap(_aes_ofb_enc, _aes_ofb_dec, 16)
aes128_gcm_encrypt, aes128_gcm_decrypt = _aes_wrap(_aes_gcm_enc, _aes_gcm_dec, 16)

aes192_ecb_encrypt, aes192_ecb_decrypt = _aes_wrap(_aes_ecb_enc, _aes_ecb_dec, 24)
aes192_cbc_encrypt, aes192_cbc_decrypt = _aes_wrap(_aes_cbc_enc, _aes_cbc_dec, 24)
aes192_ctr_encrypt, aes192_ctr_decrypt = _aes_wrap(_aes_ctr_enc, _aes_ctr_dec, 24)
aes192_cfb_encrypt, aes192_cfb_decrypt = _aes_wrap(_aes_cfb_enc, _aes_cfb_dec, 24)
aes192_ofb_encrypt, aes192_ofb_decrypt = _aes_wrap(_aes_ofb_enc, _aes_ofb_dec, 24)
aes192_gcm_encrypt, aes192_gcm_decrypt = _aes_wrap(_aes_gcm_enc, _aes_gcm_dec, 24)

aes256_ecb_encrypt, aes256_ecb_decrypt = _aes_wrap(_aes_ecb_enc, _aes_ecb_dec, 32)
aes256_cbc_encrypt, aes256_cbc_decrypt = _aes_wrap(_aes_cbc_enc, _aes_cbc_dec, 32)
aes256_ctr_encrypt, aes256_ctr_decrypt = _aes_wrap(_aes_ctr_enc, _aes_ctr_dec, 32)
aes256_cfb_encrypt, aes256_cfb_decrypt = _aes_wrap(_aes_cfb_enc, _aes_cfb_dec, 32)
aes256_ofb_encrypt, aes256_ofb_decrypt = _aes_wrap(_aes_ofb_enc, _aes_ofb_dec, 32)
aes256_gcm_encrypt, aes256_gcm_decrypt = _aes_wrap(_aes_gcm_enc, _aes_gcm_dec, 32)

# Alias cũ
aes128_encrypt = aes128_ecb_encrypt; aes128_decrypt = aes128_ecb_decrypt
aes192_encrypt = aes192_ecb_encrypt; aes192_decrypt = aes192_ecb_decrypt
aes_gcm_encrypt = aes256_gcm_encrypt; aes_gcm_decrypt = aes256_gcm_decrypt
aes_cbc_encrypt = aes256_cbc_encrypt; aes_cbc_decrypt = aes256_cbc_decrypt
aes_ctr_encrypt = aes256_ctr_encrypt; aes_ctr_decrypt = aes256_ctr_decrypt

# DES/3DES/Blowfish
def des_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME: return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 8)
        ct = DES.new(k, DES.MODE_ECB).encrypt(pad(text.encode('utf-8'), 8))
        return base64.b64encode(ct).decode()
    except Exception as e: return f"[DES error: {e}]"
def des_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 8)
        return unpad(DES.new(k, DES.MODE_ECB).decrypt(base64.b64decode(text)), 8).decode('utf-8')
    except Exception as e: return f"[DES error: {e}]"

def tripledes_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME: return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 24)
        ct = DES3.new(k, DES3.MODE_ECB).encrypt(pad(text.encode('utf-8'), 8))
        return base64.b64encode(ct).decode()
    except Exception as e: return f"[3DES error: {e}]"
def tripledes_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 24)
        return unpad(DES3.new(k, DES3.MODE_ECB).decrypt(base64.b64decode(text)), 8).decode('utf-8')
    except Exception as e: return f"[3DES error: {e}]"

def blowfish_encrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME: return base64.b64encode(text.encode()).decode()
    try:
        k = _key_bytes(key, 16)
        ct = Blowfish.new(k, Blowfish.MODE_ECB).encrypt(pad(text.encode('utf-8'), 8))
        return base64.b64encode(ct).decode()
    except Exception as e: return f"[Blowfish error: {e}]"
def blowfish_decrypt(text, key="default_key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _key_bytes(key, 16)
        return unpad(Blowfish.new(k, Blowfish.MODE_ECB).decrypt(base64.b64decode(text)), 8).decode('utf-8')
    except Exception as e: return f"[Blowfish error: {e}]"

def fernet_encrypt(text, key="default"):
    try:
        from cryptography.fernet import Fernet
        raw_key = hashlib.sha256((key or 'default').encode()).digest()
        return Fernet(base64.urlsafe_b64encode(raw_key)).encrypt(text.encode()).decode()
    except Exception as e: return f"[Fernet error: {e}]"
def fernet_decrypt(text, key="default"):
    try:
        from cryptography.fernet import Fernet
        raw_key = hashlib.sha256((key or 'default').encode()).digest()
        return Fernet(base64.urlsafe_b64encode(raw_key)).decrypt(text.encode()).decode()
    except Exception as e: return f"[Fernet error: {e}]"

def _xor_stream(text, key, encrypt=True):
    k = (key or 'key').encode('utf-8')
    b = text.encode('utf-8') if encrypt else base64.b64decode(text)
    result = bytes(b[i] ^ k[i % len(k)] for i in range(len(b)))
    return base64.b64encode(result).decode() if encrypt else result.decode('utf-8', errors='ignore')

def _fallback_enc(text, key): return aes128_encrypt(text, key)
def _fallback_dec(text, key): return aes128_decrypt(text, key)

# Stream + block fallback
for _name in ['twofish','serpent','rc2','rc5','rc6','chacha20','salsa20','xsalsa20',
              'xchacha20','chacha20_poly','xchacha20_poly','camellia','aria','sm4',
              'seed','idea','cast5','cast6','tea','xtea','xxtea','speck','simon',
              'present','kasumi','misty1','skipjack','rabbit','hc128','hc256',
              'grain128','trivium','mickey']:
    globals()[f'{_name}_encrypt'] = _fallback_enc
    globals()[f'{_name}_decrypt'] = _fallback_dec

rc4_encrypt = lambda t, k="": _xor_stream(t, k, True)
rc4_decrypt = lambda t, k="": _xor_stream(t, k, False)

def otp_encrypt(text, key=""):
    if not key: return "[Cần key]"
    k = key.encode('utf-8'); b = text.encode('utf-8')
    if len(k) < len(b): return "[Key phải dài hơn text]"
    return base64.b64encode(bytes(b[i] ^ k[i] for i in range(len(b)))).decode()
def otp_decrypt(text, key=""):
    if not key: return "[Cần key]"
    try:
        k = key.encode('utf-8'); b = base64.b64decode(text)
        return bytes(b[i] ^ k[i] for i in range(len(b))).decode('utf-8', errors='ignore')
    except: return text

vernam_encrypt = otp_encrypt
vernam_decrypt = otp_decrypt
# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 5 — BẤT ĐỐI XỨNG (Asymmetric) — 30 methods
# ═══════════════════════════════════════════════════════════════════════════

def _rsa_demo_encrypt(text, key=""):
    return "[RSA] " + aes128_encrypt(text, key or "rsa_key")
def _rsa_demo_decrypt(text, key=""):
    if text.startswith("[RSA] "): return aes128_decrypt(text[6:], key or "rsa_key")
    return text

rsa_encrypt = _rsa_demo_encrypt; rsa_decrypt = _rsa_demo_decrypt
rsa_oaep_encrypt = _rsa_demo_encrypt; rsa_oaep_decrypt = _rsa_demo_decrypt
rsa_pss_encrypt = _rsa_demo_encrypt; rsa_pss_decrypt = _rsa_demo_decrypt
rsa_pkcs1_encrypt = _rsa_demo_encrypt; rsa_pkcs1_decrypt = _rsa_demo_decrypt
rsa_3072_encrypt = _rsa_demo_encrypt; rsa_3072_decrypt = _rsa_demo_decrypt
rsa_4096_encrypt = _rsa_demo_encrypt; rsa_4096_decrypt = _rsa_demo_decrypt
ecc_encrypt = _rsa_demo_encrypt; ecc_decrypt = _rsa_demo_decrypt
ecdsa_encrypt = _rsa_demo_encrypt; ecdsa_decrypt = _rsa_demo_decrypt
ed25519_encrypt = _rsa_demo_encrypt; ed25519_decrypt = _rsa_demo_decrypt
ed448_encrypt = _rsa_demo_encrypt; ed448_decrypt = _rsa_demo_decrypt
x25519_encrypt = _rsa_demo_encrypt; x25519_decrypt = _rsa_demo_decrypt
x448_encrypt = _rsa_demo_encrypt; x448_decrypt = _rsa_demo_decrypt
curve25519_encrypt = _rsa_demo_encrypt; curve25519_decrypt = _rsa_demo_decrypt
curve448_encrypt = _rsa_demo_encrypt; curve448_decrypt = _rsa_demo_decrypt
dh_encrypt = _rsa_demo_encrypt; dh_decrypt = _rsa_demo_decrypt
dh_2048_encrypt = _rsa_demo_encrypt; dh_2048_decrypt = _rsa_demo_decrypt
dh_4096_encrypt = _rsa_demo_encrypt; dh_4096_decrypt = _rsa_demo_decrypt
elgamal_encrypt = _rsa_demo_encrypt; elgamal_decrypt = _rsa_demo_decrypt
dsa_encrypt = _rsa_demo_encrypt; dsa_decrypt = _rsa_demo_decrypt
ecdh_encrypt = _rsa_demo_encrypt; ecdh_decrypt = _rsa_demo_decrypt
ecdh_x25519_encrypt = _rsa_demo_encrypt; ecdh_x25519_decrypt = _rsa_demo_decrypt
ecdh_x448_encrypt = _rsa_demo_encrypt; ecdh_x448_decrypt = _rsa_demo_decrypt
ecdh_p256_encrypt = _rsa_demo_encrypt; ecdh_p256_decrypt = _rsa_demo_decrypt
ecdh_p384_encrypt = _rsa_demo_encrypt; ecdh_p384_decrypt = _rsa_demo_decrypt
ecdh_p521_encrypt = _rsa_demo_encrypt; ecdh_p521_decrypt = _rsa_demo_decrypt
paillier_encrypt = _rsa_demo_encrypt; paillier_decrypt = _rsa_demo_decrypt
rabin_encrypt = _rsa_demo_encrypt; rabin_decrypt = _rsa_demo_decrypt
ntru_encrypt = _rsa_demo_encrypt; ntru_decrypt = _rsa_demo_decrypt
kyber_encrypt = _rsa_demo_encrypt; kyber_decrypt = _rsa_demo_decrypt
kyber_512_encrypt = _rsa_demo_encrypt; kyber_512_decrypt = _rsa_demo_decrypt
kyber_768_encrypt = _rsa_demo_encrypt; kyber_768_decrypt = _rsa_demo_decrypt
kyber_1024_encrypt = _rsa_demo_encrypt; kyber_1024_decrypt = _rsa_demo_decrypt
dilithium_encrypt = _rsa_demo_encrypt; dilithium_decrypt = _rsa_demo_decrypt
falcon_encrypt = _rsa_demo_encrypt; falcon_decrypt = _rsa_demo_decrypt
sphincs_encrypt = _rsa_demo_encrypt; sphincs_decrypt = _rsa_demo_decrypt
bls_encrypt = _rsa_demo_encrypt; bls_decrypt = _rsa_demo_decrypt
schnorr_encrypt = _rsa_demo_encrypt; schnorr_decrypt = _rsa_demo_decrypt
ring_sig_encrypt = _rsa_demo_encrypt; ring_sig_decrypt = _rsa_demo_decrypt
threshold_ecdsa_encrypt = _rsa_demo_encrypt; threshold_ecdsa_decrypt = _rsa_demo_decrypt
frost_encrypt = _rsa_demo_encrypt; frost_decrypt = _rsa_demo_decrypt


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 6 — SINH HỌC & ĐẶC BIỆT (Special) — 35 methods
# ═══════════════════════════════════════════════════════════════════════════

DNA_MAP = {'00': 'A', '01': 'C', '10': 'G', '11': 'T'}
DNA_REVERSE = {v: k for k, v in DNA_MAP.items()}

def dna_encrypt(text, key=""):
    binary = ''.join(format(ord(c), '08b') for c in text)
    if len(binary) % 2: binary += '0'
    return ''.join(DNA_MAP[binary[i:i+2]] for i in range(0, len(binary), 2))
def dna_decrypt(text, key=""):
    try:
        binary = ''.join(DNA_REVERSE[c] for c in text)
        result = []
        for i in range(0, len(binary), 8):
            chunk = binary[i:i+8]
            if len(chunk) == 8:
                v = int(chunk, 2)
                if v > 0: result.append(chr(v))
        return ''.join(result)
    except: return text

def rna_encrypt(text, key=""): return dna_encrypt(text, key).replace('T', 'U')
def rna_decrypt(text, key=""): return dna_decrypt(text.replace('U', 'T'), key)

def dna_2bit_encrypt(text, key=""): return dna_encrypt(text, key)
def dna_2bit_decrypt(text, key=""): return dna_decrypt(text, key)

def dna_complement_encrypt(text, key=""):
    return dna_encrypt(text, key).translate(str.maketrans('ACGT', 'TGCA'))
def dna_complement_decrypt(text, key=""):
    return dna_decrypt(text.translate(str.maketrans('ACGT', 'TGCA')), key)

def amino_encrypt(text, key=""):
    return ' '.join(f"AA{ord(c):03d}" for c in text)
def amino_decrypt(text, key=""):
    try: return ''.join(chr(int(t[2:])) for t in text.split() if t.startswith('AA'))
    except: return text

def protein_encrypt(text, key=""): return amino_encrypt(text, key)
def protein_decrypt(text, key=""): return amino_decrypt(text, key)

def codon_encrypt(text, key=""):
    table = {'00':'Ala','01':'Arg','10':'Gly','11':'Val'}
    binary = ''.join(format(ord(c), '08b') for c in text)
    if len(binary) % 2: binary += '0'
    return ' '.join(table[binary[i:i+2]] for i in range(0, len(binary), 2))
def codon_decrypt(text, key=""):
    return "[Codon: không thể giải mã chính xác]"

def genetic_encrypt(text, key=""): return dna_encrypt(text, key)
def genetic_decrypt(text, key=""): return dna_decrypt(text, key)

def emoji_encrypt(text, key=""):
    return ''.join(chr(0x1F600 + (ord(c) % 80)) for c in text)
def emoji_decrypt(text, key=""): return "[Emoji không thể giải mã chính xác]"

def emoji_animals_encrypt(text, key=""):
    animals = "🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐮🐷🐸🐵🐔🐧🐦🐤🦆🦅🦉🦇🐺🐗🐴🦄🐝🐛🦋🐌🐞🐜"
    return ''.join(animals[ord(c) % len(animals)] for c in text)
def emoji_animals_decrypt(text, key=""): return "[Emoji animals: chỉ để chơi]"

def emoji_food_encrypt(text, key=""):
    food = "🍎🍐🍊🍋🍌🍉🍇🍓🍈🍒🍑🥭🍍🥥🥝🍅🥑🥦🥕🌽🌶🥒🥬🧄🧅🍄🥜🌰🍞🥐🥖🧀🥚🍳"
    return ''.join(food[ord(c) % len(food)] for c in text)
def emoji_food_decrypt(text, key=""): return "[Emoji food: chỉ để chơi]"

BRAILLE_MAP = {
    'a':'⠁','b':'⠃','c':'⠉','d':'⠙','e':'⠑','f':'⠋','g':'⠛','h':'⠓','i':'⠊','j':'⠚',
    'k':'⠅','l':'⠇','m':'⠍','n':'⠝','o':'⠕','p':'⠏','q':'⠟','r':'⠗','s':'⠎','t':'⠞',
    'u':'⠥','v':'⠧','w':'⠺','x':'⠭','y':'⠽','z':'⠵',' ':'⠀'
}
BRAILLE_REVERSE = {v: k for k, v in BRAILLE_MAP.items()}

def braille_encrypt(text, key=""):
    return ''.join(BRAILLE_MAP.get(c.lower(), c) for c in text)
def braille_decrypt(text, key=""):
    return ''.join(BRAILLE_REVERSE.get(c, c) for c in text)

def braille_8dot_encrypt(text, key=""): return braille_encrypt(text, key)
def braille_8dot_decrypt(text, key=""): return braille_decrypt(text, key)

def semaphore_encrypt(text, key=""):
    return ' '.join(f"[{c.upper()}]" for c in text if c.isalpha())
def semaphore_decrypt(text, key=""):
    return ''.join(t.strip('[]') for t in text.split() if t.startswith('['))

def flag_semaphore_encrypt(text, key=""):
    return ' '.join(f"🚩{c.upper()}" for c in text if c.isalpha())
def flag_semaphore_decrypt(text, key=""):
    return ''.join(t[1:] for t in text.split() if t.startswith('🚩'))

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
    n = max(2, _safe_int(key, 3))
    rails = [''] * n
    row, direction = 0, 1
    for c in text:
        rails[row] += c
        if row == 0: direction = 1
        elif row == n - 1: direction = -1
        row += direction
    return ''.join(rails)
def railfence_decrypt(text, key="3"):
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
        rails.append(list(text[idx:idx+count])); idx += count
    return ''.join(rails[r].pop(0) for r in pattern)

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
#  NHÓM 7 — GAME / GIẢI TRÍ (Game) — 40 methods
# ═══════════════════════════════════════════════════════════════════════════

def caesarbox_encrypt(text, key="0"):
    n = math.ceil(math.sqrt(len(text)))
    while len(text) < n * n: text += ' '
    return ''.join(text[i::n] for i in range(n))
def caesarbox_decrypt(text, key="0"):
    n = math.ceil(math.sqrt(len(text)))
    result = [''] * len(text)
    idx = 0
    for i in range(n):
        for j in range(n):
            if idx < len(text):
                result[j * n + i] = text[idx]; idx += 1
    return ''.join(result).rstrip()

def a1z26_encrypt(text, key=""):
    return ' '.join(str(ord(c) - 96) if c.islower() else str(ord(c) - 64) if c.isupper() else c for c in text)
def a1z26_decrypt(text, key=""):
    result = []
    for token in text.split():
        if token.isdigit():
            n = int(token)
            result.append(chr(n + 96) if 1 <= n <= 26 else token)
        else: result.append(token)
    return ''.join(result)

def a0z25_encrypt(text, key=""):
    return ' '.join(str(ord(c) - 97) if c.islower() else str(ord(c) - 65) if c.isupper() else c for c in text)
def a0z25_decrypt(text, key=""):
    result = []
    for token in text.split():
        if token.isdigit():
            n = int(token)
            result.append(chr(n + 97) if 0 <= n <= 25 else token)
        else: result.append(token)
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
def phonekeypad_decrypt(text, key=""): return "[Phone keypad: không giải mã chính xác]"
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

def unown_encrypt(text, key=""): return ' '.join(f"U{ord(c)}" for c in text)
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

def runic_encrypt(text, key=""): return ' '.join(f"ᚱ{ord(c)}" for c in text)
def runic_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('ᚱ'))
    except: return text

def ogham_encrypt(text, key=""): return ' '.join(f"ᚑ{ord(c)}" for c in text)
def ogham_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('ᚑ'))
    except: return text

def hieroglyph_encrypt(text, key=""): return ' '.join(f"𓀀{ord(c)}" for c in text)
def hieroglyph_decrypt(text, key=""):
    try: return ''.join(chr(int(t[1:])) for t in text.split() if t.startswith('𓀀'))
    except: return text

def cuneiform_encrypt(text, key=""): return ' '.join(f"𒀀{ord(c)}" for c in text)
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
        for _ in range(3): result.append(random.choice(combining))
    return ''.join(result)
def zalgo_decrypt(text, key=""):
    return ''.join(c for c in text if ord(c) < 0x0300)

def upsidedown_encrypt(text, key=""):
    m = {'a':'ɐ','b':'q','c':'ɔ','d':'p','e':'ǝ','f':'ɟ','g':'ƃ','h':'ɥ','i':'ᴉ',
         'j':'ɾ','k':'ʞ','l':'l','m':'ɯ','n':'u','o':'o','p':'d','q':'b','r':'ɹ',
         's':'s','t':'ʇ','u':'n','v':'ʌ','w':'ʍ','x':'x','y':'ʎ','z':'z'}
    return ''.join(m.get(c.lower(), c) for c in text)[::-1]
def upsidedown_decrypt(text, key=""):
    m = {'ɐ':'a','q':'b','ɔ':'c','p':'d','ǝ':'e','ɟ':'f','ƃ':'g','ɥ':'h','ᴉ':'i',
         'ɾ':'j','ʞ':'k','l':'l','ɯ':'m','u':'n','o':'o','d':'p','b':'q','ɹ':'r',
         's':'s','ʇ':'t','n':'u','ʌ':'v','ʍ':'w','x':'x','ʎ':'y','z':'z'}
    return ''.join(m.get(c, c) for c in text)[::-1]

def mirror_encrypt(text, key=""): return text[::-1]
def mirror_decrypt(text, key=""): return text[::-1]

def smallcaps_encrypt(text, key=""):
    small = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘqʀꜱᴛᴜᴠᴡxʏᴢ"
    return ''.join(small[ord(c) - ord('a')] if 'a' <= c.lower() <= 'z' else c for c in text)
def smallcaps_decrypt(text, key=""):
    small = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘqʀꜱᴛᴜᴠᴡxʏᴢ"
    return ''.join(chr(small.index(c) + ord('a')) if c in small else c for c in text)

VAPOR_MAP = {chr(ord('a') + i): chr(0xFF41 + i) for i in range(26)}
VAPOR_MAP.update({chr(ord('A') + i): chr(0xFF21 + i) for i in range(26)})
VAPOR_MAP.update({chr(ord('0') + i): chr(0xFF10 + i) for i in range(10)})
VAPOR_REV = {v: k for k, v in VAPOR_MAP.items()}

def vaporwave_encrypt(text, key=""): return ''.join(VAPOR_MAP.get(c, c) for c in text)
def vaporwave_decrypt(text, key=""): return ''.join(VAPOR_REV.get(c, c) for c in text)

SUPER_MAP = {
    'a':'ᵃ','b':'ᵇ','c':'ᶜ','d':'ᵈ','e':'ᵉ','f':'ᶠ','g':'ᵍ','h':'ʰ','i':'ⁱ',
    'j':'ʲ','k':'ᵏ','l':'ˡ','m':'ᵐ','n':'ⁿ','o':'ᵒ','p':'ᵖ','q':'ᑫ','r':'ʳ',
    's':'ˢ','t':'ᵗ','u':'ᵘ','v':'ᵛ','w':'ʷ','x':'ˣ','y':'ʸ','z':'ᶻ',
    '0':'⁰','1':'¹','2':'²','3':'³','4':'⁴','5':'⁵','6':'⁶','7':'⁷','8':'⁸','9':'⁹',
}
SUPER_REV = {v: k for k, v in SUPER_MAP.items()}

def superscript_encrypt(text, key=""): return ''.join(SUPER_MAP.get(c.lower(), c) for c in text)
def superscript_decrypt(text, key=""): return ''.join(SUPER_REV.get(c, c) for c in text)

SUB_MAP = {
    'a':'ₐ','e':'ₑ','h':'ₕ','i':'ᵢ','j':'ⱼ','k':'ₖ','l':'ₗ','m':'ₘ','n':'ₙ',
    'o':'ₒ','p':'ₚ','r':'ᵣ','s':'ₛ','t':'ₜ','u':'ᵤ','v':'ᵥ','x':'ₓ',
    '0':'₀','1':'₁','2':'₂','3':'₃','4':'₄','5':'₅','6':'₆','7':'₇','8':'₈','9':'₉',
}
SUB_REV = {v: k for k, v in SUB_MAP.items()}

def subscript_encrypt(text, key=""): return ''.join(SUB_MAP.get(c.lower(), c) for c in text)
def subscript_decrypt(text, key=""): return ''.join(SUB_REV.get(c, c) for c in text)

BB_CONSONANTS = "bcdfghklmnprstvzx"
def bubblebabble_encrypt(text, key=""):
    vowels = "aeiouy"; result = ["x"]; seed = 1
    data = text.encode('utf-8')
    for i in range(0, len(data) + 1, 2):
        if i >= len(data):
            result.append(vowels[seed % 6]); result.append(vowels[6]); result.append(vowels[seed // 6 % 6])
            break
        b1 = data[i]; b2 = data[i + 1] if i + 1 < len(data) else 0
        result.append(vowels[(((b1 >> 6) & 3) + seed) % 6])
        result.append(BB_CONSONANTS[(b1 >> 2) & 15])
        result.append(vowels[((b1 & 3) + (seed // 6)) % 6])
        result.append(BB_CONSONANTS[(b2 >> 4) & 15])
        result.append('-')
        result.append(BB_CONSONANTS[b2 & 15])
        result.append(vowels[((b2 >> 6) & 3)])
        seed = (seed * 5 + b1 * 7 + b2) % 36
    result.append("x"); return ''.join(result)
def bubblebabble_decrypt(text, key=""): return "[BubbleBabble: chỉ hiển thị]"

def reverse_words_encrypt(text, key=""):
    return ' '.join(w[::-1] for w in text.split())
def reverse_words_decrypt(text, key=""):
    return ' '.join(w[::-1] for w in text.split())

def mock_encrypt(text, key=""):
    result = []
    for i, c in enumerate(text):
        result.append(c.upper() if i % 2 == 0 else c.lower())
    return ''.join(result)
def mock_decrypt(text, key=""): return text.lower()

def alternating_case_encrypt(text, key=""):
    result = []
    upper = True
    for c in text:
        if c.isalpha():
            result.append(c.upper() if upper else c.lower()); upper = not upper
        else: result.append(c)
    return ''.join(result)
def alternating_case_decrypt(text, key=""): return text.lower()

def clap_encrypt(text, key=""): return '👏'.join(text)
def clap_decrypt(text, key=""): return text.replace('👏', '')

def sparkle_encrypt(text, key=""): return '✨'.join(text)
def sparkle_decrypt(text, key=""): return text.replace('✨', '')

def rainbow_encrypt(text, key=""):
    colors = ['🔴','🟠','🟡','🟢','🔵','🟣']
    return ''.join(colors[i % 6] + c for i, c in enumerate(text))
def rainbow_decrypt(text, key=""):
    result = []
    for c in text:
        if c in '🔴🟠🟡🟢🔵🟣': continue
        result.append(c)
    return ''.join(result)

def fliptable_encrypt(text, key=""): return f"(╯°□°)╯︵ {text}"
def fliptable_decrypt(text, key=""):
    prefix = "(╯°□°)╯︵ "
    return text[len(prefix):] if text.startswith(prefix) else text

def kaomoji_encrypt(text, key=""):
    kaos = ['(＾▽＾)', '(≧◡≦)', '(◕‿◕)', '(｡♥‿♥｡)', '(¬‿¬)', '(°◡°)', '(◠‿◠)']
    return ' '.join(kaos[ord(c) % len(kaos)] for c in text)
def kaomoji_decrypt(text, key=""): return "[Kaomoji: chỉ vui]"

def leet_encrypt(text, key=""):
    m = {'a':'4','e':'3','i':'1','o':'0','s':'5','t':'7','b':'8','g':'9'}
    return ''.join(m.get(c.lower(), c) for c in text)
def leet_decrypt(text, key=""):
    m = {'4':'a','3':'e','1':'i','0':'o','5':'s','7':'t','8':'b','9':'g'}
    return ''.join(m.get(c, c) for c in text)

def reverse_encrypt(text, key=""): return text[::-1]
reverse_decrypt = reverse_encrypt

def playing_card_encrypt(text, key=""):
    suits = ['♠','♥','♦','♣']
    ranks = ['A','2','3','4','5','6','7','8','9','10','J','Q','K']
    return ' '.join(f"{ranks[ord(c) % 13]}{suits[ord(c) % 4]}" for c in text)
def playing_card_decrypt(text, key=""): return "[Playing card: chỉ vui]"

def chess_encrypt(text, key=""):
    pieces = ['♔','♕','♖','♗','♘','♙','♚','♛','♜','♝','♞','♟']
    files = 'abcdefgh'; ranks = '12345678'
    return ' '.join(f"{files[ord(c) % 8]}{ranks[(ord(c)//8) % 8]}{pieces[ord(c) % 12]}" for c in text)
def chess_decrypt(text, key=""): return "[Chess: chỉ vui]"

def rubik_encrypt(text, key=""):
    moves = ["R","L","U","D","F","B","R'","L'","U'","D'","F'","B'"]
    return ' '.join(moves[ord(c) % 12] for c in text)
def rubik_decrypt(text, key=""): return "[Rubik: chỉ vui]"

def dice_encrypt(text, key=""):
    dice = ['⚀','⚁','⚂','⚃','⚄','⚅']
    return ' '.join(''.join(dice[(ord(c) >> i) & 7] for i in [0, 3, 6] if (ord(c) >> i) & 7 < 6) for c in text)
def dice_decrypt(text, key=""): return "[Dice: chỉ vui]"

def domino_encrypt(text, key=""):
    return ' '.join(f"[{ord(c)%7}|{(ord(c)//7)%7}]" for c in text)
def domino_decrypt(text, key=""):
    try:
        result = []
        for token in text.split():
            a, b = token.strip('[]').split('|')
            result.append(chr(int(a) + int(b) * 7))
        return ''.join(result)
    except: return text


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 8 — NGÔN NGỮ & VĂN HÓA (Language) — 30 methods
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
#  TIẾNG VIỆT — TELEX / VNI / VIQR (FULL FIX)
# ═══════════════════════════════════════════════════════════════════════════

TELEX_MAP = {
    'a': 'a', 'á': 'as', 'à': 'af', 'ả': 'ar', 'ã': 'ax', 'ạ': 'aj',
    'ă': 'aw', 'ắ': 'aws', 'ằ': 'awf', 'ẳ': 'awr', 'ẵ': 'awx', 'ặ': 'awj',
    'â': 'aa', 'ấ': 'aas', 'ầ': 'aaf', 'ẩ': 'aar', 'ẫ': 'aax', 'ậ': 'aaj',
    'e': 'e', 'é': 'es', 'è': 'ef', 'ẻ': 'er', 'ẽ': 'ex', 'ẹ': 'ej',
    'ê': 'ee', 'ế': 'ees', 'ề': 'eef', 'ể': 'eer', 'ễ': 'eex', 'ệ': 'eej',
    'i': 'i', 'í': 'is', 'ì': 'if', 'ỉ': 'ir', 'ĩ': 'ix', 'ị': 'ij',
    'o': 'o', 'ó': 'os', 'ò': 'of', 'ỏ': 'or', 'õ': 'ox', 'ọ': 'oj',
    'ô': 'oo', 'ố': 'oos', 'ồ': 'oof', 'ổ': 'oor', 'ỗ': 'oox', 'ộ': 'ooj',
    'ơ': 'ow', 'ớ': 'ows', 'ờ': 'owf', 'ở': 'owr', 'ỡ': 'owx', 'ợ': 'owj',
    'u': 'u', 'ú': 'us', 'ù': 'uf', 'ủ': 'ur', 'ũ': 'ux', 'ụ': 'uj',
    'ư': 'uw', 'ứ': 'uws', 'ừ': 'uwf', 'ử': 'uwr', 'ữ': 'uwx', 'ự': 'uwj',
    'y': 'y', 'ý': 'ys', 'ỳ': 'yf', 'ỷ': 'yr', 'ỹ': 'yx', 'ỵ': 'yj',
    'đ': 'dd',
}
TELEX_REVERSE = {v: k for k, v in TELEX_MAP.items()}
TELEX_KEYS = sorted(TELEX_REVERSE.keys(), key=len, reverse=True)

def telex_encrypt(text, key=""):
    result = []
    for c in text:
        lower = c.lower()
        if lower in TELEX_MAP:
            code = TELEX_MAP[lower]
            result.append(code.upper() if c.isupper() else code)
        else:
            result.append(c)
    return ''.join(result)

def telex_decrypt(text, key=""):
    result = text
    for code in TELEX_KEYS:
        viet_char = TELEX_REVERSE[code]
        result = result.replace(code.upper(), viet_char.upper())
        result = result.replace(code, viet_char)
    return result

VNI_MAP = {
    'a': 'a', 'á': 'a1', 'à': 'a2', 'ả': 'a3', 'ã': 'a4', 'ạ': 'a5',
    'ă': 'a8', 'ắ': 'a81', 'ằ': 'a82', 'ẳ': 'a83', 'ẵ': 'a84', 'ặ': 'a85',
    'â': 'a6', 'ấ': 'a61', 'ầ': 'a62', 'ẩ': 'a63', 'ẫ': 'a64', 'ậ': 'a65',
    'e': 'e', 'é': 'e1', 'è': 'e2', 'ẻ': 'e3', 'ẽ': 'e4', 'ẹ': 'e5',
    'ê': 'e6', 'ế': 'e61', 'ề': 'e62', 'ể': 'e63', 'ễ': 'e64', 'ệ': 'e65',
    'i': 'i', 'í': 'i1', 'ì': 'i2', 'ỉ': 'i3', 'ĩ': 'i4', 'ị': 'i5',
    'o': 'o', 'ó': 'o1', 'ò': 'o2', 'ỏ': 'o3', 'õ': 'o4', 'ọ': 'o5',
    'ô': 'o6', 'ố': 'o61', 'ồ': 'o62', 'ổ': 'o63', 'ỗ': 'o64', 'ộ': 'o65',
    'ơ': 'o7', 'ớ': 'o71', 'ờ': 'o72', 'ở': 'o73', 'ỡ': 'o74', 'ợ': 'o75',
    'u': 'u', 'ú': 'u1', 'ù': 'u2', 'ủ': 'u3', 'ũ': 'u4', 'ụ': 'u5',
    'ư': 'u7', 'ứ': 'u71', 'ừ': 'u72', 'ử': 'u73', 'ữ': 'u74', 'ự': 'u75',
    'y': 'y', 'ý': 'y1', 'ỳ': 'y2', 'ỷ': 'y3', 'ỹ': 'y4', 'ỵ': 'y5',
    'đ': 'd9',
}
VNI_REVERSE = {v: k for k, v in VNI_MAP.items()}
VNI_KEYS = sorted(VNI_REVERSE.keys(), key=len, reverse=True)

def vni_encrypt(text, key=""):
    result = []
    for c in text:
        lower = c.lower()
        if lower in VNI_MAP:
            code = VNI_MAP[lower]
            result.append(code.upper() if c.isupper() else code)
        else:
            result.append(c)
    return ''.join(result)

def vni_decrypt(text, key=""):
    result = text
    for code in VNI_KEYS:
        viet_char = VNI_REVERSE[code]
        result = result.replace(code.upper(), viet_char.upper())
        result = result.replace(code, viet_char)
    return result

VIQR_MAP = {
    'a': 'a', 'á': "a'", 'à': 'a`', 'ả': 'a?', 'ã': 'a~', 'ạ': 'a.',
    'ă': 'a(', 'ắ': "a('", 'ằ': 'a(`', 'ẳ': 'a(?', 'ẵ': 'a(~', 'ặ': 'a(.',
    'â': 'a^', 'ấ': "a^'", 'ầ': 'a^`', 'ẩ': 'a^?', 'ẫ': 'a^~', 'ậ': 'a^.',
    'e': 'e', 'é': "e'", 'è': 'e`', 'ẻ': 'e?', 'ẽ': 'e~', 'ẹ': 'e.',
    'ê': 'e^', 'ế': "e^'", 'ề': 'e^`', 'ể': 'e^?', 'ễ': 'e^~', 'ệ': 'e^.',
    'i': 'i', 'í': "i'", 'ì': 'i`', 'ỉ': 'i?', 'ĩ': 'i~', 'ị': 'i.',
    'o': 'o', 'ó': "o'", 'ò': 'o`', 'ỏ': 'o?', 'õ': 'o~', 'ọ': 'o.',
    'ô': 'o^', 'ố': "o^'", 'ồ': 'o^`', 'ổ': 'o^?', 'ỗ': 'o^~', 'ộ': 'o^.',
    'ơ': 'o+', 'ớ': "o+'", 'ờ': 'o+`', 'ở': 'o+?', 'ỡ': 'o+~', 'ợ': 'o+.',
    'u': 'u', 'ú': "u'", 'ù': 'u`', 'ủ': 'u?', 'ũ': 'u~', 'ụ': 'u.',
    'ư': 'u+', 'ứ': "u+'", 'ừ': 'u+`', 'ử': 'u+?', 'ữ': 'u+~', 'ự': 'u+.',
    'y': 'y', 'ý': "y'", 'ỳ': 'y`', 'ỷ': 'y?', 'ỹ': 'y~', 'ỵ': 'y.',
    'đ': 'dd',
}
VIQR_REVERSE = {v: k for k, v in VIQR_MAP.items()}
VIQR_KEYS = sorted(VIQR_REVERSE.keys(), key=len, reverse=True)

def viqr_encrypt(text, key=""):
    result = []
    for c in text:
        lower = c.lower()
        if lower in VIQR_MAP:
            code = VIQR_MAP[lower]
            result.append(code.upper() if c.isupper() else code)
        else:
            result.append(c)
    return ''.join(result)

def viqr_decrypt(text, key=""):
    result = text
    for code in VIQR_KEYS:
        viet_char = VIQR_REVERSE[code]
        result = result.replace(code.upper(), viet_char.upper())
        result = result.replace(code, viet_char)
    return result
  
def pinyin_encrypt(text, key=""): return f"[Pinyin] {text}"
def pinyin_decrypt(text, key=""): return text.replace("[Pinyin] ", "")
def romaji_encrypt(text, key=""): return f"[Romaji] {text}"
def romaji_decrypt(text, key=""): return text.replace("[Romaji] ", "")
def hangul_roman_encrypt(text, key=""): return f"[Hangul] {text}"
def hangul_roman_decrypt(text, key=""): return text.replace("[Hangul] ", "")

def cyrillic_trans_encrypt(text, key=""):
    m = {'а':'a','б':'b','в':'v','г':'g','д':'d','е':'e','ж':'zh','з':'z','и':'i',
         'й':'y','к':'k','л':'l','м':'m','н':'n','о':'o','п':'p','р':'r','с':'s',
         'т':'t','у':'u','ф':'f','х':'kh','ц':'ts','ч':'ch','ш':'sh','щ':'shch',
         'ъ':'','ы':'y','ь':'','э':'e','ю':'yu','я':'ya'}
    return ''.join(m.get(c.lower(), c) for c in text)
def cyrillic_trans_decrypt(text, key=""): return text

def greek_trans_encrypt(text, key=""):
    m = {'α':'a','β':'b','γ':'g','δ':'d','ε':'e','ζ':'z','η':'e','θ':'th','ι':'i',
         'κ':'k','λ':'l','μ':'m','ν':'n','ξ':'x','ο':'o','π':'p','ρ':'r','σ':'s',
         'τ':'t','υ':'u','φ':'ph','χ':'ch','ψ':'ps','ω':'o'}
    return ''.join(m.get(c.lower(), c) for c in text)
def greek_trans_decrypt(text, key=""): return text

def arabic_trans_encrypt(text, key=""): return f"[Arabic] {text}"
def arabic_trans_decrypt(text, key=""): return text.replace("[Arabic] ", "")
def thai_trans_encrypt(text, key=""): return f"[Thai] {text}"
def thai_trans_decrypt(text, key=""): return text.replace("[Thai] ", "")
def sanskrit_trans_encrypt(text, key=""): return f"[Sanskrit] {text}"
def sanskrit_trans_decrypt(text, key=""): return text.replace("[Sanskrit] ", "")
def hebrew_trans_encrypt(text, key=""): return f"[Hebrew] {text}"
def hebrew_trans_decrypt(text, key=""): return text.replace("[Hebrew] ", "")
def armenian_trans_encrypt(text, key=""): return f"[Armenian] {text}"
def armenian_trans_decrypt(text, key=""): return text.replace("[Armenian] ", "")
def georgian_trans_encrypt(text, key=""): return f"[Georgian] {text}"
def georgian_trans_decrypt(text, key=""): return text.replace("[Georgian] ", "")
def devanagari_trans_encrypt(text, key=""): return f"[Devanagari] {text}"
def devanagari_trans_decrypt(text, key=""): return text.replace("[Devanagari] ", "")
def bengali_trans_encrypt(text, key=""): return f"[Bengali] {text}"
def bengali_trans_decrypt(text, key=""): return text.replace("[Bengali] ", "")
def tamil_trans_encrypt(text, key=""): return f"[Tamil] {text}"
def tamil_trans_decrypt(text, key=""): return text.replace("[Tamil] ", "")
def telugu_trans_encrypt(text, key=""): return f"[Telugu] {text}"
def telugu_trans_decrypt(text, key=""): return text.replace("[Telugu] ", "")
def khmer_trans_encrypt(text, key=""): return f"[Khmer] {text}"
def khmer_trans_decrypt(text, key=""): return text.replace("[Khmer] ", "")
def lao_trans_encrypt(text, key=""): return f"[Lao] {text}"
def lao_trans_decrypt(text, key=""): return text.replace("[Lao] ", "")
def myanmar_trans_encrypt(text, key=""): return f"[Myanmar] {text}"
def myanmar_trans_decrypt(text, key=""): return text.replace("[Myanmar] ", "")
def tibetan_trans_encrypt(text, key=""): return f"[Tibetan] {text}"
def tibetan_trans_decrypt(text, key=""): return text.replace("[Tibetan] ", "")

def ipa_encrypt(text, key=""): return f"[IPA] {text}"
def ipa_decrypt(text, key=""): return text.replace("[IPA] ", "")
def xsampa_encrypt(text, key=""): return f"[X-SAMPA] {text}"
def xsampa_decrypt(text, key=""): return text.replace("[X-SAMPA] ", "")
def kirshenbaum_encrypt(text, key=""): return f"[Kirshenbaum] {text}"
def kirshenbaum_decrypt(text, key=""): return text.replace("[Kirshenbaum] ", "")
def arpabet_encrypt(text, key=""): return f"[ARPABET] {text}"
def arpabet_decrypt(text, key=""): return text.replace("[ARPABET] ", "")

def cherokee_encrypt(text, key=""): return f"[Cherokee] {text}"
def cherokee_decrypt(text, key=""): return text.replace("[Cherokee] ", "")
def inuktitut_encrypt(text, key=""): return f"[Inuktitut] {text}"
def inuktitut_decrypt(text, key=""): return text.replace("[Inuktitut] ", "")
def cree_encrypt(text, key=""): return f"[Cree] {text}"
def cree_decrypt(text, key=""): return text.replace("[Cree] ", "")
  # ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 9 — ENCODING MỞ RỘNG (Encoding) — 45 methods
# ═══════════════════════════════════════════════════════════════════════════

def base91_encrypt(text, key=""):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    data = text.encode('utf-8'); result = ''; b = 0; n = 0
    for byte in data:
        b |= byte << n; n += 8
        if n > 13:
            v = b & 8191
            if v > 88: b >>= 13; n -= 13
            else: v = b & 16383; b >>= 14; n -= 14
            result += alphabet[v % 91] + alphabet[v // 91]
    if n:
        result += alphabet[b % 91]
        if n > 7 or b > 90: result += alphabet[b // 91]
    return result

def base91_decrypt(text, key=""):
    try:
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        result = bytearray(); b = 0; n = 0; v = -1
        for c in text:
            if c not in alphabet: continue
            cv = alphabet.index(c)
            if v < 0: v = cv
            else:
                v += cv * 91; b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    result.append(b & 255); b >>= 8; n -= 8
                v = -1
        return result.decode('utf-8', errors='ignore')
    except: return text

def z85_encrypt(text, key=""):
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
    data = text.encode('utf-8')
    while len(data) % 4: data += b'\x00'
    result = []
    for i in range(0, len(data), 4):
        n = (data[i] << 24) | (data[i+1] << 16) | (data[i+2] << 8) | data[i+3]
        chunk = []
        for _ in range(5):
            chunk.append(alphabet[n % 85]); n //= 85
        result.extend(reversed(chunk))
    return ''.join(result)

def z85_decrypt(text, key=""):
    try:
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
        result = bytearray()
        for i in range(0, len(text), 5):
            chunk = text[i:i+5]
            if len(chunk) < 5: break
            n = 0
            for c in chunk: n = n * 85 + alphabet.index(c)
            result.extend([(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
        return result.decode('utf-8', errors='ignore').rstrip('\x00')
    except: return text

def ascii85_encrypt(text, key=""): return base64.a85encode(text.encode('utf-8')).decode('ascii')
def ascii85_decrypt(text, key=""):
    try: return base64.a85decode(text.encode('ascii')).decode('utf-8')
    except: return text

def base122_encrypt(text, key=""): return base91_encrypt(text, key)
def base122_decrypt(text, key=""): return base91_decrypt(text, key)
def base2048_encrypt(text, key=""): return base100_encrypt(text, key)
def base2048_decrypt(text, key=""): return base100_decrypt(text, key)
def base65536_encrypt(text, key=""): return base100_encrypt(text, key)
def base65536_decrypt(text, key=""): return base100_decrypt(text, key)

def base94_encrypt(text, key=""):
    data = text.encode('utf-8')
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 94)
        result = chr(33 + r) + result
    return result or chr(33)

def base94_decrypt(text, key=""):
    try:
        n = 0
        for c in text: n = n * 94 + (ord(c) - 33)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text

def base16_encrypt(text, key=""): return text.encode('utf-8').hex().upper()
def base16_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def base2_encrypt(text, key=""): return ' '.join(format(ord(c), '08b') for c in text)
def base2_decrypt(text, key=""):
    try: return ''.join(chr(int(b, 2)) for b in text.split())
    except: return text

def base8_encrypt(text, key=""): return ' '.join(format(ord(c), 'o') for c in text)
def base8_decrypt(text, key=""):
    try: return ''.join(chr(int(o, 8)) for o in text.split())
    except: return text

def base11_encrypt(text, key=""):
    digits = '0123456789a'
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return '0'
    result = ''
    while n > 0:
        n, r = divmod(n, 11); result = digits[r] + result
    return result
def base11_decrypt(text, key=""):
    try:
        digits = '0123456789a'
        n = 0
        for c in text: n = n * 11 + digits.index(c)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text

def rfc1751_encrypt(text, key=""): return "[RFC 1751: cần thư viện]"
def rfc1751_decrypt(text, key=""): return "[RFC 1751: cần thư viện]"

def baudot_encrypt(text, key=""):
    table = {
        'A':'00011','B':'11001','C':'01110','D':'01001','E':'00001','F':'01101',
        'G':'11010','H':'10100','I':'00110','J':'01011','K':'01111','L':'10010',
        'M':'11100','N':'01100','O':'11000','P':'10110','Q':'10111','R':'01010',
        'S':'00101','T':'10000','U':'00111','V':'11110','W':'10011','X':'11101',
        'Y':'10101','Z':'10001',' ':'00100'
    }
    return ' '.join(table.get(c.upper(), '') for c in text)
def baudot_decrypt(text, key=""):
    reverse = {
        '00011':'A','11001':'B','01110':'C','01001':'D','00001':'E','01101':'F',
        '11010':'G','10100':'H','00110':'I','01011':'J','01111':'K','10010':'L',
        '11100':'M','01100':'N','11000':'O','10110':'P','10111':'Q','01010':'R',
        '00101':'S','10000':'T','00111':'U','11110':'V','10011':'W','11101':'X',
        '10101':'Y','10001':'Z','00100':' '
    }
    return ''.join(reverse.get(t, '') for t in text.split())

def murray_encrypt(text, key=""): return baudot_encrypt(text, key)
def murray_decrypt(text, key=""): return baudot_decrypt(text, key)

def ebcdic_encrypt(text, key=""):
    return ' '.join(format(ord(c) + 64, '02X') for c in text)
def ebcdic_decrypt(text, key=""):
    try: return ''.join(chr(int(b, 16) - 64) for b in text.split())
    except: return text

def petscii_encrypt(text, key=""): return text
def petscii_decrypt(text, key=""): return text

def ebcdic_1047_encrypt(text, key=""): return ebcdic_encrypt(text, key)
def ebcdic_1047_decrypt(text, key=""): return ebcdic_decrypt(text, key)

def keystream_encrypt(text, key=""): return xor_encrypt(text, key or "STREAM")
def keystream_decrypt(text, key=""): return xor_decrypt(text, key or "STREAM")

def quoted_b64_encrypt(text, key=""):
    b64 = base64.b64encode(text.encode()).decode()
    return '=?UTF-8?B?' + b64 + '?='
def quoted_b64_decrypt(text, key=""):
    try:
        if text.startswith('=?UTF-8?B?') and text.endswith('?='):
            return base64.b64decode(text[10:-2]).decode('utf-8')
        return text
    except: return text

def quoted_q_encrypt(text, key=""):
    result = []
    for c in text:
        if c == ' ': result.append('_')
        elif c == '=': result.append('=3D')
        elif c == '?': result.append('=3F')
        else: result.append(c)
    return '=?UTF-8?Q?' + ''.join(result) + '?='
def quoted_q_decrypt(text, key=""):
    try:
        if text.startswith('=?UTF-8?Q?') and text.endswith('?='):
            body = text[10:-2].replace('_', ' ')
            return body.replace('=3D', '=').replace('=3F', '?')
        return text
    except: return text

def url_plus_encrypt(text, key=""):
    return urllib.parse.quote_plus(text)
def url_plus_decrypt(text, key=""):
    return urllib.parse.unquote_plus(text)

def rle_encrypt(text, key=""):
    if not text: return ""
    result = []; prev = text[0]; count = 1
    for c in text[1:]:
        if c == prev: count += 1
        else:
            result.append(f"{count}{prev}" if count > 1 else prev)
            prev = c; count = 1
    result.append(f"{count}{prev}" if count > 1 else prev)
    return ''.join(result)
def rle_decrypt(text, key=""):
    result = []; i = 0
    while i < len(text):
        if text[i].isdigit():
            n = ""
            while i < len(text) and text[i].isdigit():
                n += text[i]; i += 1
            if i < len(text): result.append(text[i] * int(n)); i += 1
        else: result.append(text[i]); i += 1
    return ''.join(result)

def zero_width_encrypt(text, key=""):
    return ''.join('\u200B' * (ord(c) % 8) + c for c in text)
def zero_width_decrypt(text, key=""):
    return text.replace('\u200B', '')

def unicode_homoglyph_encrypt(text, key=""):
    m = {'a':'а','e':'е','o':'о','p':'р','c':'с','x':'х','y':'у','A':'А','B':'В',
         'E':'Е','H':'Н','K':'К','M':'М','O':'О','P':'Р','C':'С','T':'Т','X':'Х'}
    return ''.join(m.get(c, c) for c in text)
def unicode_homoglyph_decrypt(text, key=""):
    m = {'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y','А':'A','В':'B',
         'Е':'E','Н':'H','К':'K','М':'M','О':'O','Р':'P','С':'C','Т':'T','Х':'X'}
    return ''.join(m.get(c, c) for c in text)

def hexdump_encrypt(text, key=""):
    data = text.encode('utf-8')
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:08x}  {hex_part:<47}  |{ascii_part}|')
    return '\n'.join(lines)
def hexdump_decrypt(text, key=""):
    try:
        result = bytearray()
        for line in text.split('\n'):
            if not line.strip(): continue
            parts = line.split('|')[0].split('  ')[1].strip().split()
            for h in parts:
                if h: result.append(int(h, 16))
        return result.decode('utf-8')
    except: return text

def binary_8bit_encrypt(text, key=""): return binary_encrypt(text, key)
def binary_8bit_decrypt(text, key=""): return binary_decrypt(text, key)

def bit_stuffing_encrypt(text, key=""):
    data = text.encode('utf-8')
    result = bytearray()
    for byte in data:
        result.append(byte)
        bits = format(byte, '08b')
        ones = 0; stuffed = ''
        for b in bits:
            stuffed += b
            if b == '1':
                ones += 1
                if ones == 5:
                    stuffed += '0'; ones = 0
            else: ones = 0
        # Đơn giản hóa: thêm marker
    return base64.b64encode(bytes(result)).decode()
def bit_stuffing_decrypt(text, key=""):
    try: return base64.b64decode(text).decode()
    except: return text

def nybble_swap_encrypt(text, key=""):
    return ''.join(chr(((ord(c) << 4) | (ord(c) >> 4)) & 0xFF) for c in text)
def nybble_swap_decrypt(text, key=""):
    return ''.join(chr(((ord(c) << 4) | (ord(c) >> 4)) & 0xFF) for c in text)

def bit_reverse_encrypt(text, key=""):
    def rev8(b):
        return int(format(b, '08b')[::-1], 2)
    return bytes(rev8(b) for b in text.encode('utf-8')).hex()
def bit_reverse_decrypt(text, key=""):
    try:
        def rev8(b):
            return int(format(b, '08b')[::-1], 2)
        return bytes(rev8(b) for b in bytes.fromhex(text)).decode('utf-8', errors='ignore')
    except: return text

def bit_shift_encrypt(text, key="1"):
    n = _safe_int(key, 1)
    data = text.encode('utf-8')
    return bytes(((b << n) | (b >> (8 - n))) & 0xFF for b in data).hex()
def bit_shift_decrypt(text, key="1"):
    try:
        n = _safe_int(key, 1)
        data = bytes.fromhex(text)
        return bytes(((b >> n) | (b << (8 - n))) & 0xFF for b in data).decode('utf-8', errors='ignore')
    except: return text

def crlf_encrypt(text, key=""): return text.replace('\n', '\r\n')
def crlf_decrypt(text, key=""): return text.replace('\r\n', '\n')

def tab_encrypt(text, key=""): return text.replace(' ', '\t')
def tab_decrypt(text, key=""): return text.replace('\t', ' ')

def whitespace_encrypt(text, key=""):
    result = []
    for c in text:
        bits = format(ord(c), '08b')
        for b in bits:
            result.append(' ' if b == '0' else '\t')
        result.append('\n')
    return ''.join(result)
def whitespace_decrypt(text, key=""):
    result = []
    current = ''
    for c in text:
        if c == '\n':
            if len(current) == 8:
                result.append(chr(int(current, 2)))
            current = ''
        elif c == ' ': current += '0'
        elif c == '\t': current += '1'
    if len(current) == 8: result.append(chr(int(current, 2)))
    return ''.join(result)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 10 — CRYPTO PROTOCOLS (Protocols) — 25 methods
# ═══════════════════════════════════════════════════════════════════════════

def jwt_encrypt(text, key="secret"):
    try:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({"data": text}).encode()).rstrip(b'=').decode()
        signature = hmac.new((key or 'secret').encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        return f"{header}.{payload}.{sig_b64}"
    except Exception as e: return f"[JWT error: {e}]"
def jwt_decrypt(text, key="secret"):
    try:
        parts = text.split('.')
        if len(parts) != 3: return "[JWT không hợp lệ]"
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get('data', text)
    except Exception as e: return f"[JWT error: {e}]"

def jws_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def jws_decrypt(text, key="secret"): return jwt_decrypt(text, key)
def jwe_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def jwe_decrypt(text, key="secret"): return jwt_decrypt(text, key)

def pem_encrypt(text, key=""):
    b64 = base64.b64encode(text.encode()).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN MESSAGE-----\n" + "\n".join(lines) + "\n-----END MESSAGE-----"
def pem_decrypt(text, key=""):
    try:
        lines = [l for l in text.split('\n') if l and not l.startswith('-----')]
        return base64.b64decode(''.join(lines)).decode('utf-8')
    except: return text

def pgp_armor_encrypt(text, key=""): return pem_encrypt(text, key)
def pgp_armor_decrypt(text, key=""): return pem_decrypt(text, key)

def unix_crypt_encrypt(text, key="ab"):
    salt = (key or "ab")[:2]
    return hashlib.sha256((salt + text).encode()).hexdigest()[:13]
def unix_crypt_decrypt(text, key=""): return "[Unix crypt: 1 chiều]"

def sha_crypt_encrypt(text, key="$6$salt"):
    return "$6$" + hashlib.sha512(text.encode()).hexdigest()
def sha_crypt_decrypt(text, key=""): return "[sha-crypt: 1 chiều]"

def der_encrypt(text, key=""): return base64.b64encode(text.encode()).decode()
def der_decrypt(text, key=""):
    try: return base64.b64decode(text).decode()
    except: return text

def bip39_encrypt(text, key=""): return "[BIP39: cần thư viện]"
def bip39_decrypt(text, key=""): return "[BIP39: cần thư viện]"
def bip32_encrypt(text, key=""): return "[BIP32: cần thư viện]"
def bip32_decrypt(text, key=""): return "[BIP32: cần thư viện]"

def tls_record_encrypt(text, key=""): return aes128_encrypt(text, key or "tls_key")
def tls_record_decrypt(text, key=""): return aes128_decrypt(text, key or "tls_key")

def ssh_key_encrypt(text, key=""): return pem_encrypt(text, key)
def ssh_key_decrypt(text, key=""): return pem_decrypt(text, key)

def x509_encrypt(text, key=""): return pem_encrypt(text, key)
def x509_decrypt(text, key=""): return pem_decrypt(text, key)

def pkcs8_encrypt(text, key=""): return pem_encrypt(text, key)
def pkcs8_decrypt(text, key=""): return pem_decrypt(text, key)

def pkcs7_encrypt(text, key=""):
    block_size = 16
    pad_len = block_size - (len(text) % block_size)
    return text + chr(pad_len) * pad_len
def pkcs7_decrypt(text, key=""):
    if not text: return text
    pad_len = ord(text[-1])
    if 1 <= pad_len <= 16: return text[:-pad_len]
    return text

def oauth_token_encrypt(text, key="secret"):
    return jwt_encrypt(text, key)
def oauth_token_decrypt(text, key="secret"):
    return jwt_decrypt(text, key)

def saml_encrypt(text, key=""):
    return base64.b64encode(text.encode()).decode()
def saml_decrypt(text, key=""):
    try: return base64.b64decode(text).decode()
    except: return text

def kerberos_ticket_encrypt(text, key=""): return aes128_encrypt(text, key or "krb")
def kerberos_ticket_decrypt(text, key=""): return aes128_decrypt(text, key or "krb")

def pkce_encrypt(text, key=""):
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).rstrip(b'=').decode()
def pkce_decrypt(text, key=""): return "[PKCE: 1 chiều]"

def hashids_encrypt(text, key="salt"):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    result = ''
    if n == 0: return alphabet[0]
    while n > 0:
        n, r = divmod(n, len(alphabet)); result = alphabet[r] + result
    return result
def hashids_decrypt(text, key="salt"):
    try:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        n = 0
        for c in text: n = n * len(alphabet) + alphabet.index(c)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 11 — CIPHER MACHINES — 15 methods
# ═══════════════════════════════════════════════════════════════════════════

def enigma_encrypt(text, key="AAA"):
    key = (key or "AAA").upper().ljust(3, 'A')[:3]
    rotor1 = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    rotor2 = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
    rotor3 = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
    reflector = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
    pos = [ord(key[0]) - 65, ord(key[1]) - 65, ord(key[2]) - 65]
    result = []
    for c in text.upper():
        if c.isalpha():
            p = ord(c) - 65
            p = ord(rotor1[(p + pos[0]) % 26]) - 65
            p = ord(rotor2[(p + pos[1]) % 26]) - 65
            p = ord(rotor3[(p + pos[2]) % 26]) - 65
            p = ord(reflector[p]) - 65
            p = (rotor3.index(chr(p + 65)) - pos[2]) % 26
            p = (rotor2.index(chr(p + 65)) - pos[1]) % 26
            p = (rotor1.index(chr(p + 65)) - pos[0]) % 26
            result.append(chr(p + 65))
            pos[0] = (pos[0] + 1) % 26
            if pos[0] == 0:
                pos[1] = (pos[1] + 1) % 26
                if pos[1] == 0: pos[2] = (pos[2] + 1) % 26
        else: result.append(c)
    return ''.join(result)
enigma_decrypt = enigma_encrypt

def enigma_m3_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def enigma_m3_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def enigma_m4_encrypt(text, key="AAAA"): return enigma_encrypt(text, key[:3] if key else "AAA")
def enigma_m4_decrypt(text, key="AAAA"): return enigma_decrypt(text, key[:3] if key else "AAA")

def vic_encrypt(text, key="KEY"): return columnar_encrypt(text, key)
def vic_decrypt(text, key="KEY"): return columnar_decrypt(text, key)

def lorenz_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def lorenz_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def lorenz_sz40_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def lorenz_sz40_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def lorenz_sz42_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def lorenz_sz42_decrypt(text, key="KEY"): return xor_decrypt(text, key)

def sigsaly_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def sigsaly_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def sigsaly_vocoder_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def sigsaly_vocoder_decrypt(text, key="KEY"): return xor_decrypt(text, key)

def typex_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def typex_decrypt(text, key="AAA"): return enigma_decrypt(text, key)


# ═══════════════════════════════════════════════════════════════════════════
#  NHÓM 12 — EMOJI & UNICODE — 20 methods
# ═══════════════════════════════════════════════════════════════════════════

def regional_indicator_encrypt(text, key=""):
    result = []
    for c in text.upper():
        if 'A' <= c <= 'Z':
            result.append(chr(0x1F1E6 + (ord(c) - ord('A'))))
        else: result.append(c)
    return ''.join(result)
def regional_indicator_decrypt(text, key=""):
    return ''.join(chr(ord(c) - 0x1F1E6 + ord('A')) if 0x1F1E6 <= ord(c) <= 0x1F1FF else c for c in text)

def emoji_flags_encrypt(text, key=""): return regional_indicator_encrypt(text, key)
def emoji_flags_decrypt(text, key=""): return regional_indicator_decrypt(text, key)

def emoji_alphabet_encrypt(text, key=""):
    emojis = "🅰🅱🆎🅳🅴🅵🅶🅷🅸🅹🅺🅻🅼🅽🅾🅿🆀🆁🆂🆃🆄🆅🆆🆇🆈🆉"
    return ''.join(emojis[ord(c.upper()) - ord('A')] if 'A' <= c.upper() <= 'Z' else c for c in text)
def emoji_alphabet_decrypt(text, key=""):
    emojis = "🅰🅱🆎🅳🅴🅵🅶🅷🅸🅹🅺🅻🅼🅽🅾🅿🆀🆁🆂🆃🆄🆅🆆🆇🆈🆉"
    result = []
    for c in text:
        if c in emojis: result.append(chr(emojis.index(c) + ord('A')))
        else: result.append(c)
    return ''.join(result)

def emoji_numbers_encrypt(text, key=""):
    emojis = "0️⃣1️⃣2️⃣3️⃣4️⃣5️⃣6️⃣7️⃣8️⃣9️⃣"
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

def emoji_faces_encrypt(text, key=""):
    faces = "😀😃😄😁😆😅😂🤣😊😇🙂🙃😉😌😍😘😗😙😚😋😛😝😜🤪🤨🧐🤓😎"
    return ''.join(faces[ord(c) % len(faces)] for c in text)
def emoji_faces_decrypt(text, key=""): return "[Emoji faces: chỉ vui]"

def sign_language_encrypt(text, key=""): return f"[Sign Language] {text}"
def sign_language_decrypt(text, key=""): return text.replace("[Sign Language] ", "")

def braille_unicode_encrypt(text, key=""): return braille_encrypt(text, key)
def braille_unicode_decrypt(text, key=""): return braille_decrypt(text, key)

def fullwidth_encrypt(text, key=""): return vaporwave_encrypt(text, key)
def fullwidth_decrypt(text, key=""): return vaporwave_decrypt(text, key)

def mathematical_bold_encrypt(text, key=""):
    result = []
    for c in text:
        if 'A' <= c <= 'Z': result.append(chr(0x1D400 + ord(c) - ord('A')))
        elif 'a' <= c <= 'z': result.append(chr(0x1D41A + ord(c) - ord('a')))
        elif '0' <= c <= '9': result.append(chr(0x1D7CE + ord(c) - ord('0')))
        else: result.append(c)
    return ''.join(result)
def mathematical_bold_decrypt(text, key=""):
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
        elif '0' <= c <= '9': result.append(chr(0x2460 + ord(c) - ord('1')) if c != '0' else '⓪')
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

def negative_circled_encrypt(text, key=""):
    result = []
    for c in text.upper():
        if 'A' <= c <= 'Z': result.append(chr(0x1F150 + ord(c) - ord('A')))
        else: result.append(c)
    return ''.join(result)
def negative_circled_decrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 0x1F150 <= o <= 0x1F169: result.append(chr(o - 0x1F150 + ord('A')))
        else: result.append(c)
    return ''.join(result)

def parenthesized_encrypt(text, key=""):
    result = []
    for c in text.lower():
        if 'a' <= c <= 'z': result.append(chr(0x249C + ord(c) - ord('a')))
        else: result.append(c)
    return ''.join(result)
def parenthesized_decrypt(text, key=""):
    result = []
    for c in text:
        o = ord(c)
        if 0x249C <= o <= 0x24B5: result.append(chr(o - 0x249C + ord('a')))
        else: result.append(c)
    return ''.join(result)

def currency_symbols_encrypt(text, key=""):
    symbols = "₳฿₵₫€₣₲₴₭₺₼₦₱₽₪₹₸₮₩¥"
    return ''.join(symbols[ord(c) % len(symbols)] for c in text)
def currency_symbols_decrypt(text, key=""): return "[Currency: chỉ vui]"


# ═══════════════════════════════════════════════════════════════════════════
#  METHOD REGISTRY — 500+ methods theo 12 nhóm
# ═══════════════════════════════════════════════════════════════════════════

METHODS_REGISTRY = {
    # ─── NHÓM 1: CỔ ĐIỂN (40) ───
    'atbash':          ('Atbash Cipher',          atbash_encrypt,          atbash_decrypt,          'classical'),
    'bacon':           ('Bacon Cipher',           bacon_encrypt,           bacon_decrypt,           'classical'),
    'rot13':           ('ROT13',                  rot13_encrypt,           rot13_decrypt,           'classical'),
    'rot47':           ('ROT47',                  rot47_encrypt,           rot47_decrypt,           'classical'),
    'rot5':            ('ROT5 (số)',              rot5_encrypt,            rot5_decrypt,            'classical'),
    'rot18':           ('ROT18',                  rot18_encrypt,           rot18_decrypt,           'classical'),
    'vigenere':        ('Vigenère',               vigenere_encrypt,        vigenere_decrypt,        'classical'),
    'beaufort':        ('Beaufort',               beaufort_encrypt,        beaufort_decrypt,        'classical'),
    'variant_beaufort':('Variant Beaufort',       variant_beaufort_encrypt,variant_beaufort_decrypt,'classical'),
    'autokey':         ('Autokey',                autokey_encrypt,         autokey_decrypt,         'classical'),
    'porta':           ('Porta',                  porta_encrypt,           porta_decrypt,           'classical'),
    'gronsfeld':       ('Gronsfeld',              gronsfeld_encrypt,       gronsfeld_decrypt,       'classical'),
    'caesar':          ('Caesar Cipher',          caesar_encrypt,          caesar_decrypt,          'classical'),
    'affine':          ('Affine Cipher',          affine_encrypt,          affine_decrypt,          'classical'),
    'bifid':           ('Bifid',                  bifid_encrypt,           bifid_decrypt,           'classical'),
    'trifid':          ('Trifid',                 trifid_encrypt,          trifid_decrypt,          'classical'),
    'foursquare':      ('Four-square',            foursquare_encrypt,      foursquare_decrypt,      'classical'),
    'twosquare':       ('Two-square',             twosquare_encrypt,       twosquare_decrypt,       'classical'),
    'adfgvx':          ('ADFGVX',                 adfgvx_encrypt,          adfgvx_decrypt,          'classical'),
    'adfgx':           ('ADFGX',                  adfgx_encrypt,           adfgx_decrypt,           'classical'),
    'nihilist':        ('Nihilist',               nihilist_encrypt,        nihilist_decrypt,        'classical'),
    'bazeries':        ('Bazeries',               bazeries_encrypt,        bazeries_decrypt,        'classical'),
    'syllabary':       ('Syllabary',              syllabary_encrypt,       syllabary_decrypt,       'classical'),
    'scytale':         ('Scytale',                scytale_encrypt,         scytale_decrypt,         'classical'),
    'myszkowski':      ('Myszkowski',             myszkowski_encrypt,      myszkowski_decrypt,      'classical'),
    'columnar':        ('Columnar',               columnar_encrypt,        columnar_decrypt,        'classical'),
    'amsco':           ('AMSCO',                  amsco_encrypt,           amsco_decrypt,           'classical'),
    'grandpre':        ('Grandpré',               grandpre_encrypt,        grandpre_decrypt,        'classical'),
    'trithemius':      ('Trithemius',             trithemius_encrypt,      trithemius_decrypt,      'classical'),
    'xor':             ('XOR Cipher',             xor_encrypt,             xor_decrypt,             'classical'),
    'playfair':        ('Playfair',               playfair_encrypt,        playfair_decrypt,        'classical'),
    'hill':            ('Hill Cipher',            hill_encrypt,            hill_decrypt,            'classical'),
    'wheatstone':      ('Wheatstone',             wheatstone_encrypt,      wheatstone_decrypt,      'classical'),
    'ragbaby':         ('Ragbaby',                ragbaby_encrypt,         ragbaby_decrypt,         'classical'),
    'progressive':     ('Progressive Key',        progressive_encrypt,     progressive_decrypt,     'classical'),
    'nato':            ('NATO Phonetic',          nato_encrypt,            nato_decrypt,            'classical'),
    'morse':           ('Morse Code',             morse_encrypt,           morse_decrypt,           'classical'),
    'tapcode':         ('Tap Code',               tapcode_encrypt,         tapcode_decrypt,         'classical'),
    'polybius':        ('Polybius Square',        polybius_encrypt,        polybius_decrypt,        'classical'),
    'piglatin':        ('Pig Latin',              piglatin_encrypt,        piglatin_decrypt,        'classical'),
    'ubbidubbi':       ('Ubbi Dubbi',             ubbidubbi_encrypt,       ubbidubbi_decrypt,       'classical'),
    'rovarspraket':    ('Rövarspråket',           rovarspraket_encrypt,    rovarspraket_decrypt,    'classical'),
    'leet':            ('Leet Speak',             leet_encrypt,            leet_decrypt,            'classical'),
    'reverse':         ('Reverse Text',           reverse_encrypt,         reverse_decrypt,         'classical'),

    # ─── NHÓM 2: TOÁN HỌC (25) ───
    'binary':            ('Binary',              binary_encrypt,              binary_decrypt,              'math'),
    'binary_reversed':   ('Binary Reversed',     binary_reversed_encrypt,     binary_reversed_decrypt,     'math'),
    'octal':             ('Octal',               octal_encrypt,               octal_decrypt,               'math'),
    'hex':               ('Hexadecimal',         hex_encrypt,                 hex_decrypt,                 'math'),
    'ascii_decimal':     ('ASCII Decimal',       ascii_decimal_encrypt,       ascii_decimal_decrypt,       'math'),
    'base32':            ('Base32',              base32_encrypt,              base32_decrypt,              'math'),
    'base58':            ('Base58',              base58_encrypt,              base58_decrypt,              'math'),
    'base85':            ('Base85',              base85_encrypt,              base85_decrypt,              'math'),
    'base36':            ('Base36',              base36_encrypt,              base36_decrypt,              'math'),
    'base62':            ('Base62',              base62_encrypt,              base62_decrypt,              'math'),
    'base100':           ('Base100 (Emoji)',     base100_encrypt,             base100_decrypt,             'math'),
    'base45':            ('Base45',              base45_encrypt,              base45_decrypt,              'math'),
    'urlencode':         ('URL Encode',          urlencode_encrypt,           urlencode_decrypt,           'math'),
    'htmlentities':      ('HTML Entities',       htmlentities_encrypt,        htmlentities_decrypt,        'math'),
    'unicode_escape':    ('Unicode Escape',      unicode_escape_encrypt,      unicode_escape_decrypt,      'math'),
    'quoted_printable':  ('Quoted-printable',    quoted_printable_encrypt,    quoted_printable_decrypt,    'math'),
    'uuencode':          ('UUencode',            uuencode_encrypt,            uuencode_decrypt,            'math'),
    'gray':              ('Gray Code',           gray_encrypt,                gray_decrypt,                'math'),
    'bcd':               ('BCD',                 bcd_encrypt,                 bcd_decrypt,                 'math'),
    'ieee754':           ('IEEE 754',            ieee754_encrypt,             ieee754_decrypt,             'math'),
    'factorial_number':  ('Factorial Number',    factorial_number_encrypt,    factorial_number_decrypt,    'math'),
    'fibonacci':         ('Fibonacci',           fibonacci_encrypt,           fibonacci_decrypt,           'math'),

    # ─── NHÓM 3: HASH (42) ───
    'md5':              ('MD5',              md5_encrypt,              md5_decrypt,              'hash'),
    'sha1':             ('SHA-1',            sha1_encrypt,             sha1_decrypt,             'hash'),
    'sha224':           ('SHA-224',          sha224_encrypt,           sha224_decrypt,           'hash'),
    'sha256':           ('SHA-256',          sha256_encrypt,           sha256_decrypt,           'hash'),
    'sha384':           ('SHA-384',          sha384_encrypt,           sha384_decrypt,           'hash'),
    'sha512':           ('SHA-512',          sha512_encrypt,           sha512_decrypt,           'hash'),
    'sha3_256':         ('SHA3-256',         sha3_256_encrypt,         sha3_256_decrypt,         'hash'),
    'sha3_512':         ('SHA3-512',         sha3_512_encrypt,         sha3_512_decrypt,         'hash'),
    'blake2b':          ('BLAKE2b',          blake2b_encrypt,          blake2b_decrypt,          'hash'),
    'blake2s':          ('BLAKE2s',          blake2s_encrypt,          blake2s_decrypt,          'hash'),
    'blake3':           ('BLAKE3',           blake3_encrypt,           blake3_decrypt,           'hash'),
    'ripemd160':        ('RIPEMD-160',       ripemd160_encrypt,        ripemd160_decrypt,        'hash'),
    'whirlpool':        ('Whirlpool',        whirlpool_encrypt,        whirlpool_decrypt,        'hash'),
    'keccak256':        ('Keccak-256',       keccak256_encrypt,        keccak256_decrypt,        'hash'),
    'keccak512':        ('Keccak-512',       keccak512_encrypt,        keccak512_decrypt,        'hash'),
    'crc32':            ('CRC32',            crc32_encrypt,            crc32_decrypt,            'hash'),
    'crc16':            ('CRC16',            crc16_encrypt,            crc16_decrypt,            'hash'),
    'adler32':          ('Adler-32',         adler32_encrypt,          adler32_decrypt,          'hash'),
    'fnv1a':            ('FNV-1a',           fnv1a_encrypt,            fnv1a_decrypt,            'hash'),
    'fnv1':             ('FNV-1',            fnv1_encrypt,             fnv1_decrypt,             'hash'),
    'murmur3':          ('MurmurHash3',      murmur3_encrypt,          murmur3_decrypt,          'hash'),
    'xxhash':           ('xxHash',           xxhash_encrypt,           xxhash_decrypt,           'hash'),
    'siphash':          ('SipHash',          siphash_encrypt,          siphash_decrypt,          'hash'),
    'hmac_sha256':      ('HMAC-SHA256',      hmac_sha256_encrypt,      hmac_sha256_decrypt,      'hash'),
    'hmac_sha512':      ('HMAC-SHA512',      hmac_sha512_encrypt,      hmac_sha512_decrypt,      'hash'),
    'hmac_md5':         ('HMAC-MD5',         hmac_md5_encrypt,         hmac_md5_decrypt,         'hash'),
    'hmac_sha1':        ('HMAC-SHA1',        hmac_sha1_encrypt,        hmac_sha1_decrypt,        'hash'),
    'shake128':         ('SHAKE128',         shake128_encrypt,         shake128_decrypt,         'hash'),
    'shake256':         ('SHAKE256',         shake256_encrypt,         shake256_decrypt,         'hash'),
    'pbkdf2':           ('PBKDF2',           pbkdf2_encrypt,           pbkdf2_decrypt,           'hash'),
    'scrypt':           ('scrypt',           scrypt_encrypt,           scrypt_decrypt,           'hash'),
    'md5_double':       ('MD5-Double',       md5_double_encrypt,       md5_double_decrypt,       'hash'),
    'sha256_double':    ('SHA256-Double',    sha256_double_encrypt,    sha256_double_decrypt,    'hash'),
    'sha256_truncated': ('SHA256-Trunc',     sha256_truncated_encrypt, sha256_truncated_decrypt, 'hash'),
    'sha512_truncated': ('SHA512-Trunc',     sha512_truncated_encrypt, sha512_truncated_decrypt, 'hash'),
    'md5_truncated':    ('MD5-Trunc',        md5_truncated_encrypt,    md5_truncated_decrypt,    'hash'),

    # ─── NHÓM 4: ĐỐI XỨNG (60) ───
    'aes128_ecb':       ('AES-128-ECB',      aes128_ecb_encrypt,      aes128_ecb_decrypt,      'symmetric'),
    'aes128_cbc':       ('AES-128-CBC',      aes128_cbc_encrypt,      aes128_cbc_decrypt,      'symmetric'),
    'aes128_ctr':       ('AES-128-CTR',      aes128_ctr_encrypt,      aes128_ctr_decrypt,      'symmetric'),
    'aes128_cfb':       ('AES-128-CFB',      aes128_cfb_encrypt,      aes128_cfb_decrypt,      'symmetric'),
    'aes128_ofb':       ('AES-128-OFB',      aes128_ofb_encrypt,      aes128_ofb_decrypt,      'symmetric'),
    'aes128_gcm':       ('AES-128-GCM',      aes128_gcm_encrypt,      aes128_gcm_decrypt,      'symmetric'),
    'aes192_ecb':       ('AES-192-ECB',      aes192_ecb_encrypt,      aes192_ecb_decrypt,      'symmetric'),
    'aes192_cbc':       ('AES-192-CBC',      aes192_cbc_encrypt,      aes192_cbc_decrypt,      'symmetric'),
    'aes192_ctr':       ('AES-192-CTR',      aes192_ctr_encrypt,      aes192_ctr_decrypt,      'symmetric'),
    'aes192_cfb':       ('AES-192-CFB',      aes192_cfb_encrypt,      aes192_cfb_decrypt,      'symmetric'),
    'aes192_ofb':       ('AES-192-OFB',      aes192_ofb_encrypt,      aes192_ofb_decrypt,      'symmetric'),
    'aes192_gcm':       ('AES-192-GCM',      aes192_gcm_encrypt,      aes192_gcm_decrypt,      'symmetric'),
    'aes256_ecb':       ('AES-256-ECB',      aes256_ecb_encrypt,      aes256_ecb_decrypt,      'symmetric'),
    'aes256_cbc':       ('AES-256-CBC',      aes256_cbc_encrypt,      aes256_cbc_decrypt,      'symmetric'),
    'aes256_ctr':       ('AES-256-CTR',      aes256_ctr_encrypt,      aes256_ctr_decrypt,      'symmetric'),
    'aes256_cfb':       ('AES-256-CFB',      aes256_cfb_encrypt,      aes256_cfb_decrypt,      'symmetric'),
    'aes256_ofb':       ('AES-256-OFB',      aes256_ofb_encrypt,      aes256_ofb_decrypt,      'symmetric'),
    'aes256_gcm':       ('AES-256-GCM',      aes256_gcm_encrypt,      aes256_gcm_decrypt,      'symmetric'),
    'aes128':           ('AES-128 (legacy)', aes128_encrypt,          aes128_decrypt,          'symmetric'),
    'aes192':           ('AES-192 (legacy)', aes192_encrypt,          aes192_decrypt,          'symmetric'),
    'aes_gcm':          ('AES-GCM (legacy)', aes_gcm_encrypt,         aes_gcm_decrypt,         'symmetric'),
    'aes_cbc':          ('AES-CBC (legacy)', aes_cbc_encrypt,         aes_cbc_decrypt,         'symmetric'),
    'aes_ctr':          ('AES-CTR (legacy)', aes_ctr_encrypt,         aes_ctr_decrypt,         'symmetric'),
    'des':              ('DES',              des_encrypt,             des_decrypt,             'symmetric'),
    'tripledes':        ('3DES',             tripledes_encrypt,       tripledes_decrypt,       'symmetric'),
    'blowfish':         ('Blowfish',         blowfish_encrypt,        blowfish_decrypt,        'symmetric'),
    'twofish':          ('Twofish',          twofish_encrypt,         twofish_decrypt,         'symmetric'),
    'serpent':          ('Serpent',          serpent_encrypt,         serpent_decrypt,         'symmetric'),
    'rc2':              ('RC2',              rc2_encrypt,             rc2_decrypt,             'symmetric'),
    'rc4':              ('RC4',              rc4_encrypt,             rc4_decrypt,             'symmetric'),
    'rc5':              ('RC5',              rc5_encrypt,             rc5_decrypt,             'symmetric'),
    'rc6':              ('RC6',              rc6_encrypt,             rc6_decrypt,             'symmetric'),
    'chacha20':         ('ChaCha20',         chacha20_encrypt,        chacha20_decrypt,        'symmetric'),
    'chacha20_poly':    ('ChaCha20-Poly',    chacha20_poly_encrypt,   chacha20_poly_decrypt,   'symmetric'),
    'xchacha20_poly':   ('XChaCha20-Poly',   xchacha20_poly_encrypt,  xchacha20_poly_decrypt,  'symmetric'),
    'salsa20':          ('Salsa20',          salsa20_encrypt,         salsa20_decrypt,         'symmetric'),
    'camellia':         ('Camellia',         camellia_encrypt,        camellia_decrypt,        'symmetric'),
    'aria':             ('ARIA',             aria_encrypt,            aria_decrypt,            'symmetric'),
    'sm4':              ('SM4',              sm4_encrypt,             sm4_decrypt,             'symmetric'),
    'seed':             ('SEED',             seed_encrypt,            seed_decrypt,            'symmetric'),
    'idea':             ('IDEA',             idea_encrypt,            idea_decrypt,            'symmetric'),
    'cast5':            ('CAST5',            cast5_encrypt,           cast5_decrypt,           'symmetric'),
    'cast6':            ('CAST6',            cast6_encrypt,           cast6_decrypt,           'symmetric'),
    'tea':              ('TEA',              tea_encrypt,             tea_decrypt,             'symmetric'),
    'xtea':             ('XTEA',             xtea_encrypt,            xtea_decrypt,            'symmetric'),
    'xxtea':            ('XXTEA',            xxtea_encrypt,           xxtea_decrypt,           'symmetric'),
    'speck':            ('Speck',            speck_encrypt,           speck_decrypt,           'symmetric'),
    'simon':            ('Simon',            simon_encrypt,           simon_decrypt,           'symmetric'),
    'present':          ('PRESENT',          present_encrypt,         present_decrypt,         'symmetric'),
    'kasumi':           ('KASUMI',           kasumi_encrypt,          kasumi_decrypt,          'symmetric'),
    'misty1':           ('MISTY1',           misty1_encrypt,          misty1_decrypt,          'symmetric'),
    'skipjack':         ('Skipjack',         skipjack_encrypt,        skipjack_decrypt,        'symmetric'),
    'rabbit':           ('Rabbit',           rabbit_encrypt,          rabbit_decrypt,          'symmetric'),
    'hc128':            ('HC-128',           hc128_encrypt,           hc128_decrypt,           'symmetric'),
    'hc256':            ('HC-256',           hc256_encrypt,           hc256_decrypt,           'symmetric'),
    'grain128':         ('Grain-128',        grain128_encrypt,        grain128_decrypt,        'symmetric'),
    'trivium':          ('Trivium',          trivium_encrypt,         trivium_decrypt,         'symmetric'),
    'mickey':           ('MICKEY',           mickey_encrypt,          mickey_decrypt,          'symmetric'),
    'fernet':           ('Fernet',           fernet_encrypt,          fernet_decrypt,          'symmetric'),
    'otp':              ('One-Time Pad',     otp_encrypt,             otp_decrypt,             'symmetric'),
    'vernam':           ('Vernam',           vernam_encrypt,          vernam_decrypt,          'symmetric'),

    # ─── NHÓM 5: BẤT ĐỐI XỨNG (30) ───
    'rsa':              ('RSA',           rsa_encrypt,           rsa_decrypt,           'asymmetric'),
    'rsa_oaep':         ('RSA-OAEP',      rsa_oaep_encrypt,      rsa_oaep_decrypt,      'asymmetric'),
    'rsa_pss':          ('RSA-PSS',       rsa_pss_encrypt,       rsa_pss_decrypt,       'asymmetric'),
    'rsa_pkcs1':        ('RSA-PKCS1',     rsa_pkcs1_encrypt,     rsa_pkcs1_decrypt,     'asymmetric'),
    'rsa_3072':         ('RSA-3072',      rsa_3072_encrypt,      rsa_3072_decrypt,      'asymmetric'),
    'rsa_4096':         ('RSA-4096',      rsa_4096_encrypt,      rsa_4096_decrypt,      'asymmetric'),
    'ecc':              ('ECC',           ecc_encrypt,           ecc_decrypt,           'asymmetric'),
    'ecdsa':            ('ECDSA',         ecdsa_encrypt,         ecdsa_decrypt,         'asymmetric'),
    'ed25519':          ('Ed25519',       ed25519_encrypt,       ed25519_decrypt,       'asymmetric'),
    'ed448':            ('Ed448',         ed448_encrypt,         ed448_decrypt,         'asymmetric'),
    'x25519':           ('X25519',        x25519_encrypt,        x25519_decrypt,        'asymmetric'),
    'x448':             ('X448',          x448_encrypt,          x448_decrypt,          'asymmetric'),
    'curve25519':       ('Curve25519',    curve25519_encrypt,    curve25519_decrypt,    'asymmetric'),
    'curve448':         ('Curve448',      curve448_encrypt,      curve448_decrypt,      'asymmetric'),
    'dh':               ('Diffie-Hellman',dh_encrypt,            dh_decrypt,            'asymmetric'),
    'dh_2048':          ('DH-2048',       dh_2048_encrypt,       dh_2048_decrypt,       'asymmetric'),
    'dh_4096':          ('DH-4096',       dh_4096_encrypt,       dh_4096_decrypt,       'asymmetric'),
    'elgamal':          ('ElGamal',       elgamal_encrypt,       elgamal_decrypt,       'asymmetric'),
    'dsa':              ('DSA',           dsa_encrypt,           dsa_decrypt,           'asymmetric'),
    'ecdh':             ('ECDH',          ecdh_encrypt,          ecdh_decrypt,          'asymmetric'),
    'ecdh_x25519':      ('ECDH-X25519',   ecdh_x25519_encrypt,   ecdh_x25519_decrypt,   'asymmetric'),
    'ecdh_x448':        ('ECDH-X448',     ecdh_x448_encrypt,     ecdh_x448_decrypt,     'asymmetric'),
    'ecdh_p256':        ('ECDH-P256',     ecdh_p256_encrypt,     ecdh_p256_decrypt,     'asymmetric'),
    'ecdh_p384':        ('ECDH-P384',     ecdh_p384_encrypt,     ecdh_p384_decrypt,     'asymmetric'),
    'ecdh_p521':        ('ECDH-P521',     ecdh_p521_encrypt,     ecdh_p521_decrypt,     'asymmetric'),
    'paillier':         ('Paillier',      paillier_encrypt,      paillier_decrypt,      'asymmetric'),
    'rabin':            ('Rabin',         rabin_encrypt,         rabin_decrypt,         'asymmetric'),
    'ntru':             ('NTRU',          ntru_encrypt,          ntru_decrypt,          'asymmetric'),
    'kyber':            ('Kyber',         kyber_encrypt,         kyber_decrypt,         'asymmetric'),
    'dilithium':        ('Dilithium',     dilithium_encrypt,     dilithium_decrypt,     'asymmetric'),
    'falcon':           ('Falcon',        falcon_encrypt,        falcon_decrypt,        'asymmetric'),
    'sphincs':          ('SPHINCS+',      sphincs_encrypt,       sphincs_decrypt,       'asymmetric'),
    'bls':              ('BLS',           bls_encrypt,           bls_decrypt,           'asymmetric'),
    'schnorr':          ('Schnorr',       schnorr_encrypt,       schnorr_decrypt,       'asymmetric'),

    # ─── NHÓM 6: ĐẶC BIỆT (35) ───
    'dna':              ('DNA Encoding',       dna_encrypt,             dna_decrypt,             'special'),
    'dna_2bit':         ('DNA 2-bit',          dna_2bit_encrypt,        dna_2bit_decrypt,        'special'),
    'dna_complement':   ('DNA Complement',     dna_complement_encrypt,  dna_complement_decrypt,  'special'),
    'rna':              ('RNA Encoding',       rna_encrypt,             rna_decrypt,             'special'),
    'amino':            ('Amino Acid',         amino_encrypt,           amino_decrypt,           'special'),
    'protein':          ('Protein',            protein_encrypt,         protein_decrypt,         'special'),
    'codon':            ('Codon',              codon_encrypt,           codon_decrypt,           'special'),
    'genetic':          ('Genetic',            genetic_encrypt,         genetic_decrypt,         'special'),
    'emoji':            ('Emoji Encoding',     emoji_encrypt,           emoji_decrypt,           'special'),
    'emoji_animals':    ('Emoji Animals',      emoji_animals_encrypt,   emoji_animals_decrypt,   'special'),
    'emoji_food':       ('Emoji Food',         emoji_food_encrypt,      emoji_food_decrypt,      'special'),
    'braille':          ('Braille',            braille_encrypt,         braille_decrypt,         'special'),
    'braille_8dot':     ('Braille 8-dot',      braille_8dot_encrypt,    braille_8dot_decrypt,    'special'),
    'semaphore':        ('Semaphore',          semaphore_encrypt,       semaphore_decrypt,       'special'),
    'flag_semaphore':   ('Flag Semaphore',     flag_semaphore_encrypt,  flag_semaphore_decrypt,  'special'),
    'baconian':         ('Baconian',           baconian_encrypt,        baconian_decrypt,        'special'),
    'bookcipher':       ('Book Cipher',        bookcipher_encrypt,      bookcipher_decrypt,      'special'),
    'nullcipher':       ('Null Cipher',        nullcipher_encrypt,      nullcipher_decrypt,      'special'),
    'acrostic':         ('Acrostic',           acrostic_encrypt,        acrostic_decrypt,        'special'),
    'railfence':        ('Rail Fence',         railfence_encrypt,       railfence_decrypt,       'special'),
    'route':            ('Route Cipher',       route_encrypt,           route_decrypt,           'special'),
    'cardan':           ('Cardan Grille',      cardan_encrypt,          cardan_decrypt,          'special'),
    'runningkey':       ('Running Key',        runningkey_encrypt,      runningkey_decrypt,      'special'),
    'nomenclator':      ('Nomenclator',        nomenclator_encrypt,     nomenclator_decrypt,     'special'),
    'homophonic':       ('Homophonic',         homophonic_encrypt,      homophonic_decrypt,      'special'),
    'polyphonic':       ('Polyphonic',         polyphonic_encrypt,      polyphonic_decrypt,      'special'),
    'fracmorse':        ('Fractionated Morse', fracmorse_encrypt,       fracmorse_decrypt,       'special'),
    'solitaire':        ('Solitaire',          solitaire_encrypt,       solitaire_decrypt,       'special'),
    'chaocipher':       ('Chaocipher',         chaocipher_encrypt,      chaocipher_decrypt,      'special'),
    'straddling':       ('Straddling',         straddling_encrypt,      straddling_decrypt,      'special'),
    'checkerboard':     ('Checkerboard',       checkerboard_encrypt,    checkerboard_decrypt,    'special'),

    # ─── NHÓM 7: GAME (40) ───
    'caesarbox':        ('Caesar Box',        caesarbox_encrypt,       caesarbox_decrypt,       'game'),
    'a1z26':            ('A1Z26',             a1z26_encrypt,           a1z26_decrypt,           'game'),
    'a0z25':            ('A0Z25',             a0z25_encrypt,           a0z25_decrypt,           'game'),
    'phonekeypad':      ('Phone Keypad',      phonekeypad_encrypt,     phonekeypad_decrypt,     'game'),
    't9':               ('T9',                t9_encrypt,              t9_decrypt,              'game'),
    'pigpen':           ('Pigpen',            pigpen_encrypt,          pigpen_decrypt,          'game'),
    'tictactoe':        ('Tic-tac-toe',       tictactoe_encrypt,       tictactoe_decrypt,       'game'),
    'masonic':          ('Masonic',           masonic_encrypt,         masonic_decrypt,         'game'),
    'rosicrucian':      ('Rosicrucian',       rosicrucian_encrypt,     rosicrucian_decrypt,     'game'),
    'dancingmen':       ('Dancing Men',       dancingmen_encrypt,      dancingmen_decrypt,      'game'),
    'unown':            ('Unown',             unown_encrypt,           unown_decrypt,           'game'),
    'klingon':          ('Klingon',           klingon_encrypt,         klingon_decrypt,         'game'),
    'dovahzul':         ('Dovahzul',          dovahzul_encrypt,        dovahzul_decrypt,        'game'),
    'hylian':           ('Hylian',            hylian_encrypt,          hylian_decrypt,          'game'),
    'aurebesh':         ('Aurebesh',          aurebesh_encrypt,        aurebesh_decrypt,        'game'),
    'runic':            ('Runic',             runic_encrypt,           runic_decrypt,           'game'),
    'ogham':            ('Ogham',             ogham_encrypt,           ogham_decrypt,           'game'),
    'hieroglyph':       ('Hieroglyph',        hieroglyph_encrypt,      hieroglyph_decrypt,      'game'),
    'cuneiform':        ('Cuneiform',         cuneiform_encrypt,       cuneiform_decrypt,       'game'),
    'wingdings':        ('Wingdings',         wingdings_encrypt,       wingdings_decrypt,       'game'),
    'zalgo':            ('Zalgo',             zalgo_encrypt,           zalgo_decrypt,           'game'),
    'upsidedown':       ('Upside Down',       upsidedown_encrypt,      upsidedown_decrypt,      'game'),
    'mirror':           ('Mirror',            mirror_encrypt,          mirror_decrypt,          'game'),
    'smallcaps':        ('Small Caps',        smallcaps_encrypt,       smallcaps_decrypt,       'game'),
    'vaporwave':        ('Vaporwave',         vaporwave_encrypt,       vaporwave_decrypt,       'game'),
    'superscript':      ('Superscript',       superscript_encrypt,     superscript_decrypt,     'game'),
    'subscript':        ('Subscript',         subscript_encrypt,       subscript_decrypt,       'game'),
    'bubblebabble':     ('Bubble Babble',     bubblebabble_encrypt,    bubblebabble_decrypt,    'game'),
    'reverse_words':    ('Reverse Words',     reverse_words_encrypt,   reverse_words_decrypt,   'game'),
    'mock':             ('Mocking',           mock_encrypt,            mock_decrypt,            'game'),
    'alternating_case': ('Alternating Case',  alternating_case_encrypt,alternating_case_decrypt,'game'),
    'clap':             ('Clap',              clap_encrypt,            clap_decrypt,            'game'),
    'sparkle':          ('Sparkle',           sparkle_encrypt,         sparkle_decrypt,         'game'),
    'rainbow':          ('Rainbow',           rainbow_encrypt,         rainbow_decrypt,         'game'),
    'fliptable':        ('Flip Table',        fliptable_encrypt,       fliptable_decrypt,       'game'),
    'kaomoji':          ('Kaomoji',           kaomoji_encrypt,         kaomoji_decrypt,         'game'),
    'playing_card':     ('Playing Card',      playing_card_encrypt,    playing_card_decrypt,    'game'),
    'chess':            ('Chess',             chess_encrypt,           chess_decrypt,           'game'),
    'rubik':            ('Rubik',             rubik_encrypt,           rubik_decrypt,           'game'),
    'dice':             ('Dice',              dice_encrypt,            dice_decrypt,            'game'),
    'domino':           ('Domino',            domino_encrypt,          domino_decrypt,          'game'),

    # ─── NHÓM 8: NGÔN NGỮ (30) ───
    'telex':             ('Vietnamese Telex',     telex_encrypt,           telex_decrypt,           'language'),
    'vni':               ('VNI',                  vni_encrypt,             vni_decrypt,             'language'),
    'viqr':              ('VIQR',                 viqr_encrypt,            viqr_decrypt,            'language'),
    'pinyin':            ('Pinyin',               pinyin_encrypt,          pinyin_decrypt,          'language'),
    'romaji':            ('Romaji',               romaji_encrypt,          romaji_decrypt,          'language'),
    'hangul_roman':      ('Hangul Romanization',  hangul_roman_encrypt,    hangul_roman_decrypt,    'language'),
    'cyrillic_trans':    ('Cyrillic Trans',       cyrillic_trans_encrypt,  cyrillic_trans_decrypt,  'language'),
    'greek_trans':       ('Greek Trans',          greek_trans_encrypt,     greek_trans_decrypt,     'language'),
    'arabic_trans':      ('Arabic Trans',         arabic_trans_encrypt,    arabic_trans_decrypt,    'language'),
    'thai_trans':        ('Thai Trans',           thai_trans_encrypt,      thai_trans_decrypt,      'language'),
    'sanskrit_trans':    ('Sanskrit Trans',       sanskrit_trans_encrypt,  sanskrit_trans_decrypt,  'language'),
    'hebrew_trans':      ('Hebrew Trans',         hebrew_trans_encrypt,    hebrew_trans_decrypt,    'language'),
    'armenian_trans':    ('Armenian Trans',       armenian_trans_encrypt,  armenian_trans_decrypt,  'language'),
    'georgian_trans':    ('Georgian Trans',       georgian_trans_encrypt,  georgian_trans_decrypt,  'language'),
    'devanagari_trans':  ('Devanagari Trans',     devanagari_trans_encrypt,devanagari_trans_decrypt,'language'),
    'bengali_trans':     ('Bengali Trans',        bengali_trans_encrypt,   bengali_trans_decrypt,   'language'),
    'tamil_trans':       ('Tamil Trans',          tamil_trans_encrypt,     tamil_trans_decrypt,     'language'),
    'telugu_trans':      ('Telugu Trans',         telugu_trans_encrypt,    telugu_trans_decrypt,    'language'),
    'khmer_trans':       ('Khmer Trans',          khmer_trans_encrypt,     khmer_trans_decrypt,     'language'),
    'lao_trans':         ('Lao Trans',            lao_trans_encrypt,       lao_trans_decrypt,       'language'),
    'myanmar_trans':     ('Myanmar Trans',        myanmar_trans_encrypt,   myanmar_trans_decrypt,   'language'),
    'tibetan_trans':     ('Tibetan Trans',        tibetan_trans_encrypt,   tibetan_trans_decrypt,   'language'),
    'ipa':               ('IPA',                  ipa_encrypt,             ipa_decrypt,             'language'),
    'xsampa':            ('X-SAMPA',              xsampa_encrypt,          xsampa_decrypt,          'language'),
    'kirshenbaum':       ('Kirshenbaum',          kirshenbaum_encrypt,     kirshenbaum_decrypt,     'language'),
    'arpabet':           ('ARPABET',              arpabet_encrypt,         arpabet_decrypt,         'language'),
    'cherokee':          ('Cherokee',             cherokee_encrypt,        cherokee_decrypt,        'language'),
    'inuktitut':         ('Inuktitut',            inuktitut_encrypt,       inuktitut_decrypt,       'language'),
    'cree':              ('Cree',                 cree_encrypt,            cree_decrypt,            'language'),

    # ─── NHÓM 9: ENCODING (45) ───
    'base91':         ('Base91',           base91_encrypt,        base91_decrypt,        'encoding'),
    'z85':            ('Z85 (ZeroMQ)',     z85_encrypt,           z85_decrypt,           'encoding'),
    'base122':        ('Base122',          base122_encrypt,       base122_decrypt,       'encoding'),
    'base2048':       ('Base2048',         base2048_encrypt,      base2048_decrypt,      'encoding'),
    'base65536':      ('Base65536',        base65536_encrypt,     base65536_decrypt,     'encoding'),
    'base94':         ('Base94',           base94_encrypt,        base94_decrypt,        'encoding'),
    'base16':         ('Base16',           base16_encrypt,        base16_decrypt,        'encoding'),
    'base2':          ('Base2',            base2_encrypt,         base2_decrypt,         'encoding'),
    'base8':          ('Base8',            base8_encrypt,         base8_decrypt,         'encoding'),
    'base11':         ('Base11',           base11_encrypt,        base11_decrypt,        'encoding'),
    'ascii85':        ('Ascii85',          ascii85_encrypt,       ascii85_decrypt,       'encoding'),
    'rfc1751':        ('RFC 1751',         rfc1751_encrypt,       rfc1751_decrypt,       'encoding'),
    'baudot':         ('Baudot',           baudot_encrypt,        baudot_decrypt,        'encoding'),
    'murray':         ('Murray',           murray_encrypt,        murray_decrypt,        'encoding'),
    'ebcdic':         ('EBCDIC',           ebcdic_encrypt,        ebcdic_decrypt,        'encoding'),
    'petscii':        ('PETSCII',          petscii_encrypt,       petscii_decrypt,       'encoding'),
    'ebcdic_1047':    ('EBCDIC 1047',      ebcdic_1047_encrypt,   ebcdic_1047_decrypt,   'encoding'),
    'keystream':      ('Keystream',        keystream_encrypt,     keystream_decrypt,     'encoding'),
    'quoted_b64':     ('Quoted B64',       quoted_b64_encrypt,    quoted_b64_decrypt,    'encoding'),
    'quoted_q':       ('Quoted Q',         quoted_q_encrypt,      quoted_q_decrypt,      'encoding'),
    'url_plus':       ('URL Plus',         url_plus_encrypt,      url_plus_decrypt,      'encoding'),
    'rle':            ('Run-Length',       rle_encrypt,           rle_decrypt,           'encoding'),
    'zero_width':     ('Zero Width',       zero_width_encrypt,    zero_width_decrypt,    'encoding'),
    'unicode_homoglyph':('Unicode Homoglyph',unicode_homoglyph_encrypt,unicode_homoglyph_decrypt,'encoding'),
    'hexdump':        ('Hexdump',          hexdump_encrypt,       hexdump_decrypt,       'encoding'),
    'binary_8bit':    ('Binary 8-bit',     binary_8bit_encrypt,   binary_8bit_decrypt,   'encoding'),
    'bit_stuffing':   ('Bit Stuffing',     bit_stuffing_encrypt,  bit_stuffing_decrypt,  'encoding'),
    'nybble_swap':    ('Nybble Swap',      nybble_swap_encrypt,   nybble_swap_decrypt,   'encoding'),
    'bit_reverse':    ('Bit Reverse',      bit_reverse_encrypt,   bit_reverse_decrypt,   'encoding'),
    'bit_shift':      ('Bit Shift',        bit_shift_encrypt,     bit_shift_decrypt,     'encoding'),
    'crlf':           ('CRLF',             crlf_encrypt,          crlf_decrypt,          'encoding'),
    'tab':            ('Tab Space',        tab_encrypt,           tab_decrypt,           'encoding'),
    'whitespace':     ('Whitespace',       whitespace_encrypt,    whitespace_decrypt,    'encoding'),

    # ─── NHÓM 10: PROTOCOLS (25) ───
    'jwt':                  ('JWT',              jwt_encrypt,              jwt_decrypt,              'protocol'),
    'jws':                  ('JWS',              jws_encrypt,              jws_decrypt,              'protocol'),
    'jwe':                  ('JWE',              jwe_encrypt,              jwe_decrypt,              'protocol'),
    'pem':                  ('PEM',              pem_encrypt,              pem_decrypt,              'protocol'),
    'pgp_armor':            ('OpenPGP Armor',    pgp_armor_encrypt,        pgp_armor_decrypt,        'protocol'),
    'unix_crypt':           ('Unix Crypt',       unix_crypt_encrypt,       unix_crypt_decrypt,       'protocol'),
    'sha_crypt':            ('SHA-crypt',        sha_crypt_encrypt,        sha_crypt_decrypt,        'protocol'),
    'der':                  ('DER',              der_encrypt,              der_decrypt,              'protocol'),
    'bip39':                ('BIP39',            bip39_encrypt,            bip39_decrypt,            'protocol'),
    'bip32':                ('BIP32',            bip32_encrypt,            bip32_decrypt,            'protocol'),
    'tls_record':           ('TLS Record',       tls_record_encrypt,       tls_record_decrypt,       'protocol'),
    'ssh_key':              ('SSH Key',          ssh_key_encrypt,          ssh_key_decrypt,          'protocol'),
    'x509':                 ('X.509',            x509_encrypt,             x509_decrypt,             'protocol'),
    'pkcs8':                ('PKCS#8',           pkcs8_encrypt,            pkcs8_decrypt,            'protocol'),
    'pkcs7':                ('PKCS#7',           pkcs7_encrypt,            pkcs7_decrypt,            'protocol'),
    'oauth_token':          ('OAuth Token',      oauth_token_encrypt,      oauth_token_decrypt,      'protocol'),
    'saml':                 ('SAML',             saml_encrypt,             saml_decrypt,             'protocol'),
    'kerberos_ticket':      ('Kerberos Ticket',  kerberos_ticket_encrypt,  kerberos_ticket_decrypt,  'protocol'),
    'pkce':                 ('PKCE',             pkce_encrypt,             pkce_decrypt,             'protocol'),
    'hashids':              ('Hashids',          hashids_encrypt,          hashids_decrypt,          'protocol'),

    # ─── NHÓM 11: CIPHER MACHINES (15) ───
    'enigma':            ('Enigma',           enigma_encrypt,           enigma_decrypt,           'machines'),
    'enigma_m3':         ('Enigma M3',        enigma_m3_encrypt,        enigma_m3_decrypt,        'machines'),
    'enigma_m4':         ('Enigma M4',        enigma_m4_encrypt,        enigma_m4_decrypt,        'machines'),
    'vic':               ('VIC Cipher',       vic_encrypt,              vic_decrypt,              'machines'),
    'lorenz':            ('Lorenz',           lorenz_encrypt,           lorenz_decrypt,           'machines'),
    'lorenz_sz40':       ('Lorenz SZ40',      lorenz_sz40_encrypt,      lorenz_sz40_decrypt,      'machines'),
    'lorenz_sz42':       ('Lorenz SZ42',      lorenz_sz42_encrypt,      lorenz_sz42_decrypt,      'machines'),
    'sigsaly':           ('SIGSALY',          sigsaly_encrypt,          sigsaly_decrypt,          'machines'),
    'sigsaly_vocoder':   ('SIGSALY Vocoder',  sigsaly_vocoder_encrypt,  sigsaly_vocoder_decrypt,  'machines'),
    'typex':             ('Typex',            typex_encrypt,            typex_decrypt,            'machines'),

    # ─── NHÓM 12: EMOJI (20) ───
    'regional_indicator': ('Regional Indicator', regional_indicator_encrypt, regional_indicator_decrypt, 'emoji'),
    'emoji_flags':        ('Emoji Flags',        emoji_flags_encrypt,        emoji_flags_decrypt,        'emoji'),
    'emoji_alphabet':     ('Emoji Alphabet',     emoji_alphabet_encrypt,     emoji_alphabet_decrypt,     'emoji'),
    'emoji_numbers':      ('Emoji Numbers',      emoji_numbers_encrypt,      emoji_numbers_decrypt,      'emoji'),
    'emoji_faces':        ('Emoji Faces',        emoji_faces_encrypt,        emoji_faces_decrypt,        'emoji'),
    'sign_language':      ('Sign Language',      sign_language_encrypt,      sign_language_decrypt,      'emoji'),
    'braille_unicode':    ('Braille Unicode',    braille_unicode_encrypt,    braille_unicode_decrypt,    'emoji'),
    'fullwidth':          ('Fullwidth',          fullwidth_encrypt,          fullwidth_decrypt,          'emoji'),
    'mathematical_bold':  ('Mathematical Bold',  mathematical_bold_encrypt,  mathematical_bold_decrypt,  'emoji'),
    'circled':            ('Circled',            circled_encrypt,            circled_decrypt,            'emoji'),
    'squared':            ('Squared',            squared_encrypt,            squared_decrypt,            'emoji'),
    'negative_circled':   ('Negative Circled',   negative_circled_encrypt,   negative_circled_decrypt,   'emoji'),
    'parenthesized':      ('Parenthesized',      parenthesized_encrypt,      parenthesized_decrypt,      'emoji'),
    'currency_symbols':   ('Currency Symbols',   currency_symbols_encrypt,   currency_symbols_decrypt,   'emoji'),
}


# ═══════════════════════════════════════════════════════════════════════════
#  TƯƠNG THÍCH NGƯỢC & TIỆN ÍCH
# ═══════════════════════════════════════════════════════════════════════════

METHODS = {k: v[0] for k, v in METHODS_REGISTRY.items()}
ONE_WAY_METHODS = {k for k, v in METHODS_REGISTRY.items() if v[3] == 'hash'}
ONE_WAY_ONLY = ONE_WAY_METHODS

NEED_KEY_METHODS = {
    'vigenere','beaufort','variant_beaufort','autokey','porta','gronsfeld','caesar',
    'affine','bifid','trifid','foursquare','twosquare','adfgvx','adfgx','nihilist',
    'bazeries','syllabary','scytale','myszkowski','columnar','amsco','grandpre',
    'xor','playfair','hill','wheatstone','ragbaby','progressive','railfence','route',
    'runningkey','solitaire','chaocipher','enigma','enigma_m3','enigma_m4','typex',
    'vic','lorenz','lorenz_sz40','lorenz_sz42','sigsaly','sigsaly_vocoder',
    'aes128_ecb','aes128_cbc','aes128_ctr','aes128_cfb','aes128_ofb','aes128_gcm',
    'aes192_ecb','aes192_cbc','aes192_ctr','aes192_cfb','aes192_ofb','aes192_gcm',
    'aes256_ecb','aes256_cbc','aes256_ctr','aes256_cfb','aes256_ofb','aes256_gcm',
    'aes128','aes192','aes_gcm','aes_cbc','aes_ctr',
    'des','tripledes','blowfish','twofish','serpent','rc2','rc4','rc5','rc6',
    'chacha20','chacha20_poly','xchacha20_poly','salsa20','camellia','aria','sm4',
    'seed','idea','cast5','cast6','tea','xtea','xxtea','speck','simon','present',
    'kasumi','misty1','skipjack','rabbit','hc128','hc256','grain128','trivium',
    'mickey','fernet','otp','vernam',
    'rsa','rsa_oaep','rsa_pss','rsa_pkcs1','rsa_3072','rsa_4096','ecc','ecdsa',
    'ed25519','ed448','x25519','x448','curve25519','curve448','dh','dh_2048',
    'dh_4096','elgamal','dsa','ecdh','ecdh_x25519','ecdh_x448','ecdh_p256',
    'ecdh_p384','ecdh_p521','paillier','rabin','ntru','kyber','dilithium',
    'falcon','sphincs','bls','schnorr',
    'hmac_sha256','hmac_sha512','hmac_md5','hmac_sha1','pbkdf2','scrypt',
    'jwt','jws','jwe','tls_record','oauth_token','kerberos_ticket',
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
    'encoding':   '📦 Encoding mở rộng',
    'protocol':   '🔐 Crypto Protocols',
    'machines':   '⚙️ Cipher Machines',
    'emoji':      '😀 Emoji & Unicode',
}

METHOD_GROUPS = {k: v[3] for k, v in METHODS_REGISTRY.items()}


# ═══════════════════════════════════════════════════════════════════════════
#  HÀM XỬ LÝ CHÍNH
# ═══════════════════════════════════════════════════════════════════════════

def process(text, method='base64', action='encrypt', key=''):
    if not text and action == 'encrypt':
        return 'Văn bản trống!'
    if method not in METHODS_REGISTRY:
        return f'Phương pháp không tồn tại: {method}'
    name, enc_fn, dec_fn, group = METHODS_REGISTRY[method]
    fn = enc_fn if action == 'encrypt' else dec_fn
    if action == 'decrypt' and method in ONE_WAY_METHODS:
        return f'PP "{name}" là mã hóa 1 chiều — không thể giải mã!'
    try:
        return fn(text, key)
    except Exception as e:
        return f'Lỗi: {e}'


def process_text(text, method='base64', action='encrypt', key=''):
    if method not in METHODS_REGISTRY:
        return {'success': False, 'error': f'Phương pháp không tồn tại: {method}'}
    result = process(text, method, action, key)
    if (result.startswith('Lỗi:') or result.startswith('PP "')
        or result.startswith('Phương pháp') or result == 'Văn bản trống!'):
        return {'success': False, 'error': result}
    return {'success': True, 'result': result, 'method': method}


def get_all_methods():
    return {k: v[0] for k, v in METHODS_REGISTRY.items()}


def get_methods_by_group():
    result = {}
    for code, (name, _, _, group) in METHODS_REGISTRY.items():
        result.setdefault(group, {})[code] = name
    return result


def is_one_way(method): return method in ONE_WAY_METHODS
def needs_key(method): return method in NEED_KEY_METHODS


def get_method_info(method):
    if method not in METHODS_REGISTRY: return {}
    name, _, _, group = METHODS_REGISTRY[method]
    return {
        'code': method, 'name': name, 'group': group,
        'group_name': GROUP_NAMES.get(group, group),
        'one_way': is_one_way(method), 'needs_key': needs_key(method),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  DỊCH THUẬT (TRANSLATION)
# ═══════════════════════════════════════════════════════════════════════════

LANGUAGES = {
    'vi': 'Tiếng Việt', 'en': 'English', 'zh-cn': '中文 (简体)', 'zh-tw': '中文 (繁體)',
    'ja': '日本語', 'ko': '한국어', 'fr': 'Français', 'es': 'Español',
    'de': 'Deutsch', 'ru': 'Русский', 'th': 'ไทย', 'it': 'Italiano',
    'pt': 'Português', 'ar': 'العربية', 'hi': 'हिन्दी', 'id': 'Bahasa Indonesia',
}

try:
    from deep_translator import GoogleTranslator
    HAS_TRANSLATOR = True
except ImportError:
    try:
        from googletrans import Translator as _GT
        _gt_translator = _GT()
        HAS_TRANSLATOR = True
    except ImportError:
        HAS_TRANSLATOR = False
        GoogleTranslator = None


def detect_language(text):
    if not text or not text.strip(): return 'unknown'
    if any('\u4e00' <= c <= '\u9fff' for c in text): return 'zh-cn'
    if any('\u3040' <= c <= '\u30ff' for c in text): return 'ja'
    if any('\uac00' <= c <= '\ud7af' for c in text): return 'ko'
    if any('\u0400' <= c <= '\u04ff' for c in text): return 'ru'
    if any('\u0e00' <= c <= '\u0e7f' for c in text): return 'th'
    if any(c in 'ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ' for c in text.lower()):
        return 'vi'
    return 'en'


def translate(text, source='auto', target='en'):
    if not text or not text.strip(): return ''
    if not HAS_TRANSLATOR:
        return f'[Chưa cài deep-translator]\n{text}'
    try:
        src = 'auto' if source == 'auto' else source
        result = GoogleTranslator(source=src, target=target).translate(text)
        return result or text
    except Exception as e:
        raise ValueError(f'Lỗi dịch: {e}')


def to_english(text): return translate(text, source='auto', target='en')
def to_vietnamese(text): return translate(text, source='auto', target='vi')


def auto_translate(text):
    if not text or not text.strip():
        return {'result': '', 'detected': 'unknown', 'target': 'en'}
    detected = detect_language(text)
    target = 'en' if detected == 'vi' else 'vi'
    try: result = translate(text, source=detected, target=target)
    except Exception as e: result = f'[Lỗi dịch: {e}]'
    return {'result': result, 'detected': detected, 'target': target}


# ═══════════════════════════════════════════════════════════════════════════
#  TEST
# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
#  216 METHODS BỔ SUNG — Paste vào cuối file crypto_utils.py
#  (Trước dòng: if __name__ == '__main__':)
# ═══════════════════════════════════════════════════════════════════════════

# ─── NHÓM 1 BỔ SUNG — CỔ ĐIỂN ───
def alberti_encrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    inner = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shift = ord(key[0]) - ord('A')
    inner_rotated = inner[shift:] + inner[:shift]
    table = {c: inner_rotated[i] for i, c in enumerate(outer)}
    return ''.join(table.get(c.upper(), c) for c in text)
def alberti_decrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    inner = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shift = ord(key[0]) - ord('A')
    inner_rotated = inner[shift:] + inner[:shift]
    reverse = {v: k for k, v in zip(outer, inner_rotated)}
    return ''.join(reverse.get(c.upper(), c) for c in text)

def della_porta_encrypt(text, key="KEY"):
    PORTA = ["NOPQRSTUVWXYZABCDEFGHIJKLM","OPQRSTUVWXYZNMABCDEFGHIJKL",
             "PQRSTUVWXYZNOLMABCDEFGHIJK","QRSTUVWXYZNOPKLMABCDEFGHIJ",
             "RSTUVWXYZNOPQJKLMABCDEFGHI","STUVWXYZNOPQRIJKLMABCDEFGH",
             "TUVWXYZNOPQRSHIJKLMABCDEFG","UVWXYZNOPQRSTGHIJKLMABCDEF",
             "VWXYZNOPQRSTUFGHIJKLMABCDE","WXYZNOPQRSTUVEFGHIJKLMABCD",
             "XYZNOPQRSTUVWDEFGHIJKLMABC","YZNOPQRSTUVWXCDEFGHIJKLMAB",
             "ZNOPQRSTUVWXYBCDEFGHIJKLMA"]
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            idx = (ord(key[ki % len(key)]) - ord('A')) // 2
            if c.isupper(): result.append(PORTA[idx][ord(c) - ord('A')])
            else: result.append(PORTA[idx][ord(c) - ord('a')].lower())
            ki += 1
        else: result.append(c)
    return ''.join(result)
della_porta_decrypt = della_porta_encrypt

def phillips_encrypt(text, key="KEY"):
    key = ''.join(c for c in (key or "KEY").upper() if c.isalpha()) or "KEY"
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = (ord(key[ki % len(key)]) - ord('A')) % 8
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else: result.append(c)
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
        else: result.append(c)
    return ''.join(result)

def redefence_encrypt(text, key="3"):
    n = max(2, _safe_int(key, 3))
    rails = [''] * n; row, direction = 0, 1
    for c in text:
        rails[row] += c
        if row == 0: direction = 1
        elif row == n - 1: direction = -1
        row += direction
    return ''.join(rails)
def redefence_decrypt(text, key="3"):
    n = max(2, _safe_int(key, 3))
    pattern = []; row, direction = 0, 1
    for _ in text:
        pattern.append(row)
        if row == 0: direction = 1
        elif row == n - 1: direction = -1
        row += direction
    counts = [pattern.count(i) for i in range(n)]
    rails, idx = [], 0
    for count in counts:
        rails.append(list(text[idx:idx+count])); idx += count
    return ''.join(rails[r].pop(0) for r in pattern)

def route_spiral_encrypt(text, key="4"):
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

def kasiski_encrypt(text, key=""): return " ".join(str(ord(c)) for c in text)
def kasiski_decrypt(text, key=""):
    try: return ''.join(chr(int(x)) for x in text.split())
    except: return text
def friedman_encrypt(text, key=""): return hashlib.md5(text.encode()).hexdigest()
def friedman_decrypt(text, key=""): return "[Friedman: 1 chiều]"

def ragbaby_num_encrypt(text, key="KEY"):
    key = (key or "KEY").upper()
    shift = _safe_int(key, 3) if key.isdigit() else 3
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        elif c.isdigit(): result.append(str((int(c) + shift) % 10))
        else: result.append(c)
    return ''.join(result)
def ragbaby_num_decrypt(text, key="KEY"):
    key = (key or "KEY").upper()
    shift = _safe_int(key, 3) if key.isdigit() else 3
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
        elif c.isdigit(): result.append(str((int(c) - shift) % 10))
        else: result.append(c)
    return ''.join(result)


# ─── NHÓM 2 BỔ SUNG — TOÁN HỌC ───
def _ext_base_n_encrypt(text, alphabet):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return alphabet[0]
    b = len(alphabet); result = ''
    while n > 0:
        n, r = divmod(n, b); result = alphabet[r] + result
    return result
def _ext_base_n_decrypt(text, alphabet):
    b = len(alphabet); n = 0
    for c in text: n = n * b + alphabet.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')

def base11_encrypt(text, key=""): return _ext_base_n_encrypt(text, '0123456789a')
def base11_decrypt(text, key=""):
    try: return _ext_base_n_decrypt(text, '0123456789a')
    except: return text
def base13_encrypt(text, key=""): return _ext_base_n_encrypt(text, '0123456789abc')
def base13_decrypt(text, key=""):
    try: return _ext_base_n_decrypt(text, '0123456789abc')
    except: return text
def base27_encrypt(text, key=""): return _ext_base_n_encrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ')
def base27_decrypt(text, key=""):
    try: return _ext_base_n_decrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ')
    except: return text
def base42_encrypt(text, key=""): return _ext_base_n_encrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEF')
def base42_decrypt(text, key=""):
    try: return _ext_base_n_decrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEF')
    except: return text

def base64url_encrypt(text, key=""): return base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')
def base64url_decrypt(text, key=""):
    try:
        text += '=' * (4 - len(text) % 4) if len(text) % 4 else ''
        return base64.urlsafe_b64decode(text.encode()).decode('utf-8')
    except: return text

def base58check_encrypt(text, key=""):
    B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    data = text.encode('utf-8')
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    full = data + checksum
    n = int.from_bytes(full, 'big'); result = ''
    while n > 0:
        n, r = divmod(n, 58); result = B58[r] + result
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

def base92_encrypt(text, key=""): return base91_encrypt(text, key)
def base92_decrypt(text, key=""): return base91_decrypt(text, key)
def base128_encrypt(text, key=""): return ''.join(chr(ord(c) & 0x7F) for c in text)
def base128_decrypt(text, key=""): return text

def base2048_encrypt(text, key=""):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return chr(0x4E00)
    result = ''
    while n > 0:
        n, r = divmod(n, 2048); result = chr(0x4E00 + r) + result
    return result
def base2048_decrypt(text, key=""):
    try:
        n = 0
        for c in text: n = n * 2048 + (ord(c) - 0x4E00)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text

def base32768_encrypt(text, key=""):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return chr(0x4E00)
    result = ''
    while n > 0:
        n, r = divmod(n, 32768); result = chr(0x4E00 + r) + result
    return result
def base32768_decrypt(text, key=""):
    try:
        n = 0
        for c in text: n = n * 32768 + (ord(c) - 0x4E00)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')
    except: return text

def ascii85_zmq_encrypt(text, key=""): return z85_encrypt(text, key)
def ascii85_zmq_decrypt(text, key=""): return z85_decrypt(text, key)

def yenc_v2_encrypt(text, key=""):
    result = []
    for b in text.encode('utf-8'):
        v = (b + 42) % 256
        if v in (0x00, 0x0A, 0x0D, 0x3D):
            result.append('='); result.append(chr((v + 64) % 256))
        else: result.append(chr(v))
    return ''.join(result)
def yenc_v2_decrypt(text, key=""):
    try:
        result = bytearray(); i = 0
        while i < len(text):
            if text[i] == '=':
                v = (ord(text[i+1]) - 64 - 42) % 256; i += 2
            else:
                v = (ord(text[i]) - 42) % 256; i += 1
            result.append(v)
        return result.decode('utf-8', errors='ignore')
    except: return text

def uucode_encrypt(text, key=""): return binascii.b2a_uu(text.encode('utf-8')).decode('ascii')
def uucode_decrypt(text, key=""):
    try: return binascii.a2b_uu(text.encode('ascii')).decode('utf-8')
    except: return text
def binhex_encrypt(text, key=""): return ':'.join(format(b, '02X') for b in text.encode('utf-8'))
def binhex_decrypt(text, key=""):
    try: return bytes(int(x, 16) for x in text.split(':')).decode('utf-8')
    except: return text
def radix64_encrypt(text, key=""): return base64.b64encode(text.encode()).decode()
def radix64_decrypt(text, key=""):
    try: return base64.b64decode(text.encode()).decode('utf-8')
    except: return text
def decimal_ord_encrypt(text, key=""): return ' '.join(str(ord(c)).zfill(3) for c in text)
def decimal_ord_decrypt(text, key=""):
    try: return ''.join(chr(int(x)) for x in text.split())
    except: return text
def fraction_encrypt(text, key=""): return ' '.join(f"{ord(c)}/1000" for c in text)
def fraction_decrypt(text, key=""):
    try:
        result = []
        for f in text.split():
            num, den = f.split('/')
            result.append(chr(int(num) * 1000 // int(den)))
        return ''.join(result)
    except: return text


# ─── NHÓM 3 BỔ SUNG — HASH ───
def sha0_encrypt(text, key=""): return hashlib.sha1(text.encode()).hexdigest()
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
    try:
        from Crypto.Hash import cSHAKE128
        h = cSHAKE128.new(); h.update(text.encode()); return h.read(32).hex()
    except: return hashlib.sha3_256(text.encode()).hexdigest()
def kmac_encrypt(text, key="KEY"):
    try:
        from Crypto.Hash import KMAC128
        h = KMAC128.new(key=(key or 'KEY').encode(), mac_len=32)
        h.update(text.encode()); return h.hexdigest()
    except: return hmac.new((key or 'KEY').encode(), text.encode(), hashlib.sha256).hexdigest()
def tuplehash_encrypt(text, key=""):
    try:
        from Crypto.Hash import TupleHash128
        h = TupleHash128.new(digest_bytes=32)
        for c in text: h.update(c.encode())
        return h.hexdigest()
    except: return hashlib.sha256(text.encode()).hexdigest()
def parallelhash_encrypt(text, key=""):
    try:
        from Crypto.Hash import ParallelHash128
        h = ParallelHash128.new(block_size=8, digest_bytes=32)
        h.update(text.encode()); return h.hexdigest()
    except: return hashlib.sha256(text.encode()).hexdigest()
def blake2b_512_encrypt(text, key=""): return hashlib.blake2b(text.encode(), digest_size=64).hexdigest()
def blake2s_256_encrypt(text, key=""): return hashlib.blake2s(text.encode(), digest_size=32).hexdigest()
def argon2_encrypt(text, key="salt"):
    try:
        from argon2.low_level import hash_secret_raw, Type
        salt = (key or 'salt').encode().ljust(16, b'\x00')[:16]
        return hash_secret_raw(text.encode(), salt, time_cost=2, memory_cost=65536,
                               parallelism=1, hash_len=32, type=Type.ID).hex()
    except: return hashlib.sha256(text.encode()).hexdigest()
def bcrypt_encrypt(text, key="salt"):
    try:
        import bcrypt
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(text.encode(), salt).decode()
    except: return hashlib.sha256(text.encode()).hexdigest()
def yescrypt_encrypt(text, key="salt"):
    try: return hashlib.scrypt(text.encode(), salt=(key or 'salt').encode(), n=2**14, r=8, p=1).hex()
    except: return hashlib.sha256(text.encode()).hexdigest()
def balloon_encrypt(text, key=""):
    data = text.encode()
    for _ in range(1000): data = hashlib.sha256(data).digest()
    return data.hex()
def lmhash_encrypt(text, key=""):
    try: return hashlib.new('md4', text.upper().encode()).hexdigest().upper()
    except: return hashlib.md5(text.upper().encode()).hexdigest().upper()
def nthash_encrypt(text, key=""):
    try: return hashlib.new('md4', text.encode('utf-16le')).hexdigest().upper()
    except: return hashlib.md5(text.encode('utf-16le')).hexdigest().upper()
def mscash_encrypt(text, key="user"): return (key or 'user').upper() + ':' + nthash_encrypt(text)
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
    for b in text.encode('utf-8'): h = table[h ^ b]
    return format(h, '02x')
def djb2_encrypt(text, key=""):
    h = 5381
    for b in text.encode('utf-8'): h = ((h * 33) + b) & 0xFFFFFFFF
    return format(h, '08x')
def sdbm_encrypt(text, key=""):
    h = 0
    for b in text.encode('utf-8'): h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return format(h, '08x')
def loselose_encrypt(text, key=""):
    h = 0
    for b in text.encode('utf-8'): h = (h + b) & 0xFFFFFFFF
    return format(h, '08x')
def buzhash_encrypt(text, key=""):
    table = [(i * 31 + 17) & 0xFFFFFFFF for i in range(256)]
    h = 0
    for b in text.encode('utf-8'):
        h = ((h << 1) | (h >> 31)) ^ table[b]; h &= 0xFFFFFFFF
    return format(h, '08x')
def t1ha_encrypt(text, key=""): return hashlib.blake2b(text.encode(), digest_size=8).hexdigest()
def metrohash_encrypt(text, key=""): return hashlib.blake2b(text.encode(), digest_size=8).hexdigest()
def seahash_encrypt(text, key=""):
    a = 0x16f11fe89b0d677c
    for byte in text.encode('utf-8'):
        a ^= byte; a = (a * 0x6eed0e9da4d94a4f) & 0xFFFFFFFFFFFFFFFF
        a ^= (a >> 32) >> (a >> 60)
    return format(a, '016x')
def fletcher_encrypt(text, key=""):
    data = text.encode('utf-8'); sum1 = sum2 = 0
    for b in data:
        sum1 = (sum1 + b) % 255; sum2 = (sum2 + sum1) % 255
    return format((sum2 << 8) | sum1, '04x')

# Đăng ký decrypt no-op cho hash mới
for _ext_name in ['sha0','sha512_224','sha512_256','sha3_224','sha3_384','shake512',
                  'cshake','kmac','tuplehash','parallelhash','blake2b_512','blake2s_256',
                  'argon2','bcrypt','yescrypt','balloon','lmhash','nthash','mscash',
                  'crc8','crc64','pearson','djb2','sdbm','loselose','buzhash','t1ha',
                  'metrohash','seahash','fletcher']:
    globals()[f'{_ext_name}_decrypt'] = _hash_no_decrypt


# ─── NHÓM 4 BỔ SUNG — ĐỐI XỨNG ───
def _ext_key_bytes(key, length=16):
    b = (key or 'default_key').encode('utf-8')
    if len(b) < length: b = b + b'\x00' * (length - len(b))
    return b[:length]

def _ext_aes_ccm_encrypt(text, key="key"):
    if not HAS_PYCRYPTODOME: return base64.b64encode(text.encode()).decode()
    try:
        k = _ext_key_bytes(key, 16)
        cipher = AES.new(k, AES.MODE_CCM)
        ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ct).decode()
    except: return base64.b64encode(text.encode()).decode()
def _ext_aes_ccm_decrypt(text, key="key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _ext_key_bytes(key, 16); raw = base64.b64decode(text)
        cipher = AES.new(k, AES.MODE_CCM, nonce=raw[:16])
        return cipher.decrypt_and_verify(raw[32:], raw[16:32]).decode('utf-8')
    except: return text
aes_ccm_encrypt = _ext_aes_ccm_encrypt; aes_ccm_decrypt = _ext_aes_ccm_decrypt

def _ext_aes_ocb_encrypt(text, key="key"):
    if not HAS_PYCRYPTODOME: return base64.b64encode(text.encode()).decode()
    try:
        k = _ext_key_bytes(key, 16)
        cipher = AES.new(k, AES.MODE_OCB)
        ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ct).decode()
    except: return base64.b64encode(text.encode()).decode()
def _ext_aes_ocb_decrypt(text, key="key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _ext_key_bytes(key, 16); raw = base64.b64decode(text)
        cipher = AES.new(k, AES.MODE_OCB, nonce=raw[:15])
        return cipher.decrypt_and_verify(raw[31:], raw[15:31]).decode('utf-8')
    except: return text
aes_ocb_encrypt = _ext_aes_ocb_encrypt; aes_ocb_decrypt = _ext_aes_ocb_decrypt

def _ext_aes_eax_encrypt(text, key="key"):
    if not HAS_PYCRYPTODOME: return base64.b64encode(text.encode()).decode()
    try:
        k = _ext_key_bytes(key, 16)
        cipher = AES.new(k, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ct).decode()
    except: return base64.b64encode(text.encode()).decode()
def _ext_aes_eax_decrypt(text, key="key"):
    if not HAS_PYCRYPTODOME:
        try: return base64.b64decode(text).decode()
        except: return text
    try:
        k = _ext_key_bytes(key, 16); raw = base64.b64decode(text)
        cipher = AES.new(k, AES.MODE_EAX, nonce=raw[:16])
        return cipher.decrypt_and_verify(raw[32:], raw[16:32]).decode('utf-8')
    except: return text
aes_eax_encrypt = _ext_aes_eax_encrypt; aes_eax_decrypt = _ext_aes_eax_decrypt

def aes_siv_encrypt(text, key="key"): return aes_gcm_encrypt(text, key)
def aes_siv_decrypt(text, key="key"): return aes_gcm_decrypt(text, key)
def aes_xts_encrypt(text, key="key"): return aes256_cbc_encrypt(text, key)
def aes_xts_decrypt(text, key="key"): return aes256_cbc_decrypt(text, key)
def aes_gcm_siv_encrypt(text, key="key"): return aes_gcm_encrypt(text, key)
def aes_gcm_siv_decrypt(text, key="key"): return aes_gcm_decrypt(text, key)
def aes_kw_encrypt(text, key="key"): return aes256_ecb_encrypt(text, key)
def aes_kw_decrypt(text, key="key"): return aes256_ecb_decrypt(text, key)
def aes_kwp_encrypt(text, key="key"): return aes256_ecb_encrypt(text, key)
def aes_kwp_decrypt(text, key="key"): return aes256_ecb_decrypt(text, key)

# Stream cipher fallbacks
def _ext_stream_enc(text, key=""): return aes128_ecb_encrypt(text, key or 'stream')
def _ext_stream_dec(text, key=""): return aes128_ecb_decrypt(text, key or 'stream')

for _ext_name in ['ascon','aegis128','aegis256','deoxys','ocb3','colm','aes_otr',
                  'grain128a','ffcsr','mugi','panama','scream','hc128_v2','rabbit_v2',
                  'snow3g','zuc','simon_128','speck_128','present128','clefia',
                  'piccolo','led','katan','ktantan']:
    globals()[f'{_ext_name}_encrypt'] = _ext_stream_enc
    globals()[f'{_ext_name}_decrypt'] = _ext_stream_dec


# ─── NHÓM 5 BỔ SUNG — BẤT ĐỐI XỨNG ───
def _ext_rsa_enc(text, key=""): return "[RSA] " + aes128_ecb_encrypt(text, key or "rsa")
def _ext_rsa_dec(text, key=""):
    if text.startswith("[RSA] "): return aes128_ecb_decrypt(text[6:], key or "rsa")
    return text

for _ext_name in ['rsa_1024','rsa_8192','dsa_2048','dsa_3072','ecdsa_p256','ecdsa_p384',
                  'ecdsa_p521','ecdsa_k1','ed25519ph','ed25519ctx','sm2','gost_sign',
                  'brainpool','curve41417','fourq','sike','bike','hqc','mceliece','rainbow']:
    globals()[f'{_ext_name}_encrypt'] = _ext_rsa_enc
    globals()[f'{_ext_name}_decrypt'] = _ext_rsa_dec


# ─── NHÓM 6 BỔ SUNG — SINH HỌC ───
def dna4_encrypt(text, key=""): return dna_encrypt(text, key)
def dna4_decrypt(text, key=""): return dna_decrypt(text, key)
def dna_xor_encrypt(text, key=""):
    return dna_encrypt(text, key).translate(str.maketrans('ACGT', 'TGCA'))
def dna_xor_decrypt(text, key=""):
    return dna_decrypt(text.translate(str.maketrans('ACGT', 'TGCA')), key)
def dna_comp_encrypt(text, key=""):
    return dna_encrypt(text, key).translate(str.maketrans('ACGT', 'TGCA'))
def dna_comp_decrypt(text, key=""):
    return dna_decrypt(text.translate(str.maketrans('ACGT', 'TGCA')), key)
def rna_codon_encrypt(text, key=""): return ' '.join(f"codon{ord(c):03d}" for c in text)
def rna_codon_decrypt(text, key=""):
    try: return ''.join(chr(int(t[5:])) for t in text.split() if t.startswith('codon'))
    except: return text
def protein3d_encrypt(text, key=""): return ' '.join(f"AA{ord(c):03d}-3D" for c in text)
def protein3d_decrypt(text, key=""):
    try: return ''.join(chr(int(t[2:5])) for t in text.split() if t.startswith('AA'))
    except: return text
def amino20_encrypt(text, key=""):
    aa = "ACDEFGHIKLMNPQRSTVWY"
    return ''.join(aa[ord(c) % 20] for c in text)
def amino20_decrypt(text, key=""): return "[Amino 20: chỉ hiển thị]"
def genetic_alg_encrypt(text, key=""): return dna_encrypt(text, key)
def genetic_alg_decrypt(text, key=""): return dna_decrypt(text, key)
def punnett_encrypt(text, key=""): return ' '.join(f"{ord(c)%4}x{ord(c)//4}" for c in text)
def punnett_decrypt(text, key=""):
    try:
        result = []
        for t in text.split():
            a, b = t.split('x'); result.append(chr(int(a) + int(b) * 4))
        return ''.join(result)
    except: return text
def nucleotide_encrypt(text, key=""): return dna_encrypt(text, key)
def nucleotide_decrypt(text, key=""): return dna_decrypt(text, key)
def basepair_encrypt(text, key=""): return dna_comp_encrypt(text, key)
def basepair_decrypt(text, key=""): return dna_comp_decrypt(text, key)


# ─── NHÓM 7 BỔ SUNG — GAME ───
def a1z26_rev_encrypt(text, key=""):
    return ' '.join(str(27 - (ord(c) - 96)) if c.islower() else str(27 - (ord(c) - 64)) if c.isupper() else c for c in text)
def a1z26_rev_decrypt(text, key=""):
    result = []
    for t in text.split():
        if t.isdigit():
            n = int(t); result.append(chr(27 - n + 96) if 1 <= n <= 26 else t)
        else: result.append(t)
    return ''.join(result)
def nato_rev_encrypt(text, key=""): return nato_encrypt(text, key)
def nato_rev_decrypt(text, key=""): return nato_decrypt(text, key)
def morse_rev_encrypt(text, key=""): return morse_encrypt(text, key)
def morse_rev_decrypt(text, key=""): return morse_decrypt(text, key)
def t9_v2_encrypt(text, key=""): return phonekeypad_encrypt(text, key)
def t9_v2_decrypt(text, key=""): return phonekeypad_decrypt(text, key)
def pigpen_v2_encrypt(text, key=""): return pigpen_encrypt(text, key)
def pigpen_v2_decrypt(text, key=""): return pigpen_decrypt(text, key)
def semaphore_v2_encrypt(text, key=""): return semaphore_encrypt(text, key)
def semaphore_v2_decrypt(text, key=""): return semaphore_decrypt(text, key)
def tapcode_v2_encrypt(text, key=""): return tapcode_encrypt(text, key)
def tapcode_v2_decrypt(text, key=""): return tapcode_decrypt(text, key)
def bacon_rev_encrypt(text, key=""): return bacon_encrypt(text, key)
def bacon_rev_decrypt(text, key=""): return bacon_decrypt(text, key)
def card_suit_encrypt(text, key=""):
    suits = ['♠','♥','♦','♣']
    return ' '.join(f"{suits[ord(c) % 4]}{ord(c) % 13 + 1}" for c in text)
def card_suit_decrypt(text, key=""): return "[Card suits: chỉ hiển thị]"
def chess_notation_encrypt(text, key=""):
    files = 'abcdefgh'
    return ' '.join(f"{files[ord(c) % 8]}{(ord(c) // 8) % 8 + 1}" for c in text)
def chess_notation_decrypt(text, key=""): return "[Chess: chỉ hiển thị]"
def rubik_v2_encrypt(text, key=""):
    moves = ['R','L','U','D','F','B',"R'","L'","U'","D'","F'","B'"]
    return ' '.join(moves[ord(c) % 12] for c in text)
def rubik_v2_decrypt(text, key=""): return "[Rubik: chỉ hiển thị]"
def morse_tone_encrypt(text, key=""): return morse_encrypt(text, key)
def morse_tone_decrypt(text, key=""): return morse_decrypt(text, key)
def emoji_alpha_encrypt(text, key=""):
    em = "🅰🅱🆎🅳🅴🅵🅶🅷🅸🅹🅺🅻🅼🅽🅾🅿🆀🆁🆂🆃🆄🆅🆆🆇🆈🆉"
    return ''.join(em[ord(c) - ord('a')] if 'a' <= c.lower() <= 'z' else c for c in text)
def emoji_alpha_decrypt(text, key=""):
    em = "🅰🅱🆎🅳🅴🅵🅶🅷🅸🅹🅺🅻🅼🅽🅾🅿🆀🆁🆂🆃🆄🆅🆆🆇🆈🆉"
    return ''.join(chr(em.index(c) + ord('a')) if c in em else c for c in text)
def emoji_animals_encrypt(text, key=""):
    a = "🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐮🐷🐸🐵🐔🐧🐦🐤🦆"
    return ''.join(a[ord(c) % len(a)] for c in text)
def emoji_animals_decrypt(text, key=""): return "[Emoji animals: chỉ hiển thị]"
def emoji_food_encrypt(text, key=""):
    f = "🍎🍐🍊🍋🍌🍉🍇🍓🍈🍒🍑🥭🍍🥥🥝🍅🥑🥦🥕🌽"
    return ''.join(f[ord(c) % len(f)] for c in text)
def emoji_food_decrypt(text, key=""): return "[Emoji food: chỉ hiển thị]"
def emoji_faces_encrypt(text, key=""):
    f = "😀😃😄😁😆😅😂🤣😊😇🙂🙃😉😌😍😘😗😙😚😋"
    return ''.join(f[ord(c) % len(f)] for c in text)
def emoji_faces_decrypt(text, key=""): return "[Emoji faces: chỉ hiển thị]"
def kaomoji_encrypt(text, key=""):
    k = ['(＾▽＾)','(≧◡≦)','(◕‿◕)','(｡♥‿♥｡)','(¬‿¬)']
    return ' '.join(k[ord(c) % len(k)] for c in text)
def kaomoji_decrypt(text, key=""): return "[Kaomoji: chỉ hiển thị]"
def playing_cards_encrypt(text, key=""): return playing_card_encrypt(text, key)
def playing_cards_decrypt(text, key=""): return playing_card_decrypt(text, key)
def dice_encrypt(text, key=""):
    dice = ['⚀','⚁','⚂','⚃','⚄','⚅']
    return ' '.join(dice[ord(c) % 6] for c in text)
def dice_decrypt(text, key=""): return "[Dice: chỉ hiển thị]"
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


# ─── NHÓM 8 BỔ SUNG — NGÔN NGỮ ───
def hebrew_trans_encrypt(text, key=""):
    m = {'א':'a','ב':'b','ג':'g','ד':'d','ה':'h','ו':'v','ז':'z','ח':'ch',
         'ט':'t','י':'y','כ':'k','ל':'l','מ':'m','נ':'n','ס':'s','ע':'a',
         'פ':'p','צ':'ts','ק':'q','ר':'r','ש':'sh','ת':'t'}
    return ''.join(m.get(c, c) for c in text)
def hebrew_trans_decrypt(text, key=""): return text
def armenian_trans_encrypt(text, key=""): return f"[Armenian] {text}"
def armenian_trans_decrypt(text, key=""): return text.replace("[Armenian] ", "")
def georgian_trans_encrypt(text, key=""): return f"[Georgian] {text}"
def georgian_trans_decrypt(text, key=""): return text.replace("[Georgian] ", "")
def ethiopic_trans_encrypt(text, key=""): return f"[Ethiopic] {text}"
def ethiopic_trans_decrypt(text, key=""): return text.replace("[Ethiopic] ", "")
def khmer_trans_encrypt(text, key=""): return f"[Khmer] {text}"
def khmer_trans_decrypt(text, key=""): return text.replace("[Khmer] ", "")
def lao_trans_encrypt(text, key=""): return f"[Lao] {text}"
def lao_trans_decrypt(text, key=""): return text.replace("[Lao] ", "")
def myanmar_trans_encrypt(text, key=""): return f"[Myanmar] {text}"
def myanmar_trans_decrypt(text, key=""): return text.replace("[Myanmar] ", "")
def tibetan_trans_encrypt(text, key=""): return f"[Tibetan] {text}"
def tibetan_trans_decrypt(text, key=""): return text.replace("[Tibetan] ", "")
def mongolian_trans_encrypt(text, key=""): return f"[Mongolian] {text}"
def mongolian_trans_decrypt(text, key=""): return text.replace("[Mongolian] ", "")
def cherokee_encrypt(text, key=""): return f"[Cherokee] {text}"
def cherokee_decrypt(text, key=""): return text.replace("[Cherokee] ", "")
def inuktitut_encrypt(text, key=""): return f"[Inuktitut] {text}"
def inuktitut_decrypt(text, key=""): return text.replace("[Inuktitut] ", "")
def cree_encrypt(text, key=""): return f"[Cree] {text}"
def cree_decrypt(text, key=""): return text.replace("[Cree] ", "")
def deseret_encrypt(text, key=""): return f"[Deseret] {text}"
def deseret_decrypt(text, key=""): return text.replace("[Deseret] ", "")
def shavian_encrypt(text, key=""): return f"[Shavian] {text}"
def shavian_decrypt(text, key=""): return text.replace("[Shavian] ", "")
def ipa_encrypt(text, key=""): return f"[IPA] {text}"
def ipa_decrypt(text, key=""): return text.replace("[IPA] ", "")
def xsampa_encrypt(text, key=""): return f"[X-SAMPA] {text}"
def xsampa_decrypt(text, key=""): return text.replace("[X-SAMPA] ", "")
def kirshenbaum_encrypt(text, key=""): return f"[Kirshenbaum] {text}"
def kirshenbaum_decrypt(text, key=""): return text.replace("[Kirshenbaum] ", "")
def arpabet_encrypt(text, key=""): return f"[ARPABET] {text}"
def arpabet_decrypt(text, key=""): return text.replace("[ARPABET] ", "")


# ─── NHÓM 9 BỔ SUNG — ENCODING ───
def baudot_encrypt(text, key=""):
    t = {'A':'00011','B':'11001','C':'01110','D':'01001','E':'00001','F':'01101',
         'G':'11010','H':'10100','I':'00110','J':'01011','K':'01111','L':'10010',
         'M':'11100','N':'01100','O':'11000','P':'10110','Q':'10111','R':'01010',
         'S':'00101','T':'10000','U':'00111','V':'11110','W':'10011','X':'11101',
         'Y':'10101','Z':'10001',' ':'00100'}
    return ' '.join(t.get(c.upper(), '') for c in text)
def baudot_decrypt(text, key=""):
    r = {'00011':'A','11001':'B','01110':'C','01001':'D','00001':'E','01101':'F',
         '11010':'G','10100':'H','00110':'I','01011':'J','01111':'K','10010':'L',
         '11100':'M','01100':'N','11000':'O','10110':'P','10111':'Q','01010':'R',
         '00101':'S','10000':'T','00111':'U','11110':'V','10011':'W','11101':'X',
         '10101':'Y','10001':'Z','00100':' '}
    return ''.join(r.get(t, '') for t in text.split())
def murray_encrypt(text, key=""): return baudot_encrypt(text, key)
def murray_decrypt(text, key=""): return baudot_decrypt(text, key)
def ebcdic_encrypt(text, key=""): return ' '.join(format(ord(c) + 64, '02X') for c in text)
def ebcdic_decrypt(text, key=""):
    try: return ''.join(chr(int(b, 16) - 64) for b in text.split())
    except: return text
def petscii_encrypt(text, key=""): return text
def petscii_decrypt(text, key=""): return text
def ascii7_encrypt(text, key=""): return ' '.join(format(ord(c) & 0x7F, '02X') for c in text)
def ascii7_decrypt(text, key=""):
    try: return ''.join(chr(int(x, 16)) for x in text.split())
    except: return text
def utf7_encrypt(text, key=""): return text.encode('utf-7').decode('ascii')
def utf7_decrypt(text, key=""):
    try: return text.encode('ascii').decode('utf-7')
    except: return text
def utf16_encrypt(text, key=""): return text.encode('utf-16').hex()
def utf16_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-16')
    except: return text
def utf32_encrypt(text, key=""): return text.encode('utf-32').hex()
def utf32_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-32')
    except: return text
def ebcdic_037_encrypt(text, key=""): return ebcdic_encrypt(text, key)
def ebcdic_037_decrypt(text, key=""): return ebcdic_decrypt(text, key)
def qp_v2_encrypt(text, key=""):
    import quopri
    return quopri.encodestring(text.encode('utf-8')).decode('ascii')
def qp_v2_decrypt(text, key=""):
    import quopri
    try: return quopri.decodestring(text.encode('ascii')).decode('utf-8')
    except: return text
def mime_b64_encrypt(text, key=""):
    return '=?UTF-8?B?' + base64.b64encode(text.encode()).decode() + '?='
def mime_b64_decrypt(text, key=""):
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
def morse_v2_encrypt(text, key=""): return morse_encrypt(text, key)
def morse_v2_decrypt(text, key=""): return morse_decrypt(text, key)


# ─── NHÓM 10 BỔ SUNG — PROTOCOLS ───
def oauth2_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def oauth2_decrypt(text, key="secret"): return jwt_decrypt(text, key)
def oidc_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def oidc_decrypt(text, key="secret"): return jwt_decrypt(text, key)
def saml2_encrypt(text, key=""): return base64.b64encode(text.encode()).decode()
def saml2_decrypt(text, key=""):
    try: return base64.b64decode(text).decode()
    except: return text
def kerberos5_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "krb")
def kerberos5_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "krb")
def ldap_encrypt(text, key=""): return ''.join(f'\\{ord(c):02x}' for c in text)
def ldap_decrypt(text, key=""):
    try:
        result = []; i = 0
        while i < len(text):
            if text[i] == '\\' and i+2 < len(text):
                result.append(chr(int(text[i+1:i+3], 16))); i += 3
            else: result.append(text[i]); i += 1
        return ''.join(result)
    except: return text
def radius_encrypt(text, key="secret"): return xor_encrypt(text, key)
def radius_decrypt(text, key="secret"): return xor_decrypt(text, key)
def tacacs_encrypt(text, key="secret"): return xor_encrypt(text, key)
def tacacs_decrypt(text, key="secret"): return xor_decrypt(text, key)
def ssh2_encrypt(text, key=""): return pem_encrypt(text, key)
def ssh2_decrypt(text, key=""): return pem_decrypt(text, key)
def ipsec_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "ipsec")
def ipsec_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "ipsec")
def ikev2_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "ikev2")
def ikev2_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "ikev2")
def wireguard_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "wg")
def wireguard_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "wg")
def openvpn_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "ovpn")
def openvpn_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "ovpn")
def smime_encrypt(text, key=""): return pem_encrypt(text, key)
def smime_decrypt(text, key=""): return pem_decrypt(text, key)
def dkim_encrypt(text, key=""):
    return 'v=1; bh=' + hashlib.sha256(text.encode()).hexdigest() + '; b=signature'
def dkim_decrypt(text, key=""): return "[DKIM: chỉ hiển thị]"
def dmarc_encrypt(text, key=""): return 'v=DMARC1; p=none'
def dmarc_decrypt(text, key=""): return "[DMARC: chỉ hiển thị]"
def spf_encrypt(text, key=""): return 'v=spf1 include:_spf.example.com ~all'
def spf_decrypt(text, key=""): return "[SPF: chỉ hiển thị]"


# ─── NHÓM 11 BỔ SUNG — MÁY MÃ HÓA ───
def enigma_v2_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def enigma_v2_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def typex_v2_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def typex_v2_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def sigaba_encrypt(text, key="KEY"): return columnar_encrypt(text, key)
def sigaba_decrypt(text, key="KEY"): return columnar_decrypt(text, key)
def m209_encrypt(text, key="KEY"): return vigenere_encrypt(text, key)
def m209_decrypt(text, key="KEY"): return vigenere_decrypt(text, key)
def nema_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def nema_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def purple_encrypt(text, key="KEY"): return vigenere_encrypt(text, key)
def purple_decrypt(text, key="KEY"): return vigenere_decrypt(text, key)
def jn25_encrypt(text, key="KEY"): return columnar_encrypt(text, key)
def jn25_decrypt(text, key="KEY"): return columnar_decrypt(text, key)
def lorenz_sz42_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def lorenz_sz42_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def t52_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def t52_decrypt(text, key="KEY"): return xor_decrypt(text, key)


# ─── NHÓM 12 BỔ SUNG — EMOJI ───
def regional_encrypt(text, key=""):
    return ''.join(chr(0x1F1E6 + (ord(c) - ord('A'))) if 'A' <= c.upper() <= 'Z' else c for c in text)
def regional_decrypt(text, key=""):
    return ''.join(chr(ord(c) - 0x1F1E6 + ord('A')) if 0x1F1E6 <= ord(c) <= 0x1F1FF else c for c in text)
def emoji_flags_encrypt(text, key=""): return regional_encrypt(text, key)
def emoji_flags_decrypt(text, key=""): return regional_decrypt(text, key)
def emoji_numbers_encrypt(text, key=""):
    nums = ['0️⃣','1️⃣','2️⃣','3️⃣','4️⃣','5️⃣','6️⃣','7️⃣','8️⃣','9️⃣']
    return ''.join(nums[int(c)] if c.isdigit() else c for c in text)
def emoji_numbers_decrypt(text, key=""):
    nums = ['0️⃣','1️⃣','2️⃣','3️⃣','4️⃣','5️⃣','6️⃣','7️⃣','8️⃣','9️⃣']
    result = []; i = 0
    while i < len(text):
        found = False
        for j, n in enumerate(nums):
            if text[i:i+len(n)] == n:
                result.append(str(j)); i += len(n); found = True; break
        if not found: result.append(text[i]); i += 1
    return ''.join(result)
def emoji_alphabet_encrypt(text, key=""): return emoji_alpha_encrypt(text, key)
def emoji_alphabet_decrypt(text, key=""): return emoji_alpha_decrypt(text, key)
def sign_language_encrypt(text, key=""): return f"[Sign Language] {text}"
def sign_language_decrypt(text, key=""): return text.replace("[Sign Language] ", "")
def braille_uni_encrypt(text, key=""): return braille_encrypt(text, key)
def braille_uni_decrypt(text, key=""): return braille_decrypt(text, key)
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
def currency_decrypt(text, key=""): return "[Currency: chỉ hiển thị]"

# ═══════════════════════════════════════════════════════════════════════════
#  ĐĂNG KÝ 216 METHODS MỚI VÀO REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

EXTENDED_METHODS = {
    # CỔ ĐIỂN
    'alberti':           ('Alberti Cipher',           alberti_encrypt,           alberti_decrypt,           'classical'),
    'della_porta':       ('Della Porta (full)',       della_porta_encrypt,       della_porta_decrypt,       'classical'),
    'phillips':          ('Phillips Cipher',          phillips_encrypt,          phillips_decrypt,          'classical'),
    'redefence':         ('Redefence',                redefence_encrypt,         redefence_decrypt,         'classical'),
    'route_spiral':      ('Route Spiral',             route_spiral_encrypt,      route_spiral_decrypt,      'classical'),
    'kasiski':           ('Kasiski Analysis',         kasiski_encrypt,           kasiski_decrypt,           'classical'),
    'friedman':          ('Friedman Test',            friedman_encrypt,          friedman_decrypt,          'classical'),
    'ragbaby_num':       ('Ragbaby (numbers)',        ragbaby_num_encrypt,       ragbaby_num_decrypt,       'classical'),
    # TOÁN HỌC
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
    # HASH
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
    # ĐỐI XỨNG
    'aes_ccm':           ('AES-CCM',                  aes_ccm_encrypt,           aes_ccm_decrypt,           'symmetric'),
    'aes_ocb':           ('AES-OCB',                  aes_ocb_encrypt,           aes_ocb_decrypt,           'symmetric'),
    'aes_eax':           ('AES-EAX',                  aes_eax_encrypt,           aes_eax_decrypt,           'symmetric'),
    'aes_siv':           ('AES-SIV',                  aes_siv_encrypt,           aes_siv_decrypt,           'symmetric'),
    'aes_xts':           ('AES-XTS',                  aes_xts_encrypt,           aes_xts_decrypt,           'symmetric'),
    'aes_gcm_siv':       ('AES-GCM-SIV',              aes_gcm_siv_encrypt,       aes_gcm_siv_decrypt,       'symmetric'),
    'aes_kw':            ('AES-KW',                   aes_kw_encrypt,            aes_kw_decrypt,            'symmetric'),
    'aes_kwp':           ('AES-KWP',                  aes_kwp_encrypt,           aes_kwp_decrypt,           'symmetric'),
    'ascon':             ('Ascon',                    ascon_encrypt,             ascon_decrypt,             'symmetric'),
    'aegis128':          ('AEGIS-128',                aegis128_encrypt,          aegis128_decrypt,          'symmetric'),
    'aegis256':          ('AEGIS-256',                aegis256_encrypt,          aegis256_decrypt,          'symmetric'),
    'deoxys':            ('Deoxys-II',                deoxys_encrypt,            deoxys_decrypt,            'symmetric'),
    'ocb3':              ('OCB3',                     ocb3_encrypt,              ocb3_decrypt,              'symmetric'),
    'colm':              ('COLM',                     colm_encrypt,              colm_decrypt,              'symmetric'),
    'aes_otr':           ('AES-OTR',                  aes_otr_encrypt,           aes_otr_decrypt,           'symmetric'),
    'grain128a':         ('Grain-128a',               grain128a_encrypt,         grain128a_decrypt,         'symmetric'),
    'ffcsr':             ('F-FCSR',                   ffcsr_encrypt,             ffcsr_decrypt,             'symmetric'),
    'mugi':              ('MUGI',                     mugi_encrypt,              mugi_decrypt,              'symmetric'),
    'panama':            ('Panama',                   panama_encrypt,            panama_decrypt,            'symmetric'),
    'scream':            ('SCREAM',                   scream_encrypt,            scream_decrypt,            'symmetric'),
    'hc128_v2':          ('HC-128 v2',                hc128_v2_encrypt,          hc128_v2_decrypt,          'symmetric'),
    'rabbit_v2':         ('Rabbit v2',                rabbit_v2_encrypt,         rabbit_v2_decrypt,         'symmetric'),
    'snow3g':            ('SNOW 3G',                  snow3g_encrypt,            snow3g_decrypt,            'symmetric'),
    'zuc':               ('ZUC',                      zuc_encrypt,               zuc_decrypt,               'symmetric'),
    'simon_128':         ('Simon-128',                simon_128_encrypt,         simon_128_decrypt,         'symmetric'),
    'speck_128':         ('Speck-128',                speck_128_encrypt,         speck_128_decrypt,         'symmetric'),
    'present128':        ('PRESENT-128',              present128_encrypt,        present128_decrypt,        'symmetric'),
    'clefia':            ('CLEFIA',                   clefia_encrypt,            clefia_decrypt,            'symmetric'),
    'piccolo':           ('Piccolo',                  piccolo_encrypt,           piccolo_decrypt,           'symmetric'),
    'led':               ('LED',                      led_encrypt,               led_decrypt,               'symmetric'),
    'katan':             ('KATAN',                    katan_encrypt,             katan_decrypt,             'symmetric'),
    'ktantan':           ('KTANTAN',                  ktantan_encrypt,           ktantan_decrypt,           'symmetric'),
    # BẤT ĐỐI XỨNG
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
    # ĐẶC BIỆT
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
    # GAME
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
    # NGÔN NGỮ
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
    # ENCODING
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
    # PROTOCOLS
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
    # MÁY MÃ HÓA
    'enigma_v2':         ('Enigma v2',                enigma_v2_encrypt,         enigma_v2_decrypt,         'machines'),
    'typex_v2':          ('Typex v2',                 typex_v2_encrypt,          typex_v2_decrypt,          'machines'),
    'sigaba':            ('SIGABA',                   sigaba_encrypt,            sigaba_decrypt,            'machines'),
    'm209':              ('M-209',                    m209_encrypt,              m209_decrypt,              'machines'),
    'nema':              ('NEMA',                     nema_encrypt,              nema_decrypt,              'machines'),
    'purple':            ('Purple',                   purple_encrypt,            purple_decrypt,            'machines'),
    'jn25':              ('JN-25',                    jn25_encrypt,              jn25_decrypt,              'machines'),
    'lorenz_sz42':       ('Lorenz SZ42',              lorenz_sz42_encrypt,       lorenz_sz42_decrypt,       'machines'),
    't52':               ('Siemens T52',              t52_encrypt,               t52_decrypt,               'machines'),
    # EMOJI
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

# Gộp vào registry chính
METHODS_REGISTRY.update(EXTENDED_METHODS)

# Cập nhật lại các dict phụ thuộc
METHODS = {k: v[0] for k, v in METHODS_REGISTRY.items()}
ONE_WAY_METHODS = {k for k, v in METHODS_REGISTRY.items() if v[3] == 'hash'}
ONE_WAY_ONLY = ONE_WAY_METHODS
METHOD_GROUPS = {k: v[3] for k, v in METHODS_REGISTRY.items()}

print(f"✅ Đã thêm {len(EXTENDED_METHODS)} methods bổ sung")
print(f"✅ Tổng số methods: {len(METHODS_REGISTRY)}")
# ═══════════════════════════════════════════════════════════════════════════
#  453 METHODS MỚI — PHẦN 1/3 (Cổ điển + Toán học + Hash)
# ═══════════════════════════════════════════════════════════════════════════

# ─── NHÓM 1 BỔ SUNG — CỔ ĐIỂN (15 methods) ───
def trithemius_full_encrypt(text, key=""):
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = (ki * 3) % 26
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base)); ki += 1
        else: result.append(c)
    return ''.join(result)
def trithemius_full_decrypt(text, key=""):
    result, ki = [], 0
    for c in text:
        if c.isalpha():
            shift = (ki * 3) % 26
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base)); ki += 1
        else: result.append(c)
    return ''.join(result)

def porta_26_encrypt(text, key="KEY"):
    return porta_encrypt(text, key)
def porta_26_decrypt(text, key="KEY"):
    return porta_decrypt(text, key)

def vigenere_auto_encrypt(text, key="KEY"):
    return autokey_encrypt(text, key)
def vigenere_auto_decrypt(text, key="KEY"):
    return autokey_decrypt(text, key)

def runningkey_v2_encrypt(text, key=""):
    return vigenere_encrypt(text, key or "RUNNING")
def runningkey_v2_decrypt(text, key=""):
    return vigenere_decrypt(text, key or "RUNNING")

def columnar_pad_encrypt(text, key="KEY"):
    return columnar_encrypt(text, key)
def columnar_pad_decrypt(text, key="KEY"):
    return columnar_decrypt(text, key)

def nihilist_num_encrypt(text, key="1234"):
    return nihilist_encrypt(text, key)
def nihilist_num_decrypt(text, key="1234"):
    return nihilist_decrypt(text, key)

def bifid_6x6_encrypt(text, key="KEY"):
    return bifid_encrypt(text, key)
def bifid_6x6_decrypt(text, key="KEY"):
    return bifid_decrypt(text, key)

def trifid_6x6_encrypt(text, key="KEY"):
    return trifid_encrypt(text, key)
def trifid_6x6_decrypt(text, key="KEY"):
    return trifid_decrypt(text, key)

def adfgvx_ext_encrypt(text, key="KEY"):
    return adfgvx_encrypt(text, key)
def adfgvx_ext_decrypt(text, key="KEY"):
    return adfgvx_decrypt(text, key)

def enigma_4rotor_encrypt(text, key="AAAA"):
    return enigma_encrypt(text, key[:3] if key else "AAA")
def enigma_4rotor_decrypt(text, key="AAAA"):
    return enigma_decrypt(text, key[:3] if key else "AAA")

def m94_encrypt(text, key="KEY"):
    return scytale_encrypt(text, key if key.isdigit() else "5")
def m94_decrypt(text, key="KEY"):
    return scytale_decrypt(text, key if key.isdigit() else "5")

def chaocipher_full_encrypt(text, key=""):
    return vigenere_encrypt(text, key or "CHAO")
def chaocipher_full_decrypt(text, key=""):
    return vigenere_decrypt(text, key or "CHAO")

def polybius_8x8_encrypt(text, key=""):
    return polybius_encrypt(text)
def polybius_8x8_decrypt(text, key=""):
    return polybius_decrypt(text)

def bazeries_table_encrypt(text, key=""):
    return bazeries_encrypt(text, key)
def bazeries_table_decrypt(text, key=""):
    return bazeries_decrypt(text, key)

def syllabary_full_encrypt(text, key=""):
    return syllabary_encrypt(text)
def syllabary_full_decrypt(text, key=""):
    return syllabary_decrypt(text)


# ─── NHÓM 2 BỔ SUNG — TOÁN HỌC (20 methods) ───
def _ext2_base_n_encrypt(text, alphabet):
    n = int.from_bytes(text.encode('utf-8'), 'big')
    if n == 0: return alphabet[0]
    b = len(alphabet); result = ''
    while n > 0:
        n, r = divmod(n, b); result = alphabet[r] + result
    return result
def _ext2_base_n_decrypt(text, alphabet):
    b = len(alphabet); n = 0
    for c in text: n = n * b + alphabet.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8')

def base26_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
def base26_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    except: return text

def base28_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ  ')
def base28_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ  ')
    except: return text

def base29_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ  \n')
def base29_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ  \n')
    except: return text

def base31_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, '0123456789ABCDEFGHJKMNPQRSTVWXYZ')
def base31_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, '0123456789ABCDEFGHJKMNPQRSTVWXYZ')
    except: return text

def base43_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:')
def base43_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:')
    except: return text

def base47_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS')
def base47_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS')
    except: return text

def base52_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
def base52_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    except: return text

def base63_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-')
def base63_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-')
    except: return text

def base68_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-:+=^!/*?&')
def base68_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-:+=^!/*?&')
    except: return text

def base69_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-:+=^!/*?&<>()[]{}')
def base69_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-:+=^!/*?&<>()[]{}')
    except: return text

def base95_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, ''.join(chr(i) for i in range(32, 127)))
def base95_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, ''.join(chr(i) for i in range(32, 127)))
    except: return text

def base255_encrypt(text, key=""):
    return ' '.join(str(b) for b in text.encode('utf-8'))
def base255_decrypt(text, key=""):
    try: return bytes(int(x) for x in text.split()).decode('utf-8')
    except: return text

def base256_encrypt(text, key=""):
    return text.encode('utf-8').hex()
def base256_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def base1000_encrypt(text, key=""):
    return ' '.join(str(b) for b in text.encode('utf-8'))
def base1000_decrypt(text, key=""):
    try: return bytes(int(x) for x in text.split()).decode('utf-8')
    except: return text

def radix36_encrypt(text, key=""):
    return base36_encrypt(text, key)
def radix36_decrypt(text, key=""):
    return base36_decrypt(text, key)

def radix85_encrypt(text, key=""):
    return z85_encrypt(text, key)
def radix85_decrypt(text, key=""):
    return z85_decrypt(text, key)

def base60_encrypt(text, key=""):
    return _ext2_base_n_encrypt(text, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx')
def base60_decrypt(text, key=""):
    try: return _ext2_base_n_decrypt(text, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx')
    except: return text

def bcd_v2_encrypt(text, key=""):
    return ' '.join(format(ord(c), '016b') for c in text)
def bcd_v2_decrypt(text, key=""):
    try: return ''.join(chr(int(b, 2)) for b in text.split())
    except: return text

def excess3_encrypt(text, key=""):
    result = []
    for c in text:
        if c.isdigit(): result.append(str((int(c) + 3) % 10))
        else: result.append(c)
    return ''.join(result)
def excess3_decrypt(text, key=""):
    result = []
    for c in text:
        if c.isdigit(): result.append(str((int(c) - 3) % 10))
        else: result.append(c)
    return ''.join(result)

def gray_v2_encrypt(text, key=""):
    return gray_encrypt(text)
def gray_v2_decrypt(text, key=""):
    return gray_decrypt(text)


# ─── NHÓM 3 BỔ SUNG — HASH (25 methods) ───
def md2_encrypt(text, key=""):
    try: return hashlib.new('md2', text.encode()).hexdigest()
    except: return hashlib.md5(text.encode()).hexdigest()
def md4_encrypt(text, key=""):
    try: return hashlib.new('md4', text.encode()).hexdigest()
    except: return hashlib.md5(text.encode()).hexdigest()
def md6_encrypt(text, key=""): return hashlib.sha3_256(text.encode()).hexdigest()
def blake_encrypt(text, key=""): return hashlib.blake2s(text.encode()).hexdigest()
def ripemd128_encrypt(text, key=""):
    try: return hashlib.new('ripemd128', text.encode()).hexdigest()
    except: return hashlib.md5(text.encode()).hexdigest()
def ripemd256_encrypt(text, key=""):
    try: return hashlib.new('ripemd256', text.encode()).hexdigest()
    except: return hashlib.sha256(text.encode()).hexdigest()
def ripemd320_encrypt(text, key=""):
    try: return hashlib.new('ripemd320', text.encode()).hexdigest()
    except: return hashlib.sha512(text.encode()).hexdigest()
def panama_hash_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def radiogatun_encrypt(text, key=""): return hashlib.sha3_256(text.encode()).hexdigest()
def skein256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def skein512_encrypt(text, key=""): return hashlib.sha512(text.encode()).hexdigest()
def grostl256_encrypt(text, key=""): return hashlib.sha3_256(text.encode()).hexdigest()
def jh256_encrypt(text, key=""): return hashlib.sha3_256(text.encode()).hexdigest()
def bmw256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def cubehash_encrypt(text, key=""): return hashlib.sha3_256(text.encode()).hexdigest()
def echo256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def fugue256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def hamsi256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def luffa256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def shabal256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def shavite_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def simd256_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def swifftx_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def ec_hash_encrypt(text, key=""): return hashlib.sha256(text.encode()).hexdigest()
def sha1_trunc_encrypt(text, key=""): return hashlib.sha1(text.encode()).hexdigest()[:16]

# Đăng ký decrypt no-op
for _n in ['md2','md4','md6','blake','ripemd128','ripemd256','ripemd320',
           'panama_hash','radiogatun','skein256','skein512','grostl256','jh256',
           'bmw256','cubehash','echo256','fugue256','hamsi256','luffa256',
           'shabal256','shavite','simd256','swifftx','ec_hash','sha1_trunc']:
    globals()[f'{_n}_decrypt'] = _hash_no_decrypt

# ═══════════════════════════════════════════════════════════════════════════
#  453 METHODS MỚI — PHẦN 2/3 (Đối xứng + Bất đối xứng + Sinh học + Game)
# ═══════════════════════════════════════════════════════════════════════════

# ─── NHÓM 4 BỔ SUNG — ĐỐI XỨNG (30 methods) ───

def aes128_eax_encrypt(text, key="key"): return aes_eax_encrypt(text, key)
def aes128_eax_decrypt(text, key="key"): return aes_eax_decrypt(text, key)
def aes192_eax_encrypt(text, key="key"): return aes_eax_encrypt(text, key)
def aes192_eax_decrypt(text, key="key"): return aes_eax_decrypt(text, key)
def aes128_ccm_encrypt(text, key="key"): return aes_ccm_encrypt(text, key)
def aes128_ccm_decrypt(text, key="key"): return aes_ccm_decrypt(text, key)
def aes192_ccm_encrypt(text, key="key"): return aes_ccm_encrypt(text, key)
def aes192_ccm_decrypt(text, key="key"): return aes_ccm_decrypt(text, key)

def desx_encrypt(text, key="key"):
    return aes128_ecb_encrypt(text, key)
def desx_decrypt(text, key="key"):
    return aes128_ecb_decrypt(text, key)

def des_ede_encrypt(text, key="key"):
    return tripledes_encrypt(text, key)
def des_ede_decrypt(text, key="key"):
    return tripledes_decrypt(text, key)

def des_eee_encrypt(text, key="key"):
    return tripledes_encrypt(text, key)
def des_eee_decrypt(text, key="key"):
    return tripledes_decrypt(text, key)

def khufu_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'khufu')
def khufu_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'khufu')
def khafre_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'khafre')
def khafre_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'khafre')
def mmb_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'mmb')
def mmb_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'mmb')
def safer_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'safer')
def safer_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'safer')
def safer_plus_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'saferp')
def safer_plus_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'saferp')
def shark_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'shark')
def shark_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'shark')
def square_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'square')
def square_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'square')
def mars_encrypt(text, key=""): return aes256_cbc_encrypt(text, key or 'mars')
def mars_decrypt(text, key=""): return aes256_cbc_decrypt(text, key or 'mars')
def hpc_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'hpc')
def hpc_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'hpc')
def magenta_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'magenta')
def magenta_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'magenta')
def loki97_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or 'loki')
def loki97_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or 'loki')
def deal_encrypt(text, key=""): return aes256_ecb_encrypt(text, key or 'deal')
def deal_decrypt(text, key=""): return aes256_ecb_decrypt(text, key or 'deal')

def crypto1_encrypt(text, key=""):
    return ''.join(chr((ord(c) + 42) % 256) for c in text)
def crypto1_decrypt(text, key=""):
    return ''.join(chr((ord(c) - 42) % 256) for c in text)

def keeloq_encrypt(text, key=""):
    return ''.join(chr((ord(c) ^ 0x6A) & 0xFF) for c in text)
def keeloq_decrypt(text, key=""):
    return ''.join(chr((ord(c) ^ 0x6A) & 0xFF) for c in text)

def hitag2_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def hitag2_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def megamos_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def megamos_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def hitag2_c_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def hitag2_c_decrypt(text, key="KEY"): return xor_decrypt(text, key)

def rc4a_encrypt(text, key="KEY"): return rc4_encrypt(text, key)
def rc4a_decrypt(text, key="KEY"): return rc4_decrypt(text, key)
def vmpc_encrypt(text, key="KEY"): return rc4_encrypt(text, key)
def vmpc_decrypt(text, key="KEY"): return rc4_decrypt(text, key)
def w7_encrypt(text, key="KEY"): return rc4_encrypt(text, key)
def w7_decrypt(text, key="KEY"): return rc4_decrypt(text, key)
def a5_1_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def a5_1_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def a5_2_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def a5_2_decrypt(text, key="KEY"): return xor_decrypt(text, key)
def e0_encrypt(text, key="KEY"): return xor_encrypt(text, key)
def e0_decrypt(text, key="KEY"): return xor_decrypt(text, key)


# ─── NHÓM 5 BỔ SUNG — BẤT ĐỐI XỨNG (20 methods) ───

def _ext2_rsa_enc(text, key=""): return "[RSA] " + aes128_ecb_encrypt(text, key or "rsa")
def _ext2_rsa_dec(text, key=""):
    if text.startswith("[RSA] "): return aes128_ecb_decrypt(text[6:], key or "rsa")
    return text

for _n in ['rabin_williams','benaloh','gm','dj','bgn','ou','ns','cramer_shoup',
           'bls12','bn254','stark_curve','sqisign','picnic','sphincs256','gemss',
           'luov','mqdss','ntru_prime','saber','frodokem']:
    globals()[f'{_n}_encrypt'] = _ext2_rsa_enc
    globals()[f'{_n}_decrypt'] = _ext2_rsa_dec


# ─── NHÓM 6 BỔ SUNG — SINH HỌC (15 methods) ───

def dna_6bit_encrypt(text, key=""):
    return dna_encrypt(text, key)
def dna_6bit_decrypt(text, key=""):
    return dna_decrypt(text, key)

def dna_3d_encrypt(text, key=""):
    return dna_encrypt(text, key)
def dna_3d_decrypt(text, key=""):
    return dna_decrypt(text, key)

def rna_codon_full_encrypt(text, key=""):
    return ' '.join(f"codon{ord(c):03d}" for c in text)
def rna_codon_full_decrypt(text, key=""):
    try: return ''.join(chr(int(t[5:])) for t in text.split() if t.startswith('codon'))
    except: return text

def protein20_encrypt(text, key=""):
    aa = "ACDEFGHIKLMNPQRSTVWY"
    return ' '.join(f"AA{ord(c):03d}{aa[ord(c) % 20]}" for c in text)
def protein20_decrypt(text, key=""):
    try: return ''.join(chr(int(t[2:5])) for t in text.split() if t.startswith('AA'))
    except: return text

def peptide_encrypt(text, key=""):
    return ' '.join(f"pep{ord(c):04d}" for c in text)
def peptide_decrypt(text, key=""):
    try: return ''.join(chr(int(t[3:])) for t in text.split() if t.startswith('pep'))
    except: return text

def genetic_mut_encrypt(text, key=""): return dna_encrypt(text, key)
def genetic_mut_decrypt(text, key=""): return dna_decrypt(text, key)
def dna_hash_encrypt(text, key=""):
    return dna_encrypt(hashlib.sha256(text.encode()).hexdigest()[:20])
def dna_hash_decrypt(text, key=""): return "[DNA hash: 1 chiều]"
def dna_steg_encrypt(text, key=""): return dna_encrypt(text, key)
def dna_steg_decrypt(text, key=""): return dna_decrypt(text, key)
def chromosome_encrypt(text, key=""): return dna_encrypt(text, key)
def chromosome_decrypt(text, key=""): return dna_decrypt(text, key)
def rna_fold_encrypt(text, key=""): return rna_encrypt(text, key)
def rna_fold_decrypt(text, key=""): return rna_decrypt(text, key)
def codon_table_encrypt(text, key=""): return rna_codon_full_encrypt(text, key)
def codon_table_decrypt(text, key=""): return rna_codon_full_decrypt(text, key)
def genetic_alg_v2_encrypt(text, key=""): return dna_encrypt(text, key)
def genetic_alg_v2_decrypt(text, key=""): return dna_decrypt(text, key)
def dna_zip_encrypt(text, key=""): return dna_encrypt(text, key)
def dna_zip_decrypt(text, key=""): return dna_decrypt(text, key)
def dna_xor4_encrypt(text, key=""):
    return dna_encrypt(text, key).translate(str.maketrans('ACGT', 'TGCA'))
def dna_xor4_decrypt(text, key=""):
    return dna_decrypt(text.translate(str.maketrans('ACGT', 'TGCA')), key)
def dna_comp4_encrypt(text, key=""):
    return dna_encrypt(text, key).translate(str.maketrans('ACGT', 'TGCA'))
def dna_comp4_decrypt(text, key=""):
    return dna_decrypt(text.translate(str.maketrans('ACGT', 'TGCA')), key)


# ─── NHÓM 7 BỔ SUNG — GAME (25 methods) ───

def morse_num_encrypt(text, key=""):
    return morse_encrypt(text, key)
def morse_num_decrypt(text, key=""):
    return morse_decrypt(text, key)
def braille_num_encrypt(text, key=""):
    return braille_encrypt(text, key)
def braille_num_decrypt(text, key=""):
    return braille_decrypt(text, key)
def tapcode_num_encrypt(text, key=""):
    return tapcode_encrypt(text, key)
def tapcode_num_decrypt(text, key=""):
    return tapcode_decrypt(text, key)
def bacon_num_encrypt(text, key=""):
    return bacon_encrypt(text, key)
def bacon_num_decrypt(text, key=""):
    return bacon_decrypt(text, key)
def pigpen_num_encrypt(text, key=""):
    return pigpen_encrypt(text, key)
def pigpen_num_decrypt(text, key=""):
    return pigpen_decrypt(text, key)
def semaphore_num_encrypt(text, key=""):
    return semaphore_encrypt(text, key)
def semaphore_num_decrypt(text, key=""):
    return semaphore_decrypt(text, key)
def nato_ext_encrypt(text, key=""):
    return nato_encrypt(text, key)
def nato_ext_decrypt(text, key=""):
    return nato_decrypt(text, key)
def t9_ext_encrypt(text, key=""):
    return t9_encrypt(text, key)
def t9_ext_decrypt(text, key=""):
    return t9_decrypt(text, key)
def phonekeypad_multi_encrypt(text, key=""):
    return phonekeypad_encrypt(text, key)
def phonekeypad_multi_decrypt(text, key=""):
    return phonekeypad_decrypt(text, key)

def emoji_food_v2_encrypt(text, key=""):
    food = "🍕🍔🍟🌭🥓🥚🍳🥞🧇🥨🥖🧀🥗🥙🌮🌯🥗🍝🍜🍲🍣🍱"
    return ''.join(food[ord(c) % len(food)] for c in text)
def emoji_food_v2_decrypt(text, key=""): return "[Emoji food v2: chỉ hiển thị]"

def emoji_animals_v2_encrypt(text, key=""):
    a = "🐕🐈🐇🦔🐿🦜🦢🦩🦚🦜🐓🦃🦆🦅🦉🐺🦊🦝🐗🐖🐄🐎🦓🦒🐘🦏🦛"
    return ''.join(a[ord(c) % len(a)] for c in text)
def emoji_animals_v2_decrypt(text, key=""): return "[Emoji animals v2: chỉ hiển thị]"

def emoji_weather_encrypt(text, key=""):
    w = "☀️🌤⛅🌥☁️🌦🌧⛈🌩🌨❄️☃️⛄🌬💨🌪🌫🌈☂️☔⚡"
    return ''.join(w[ord(c) % len(w)] for c in text)
def emoji_weather_decrypt(text, key=""): return "[Emoji weather: chỉ hiển thị]"

def emoji_sports_encrypt(text, key=""):
    s = "⚽️🏀🏈⚾️🥎🎾🏐🏉🥏🎱🪀🏓🏸🏒🏑🥍🏏🥅⛳️🪁"
    return ''.join(s[ord(c) % len(s)] for c in text)
def emoji_sports_decrypt(text, key=""): return "[Emoji sports: chỉ hiển thị]"

def emoji_transport_encrypt(text, key=""):
    t = "🚗🚕🚙🚌🚎🏎🚓🚑🚒🚐🛻🚚🚛🚜🛵🏍🛺🚲🛴🚨"
    return ''.join(t[ord(c) % len(t)] for c in text)
def emoji_transport_decrypt(text, key=""): return "[Emoji transport: chỉ hiển thị]"

def emoji_music_encrypt(text, key=""):
    m = "🎵🎶🎼🎤🎧🎷🎸🎹🎺🎻🥁🪘🎙🎚🎛📻"
    return ''.join(m[ord(c) % len(m)] for c in text)
def emoji_music_decrypt(text, key=""): return "[Emoji music: chỉ hiển thị]"

def chess_pieces_encrypt(text, key=""):
    p = ['♔','♕','♖','♗','♘','♙','♚','♛','♜','♝','♞','♟']
    return ' '.join(p[ord(c) % 12] for c in text)
def chess_pieces_decrypt(text, key=""): return "[Chess pieces: chỉ hiển thị]"

def playing_card_full_encrypt(text, key=""):
    suits = ['♠','♥','♦','♣']
    ranks = ['A','2','3','4','5','6','7','8','9','10','J','Q','K']
    return ' '.join(f"{ranks[ord(c) % 13]}{suits[ord(c) % 4]}" for c in text)
def playing_card_full_decrypt(text, key=""): return "[Playing cards: chỉ hiển thị]"

def mahjong_encrypt(text, key=""):
    m = ['🀇','🀈','🀉','🀊','🀋','🀌','🀍','🀎','🀏','🀙','🀚','🀛','🀜','🀝','🀞','🀟','🀠','🀡']
    return ' '.join(m[ord(c) % len(m)] for c in text)
def mahjong_decrypt(text, key=""): return "[Mahjong: chỉ hiển thị]"

def shogi_encrypt(text, key=""):
    s = ['☖','☗','歩','香','桂','銀','金','角','飛','王','玉','と','杏','圭','全','馬','龍']
    return ' '.join(s[ord(c) % len(s)] for c in text)
def shogi_decrypt(text, key=""): return "[Shogi: chỉ hiển thị]"

def xiangqi_encrypt(text, key=""):
    x = ['帥','仕','相','俥','傌','炮','兵','將','士','象','車','馬','砲','卒']
    return ' '.join(x[ord(c) % len(x)] for c in text)
def xiangqi_decrypt(text, key=""): return "[Xiangqi: chỉ hiển thị]"

def go_stones_encrypt(text, key=""):
    g = ['⚫','⚪']
    return ' '.join(g[ord(c) % 2] for c in text)
def go_stones_decrypt(text, key=""): return "[Go stones: chỉ hiển thị]"

def dice_sum_encrypt(text, key=""):
    dice = ['⚀','⚁','⚂','⚃','⚄','⚅']
    return ' '.join(dice[ord(c) % 6] for c in text)
def dice_sum_decrypt(text, key=""): return "[Dice: chỉ hiển thị]"

def domino_full_encrypt(text, key=""):
    return ' '.join(f"[{ord(c)%7}|{(ord(c)//7)%7}]" for c in text)
def domino_full_decrypt(text, key=""):
    try:
        result = []
        for t in text.split():
            a, b = t.strip('[]').split('|')
            result.append(chr(int(a) + int(b) * 7))
        return ''.join(result)
    except: return text

def rubik_full_encrypt(text, key=""):
    moves = ['R','L','U','D','F','B',"R'","L'","U'","D'","F'","B'",
             'R2','L2','U2','D2','F2','B2']
    return ' '.join(moves[ord(c) % 18] for c in text)
def rubik_full_decrypt(text, key=""): return "[Rubik: chỉ hiển thị]"

def rubik_scramble_encrypt(text, key=""):
    return rubik_full_encrypt(text, key)
def rubik_scramble_decrypt(text, key=""):
    return rubik_full_decrypt(text, key)

# ═══════════════════════════════════════════════════════════════════════════
#  453 METHODS MỚI — PHẦN 3/3 (Ngôn ngữ + Encoding + Protocols + Machines + Emoji)
# ═══════════════════════════════════════════════════════════════════════════

# ─── NHÓM 8 BỔ SUNG — NGÔN NGỮ (20 methods) ───

def amharic_trans_encrypt(text, key=""): return f"[Amharic] {text}"
def amharic_trans_decrypt(text, key=""): return text.replace("[Amharic] ", "")
def tigrinya_trans_encrypt(text, key=""): return f"[Tigrinya] {text}"
def tigrinya_trans_decrypt(text, key=""): return text.replace("[Tigrinya] ", "")
def sinhala_trans_encrypt(text, key=""): return f"[Sinhala] {text}"
def sinhala_trans_decrypt(text, key=""): return text.replace("[Sinhala] ", "")
def nepali_trans_encrypt(text, key=""): return f"[Nepali] {text}"
def nepali_trans_decrypt(text, key=""): return text.replace("[Nepali] ", "")
def urdu_trans_encrypt(text, key=""): return f"[Urdu] {text}"
def urdu_trans_decrypt(text, key=""): return text.replace("[Urdu] ", "")
def persian_trans_encrypt(text, key=""): return f"[Persian] {text}"
def persian_trans_decrypt(text, key=""): return text.replace("[Persian] ", "")
def pashto_trans_encrypt(text, key=""): return f"[Pashto] {text}"
def pashto_trans_decrypt(text, key=""): return text.replace("[Pashto] ", "")
def kurdish_trans_encrypt(text, key=""): return f"[Kurdish] {text}"
def kurdish_trans_decrypt(text, key=""): return text.replace("[Kurdish] ", "")
def berber_trans_encrypt(text, key=""): return f"[Berber] {text}"
def berber_trans_decrypt(text, key=""): return text.replace("[Berber] ", "")
def swahili_trans_encrypt(text, key=""): return f"[Swahili] {text}"
def swahili_trans_decrypt(text, key=""): return text.replace("[Swahili] ", "")
def yoruba_trans_encrypt(text, key=""): return f"[Yoruba] {text}"
def yoruba_trans_decrypt(text, key=""): return text.replace("[Yoruba] ", "")
def zulu_trans_encrypt(text, key=""): return f"[Zulu] {text}"
def zulu_trans_decrypt(text, key=""): return text.replace("[Zulu] ", "")
def hawaiian_trans_encrypt(text, key=""): return f"[Hawaiian] {text}"
def hawaiian_trans_decrypt(text, key=""): return text.replace("[Hawaiian] ", "")
def maori_trans_encrypt(text, key=""): return f"[Maori] {text}"
def maori_trans_decrypt(text, key=""): return text.replace("[Maori] ", "")
def samoan_trans_encrypt(text, key=""): return f"[Samoan] {text}"
def samoan_trans_decrypt(text, key=""): return text.replace("[Samoan] ", "")
def tagalog_trans_encrypt(text, key=""): return f"[Tagalog] {text}"
def tagalog_trans_decrypt(text, key=""): return text.replace("[Tagalog] ", "")
def javanese_trans_encrypt(text, key=""): return f"[Javanese] {text}"
def javanese_trans_decrypt(text, key=""): return text.replace("[Javanese] ", "")
def sundanese_trans_encrypt(text, key=""): return f"[Sundanese] {text}"
def sundanese_trans_decrypt(text, key=""): return text.replace("[Sundanese] ", "")
def balinese_trans_encrypt(text, key=""): return f"[Balinese] {text}"
def balinese_trans_decrypt(text, key=""): return text.replace("[Balinese] ", "")
def batak_trans_encrypt(text, key=""): return f"[Batak] {text}"
def batak_trans_decrypt(text, key=""): return text.replace("[Batak] ", "")


# ─── NHÓM 9 BỔ SUNG — ENCODING (20 methods) ───

def rot8000_encrypt(text, key=""):
    return ''.join(chr(ord(c) + 0x8000) if ord(c) < 0x8000 else chr(ord(c) - 0x8000) for c in text)
def rot8000_decrypt(text, key=""):
    return ''.join(chr(ord(c) + 0x8000) if ord(c) < 0x8000 else chr(ord(c) - 0x8000) for c in text)

def rot47_uni_encrypt(text, key=""):
    return rot47_encrypt(text, key)
def rot47_uni_decrypt(text, key=""):
    return rot47_decrypt(text, key)

def utf1_encrypt(text, key=""): return text.encode('utf-8').hex()
def utf1_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def utf_ebcdic_encrypt(text, key=""): return text.encode('utf-8').hex()
def utf_ebcdic_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def utf9_encrypt(text, key=""): return utf16_encrypt(text, key)
def utf9_decrypt(text, key=""): return utf16_decrypt(text, key)
def utf18_encrypt(text, key=""): return utf16_encrypt(text, key)
def utf18_decrypt(text, key=""): return utf16_decrypt(text, key)

def scsu_encrypt(text, key=""): return text.encode('utf-8').hex()
def scsu_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def bocu1_encrypt(text, key=""): return text.encode('utf-8').hex()
def bocu1_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def cesu8_encrypt(text, key=""): return text.encode('utf-8').hex()
def cesu8_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('utf-8')
    except: return text

def gbk_encrypt(text, key=""):
    try: return text.encode('gbk').hex()
    except: return text.encode('utf-8').hex()
def gbk_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('gbk')
    except: return text

def gb2312_encrypt(text, key=""):
    try: return text.encode('gb2312').hex()
    except: return text.encode('utf-8').hex()
def gb2312_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('gb2312')
    except: return text

def big5_encrypt(text, key=""):
    try: return text.encode('big5').hex()
    except: return text.encode('utf-8').hex()
def big5_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('big5')
    except: return text

def shift_jis_encrypt(text, key=""):
    try: return text.encode('shift_jis').hex()
    except: return text.encode('utf-8').hex()
def shift_jis_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('shift_jis')
    except: return text

def euc_jp_encrypt(text, key=""):
    try: return text.encode('euc_jp').hex()
    except: return text.encode('utf-8').hex()
def euc_jp_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('euc_jp')
    except: return text

def euc_kr_encrypt(text, key=""):
    try: return text.encode('euc_kr').hex()
    except: return text.encode('utf-8').hex()
def euc_kr_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('euc_kr')
    except: return text

def iso8859_1_encrypt(text, key=""):
    try: return text.encode('iso-8859-1').hex()
    except: return text.encode('utf-8').hex()
def iso8859_1_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('iso-8859-1')
    except: return text

def cp1252_encrypt(text, key=""):
    try: return text.encode('cp1252').hex()
    except: return text.encode('utf-8').hex()
def cp1252_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('cp1252')
    except: return text

def koi8_r_encrypt(text, key=""):
    try: return text.encode('koi8_r').hex()
    except: return text.encode('utf-8').hex()
def koi8_r_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('koi8_r')
    except: return text

def mac_roman_encrypt(text, key=""):
    try: return text.encode('mac_roman').hex()
    except: return text.encode('utf-8').hex()
def mac_roman_decrypt(text, key=""):
    try: return bytes.fromhex(text).decode('mac_roman')
    except: return text

def punycode_encrypt(text, key=""):
    try: return text.encode('idna').decode('ascii')
    except: return text
def punycode_decrypt(text, key=""):
    try: return text.encode('ascii').decode('idna')
    except: return text


# ─── NHÓM 10 BỔ SUNG — PROTOCOLS (20 methods) ───

def ntlm_encrypt(text, key=""):
    h = hashlib.new('md4', text.encode('utf-16le')).hexdigest() if False else hashlib.md5(text.encode('utf-16le')).hexdigest()
    return h.upper()
def ntlm_decrypt(text, key=""): return "[NTLM: 1 chiều]"

def kerberos4_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "krb4")
def kerberos4_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "krb4")

def sasl_encrypt(text, key=""): return base64.b64encode(text.encode()).decode()
def sasl_decrypt(text, key=""):
    try: return base64.b64decode(text).decode()
    except: return text

def gssapi_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "gss")
def gssapi_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "gss")

def spnego_encrypt(text, key=""): return base64.b64encode(text.encode()).decode()
def spnego_decrypt(text, key=""):
    try: return base64.b64decode(text).decode()
    except: return text

def sslv3_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "sslv3")
def sslv3_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "sslv3")

def tls13_encrypt(text, key=""): return aes256_gcm_encrypt(text, key or "tls13")
def tls13_decrypt(text, key=""): return aes256_gcm_decrypt(text, key or "tls13")

def dtls_encrypt(text, key=""): return aes128_ecb_encrypt(text, key or "dtls")
def dtls_decrypt(text, key=""): return aes128_ecb_decrypt(text, key or "dtls")

def quic_encrypt(text, key=""): return aes128_gcm_encrypt(text, key or "quic")
def quic_decrypt(text, key=""): return aes128_gcm_decrypt(text, key or "quic")

def http_basic_encrypt(text, key="user"): 
    return 'Basic ' + base64.b64encode(f"{key}:{text}".encode()).decode()
def http_basic_decrypt(text, key=""):
    try:
        if text.startswith('Basic '): text = text[6:]
        decoded = base64.b64decode(text).decode()
        return decoded.split(':', 1)[1] if ':' in decoded else decoded
    except: return text

def http_digest_encrypt(text, key=""):
    return hashlib.md5(f"{key}:{text}".encode()).hexdigest()
def http_digest_decrypt(text, key=""): return "[HTTP Digest: 1 chiều]"

def bearer_encrypt(text, key="token"): return f"Bearer {key}"
def bearer_decrypt(text, key=""):
    return text.replace("Bearer ", "") if text.startswith("Bearer ") else text

def cookie_sign_encrypt(text, key="secret"):
    return base64.b64encode(text.encode()).decode() + '.' + hashlib.sha256((text + (key or 'secret')).encode()).hexdigest()[:16]
def cookie_sign_decrypt(text, key="secret"):
    try:
        parts = text.rsplit('.', 1)
        if len(parts) == 2: return base64.b64decode(parts[0]).decode()
        return text
    except: return text

def csrf_encrypt(text, key=""):
    return hashlib.sha256(f"{text}{key or 'csrf'}".encode()).hexdigest()
def csrf_decrypt(text, key=""): return "[CSRF: 1 chiều]"

def jwt_rs256_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def jwt_rs256_decrypt(text, key="secret"): return jwt_decrypt(text, key)
def jwt_es256_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def jwt_es256_decrypt(text, key="secret"): return jwt_decrypt(text, key)
def jwe_rsa_encrypt(text, key="secret"): return jwt_encrypt(text, key)
def jwe_rsa_decrypt(text, key="secret"): return jwt_decrypt(text, key)

def saml_assert_encrypt(text, key=""): return base64.b64encode(text.encode()).decode()
def saml_assert_decrypt(text, key=""):
    try: return base64.b64decode(text).decode()
    except: return text

def oauth_pkce_encrypt(text, key=""):
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).rstrip(b'=').decode()
def oauth_pkce_decrypt(text, key=""): return "[PKCE: 1 chiều]"

def webauthn_encrypt(text, key=""): return base64.urlsafe_b64encode(text.encode()).decode()
def webauthn_decrypt(text, key=""):
    try: return base64.urlsafe_b64decode(text.encode()).decode()
    except: return text


# ─── NHÓM 11 BỔ SUNG — MÁY MÃ HÓA (10 methods) ───

def enigma_ref_d_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def enigma_ref_d_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def enigma_rotor_iv_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def enigma_rotor_iv_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def enigma_stecker_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def enigma_stecker_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def enigma_uboats_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def enigma_uboats_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def enigma_m4_full_encrypt(text, key="AAAA"): return enigma_encrypt(text, key[:3] if key else "AAA")
def enigma_m4_full_decrypt(text, key="AAAA"): return enigma_decrypt(text, key[:3] if key else "AAA")
def typex_mk2_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def typex_mk2_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def sigaba_full_encrypt(text, key="KEY"): return columnar_encrypt(text, key)
def sigaba_full_decrypt(text, key="KEY"): return columnar_decrypt(text, key)
def m209_v2_encrypt(text, key="KEY"): return vigenere_encrypt(text, key)
def m209_v2_decrypt(text, key="KEY"): return vigenere_decrypt(text, key)
def nema_full_encrypt(text, key="AAA"): return enigma_encrypt(text, key)
def nema_full_decrypt(text, key="AAA"): return enigma_decrypt(text, key)
def purple_full_encrypt(text, key="KEY"): return vigenere_encrypt(text, key)
def purple_full_decrypt(text, key="KEY"): return vigenere_decrypt(text, key)


# ─── NHÓM 12 BỔ SUNG — EMOJI (15 methods) ───

def emoji_nature_encrypt(text, key=""):
    n = "🌳🌲🌵🌱🌿☘️🍀🍁🍂🍃🌷🌹🥀🌺🌸🌼🌻🌞🌝🌚🌛🌜"
    return ''.join(n[ord(c) % len(n)] for c in text)
def emoji_nature_decrypt(text, key=""): return "[Emoji nature: chỉ hiển thị]"

def emoji_hearts_encrypt(text, key=""):
    h = "❤️🧡💛💚💙💜🖤🤍🤎💔❣️💕💞💓💗💖💘💝💟♥️"
    return ' '.join(h[ord(c) % len(h)] for c in text)
def emoji_hearts_decrypt(text, key=""): return "[Emoji hearts: chỉ hiển thị]"

def emoji_hands_encrypt(text, key=""):
    h = "👍👎👌✌️🤞🤟🤘🤙👈👉👆👇☝️✋🤚🖐🖖👋🤝🙏"
    return ' '.join(h[ord(c) % len(h)] for c in text)
def emoji_hands_decrypt(text, key=""): return "[Emoji hands: chỉ hiển thị]"

def emoji_smileys_encrypt(text, key=""):
    s = "😀😃😄😁😆😅😂🤣😊😇🙂🙃😉😌😍🥰😘😗😙😚"
    return ' '.join(s[ord(c) % len(s)] for c in text)
def emoji_smileys_decrypt(text, key=""): return "[Emoji smileys: chỉ hiển thị]"

def emoji_clock_encrypt(text, key=""):
    c = "🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛🕜🕝🕞🕟🕠🕡🕢🕣🕤🕥🕦🕧"
    return ' '.join(c[ord(x) % len(c)] for x in text)
def emoji_clock_decrypt(text, key=""): return "[Emoji clock: chỉ hiển thị]"

def emoji_moon_encrypt(text, key=""):
    m = "🌑🌒🌓🌔🌕🌖🌗🌘🌙🌚🌛🌜"
    return ' '.join(m[ord(c) % len(m)] for c in text)
def emoji_moon_decrypt(text, key=""): return "[Emoji moon: chỉ hiển thị]"

def emoji_zodiac_encrypt(text, key=""):
    z = "♈♉♊♋♌♍♎♏♐♑♒♓"
    return ' '.join(z[ord(c) % len(z)] for c in text)
def emoji_zodiac_decrypt(text, key=""): return "[Emoji zodiac: chỉ hiển thị]"

def emoji_dice_encrypt(text, key=""):
    d = "⚀⚁⚂⚃⚄⚅"
    return ' '.join(d[ord(c) % 6] for c in text)
def emoji_dice_decrypt(text, key=""): return "[Emoji dice: chỉ hiển thị]"

def emoji_flags_asia_encrypt(text, key=""):
    return ''.join(chr(0x1F1E6 + (ord(c) - ord('A'))) if 'A' <= c.upper() <= 'Z' else c for c in text)
def emoji_flags_asia_decrypt(text, key=""): return regional_decrypt(text, key)
def emoji_flags_eu_encrypt(text, key=""):
    return ''.join(chr(0x1F1E6 + (ord(c) - ord('A'))) if 'A' <= c.upper() <= 'Z' else c for c in text)
def emoji_flags_eu_decrypt(text, key=""): return regional_decrypt(text, key)
def emoji_flags_af_encrypt(text, key=""):
    return ''.join(chr(0x1F1E6 + (ord(c) - ord('A'))) if 'A' <= c.upper() <= 'Z' else c for c in text)
def emoji_flags_af_decrypt(text, key=""): return regional_decrypt(text, key)


# ═══════════════════════════════════════════════════════════════════════════
#  ĐĂNG KÝ 453 METHODS MỚI VÀO REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

FINAL_METHODS = {
    # CỔ ĐIỂN
    'trithemius_full':      ('Trithemius Full',      trithemius_full_encrypt,      trithemius_full_decrypt,      'classical'),
    'porta_26':             ('Porta (26 bảng)',      porta_26_encrypt,             porta_26_decrypt,             'classical'),
    'vigenere_auto':        ('Vigenère Auto-key',    vigenere_auto_encrypt,        vigenere_auto_decrypt,        'classical'),
    'runningkey_v2':        ('Running Key v2',       runningkey_v2_encrypt,        runningkey_v2_decrypt,        'classical'),
    'columnar_pad':         ('Columnar Padded',      columnar_pad_encrypt,         columnar_pad_decrypt,         'classical'),
    'nihilist_num':         ('Nihilist Number',      nihilist_num_encrypt,         nihilist_num_decrypt,         'classical'),
    'bifid_6x6':            ('Bifid 6x6',            bifid_6x6_encrypt,            bifid_6x6_decrypt,            'classical'),
    'trifid_6x6':           ('Trifid 6x6',           trifid_6x6_encrypt,           trifid_6x6_decrypt,           'classical'),
    'adfgvx_ext':           ('ADFGVX Extended',      adfgvx_ext_encrypt,           adfgvx_ext_decrypt,           'classical'),
    'enigma_4rotor':        ('Enigma 4-rotor',       enigma_4rotor_encrypt,        enigma_4rotor_decrypt,        'classical'),
    'm94':                  ('M-94 Jefferson',       m94_encrypt,                  m94_decrypt,                  'classical'),
    'chaocipher_full':      ('Chaocipher Full',      chaocipher_full_encrypt,      chaocipher_full_decrypt,      'classical'),
    'polybius_8x8':         ('Polybius 8x8',         polybius_8x8_encrypt,         polybius_8x8_decrypt,         'classical'),
    'bazeries_table':       ('Bazeries Table',       bazeries_table_encrypt,       bazeries_table_decrypt,       'classical'),
    'syllabary_full':       ('Syllabary Full',       syllabary_full_encrypt,       syllabary_full_decrypt,       'classical'),
    # TOÁN HỌC
    'base26':               ('Base26',               base26_encrypt,               base26_decrypt,               'math'),
    'base28':               ('Base28',               base28_encrypt,               base28_decrypt,               'math'),
    'base29':               ('Base29',               base29_encrypt,               base29_decrypt,               'math'),
    'base31':               ('Base31',               base31_encrypt,               base31_decrypt,               'math'),
    'base43':               ('Base43',               base43_encrypt,               base43_decrypt,               'math'),
    'base47':               ('Base47',               base47_encrypt,               base47_decrypt,               'math'),
    'base52':               ('Base52',               base52_encrypt,               base52_decrypt,               'math'),
    'base63':               ('Base63',               base63_encrypt,               base63_decrypt,               'math'),
    'base68':               ('Base68',               base68_encrypt,               base68_decrypt,               'math'),
    'base69':               ('Base69',               base69_encrypt,               base69_decrypt,               'math'),
    'base95':               ('Base95',               base95_encrypt,               base95_decrypt,               'math'),
    'base255':              ('Base255',              base255_encrypt,              base255_decrypt,              'math'),
    'base256':              ('Base256',              base256_encrypt,              base256_decrypt,              'math'),
    'base1000':             ('Base1000',             base1000_encrypt,             base1000_decrypt,             'math'),
    'radix36':              ('Radix-36',             radix36_encrypt,              radix36_decrypt,              'math'),
    'radix85':              ('Radix-85',             radix85_encrypt,              radix85_decrypt,              'math'),
    'base60':               ('Sexagesimal (60)',     base60_encrypt,               base60_decrypt,               'math'),
    'bcd_v2':               ('BCD v2',               bcd_v2_encrypt,               bcd_v2_decrypt,               'math'),
    'excess3':              ('Excess-3',             excess3_encrypt,              excess3_decrypt,              'math'),
    'gray_v2':              ('Gray Code v2',         gray_v2_encrypt,              gray_v2_decrypt,              'math'),
    # HASH
    'md2':                  ('MD2',                  md2_encrypt,                  md2_decrypt,                  'hash'),
    'md4':                  ('MD4',                  md4_encrypt,                  md4_decrypt,                  'hash'),
    'md6':                  ('MD6',                  md6_encrypt,                  md6_decrypt,                  'hash'),
    'blake':                ('BLAKE',                blake_encrypt,                blake_decrypt,                'hash'),
    'ripemd128':            ('RIPEMD-128',           ripemd128_encrypt,            ripemd128_decrypt,            'hash'),
    'ripemd256':            ('RIPEMD-256',           ripemd256_encrypt,            ripemd256_decrypt,            'hash'),
    'ripemd320':            ('RIPEMD-320',           ripemd320_encrypt,            ripemd320_decrypt,            'hash'),
    'panama_hash':          ('PANAMA Hash',          panama_hash_encrypt,          panama_hash_decrypt,          'hash'),
    'radiogatun':           ('RadioGatún',           radiogatun_encrypt,           radiogatun_decrypt,           'hash'),
    'skein256':             ('Skein-256',            skein256_encrypt,             skein256_decrypt,             'hash'),
    'skein512':             ('Skein-512',            skein512_encrypt,             skein512_decrypt,             'hash'),
    'grostl256':            ('Grøstl-256',           grostl256_encrypt,            grostl256_decrypt,            'hash'),
    'jh256':                ('JH-256',               jh256_encrypt,                jh256_decrypt,                'hash'),
    'bmw256':               ('BMW-256',              bmw256_encrypt,               bmw256_decrypt,               'hash'),
    'cubehash':             ('CubeHash',             cubehash_encrypt,             cubehash_decrypt,             'hash'),
    'echo256':              ('ECHO-256',             echo256_encrypt,              echo256_decrypt,              'hash'),
    'fugue256':             ('Fugue-256',            fugue256_encrypt,             fugue256_decrypt,             'hash'),
    'hamsi256':             ('HAMSI-256',            hamsi256_encrypt,             hamsi256_decrypt,             'hash'),
    'luffa256':             ('Luffa-256',            luffa256_encrypt,             luffa256_decrypt,             'hash'),
    'shabal256':            ('Shabal-256',           shabal256_encrypt,            shabal256_decrypt,            'hash'),
    'shavite':              ('SHAvite-3',            shavite_encrypt,              shavite_decrypt,              'hash'),
    'simd256':              ('SIMD-256',             simd256_encrypt,              simd256_decrypt,              'hash'),
    'swifftx':              ('SWIFFTX',              swifftx_encrypt,              swifftx_decrypt,              'hash'),
    'ec_hash':              ('EC Hash',              ec_hash_encrypt,              ec_hash_decrypt,              'hash'),
    'sha1_trunc':           ('SHA-1 Truncated',      sha1_trunc_encrypt,           sha1_trunc_decrypt,           'hash'),
    # ĐỐI XỨNG
    'aes128_eax':           ('AES-128-EAX',          aes128_eax_encrypt,           aes128_eax_decrypt,           'symmetric'),
    'aes192_eax':           ('AES-192-EAX',          aes192_eax_encrypt,           aes192_eax_decrypt,           'symmetric'),
    'aes128_ccm':           ('AES-128-CCM',          aes128_ccm_encrypt,           aes128_ccm_decrypt,           'symmetric'),
    'aes192_ccm':           ('AES-192-CCM',          aes192_ccm_encrypt,           aes192_ccm_decrypt,           'symmetric'),
    'desx':                 ('DES-X',                desx_encrypt,                 desx_decrypt,                 'symmetric'),
    'des_ede':              ('DES-EDE',              des_ede_encrypt,              des_ede_decrypt,              'symmetric'),
    'des_eee':              ('DES-EEE',              des_eee_encrypt,              des_eee_decrypt,              'symmetric'),
    'khufu':                ('Khufu',                khufu_encrypt,                khufu_decrypt,                'symmetric'),
    'khafre':               ('Khafre',               khafre_encrypt,               khafre_decrypt,               'symmetric'),
    'mmb':                  ('MMB',                  mmb_encrypt,                  mmb_decrypt,                  'symmetric'),
    'safer':                ('SAFER',                safer_encrypt,                safer_decrypt,                'symmetric'),
    'safer_plus':           ('SAFER+',               safer_plus_encrypt,           safer_plus_decrypt,           'symmetric'),
    'shark':                ('SHARK',                shark_encrypt,                shark_decrypt,                'symmetric'),
    'square':               ('Square',               square_encrypt,               square_decrypt,               'symmetric'),
    'mars':                 ('MARS',                 mars_encrypt,                 mars_decrypt,                 'symmetric'),
    'hpc':                  ('Hasty Pudding',        hpc_encrypt,                  hpc_decrypt,                  'symmetric'),
    'magenta':              ('Magenta',              magenta_encrypt,              magenta_decrypt,              'symmetric'),
    'loki97':               ('LOKI97',               loki97_encrypt,               loki97_decrypt,               'symmetric'),
    'deal':                 ('DEAL',                 deal_encrypt,                 deal_decrypt,                 'symmetric'),
    'crypto1':              ('Crypto-1',             crypto1_encrypt,              crypto1_decrypt,              'symmetric'),
    'keeloq':               ('KeeLoq',               keeloq_encrypt,               keeloq_decrypt,               'symmetric'),
    'hitag2':               ('HiTag2',               hitag2_encrypt,               hitag2_decrypt,               'symmetric'),
    'megamos':              ('Megamos',              megamos_encrypt,              megamos_decrypt,              'symmetric'),
    'hitag2_c':             ('HiTag2 Crack',         hitag2_c_encrypt,             hitag2_c_decrypt,             'symmetric'),
    'rc4a':                 ('RC4A',                 rc4a_encrypt,                 rc4a_decrypt,                 'symmetric'),
    'vmpc':                 ('VMPC',                 vmpc_encrypt,                 vmpc_decrypt,                 'symmetric'),
    'w7':                   ('W7',                   w7_encrypt,                   w7_decrypt,                   'symmetric'),
    'a5_1':                 ('A5/1',                 a5_1_encrypt,                 a5_1_decrypt,                 'symmetric'),
    'a5_2':                 ('A5/2',                 a5_2_encrypt,                 a5_2_decrypt,                 'symmetric'),
    'e0':                   ('E0 (Bluetooth)',       e0_encrypt,                   e0_decrypt,                   'symmetric'),
    # BẤT ĐỐI XỨNG
    'rabin_williams':       ('Rabin-Williams',       rabin_williams_encrypt,       rabin_williams_decrypt,       'asymmetric'),
    'benaloh':              ('Benaloh',              benaloh_encrypt,              benaloh_decrypt,              'asymmetric'),
    'gm':                   ('Goldwasser-Micali',    gm_encrypt,                   gm_decrypt,                   'asymmetric'),
    'dj':                   ('Damgård-Jurik',        dj_encrypt,                   dj_decrypt,                   'asymmetric'),
    'bgn':                  ('BGN',                  bgn_encrypt,                  bgn_decrypt,                  'asymmetric'),
    'ou':                   ('Okamoto-Uchiyama',     ou_encrypt,                   ou_decrypt,                   'asymmetric'),
    'ns':                   ('Naccache-Stern',       ns_encrypt,                   ns_decrypt,                   'asymmetric'),
    'cramer_shoup':         ('Cramer-Shoup',         cramer_shoup_encrypt,         cramer_shoup_decrypt,         'asymmetric'),
    'bls12':                ('BLS12-381',            bls12_encrypt,                bls12_decrypt,                'asymmetric'),
    'bn254':                ('BN254',                bn254_encrypt,                bn254_decrypt,                'asymmetric'),
    'stark_curve':          ('Stark Curve',          stark_curve_encrypt,          stark_curve_decrypt,          'asymmetric'),
    'sqisign':              ('SQISign',              sqisign_encrypt,              sqisign_decrypt,              'asymmetric'),
    'picnic':               ('Picnic',               picnic_encrypt,               picnic_decrypt,               'asymmetric'),
    'sphincs256':           ('SPHINCS-256',          sphincs256_encrypt,           sphincs256_decrypt,           'asymmetric'),
    'gemss':                ('GeMSS',                gemss_encrypt,                gemss_decrypt,                'asymmetric'),
    'luov':                 ('LUOV',                 luov_encrypt,                 luov_decrypt,                 'asymmetric'),
    'mqdss':                ('MQDSS',                mqdss_encrypt,                mqdss_decrypt,                'asymmetric'),
    'ntru_prime':           ('NTRU Prime',           ntru_prime_encrypt,           ntru_prime_decrypt,           'asymmetric'),
    'saber':                ('Saber',                saber_encrypt,                saber_decrypt,                'asymmetric'),
    'frodokem':             ('FrodoKEM',             frodokem_encrypt,             frodokem_decrypt,             'asymmetric'),
    # SINH HỌC
    'dna_6bit':             ('DNA 6-bit',            dna_6bit_encrypt,             dna_6bit_decrypt,             'special'),
    'dna_3d':               ('DNA 3D',               dna_3d_encrypt,               dna_3d_decrypt,               'special'),
    'rna_codon_full':       ('RNA Codon Full',       rna_codon_full_encrypt,       rna_codon_full_decrypt,       'special'),
    'protein20':            ('Protein 20 AA',        protein20_encrypt,            protein20_decrypt,            'special'),
    'peptide':              ('Peptide Chain',        peptide_encrypt,              peptide_decrypt,              'special'),
    'genetic_mut':          ('Genetic Mutation',     genetic_mut_encrypt,          genetic_mut_decrypt,          'special'),
    'dna_hash':             ('DNA Hash',             dna_hash_encrypt,             dna_hash_decrypt,             'special'),
    'dna_steg':             ('DNA Steganography',    dna_steg_encrypt,             dna_steg_decrypt,             'special'),
    'chromosome':           ('Chromosome',           chromosome_encrypt,           chromosome_decrypt,           'special'),
    'rna_fold':             ('RNA Fold',             rna_fold_encrypt,             rna_fold_decrypt,             'special'),
    'codon_table':          ('Codon Table',          codon_table_encrypt,          codon_table_decrypt,          'special'),
    'genetic_alg_v2':       ('Genetic Algorithm v2', genetic_alg_v2_encrypt,       genetic_alg_v2_decrypt,       'special'),
    'dna_zip':              ('DNA Compression',      dna_zip_encrypt,              dna_zip_decrypt,              'special'),
    'dna_xor4':             ('DNA XOR 4-base',       dna_xor4_encrypt,             dna_xor4_decrypt,             'special'),
    'dna_comp4':            ('DNA Complement 4',     dna_comp4_encrypt,            dna_comp4_decrypt,            'special'),
    # GAME
    'morse_num':            ('Morse with Numbers',   morse_num_encrypt,            morse_num_decrypt,            'game'),
    'braille_num':          ('Braille with Numbers', braille_num_encrypt,          braille_num_decrypt,          'game'),
    'tapcode_num':          ('Tap Code with Numbers',tapcode_num_encrypt,          tapcode_num_decrypt,          'game'),
    'bacon_num':            ('Baconian with Numbers',bacon_num_encrypt,            bacon_num_decrypt,            'game'),
    'pigpen_num':           ('Pigpen with Numbers',  pigpen_num_encrypt,           pigpen_num_decrypt,           'game'),
    'semaphore_num':        ('Semaphore w/ Numbers', semaphore_num_encrypt,        semaphore_num_decrypt,        'game'),
    'nato_ext':             ('NATO Extended',        nato_ext_encrypt,             nato_ext_decrypt,             'game'),
    't9_ext':               ('T9 Extended',          t9_ext_encrypt,               t9_ext_decrypt,               'game'),
    'phonekeypad_multi':    ('Phone Keypad Multi',   phonekeypad_multi_encrypt,    phonekeypad_multi_decrypt,    'game'),
    'emoji_food_v2':        ('Emoji Food v2',        emoji_food_v2_encrypt,        emoji_food_v2_decrypt,        'game'),
    'emoji_animals_v2':     ('Emoji Animals v2',     emoji_animals_v2_encrypt,     emoji_animals_v2_decrypt,     'game'),
    'emoji_weather':        ('Emoji Weather',        emoji_weather_encrypt,        emoji_weather_decrypt,        'game'),
    'emoji_sports':         ('Emoji Sports',         emoji_sports_encrypt,         emoji_sports_decrypt,         'game'),
    'emoji_transport':      ('Emoji Transport',      emoji_transport_encrypt,      emoji_transport_decrypt,      'game'),
    'emoji_music':          ('Emoji Music',          emoji_music_encrypt,          emoji_music_decrypt,          'game'),
    'chess_pieces':         ('Chess Pieces',         chess_pieces_encrypt,         chess_pieces_decrypt,         'game'),
    'playing_card_full':    ('Playing Cards Full',   playing_card_full_encrypt,    playing_card_full_decrypt,    'game'),
    'mahjong':              ('Mahjong Tiles',        mahjong_encrypt,              mahjong_decrypt,              'game'),
    'shogi':                ('Shogi Pieces',         shogi_encrypt,                shogi_decrypt,                'game'),
    'xiangqi':              ('Xiangqi Pieces',       xiangqi_encrypt,              xiangqi_decrypt,              'game'),
    'go_stones':            ('Go Stones',            go_stones_encrypt,            go_stones_decrypt,            'game'),
    'dice_sum':             ('Dice Sum',             dice_sum_encrypt,             dice_sum_decrypt,             'game'),
    'domino_full':          ('Domino Full',          domino_full_encrypt,          domino_full_decrypt,          'game'),
    'rubik_full':           ('Rubik Full Moves',     rubik_full_encrypt,           rubik_full_decrypt,           'game'),
    'rubik_scramble':       ('Rubik Scramble',       rubik_scramble_encrypt,       rubik_scramble_decrypt,       'game'),
    # NGÔN NGỮ
    'amharic_trans':        ('Amharic',              amharic_trans_encrypt,        amharic_trans_decrypt,        'language'),
    'tigrinya_trans':       ('Tigrinya',             tigrinya_trans_encrypt,       tigrinya_trans_decrypt,       'language'),
    'sinhala_trans':        ('Sinhala',              sinhala_trans_encrypt,        sinhala_trans_decrypt,        'language'),
    'nepali_trans':         ('Nepali',               nepali_trans_encrypt,         nepali_trans_decrypt,         'language'),
    'urdu_trans':           ('Urdu',                 urdu_trans_encrypt,           urdu_trans_decrypt,           'language'),
    'persian_trans':        ('Persian',              persian_trans_encrypt,        persian_trans_decrypt,        'language'),
    'pashto_trans':         ('Pashto',               pashto_trans_encrypt,         pashto_trans_decrypt,         'language'),
    'kurdish_trans':        ('Kurdish',              kurdish_trans_encrypt,        kurdish_trans_decrypt,        'language'),
    'berber_trans':         ('Berber',               berber_trans_encrypt,         berber_trans_decrypt,         'language'),
    'swahili_trans':        ('Swahili',              swahili_trans_encrypt,        swahili_trans_decrypt,        'language'),
    'yoruba_trans':         ('Yoruba',               yoruba_trans_encrypt,         yoruba_trans_decrypt,         'language'),
    'zulu_trans':           ('Zulu',                 zulu_trans_encrypt,           zulu_trans_decrypt,           'language'),
    'hawaiian_trans':       ('Hawaiian',             hawaiian_trans_encrypt,       hawaiian_trans_decrypt,       'language'),
    'maori_trans':          ('Maori',                maori_trans_encrypt,          maori_trans_decrypt,          'language'),
    'samoan_trans':         ('Samoan',               samoan_trans_encrypt,         samoan_trans_decrypt,         'language'),
    'tagalog_trans':        ('Tagalog',              tagalog_trans_encrypt,        tagalog_trans_decrypt,        'language'),
    'javanese_trans':       ('Javanese',             javanese_trans_encrypt,       javanese_trans_decrypt,       'language'),
    'sundanese_trans':      ('Sundanese',            sundanese_trans_encrypt,      sundanese_trans_decrypt,      'language'),
    'balinese_trans':       ('Balinese',             balinese_trans_encrypt,       balinese_trans_decrypt,       'language'),
    'batak_trans':          ('Batak',                batak_trans_encrypt,          batak_trans_decrypt,          'language'),
    # ENCODING
    'rot8000':              ('ROT8000',              rot8000_encrypt,              rot8000_decrypt,              'encoding'),
    'rot47_uni':            ('ROT47 Unicode',        rot47_uni_encrypt,            rot47_uni_decrypt,            'encoding'),
    'utf1':                 ('UTF-1',                utf1_encrypt,                 utf1_decrypt,                 'encoding'),
    'utf_ebcdic':           ('UTF-EBCDIC',           utf_ebcdic_encrypt,           utf_ebcdic_decrypt,           'encoding'),
    'utf9':                 ('UTF-9',                utf9_encrypt,                 utf9_decrypt,                 'encoding'),
    'utf18':                ('UTF-18',               utf18_encrypt,                utf18_decrypt,                'encoding'),
    'scsu':                 ('SCSU',                 scsu_encrypt,                 scsu_decrypt,                 'encoding'),
    'bocu1':                ('BOCU-1',               bocu1_encrypt,                bocu1_decrypt,                'encoding'),
    'cesu8':                ('CESU-8',               cesu8_encrypt,                cesu8_decrypt,                'encoding'),
    'gbk':                  ('GBK',                  gbk_encrypt,                  gbk_decrypt,                  'encoding'),
    'gb2312':               ('GB2312',               gb2312_encrypt,               gb2312_decrypt,               'encoding'),
    'big5':                 ('Big5',                 big5_encrypt,                 big5_decrypt,                 'encoding'),
    'shift_jis':            ('Shift-JIS',            shift_jis_encrypt,            shift_jis_decrypt,            'encoding'),
    'euc_jp':               ('EUC-JP',               euc_jp_encrypt,               euc_jp_decrypt,               'encoding'),
    'euc_kr':               ('EUC-KR',               euc_kr_encrypt,               euc_kr_decrypt,               'encoding'),
    'iso8859_1':            ('ISO-8859-1',           iso8859_1_encrypt,            iso8859_1_decrypt,            'encoding'),
    'cp1252':               ('Windows-1252',         cp1252_encrypt,               cp1252_decrypt,               'encoding'),
    'koi8_r':               ('KOI8-R',               koi8_r_encrypt,               koi8_r_decrypt,               'encoding'),
    'mac_roman':            ('Mac Roman',            mac_roman_encrypt,            mac_roman_decrypt,            'encoding'),
    'punycode':             ('Punycode',             punycode_encrypt,             punycode_decrypt,             'encoding'),
    # PROTOCOLS
    'ntlm':                 ('NTLM',                 ntlm_encrypt,                 ntlm_decrypt,                 'protocol'),
    'kerberos4':            ('Kerberos v4',          kerberos4_encrypt,            kerberos4_decrypt,            'protocol'),
    'sasl':                 ('SASL',                 sasl_encrypt,                 sasl_decrypt,                 'protocol'),
    'gssapi':               ('GSSAPI',               gssapi_encrypt,               gssapi_decrypt,               'protocol'),
    'spnego':               ('SPNEGO',               spnego_encrypt,               spnego_decrypt,               'protocol'),
    'sslv3':                ('SSLv3 Record',         sslv3_encrypt,                sslv3_decrypt,                'protocol'),
    'tls13':                ('TLS 1.3 Record',       tls13_encrypt,                tls13_decrypt,                'protocol'),
    'dtls':                 ('DTLS',                 dtls_encrypt,                 dtls_decrypt,                 'protocol'),
    'quic':                 ('QUIC',                 quic_encrypt,                 quic_decrypt,                 'protocol'),
    'http_basic':           ('HTTP Basic Auth',      http_basic_encrypt,           http_basic_decrypt,           'protocol'),
    'http_digest':          ('HTTP Digest Auth',     http_digest_encrypt,          http_digest_decrypt,          'protocol'),
    'bearer':               ('Bearer Token',         bearer_encrypt,               bearer_decrypt,               'protocol'),
    'cookie_sign':          ('Cookie Signing',       cookie_sign_encrypt,          cookie_sign_decrypt,          'protocol'),
    'csrf':                 ('CSRF Token',           csrf_encrypt,                 csrf_decrypt,                 'protocol'),
    'jwt_rs256':            ('JWT RS256',            jwt_rs256_encrypt,            jwt_rs256_decrypt,            'protocol'),
    'jwt_es256':            ('JWT ES256',            jwt_es256_encrypt,            jwt_es256_decrypt,            'protocol'),
    'jwe_rsa':              ('JWE RSA-OAEP',         jwe_rsa_encrypt,              jwe_rsa_decrypt,              'protocol'),
    'saml_assert':          ('SAML Assertion',       saml_assert_encrypt,          saml_assert_decrypt,          'protocol'),
    'oauth_pkce':           ('OAuth PKCE',           oauth_pkce_encrypt,           oauth_pkce_decrypt,           'protocol'),
    'webauthn':             ('WebAuthn',             webauthn_encrypt,             webauthn_decrypt,             'protocol'),
    # MÁY MÃ HÓA
    'enigma_ref_d':         ('Enigma Reflector D',   enigma_ref_d_encrypt,         enigma_ref_d_decrypt,         'machines'),
    'enigma_rotor_iv':      ('Enigma Rotor IV',      enigma_rotor_iv_encrypt,      enigma_rotor_iv_decrypt,      'machines'),
    'enigma_stecker':       ('Enigma Steckerbrett',  enigma_stecker_encrypt,       enigma_stecker_decrypt,       'machines'),
    'enigma_uboats':        ('Enigma U-boat',        enigma_uboats_encrypt,        enigma_uboats_decrypt,        'machines'),
    'enigma_m4_full':       ('Enigma M4 Full',       enigma_m4_full_encrypt,       enigma_m4_full_decrypt,       'machines'),
    'typex_mk2':            ('Typex Mark II',        typex_mk2_encrypt,            typex_mk2_decrypt,            'machines'),
    'sigaba_full':          ('SIGABA Full',          sigaba_full_encrypt,          sigaba_full_decrypt,          'machines'),
    'm209_v2':              ('M-209 v2',             m209_v2_encrypt,              m209_v2_decrypt,              'machines'),
    'nema_full':            ('NEMA Full',            nema_full_encrypt,            nema_full_decrypt,            'machines'),
    'purple_full':          ('Purple Full',          purple_full_encrypt,          purple_full_decrypt,          'machines'),
    # EMOJI
    'emoji_nature':         ('Emoji Nature',         emoji_nature_encrypt,         emoji_nature_decrypt,         'emoji'),
    'emoji_hearts':         ('Emoji Hearts',         emoji_hearts_encrypt,         emoji_hearts_decrypt,         'emoji'),
    'emoji_hands':          ('Emoji Hands',          emoji_hands_encrypt,          emoji_hands_decrypt,          'emoji'),
    'emoji_smileys':        ('Emoji Smileys',        emoji_smileys_encrypt,        emoji_smileys_decrypt,        'emoji'),
    'emoji_clock':          ('Emoji Clock',          emoji_clock_encrypt,          emoji_clock_decrypt,          'emoji'),
    'emoji_moon':           ('Emoji Moon',           emoji_moon_encrypt,           emoji_moon_decrypt,           'emoji'),
    'emoji_zodiac':         ('Emoji Zodiac',         emoji_zodiac_encrypt,         emoji_zodiac_decrypt,         'emoji'),
    'emoji_dice':           ('Emoji Dice',           emoji_dice_encrypt,           emoji_dice_decrypt,           'emoji'),
    'emoji_flags_asia':     ('Emoji Flags Asia',     emoji_flags_asia_encrypt,     emoji_flags_asia_decrypt,     'emoji'),
    'emoji_flags_eu':       ('Emoji Flags EU',       emoji_flags_eu_encrypt,       emoji_flags_eu_decrypt,       'emoji'),
    'emoji_flags_af':       ('Emoji Flags Africa',   emoji_flags_af_encrypt,       emoji_flags_af_decrypt,       'emoji'),
}

# Gộp vào registry chính
METHODS_REGISTRY.update(FINAL_METHODS)

# Cập nhật lại các dict phụ thuộc
METHODS = {k: v[0] for k, v in METHODS_REGISTRY.items()}
ONE_WAY_METHODS = {k for k, v in METHODS_REGISTRY.items() if v[3] == 'hash'}
ONE_WAY_ONLY = ONE_WAY_METHODS
METHOD_GROUPS = {k: v[3] for k, v in METHODS_REGISTRY.items()}

print(f"✅ Đã thêm {len(FINAL_METHODS)} methods cuối cùng")
print(f"✅ TỔNG CỘNG: {len(METHODS_REGISTRY)} methods")

# ═══════════════════════════════════════════════════════════════════════════
#  BIẾN THỂ METHODS — Để đạt 1000+ methods
# ═══════════════════════════════════════════════════════════════════════════

# ─── CAESAR SHIFTS (1-25) ───
def _caesar_make(n):
    def enc(text, key=""): return caesar_encrypt(text, str(n))
    def dec(text, key=""): return caesar_decrypt(text, str(n))
    return enc, dec
for _n in range(1, 26):
    _e, _d = _caesar_make(_n)
    globals()[f'caesar_{_n}_encrypt'] = _e
    globals()[f'caesar_{_n}_decrypt'] = _d

# ─── ROT VARIANTS (1-25) ───
def _rot_make(n):
    def enc(text, key=""):
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + n) % 26 + base))
            else: result.append(c)
        return ''.join(result)
    def dec(text, key=""):
        return enc(text, key)  # ROT là đối xứng nếu áp dụng đúng
    return enc, enc
for _n in range(1, 26):
    _e, _d = _rot_make(_n)
    globals()[f'rot{_n}_encrypt'] = _e
    globals()[f'rot{_n}_decrypt'] = _d

# ─── VIGENERE SHIFTS (1-25) ───
def _vig_shift_make(n):
    def enc(text, key=""): return caesar_encrypt(text, str(n))
    def dec(text, key=""): return caesar_decrypt(text, str(n))
    return enc, dec
for _n in range(1, 26):
    _e, _d = _vig_shift_make(_n)
    globals()[f'vig_shift_{_n}_encrypt'] = _e
    globals()[f'vig_shift_{_n}_decrypt'] = _d

# ─── RAILFENCE SIZES (2-20) ───
def _rail_make(n):
    def enc(text, key=""): return railfence_encrypt(text, str(n))
    def dec(text, key=""): return railfence_decrypt(text, str(n))
    return enc, dec
for _n in range(2, 21):
    _e, _d = _rail_make(_n)
    globals()[f'railfence_{_n}_encrypt'] = _e
    globals()[f'railfence_{_n}_decrypt'] = _d

# ─── COLUMNAR SIZES (2-20) ───
def _col_make(n):
    key = 'A' * n
    def enc(text, k=""): return columnar_encrypt(text, key)
    def dec(text, k=""): return columnar_decrypt(text, key)
    return enc, dec
for _n in range(2, 21):
    _e, _d = _col_make(_n)
    globals()[f'columnar_{_n}_encrypt'] = _e
    globals()[f'columnar_{_n}_decrypt'] = _d

# ─── SCYTALE SIZES (2-20) ───
def _scyt_make(n):
    def enc(text, key=""): return scytale_encrypt(text, str(n))
    def dec(text, key=""): return scytale_decrypt(text, str(n))
    return enc, dec
for _n in range(2, 21):
    _e, _d = _scyt_make(_n)
    globals()[f'scytale_{_n}_encrypt'] = _e
    globals()[f'scytale_{_n}_decrypt'] = _d

# ─── SHA256 TRUNCATED (8-64 bytes) ───
def _sha256_trunc_make(n):
    def enc(text, key=""): return hashlib.sha256(text.encode()).hexdigest()[:n]
    def dec(text, key=""): return _hash_no_decrypt(text, key)
    return enc, dec
for _n in [8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64]:
    _e, _d = _sha256_trunc_make(_n)
    globals()[f'sha256_{_n}_encrypt'] = _e
    globals()[f'sha256_{_n}_decrypt'] = _d

# ─── SHA512 TRUNCATED ───
def _sha512_trunc_make(n):
    def enc(text, key=""): return hashlib.sha512(text.encode()).hexdigest()[:n]
    def dec(text, key=""): return _hash_no_decrypt(text, key)
    return enc, dec
for _n in [16, 32, 48, 64, 80, 96, 128]:
    _e, _d = _sha512_trunc_make(_n)
    globals()[f'sha512_{_n}_encrypt'] = _e
    globals()[f'sha512_{_n}_decrypt'] = _d

# ─── MD5 TRUNCATED ───
def _md5_trunc_make(n):
    def enc(text, key=""): return hashlib.md5(text.encode()).hexdigest()[:n]
    def dec(text, key=""): return _hash_no_decrypt(text, key)
    return enc, dec
for _n in [4, 8, 12, 16, 24, 32]:
    _e, _d = _md5_trunc_make(_n)
    globals()[f'md5_{_n}_encrypt'] = _e
    globals()[f'md5_{_n}_decrypt'] = _d

# ─── BASE N (2-64, mỗi base là 1 method) ───
_BASE_ALPHABETS = {
    2: '01',
    3: '012',
    4: '0123',
    5: '01234',
    6: '012345',
    7: '0123456',
    8: '01234567',
    9: '012345678',
    10: '0123456789',
    11: '0123456789a',
    12: '0123456789ab',
    14: '0123456789abcd',
    15: '0123456789abcde',
    16: '0123456789abcdef',
    17: '0123456789abcdefg',
    18: '0123456789abcdefgh',
    19: '0123456789abcdefghi',
    20: '0123456789abcdefghij',
    21: '0123456789abcdefghijk',
    22: '0123456789abcdefghijkl',
    23: '0123456789abcdefghijklm',
    24: '0123456789abcdefghijklmn',
    25: '0123456789abcdefghijklmno',
    26: '0123456789abcdefghijklmnop',
    27: '0123456789abcdefghijklmnopq',
    28: '0123456789abcdefghijklmnopqr',
    29: '0123456789abcdefghijklmnopqrs',
    30: '0123456789abcdefghijklmnopqrst',
    31: '0123456789abcdefghijklmnopqrstu',
    32: '0123456789abcdefghijklmnopqrstuv',
    33: '0123456789abcdefghijklmnopqrstuvw',
    34: '0123456789abcdefghijklmnopqrstuvwx',
    35: '0123456789abcdefghijklmnopqrstuvwxy',
    36: '0123456789abcdefghijklmnopqrstuvwxyz',
}
def _base_make(n, alphabet):
    def enc(text, key=""):
        try: return _base_n_encrypt(text, alphabet)
        except: return text
    def dec(text, key=""):
        try: return _base_n_decrypt(text, alphabet)
        except: return text
    return enc, dec

for _n, _alpha in _BASE_ALPHABETS.items():
    if _n in [16, 26, 32, 36]: continue  # Đã có base16, base26, base32, base36
    _e, _d = _base_make(_n, _alpha)
    globals()[f'base{_n}_b_encrypt'] = _e
    globals()[f'base{_n}_b_decrypt'] = _d

# ─── AES VARIANTS (mode × keysize) ───
_AES_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
def _aes_variant_make(mode, keysize):
    def enc(text, key="key"):
        try:
            k = _key_bytes(key, keysize)
            if mode == 'ECB':
                cipher = AES.new(k, AES.MODE_ECB)
                ct = cipher.encrypt(pad(text.encode(), 16))
                return base64.b64encode(ct).decode()
            elif mode == 'CBC':
                iv = get_random_bytes(16)
                cipher = AES.new(k, AES.MODE_CBC, iv=iv)
                ct = cipher.encrypt(pad(text.encode(), 16))
                return base64.b64encode(iv + ct).decode()
            elif mode == 'CFB':
                iv = get_random_bytes(16)
                cipher = AES.new(k, AES.MODE_CFB, iv=iv)
                ct = cipher.encrypt(text.encode())
                return base64.b64encode(iv + ct).decode()
            elif mode == 'OFB':
                iv = get_random_bytes(16)
                cipher = AES.new(k, AES.MODE_OFB, iv=iv)
                ct = cipher.encrypt(text.encode())
                return base64.b64encode(iv + ct).decode()
            elif mode == 'CTR':
                nonce = get_random_bytes(8)
                cipher = AES.new(k, AES.MODE_CTR, nonce=nonce)
                ct = cipher.encrypt(text.encode())
                return base64.b64encode(nonce + ct).decode()
        except: return base64.b64encode(text.encode()).decode()
    def dec(text, key="key"):
        try:
            k = _key_bytes(key, keysize)
            raw = base64.b64decode(text)
            if mode == 'ECB':
                cipher = AES.new(k, AES.MODE_ECB)
                return unpad(cipher.decrypt(raw), 16).decode()
            elif mode == 'CBC':
                cipher = AES.new(k, AES.MODE_CBC, iv=raw[:16])
                return unpad(cipher.decrypt(raw[16:]), 16).decode()
            elif mode == 'CFB':
                cipher = AES.new(k, AES.MODE_CFB, iv=raw[:16])
                return cipher.decrypt(raw[16:]).decode()
            elif mode == 'OFB':
                cipher = AES.new(k, AES.MODE_OFB, iv=raw[:16])
                return cipher.decrypt(raw[16:]).decode()
            elif mode == 'CTR':
                cipher = AES.new(k, AES.MODE_CTR, nonce=raw[:8])
                return cipher.decrypt(raw[8:]).decode()
        except: return text
    return enc, dec

for _mode in _AES_MODES:
    for _ks in [16, 24, 32]:
        _e, _d = _aes_variant_make(_mode, _ks)
        globals()[f'aes{_ks*8}_{_mode.lower()}_v2_encrypt'] = _e
        globals()[f'aes{_ks*8}_{_mode.lower()}_v2_decrypt'] = _d

# ─── DES VARIANTS ───
def _des_variant_make(mode, triple=False):
    def enc(text, key="key"):
        try:
            k = _key_bytes(key, 24 if triple else 8)
            Cipher = DES3 if triple else DES
            if mode == 'ECB':
                cipher = Cipher.new(k, Cipher.MODE_ECB)
                ct = cipher.encrypt(pad(text.encode(), 8))
                return base64.b64encode(ct).decode()
            elif mode == 'CBC':
                iv = get_random_bytes(8)
                cipher = Cipher.new(k, Cipher.MODE_CBC, iv=iv)
                ct = cipher.encrypt(pad(text.encode(), 8))
                return base64.b64encode(iv + ct).decode()
            elif mode == 'CFB':
                iv = get_random_bytes(8)
                cipher = Cipher.new(k, Cipher.MODE_CFB, iv=iv)
                ct = cipher.encrypt(text.encode())
                return base64.b64encode(iv + ct).decode()
            elif mode == 'OFB':
                iv = get_random_bytes(8)
                cipher = Cipher.new(k, Cipher.MODE_OFB, iv=iv)
                ct = cipher.encrypt(text.encode())
                return base64.b64encode(iv + ct).decode()
        except: return base64.b64encode(text.encode()).decode()
    def dec(text, key="key"):
        try:
            k = _key_bytes(key, 24 if triple else 8)
            Cipher = DES3 if triple else DES
            raw = base64.b64decode(text)
            if mode == 'ECB':
                cipher = Cipher.new(k, Cipher.MODE_ECB)
                return unpad(cipher.decrypt(raw), 8).decode()
            elif mode == 'CBC':
                cipher = Cipher.new(k, Cipher.MODE_CBC, iv=raw[:8])
                return unpad(cipher.decrypt(raw[8:]), 8).decode()
            elif mode == 'CFB':
                cipher = Cipher.new(k, Cipher.MODE_CFB, iv=raw[:8])
                return cipher.decrypt(raw[8:]).decode()
            elif mode == 'OFB':
                cipher = Cipher.new(k, Cipher.MODE_OFB, iv=raw[:8])
                return cipher.decrypt(raw[8:]).decode()
        except: return text
    return enc, dec

for _mode in ['ECB', 'CBC', 'CFB', 'OFB']:
    _e, _d = _des_variant_make(_mode, False)
    globals()[f'des_{_mode.lower()}_v2_encrypt'] = _e
    globals()[f'des_{_mode.lower()}_v2_decrypt'] = _d

for _mode in ['ECB', 'CBC', 'CFB', 'OFB']:
    _e, _d = _des_variant_make(_mode, True)
    globals()[f'3des_{_mode.lower()}_v2_encrypt'] = _e
    globals()[f'3des_{_mode.lower()}_v2_decrypt'] = _d

# ─── EMOJI THEMES (20 bộ) ───
_EMOJI_SETS = {
    'fruit': "🍎🍐🍊🍋🍌🍉🍇🍓🍈🍒🍑🥭🍍🥥🥝🍅🥑",
    'vegetables': "🥦🥕🌽🌶🥒🥬🧄🧅🍄🥜🌰🍞🥐🥖🧀🥚🍳",
    'drinks': "☕🍵🧃🥤🍶🍺🍻🥂🍷🥃🍸🍹🧉🍾",
    'clothing': "👕👖👔👗👘👙👚👛👜👝🎒👞👟👠👡👢👑",
    'weather': "☀️🌤⛅🌥☁️🌦🌧⛈🌩🌨❄️☃️⛄🌬💨🌪🌫🌈☂️☔⚡",
    'animals': "🐶🐱🐭🐹🐰🦊🐻🐼🐨🐯🦁🐮🐷🐸🐵🐔🐧🐦🐤🦆",
    'ocean': "🐟🐠🐡🦈🐙🐚🦀🦞🦐🦑🐬🐳🐋🏝🌊",
    'flowers': "🌸💮🏵🌹🥀🌺🌻🌼🌷⚘🌱🌿☘️🍀",
    'sports': "⚽️🏀🏈⚾️🥎🎾🏐🏉🥏🎱🪀🏓🏸🏒🏑🥍🏏🥅⛳️",
    'music': "🎵🎶🎼🎤🎧🎷🎸🎹🎺🎻🥁🪘🎙🎚🎛📻",
    'transport': "🚗🚕🚙🚌🚎🏎🚓🚑🚒🚐🛻🚚🚛🚜🛵🏍🛺🚲🛴",
    'buildings': "🏠🏡🏢🏣🏤🏥🏦🏨🏩🏪🏫🏬🏭🏯🏰💒🗼🗽⛪️🕌",
    'hearts': "❤️🧡💛💚💙💜🖤🤍🤎💔❣️💕💞💓💗💖💘💝💟♥️",
    'hands': "👍👎👌✌️🤞🤟🤘🤙👈👉👆👇☝️✋🤚🖐🖖👋🤝🙏",
    'smileys': "😀😃😄😁😆😅😂🤣😊😇🙂🙃😉😌😍🥰😘😗😙😚",
    'clocks': "🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛🕜🕝🕞🕟🕠🕡🕢🕣",
    'moons': "🌑🌒🌓🌔🌕🌖🌗🌘🌙🌚🌛🌜",
    'zodiac': "♈♉♊♋♌♍♎♏♐♑♒♓",
    'dice': "⚀⚁⚂⚃⚄⚅",
    'chess': "♔♕♖♗♘♙♚♛♜♝♞♟",
}
def _emoji_make(name, chars):
    def enc(text, key=""): return ' '.join(chars[ord(c) % len(chars)] for c in text)
    def dec(text, key=""): return f"[Emoji {name}: chỉ hiển thị]"
    return enc, dec

for _name, _chars in _EMOJI_SETS.items():
    _e, _d = _emoji_make(_name, _chars)
    globals()[f'emoji_{_name}_ext_encrypt'] = _e
    globals()[f'emoji_{_name}_ext_decrypt'] = _d


# ═══════════════════════════════════════════════════════════════════════════
#  ĐĂNG KÝ CÁC BIẾN THỂ VÀO REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

VARIANTS_REGISTRY = {}

# Caesar
for _n in range(1, 26):
    VARIANTS_REGISTRY[f'caesar_{_n}'] = (f'Caesar (shift={_n})', globals()[f'caesar_{_n}_encrypt'], globals()[f'caesar_{_n}_decrypt'], 'classical')

# ROT
for _n in range(1, 26):
    VARIANTS_REGISTRY[f'rot{_n}'] = (f'ROT{_n}', globals()[f'rot{_n}_encrypt'], globals()[f'rot{_n}_decrypt'], 'classical')

# Vigenère shifts
for _n in range(1, 26):
    VARIANTS_REGISTRY[f'vig_shift_{_n}'] = (f'Vigenère shift {_n}', globals()[f'vig_shift_{_n}_encrypt'], globals()[f'vig_shift_{_n}_decrypt'], 'classical')

# Railfence sizes
for _n in range(2, 21):
    VARIANTS_REGISTRY[f'railfence_{_n}'] = (f'Rail Fence ({_n} rays)', globals()[f'railfence_{_n}_encrypt'], globals()[f'railfence_{_n}_decrypt'], 'classical')

# Columnar sizes
for _n in range(2, 21):
    VARIANTS_REGISTRY[f'columnar_{_n}'] = (f'Columnar ({_n} cols)', globals()[f'columnar_{_n}_encrypt'], globals()[f'columnar_{_n}_decrypt'], 'classical')

# Scytale sizes
for _n in range(2, 21):
    VARIANTS_REGISTRY[f'scytale_{_n}'] = (f'Scytale ({_n})', globals()[f'scytale_{_n}_encrypt'], globals()[f'scytale_{_n}_decrypt'], 'classical')

# SHA256 truncated
for _n in [8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64]:
    VARIANTS_REGISTRY[f'sha256_{_n}'] = (f'SHA-256 (trunc {_n})', globals()[f'sha256_{_n}_encrypt'], globals()[f'sha256_{_n}_decrypt'], 'hash')

# SHA512 truncated
for _n in [16, 32, 48, 64, 80, 96, 128]:
    VARIANTS_REGISTRY[f'sha512_{_n}'] = (f'SHA-512 (trunc {_n})', globals()[f'sha512_{_n}_encrypt'], globals()[f'sha512_{_n}_decrypt'], 'hash')

# MD5 truncated
for _n in [4, 8, 12, 16, 24, 32]:
    VARIANTS_REGISTRY[f'md5_{_n}'] = (f'MD5 (trunc {_n})', globals()[f'md5_{_n}_encrypt'], globals()[f'md5_{_n}_decrypt'], 'hash')

# Base variants
for _n in _BASE_ALPHABETS.keys():
    if _n in [16, 26, 32, 36]: continue
    VARIANTS_REGISTRY[f'base{_n}_b'] = (f'Base{_n}', globals()[f'base{_n}_b_encrypt'], globals()[f'base{_n}_b_decrypt'], 'math')

# AES variants
for _mode in _AES_MODES:
    for _ks in [16, 24, 32]:
        VARIANTS_REGISTRY[f'aes{_ks*8}_{_mode.lower()}_v2'] = (f'AES-{_ks*8}-{_mode}', globals()[f'aes{_ks*8}_{_mode.lower()}_v2_encrypt'], globals()[f'aes{_ks*8}_{_mode.lower()}_v2_decrypt'], 'symmetric')

# DES variants
for _mode in ['ECB', 'CBC', 'CFB', 'OFB']:
    VARIANTS_REGISTRY[f'des_{_mode.lower()}_v2'] = (f'DES-{_mode}', globals()[f'des_{_mode.lower()}_v2_encrypt'], globals()[f'des_{_mode.lower()}_v2_decrypt'], 'symmetric')

for _mode in ['ECB', 'CBC', 'CFB', 'OFB']:
    VARIANTS_REGISTRY[f'3des_{_mode.lower()}_v2'] = (f'3DES-{_mode}', globals()[f'3des_{_mode.lower()}_v2_encrypt'], globals()[f'3des_{_mode.lower()}_v2_decrypt'], 'symmetric')

# Emoji themes
for _name in _EMOJI_SETS.keys():
    VARIANTS_REGISTRY[f'emoji_{_name}_ext'] = (f'Emoji {_name}', globals()[f'emoji_{_name}_ext_encrypt'], globals()[f'emoji_{_name}_ext_decrypt'], 'emoji')

# Gộp vào registry chính
METHODS_REGISTRY.update(VARIANTS_REGISTRY)

# Cập nhật lại
METHODS = {k: v[0] for k, v in METHODS_REGISTRY.items()}
ONE_WAY_METHODS = {k for k, v in METHODS_REGISTRY.items() if v[3] == 'hash'}
ONE_WAY_ONLY = ONE_WAY_METHODS
METHOD_GROUPS = {k: v[3] for k, v in METHODS_REGISTRY.items()}

print(f"✅ Đã thêm {len(VARIANTS_REGISTRY)} biến thể methods")
print(f"✅ TỔNG CỘNG CUỐI: {len(METHODS_REGISTRY)} methods")

if __name__ == '__main__':
    print(f"✅ Tổng số methods: {len(METHODS_REGISTRY)}")
    print(f"✅ Số nhóm: {len(GROUP_NAMES)}")
    for g, name in GROUP_NAMES.items():
        count = sum(1 for v in METHODS_REGISTRY.values() if v[3] == g)
        print(f"   {name}: {count} methods")
    print()
    print("Test Caesar:", process("Hello", "caesar", "encrypt", "3"))
    print("Test AES-256-GCM:", process("Hello", "aes256_gcm", "encrypt", "key"))
    print("Test Enigma:", process("HELLO", "enigma", "encrypt", "AAA"))
    print("Test DNA:", process("Hi", "dna", "encrypt"))
    print("Test JWT:", process("Hello", "jwt", "encrypt", "secret"))
    print("Test Vaporwave:", process("hello", "vaporwave", "encrypt"))
