import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ===== Base64 =====
def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')


def base64_decode(text: str) -> str:
    return base64.b64decode(text.encode('utf-8')).decode('utf-8')


# ===== Caesar Cipher =====
def caesar_cipher(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


# ===== ROT13 =====
def rot13(text: str) -> str:
    return caesar_cipher(text, 13)


# ===== Binary =====
def binary_encode(text: str) -> str:
    return ' '.join(format(ord(c), '08b') for c in text)


def binary_decode(text: str) -> str:
    return ''.join(chr(int(b, 2)) for b in text.strip().split())


# ===== Hex =====
def hex_encode(text: str) -> str:
    return ' '.join(format(ord(c), '02x') for c in text)


def hex_decode(text: str) -> str:
    return ''.join(chr(int(h, 16)) for h in text.strip().split())


# ===== AES (Fernet - dựa trên AES-128-CBC) =====
def _derive_key(password: str, salt: bytes = b'ma-hoa-salt-2024') -> bytes:
    """Tạo key AES từ password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def aes_encrypt(text: str, password: str) -> str:
    """Mã hóa AES"""
    key = _derive_key(password)
    f = Fernet(key)
    encrypted = f.encrypt(text.encode('utf-8'))
    return encrypted.decode('utf-8')


def aes_decrypt(text: str, password: str) -> str:
    """Giải mã AES"""
    key = _derive_key(password)
    f = Fernet(key)
    decrypted = f.decrypt(text.encode('utf-8'))
    return decrypted.decode('utf-8')
