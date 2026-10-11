"""
Script tự động fix VNI/TELEX/VIQR trong crypto_utils.py
Chạy: python fix_vietnamese.py
"""

import re
import sys
import os

FILE = 'crypto_utils.py'

# ═══════════════════════════════════════════════════════════════
#  CODE MỚI — 3 hàm đầy đủ 134 ký tự tiếng Việt có dấu
# ═══════════════════════════════════════════════════════════════
NEW_CODE = '''
# ═══════════════════════════════════════════════════════════════════════════
#  TIẾNG VIỆT — TELEX / VNI / VIQR (FULL FIX)
# ═══════════════════════════════════════════════════════════════════════════

# ─── TELEX ───
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


# ─── VNI ───
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


# ─── VIQR ───
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

'''


def main():
    if not os.path.exists(FILE):
        print(f"❌ Không tìm thấy file {FILE}!")
        print(f"   Hãy đặt script này cùng thư mục với {FILE}")
        sys.exit(1)

    print(f"📖 Đang đọc {FILE}...")
    with open(FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    original_len = len(content)
    print(f"   Kích thước ban đầu: {original_len} ký tự")

    # ─── 1. Xóa các hàm cũ ───
    funcs = ['telex_encrypt', 'telex_decrypt',
             'vni_encrypt', 'vni_decrypt',
             'viqr_encrypt', 'viqr_decrypt']

    print("🗑️  Đang xóa các hàm cũ...")
    for fn in funcs:
        # Match def fn_name(...): cho tới khi gặp def khác hoặc comment ═══
        pattern = rf'\ndef {fn}\(text, key="[^"]*"\):.*?(?=\ndef |\n# ═{{10,}}|\Z)'
        new_content = re.sub(pattern, '', content, flags=re.DOTALL)
        if new_content != content:
            print(f"   ✅ Đã xóa: {fn}")
            content = new_content
        else:
            print(f"   ⚠️  Không tìm thấy: {fn}")

    # ─── 2. Tìm vị trí chèn (trước NHÓM 9 hoặc NHÓM 10) ───
    print("📍 Đang tìm vị trí chèn code mới...")

    # Thử tìm marker của NHÓM 9, 10, hoặc 11
    markers = [
        '#  NHÓM 9 — ENCODING',
        '#  NHÓM 9 — ENCODING MỞ RỘNG',
        '# NHÓM 9 —',
        '#  NHÓM 10 —',
        '# NHÓM 10 —',
        '#  NHÓM 11 —',
    ]

    insert_pos = -1
    for marker in markers:
        pos = content.find(marker)
        if pos > 0:
            insert_pos = pos
            print(f"   ✅ Tìm thấy marker: {marker}")
            break

    if insert_pos < 0:
        # Fallback: chèn trước METHODS_REGISTRY
        pos = content.find('METHODS_REGISTRY = {')
        if pos > 0:
            insert_pos = pos
            print("   ✅ Chèn trước METHODS_REGISTRY")
        else:
            # Chèn cuối file (trước if __name__)
            pos = content.find("if __name__ == '__main__':")
            if pos > 0:
                insert_pos = pos
                print("   ✅ Chèn trước if __name__")
            else:
                insert_pos = len(content)
                print("   ⚠️  Chèn cuối file")

    # Lùi lại tìm dòng ═══ mở đầu
    line_start = content.rfind('# ═══', 0, insert_pos)
    if line_start > 0 and insert_pos - line_start < 200:
        insert_pos = line_start

    # ─── 3. Chèn code mới ───
    print("💉 Đang chèn code fix...")
    content = content[:insert_pos] + NEW_CODE + '\n\n' + content[insert_pos:]

    # ─── 4. Ghi file ───
    backup = FILE + '.bak'
    print(f"💾 Đang sao lưu bản cũ vào {backup}...")
    with open(backup, 'w', encoding='utf-8') as f:
        f.write(open(FILE, 'r', encoding='utf-8').read())

    print(f"💾 Đang ghi file {FILE}...")
    with open(FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    new_len = len(content)
    print()
    print("═" * 60)
    print(f"✅ HOÀN TẤT!")
    print(f"   Kích thước cũ: {original_len} ký tự")
    print(f"   Kích thước mới: {new_len} ký tự")
    print(f"   Chênh lệch: +{new_len - original_len} ký tự")
    print(f"   Backup: {backup}")
    print("═" * 60)
    print()
    print("📋 Bước tiếp theo:")
    print("   1. Kiểm tra file crypto_utils.py")
    print("   2. Test: python -c \"from crypto_utils import vni_encrypt; print(vni_encrypt('Xin chào các bạn'))\"")
    print("   3. Push: git add crypto_utils.py && git commit -m 'Fix VNI/TELEX/VIQR' && git push")


if __name__ == '__main__':
    main()
