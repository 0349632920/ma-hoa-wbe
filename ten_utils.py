# ten_utils.py — Từ điển Hán Việt + logic chế tên (FALLBACK khi AI lỗi)
import random

# ═══════════════════════════════════════════════
# TỪ ĐIỂN HÁN VIỆT — 200+ âm tiết phổ biến
# ═══════════════════════════════════════════════
TEN_DICT = {
    # ═══ Trí tuệ / Học vấn ═══
    'trí': ['trí tuệ', 'thông minh', 'sáng suốt', 'hiểu biết', 'khôn ngoan'],
    'minh': ['sáng suốt', 'minh mẫn', 'hiểu biết', 'sáng tỏ'],
    'tuệ': ['trí tuệ', 'thông thái', 'sáng suốt'],
    'học': ['học thức', 'hiếu học', 'tri thức'],
    'văn': ['văn chương', 'học thức', 'văn minh', 'lịch sự'],
    'khoa': ['khoa học', 'tri thức', 'hiểu biết'],
    'tuấn': ['tuấn tú', 'khôi ngô', 'tài hoa', 'xuất chúng'],
    'tài': ['tài năng', 'tài giỏi', 'xuất sắc'],
    'năng': ['năng lực', 'tài năng', 'khả năng'],
    'kiến': ['kiến thức', 'hiểu biết', 'tầm nhìn'],

    # ═══ Dũng cảm / Mạnh mẽ ═══
    'dũng': ['dũng cảm', 'gan dạ', 'mạnh mẽ', 'kiên cường'],
    'hùng': ['hùng mạnh', 'oai phong', 'vĩ đại', 'uy nghi'],
    'mạnh': ['mạnh mẽ', 'cường tráng', 'vững vàng'],
    'cường': ['cường mạnh', 'kiên cường', 'mạnh mẽ'],
    'kiên': ['kiên định', 'kiên cường', 'vững chí'],
    'quyết': ['quyết đoán', 'dứt khoát', 'cương quyết'],
    'chiến': ['chiến đấu', 'chiến thắng', 'dũng mãnh'],
    'võ': ['võ công', 'vũ dũng', 'mạnh mẽ'],
    'sơn': ['núi cao', 'vững chãi', 'hùng vĩ'],

    # ═══ Anh hùng / Vĩ đại ═══
    'anh': ['anh hùng', 'tài giỏi', 'xuất chúng'],
    'hào': ['hào kiệt', 'anh hùng', 'xuất chúng'],
    'kiệt': ['kiệt xuất', 'tài ba', 'xuất chúng'],
    'vĩ': ['vĩ đại', 'to lớn', 'vĩ nhân'],
    'đại': ['vĩ đại', 'to lớn', 'cao cả'],
    'long': ['rồng thiêng', 'cao quý', 'mạnh mẽ'],
    'phượng': ['phượng hoàng', 'cao quý', 'rực rỡ'],
    'hổ': ['mãnh hổ', 'dũng mãnh', 'uy vũ'],
    'bảo': ['bảo vật', 'quý giá', 'trân quý'],
    'quốc': ['quốc gia', 'đất nước', 'tổ quốc'],
    'dân': ['nhân dân', 'dân tộc', 'con người'],

    # ═══ Đức hạnh / Phẩm chất ═══
    'đức': ['đạo đức', 'phẩm hạnh', 'cao cả'],
    'nhân': ['nhân từ', 'lòng nhân', 'nhân ái'],
    'nghĩa': ['nghĩa khí', 'chính nghĩa', 'tình nghĩa'],
    'lễ': ['lễ nghĩa', 'lịch sự', 'kính trọng'],
    'tín': ['tín nghĩa', 'uy tín', 'đáng tin'],
    'trung': ['trung thành', 'trung nghĩa', 'thủy chung'],
    'hiếu': ['hiếu thảo', 'hiếu nghĩa', 'kính mến'],
    'thiện': ['thiện lương', 'tốt lành', 'lương thiện'],
    'lương': ['lương thiện', 'tốt đẹp', 'hiền lành'],
    'hòa': ['hòa nhã', 'hòa hợp', 'thân thiện'],
    'an': ['an lành', 'bình an', 'yên ổn'],
    'bình': ['bình an', 'thanh bình', 'yên tĩnh'],
    'phúc': ['phúc lành', 'may mắn', 'hạnh phúc'],
    'lộc': ['tài lộc', 'may mắn', 'phú quý'],
    'thọ': ['trường thọ', 'sống lâu', 'bền bỉ'],

    # ═══ Sắc đẹp / Tươi sáng ═══
    'châu': ['châu báu', 'quý giá', 'ngọc quý'],
    'ngọc': ['ngọc quý', 'trong sáng', 'quý giá'],
    'kim': ['vàng quý', 'kim cương', 'quý giá'],
    'hồng': ['hồng hào', 'tươi đẹp', 'rực rỡ'],
    'lan': ['hoa lan', 'cao quý', 'thanh tao'],
    'mai': ['hoa mai', 'tươi đẹp', 'thanh khiết'],
    'đào': ['hoa đào', 'tươi thắm', 'duyên dáng'],
    'quỳnh': ['hoa quỳnh', 'thanh tao', 'quý phái'],
    'thúy': ['xinh đẹp', 'duyên dáng', 'thanh tú'],
    'diễm': ['diễm lệ', 'xinh đẹp', 'lộng lẫy'],
    'lệ': ['xinh đẹp', 'kiều diễm', 'yêu kiều'],
    'kiều': ['kiều diễm', 'xinh đẹp', 'duyên dáng'],
    'yên': ['yên bình', 'thanh thản', 'dịu dàng'],
    'thu': ['mùa thu', 'dịu dàng', 'thanh tao'],
    'xuân': ['mùa xuân', 'tươi trẻ', 'sức sống'],
    'tuyết': ['tuyết trắng', 'tinh khôi', 'trong sạch'],

    # ═══ Ánh sáng / Rạng rỡ ═══
    'quang': ['ánh sáng', 'rạng rỡ', 'quang minh'],
    'dương': ['mặt trời', 'ánh dương', 'tỏa sáng'],
    'nhật': ['mặt trời', 'ánh sáng', 'rạng đông'],
    'huy': ['rực rỡ', 'huy hoàng', 'sáng chói'],
    'hoàng': ['huy hoàng', 'rực rỡ', 'cao quý'],
    'ngân': ['bạc', 'sáng bóng', 'quý giá'],
    'tinh': ['tinh tú', 'trong sáng', 'tinh anh'],
    'sao': ['ngôi sao', 'tỏa sáng', 'rực rỡ'],

    # ═══ Tình cảm / Tâm hồn ═══
    'tâm': ['tấm lòng', 'trái tim', 'tâm hồn'],
    'tình': ['tình cảm', 'yêu thương', 'tình nghĩa'],
    'ái': ['yêu thương', 'thương yêu', 'ái tình'],
    'thương': ['yêu thương', 'thương mến', 'nhân từ'],
    'duyên': ['duyên phận', 'may mắn', 'duyên dáng'],
    'hạnh': ['hạnh phúc', 'may mắn', 'phúc lành'],

    # ═══ Khát vọng / Ý chí ═══
    'chí': ['ý chí', 'chí hướng', 'hoài bão'],
    'khát': ['khát vọng', 'khao khát', 'mong mỏi'],
    'vọng': ['khát vọng', 'hi vọng', 'mong ước'],
    'ước': ['ước mơ', 'mong ước', 'hi vọng'],
    'mơ': ['giấc mơ', 'ước mơ', 'khát vọng'],
    'hi': ['hi vọng', 'mong đợi', 'ước mong'],

    # ═══ Tự nhiên ═══
    'hà': ['sông nước', 'dòng sông', 'mênh mông'],
    'giang': ['sông lớn', 'mênh mông', 'bao la'],
    'hải': ['biển cả', 'mênh mông', 'sâu thẳm'],
    'lâm': ['rừng xanh', 'cây cối', 'tươi mát'],
    'phong': ['gió lớn', 'phóng khoáng', 'tự do'],
    'vân': ['mây trời', 'thanh cao', 'nhẹ nhàng'],
    'tuyền': ['suối mát', 'trong lành', 'tinh khiết'],
    'thủy': ['nước', 'suối', 'mềm mại'],
    'điền': ['ruộng đồng', 'đất đai', 'no ấm'],
    'địa': ['đất đai', 'vững chãi', 'địa linh'],

    # ═══ Tài lộc / Phú quý ═══
    'phú': ['phú quý', 'giàu có', 'sung túc'],
    'quý': ['quý giá', 'cao quý', 'đáng trọng'],
    'thịnh': ['thịnh vượng', 'phát đạt', 'hưng thịnh'],
    'vượng': ['hưng vượng', 'phát đạt', 'thịnh vượng'],
    'tấn': ['tấn tới', 'phát triển', 'tiến bộ'],
    'phát': ['phát triển', 'phát đạt', 'tiến bộ'],

    # ═══ Khác ═══
    'nam': ['phương Nam', 'mạnh mẽ', 'nam nhi'],
    'bắc': ['phương Bắc', 'vững chãi', 'kiên cường'],
    'đông': ['phương Đông', 'rực rỡ', 'sức sống'],
    'tây': ['phương Tây', 'mới mẻ', 'hiện đại'],
    'kỳ': ['kỳ diệu', 'phi thường', 'kỳ vĩ'],
    'diệu': ['kỳ diệu', 'huyền diệu', 'tuyệt vời'],
    'thần': ['thần kỳ', 'linh thiêng', 'siêu phàm'],
    'tiên': ['tiên cảnh', 'thanh cao', 'đẹp đẽ'],
    'thánh': ['thánh thiện', 'cao cả', 'thiêng liêng'],
    'vương': ['vua', 'vương giả', 'cao quý'],
    'đế': ['hoàng đế', 'tối cao', 'vĩ đại'],
    'hậu': ['hoàng hậu', 'cao quý', 'xinh đẹp'],
    'công': ['công lao', 'công đức', 'thành tựu'],
    'thành': ['thành công', 'thành đạt', 'viên mãn'],
    'đạt': ['đạt được', 'thành đạt', 'viên mãn'],

    # ═══ Tên đơn âm phổ biến khác ═══
    'linh': ['linh thiêng', 'thông minh', 'nhanh nhẹn'],
    'trang': ['trang nghiêm', 'đoan trang', 'trang nhã'],
    'nga': ['xinh đẹp', 'kiều diễm', 'duyên dáng'],
    'thảo': ['hiền thảo', 'cỏ thơm', 'dịu dàng'],
    'vy': ['nhỏ nhắn', 'xinh xắn', 'đáng yêu'],
    'my': ['xinh đẹp', 'đáng yêu', 'dễ thương'],
    'nhi': ['nhỏ nhắn', 'đáng yêu', 'xinh xắn'],
    'thư': ['thư thái', 'thư giãn', 'thanh thản'],
    'khang': ['khỏe mạnh', 'an khang', 'thịnh vượng'],
    'lực': ['sức mạnh', 'năng lực', 'mạnh mẽ'],
    'tùng': ['cây tùng', 'vững chãi', 'kiên cường'],
    'bách': ['cây bách', 'trường thọ', 'bền bỉ'],
    'trúc': ['cây trúc', 'thanh cao', 'ngay thẳng'],
    'cúc': ['hoa cúc', 'thanh khiết', 'cao quý'],
    'nhàn': ['thanh nhàn', 'thư thái', 'an nhàn'],
    'thanh': ['thanh khiết', 'trong sạch', 'thanh cao'],
    'tịnh': ['yên tĩnh', 'thanh tịnh', 'bình yên'],
    'bích': ['ngọc bích', 'xanh biếc', 'quý giá'],
    'lam': ['xanh lam', 'thanh khiết', 'dịu dàng'],
}


# ═══════════════════════════════════════════════
# TEMPLATE CÂU — 3 CHẾ ĐỘ
# ═══════════════════════════════════════════════

NGHIEM_TEMPLATES = [
    "{A} kết hợp cùng {B} — người {a} và {b}.",
    "Mang trong mình {a} cùng {b}.",
    "Hội tụ cả {a} lẫn {b}.",
    "Một con người vừa {a} vừa {b}.",
    "{A} và {B} hòa quyện — {a} cùng {b}.",
    "Tên gọi chứa đựng {a} và {b}.",
    "Được phú cho {a}, lại thêm {b}.",
    "Kết tinh của {a} và {b}.",
]

NGAU_TEMPLATES = [
    "⚔️ {A} Chi Thần kết hợp cùng {B} Bất Khuất — Bậc thầy của {a} và {b}.",
    "👑 Huyền thoại {a} tái thế, cùng {b} tuyệt đỉnh — Đế vương bất bại!",
    "🔥 Sở hữu {a} vô song và {b} vô địch — Kẻ thống trị mọi chiến trường!",
    "⚡ {A} Tối Thượng + {B} Vô Song = Chiến thần huyền thoại của {a} và {b}!",
    "🌟 Vị thần {a} giáng thế, mang theo {b} tuyệt đối — Không ai sánh bằng!",
    "💎 {A} Đại Đế + {B} Bá Vương — Đỉnh cao của {a} và {b}!",
    "🐉 Rồng thiêng {a} hóa thân, cùng {b} bất diệt — Uy chấn thiên hạ!",
    "⚔️ {A} Kiếm Thánh + {B} Đao Vương = Bất khả chiến bại với {a} và {b}!",
    "👊 Sức mạnh {a} vô đối + {b} tuyệt luân — Kẻ hủy diệt mọi giới hạn!",
    "🏆 {A} Vô Địch + {B} Trường Tồn — Huyền thoại {a} và {b} sống mãi!",
]

MIX_TEMPLATES = NGHIEM_TEMPLATES + NGAU_TEMPLATES + [
    "😎 {A} thì {a}, {B} thì {b} — Vậy rốt cuộc là {a} hay {b}?",
    "🤔 {A} hay {B}? Nhưng bạn có cả {a} lẫn {b} — Gọi là... {a} + {b}!",
    "😂 {A} {a} mà {B} {b} — Bạn là {a} {b} chính hiệu!",
    "🎭 Nửa {a}, nửa {b} — Bạn là phiên bản {a} + {b} độc nhất vô nhị!",
    "✨ {A} + {B} = {a} × {b} — Công thức độc quyền của bạn!",
]


def _lookup_meaning(part):
    """Tra nghĩa của 1 âm tiết."""
    part_lower = part.lower().strip()
    if part_lower in TEN_DICT:
        return random.choice(TEN_DICT[part_lower])
    return part_lower


def _split_name(full_name):
    """Tách tên thành các âm tiết."""
    return [p.strip() for p in full_name.strip().split() if p.strip()]


def _title_case(s):
    """Viết hoa chữ đầu."""
    return s[0].upper() + s[1:] if s else s


def generate_name(full_name, mode='nghiem'):
    """
    Chế tên bằng từ điển tĩnh (FALLBACK).
    mode: 'nghiem' | 'ngau' | 'mix'
    """
    parts = _split_name(full_name)
    if not parts:
        return {'error': 'Vui lòng nhập tên!'}

    if len(parts) == 1:
        parts = [parts[0], parts[0]]

    first = parts[0]
    last = parts[-1]

    a = _lookup_meaning(first)
    b = _lookup_meaning(last)

    A = _title_case(first)
    B = _title_case(last)

    if mode == 'nghiem':
        templates = NGHIEM_TEMPLATES
    elif mode == 'ngau':
        templates = NGAU_TEMPLATES
    else:
        templates = MIX_TEMPLATES

    chosen = random.sample(templates, min(3, len(templates)))

    results = []
    for tpl in chosen:
        try:
            results.append(tpl.format(A=A, B=B, a=a, b=b))
        except Exception:
            continue

    meanings = [{'part': _title_case(p), 'meaning': _lookup_meaning(p)} for p in parts]

    return {
        'name': full_name.strip(),
        'parts': parts,
        'meanings': meanings,
        'results': results,
        'mode': mode,
    }
