# poi_utils.py — Data bói vui + thơ fallback
import random
from datetime import datetime

# ═══════════════════════════════════════════════
# DATA BÓI VUI
# ═══════════════════════════════════════════════

# Quẻ bói
QUE_BOI = [
    "Cát tường như ý", "Đại cát đại lợi", "Vạn sự hanh thông",
    "Phúc lộc song toàn", "May mắn bất ngờ", "Tiền đồ rộng mở",
    "Hanh thông thuận lợi", "Bình an vô sự", "Như ý cát tường",
    "Thịnh vượng phát tài", "Sự nghiệp hưng thịnh", "Tình duyên viên mãn",
    "Tài lộc dồi dào", "Gia đình hòa thuận", "Sức khỏe dồi dào",
    "Quý nhân phù trợ", "Vạn sự như ý", "Đắc ý mãn nguyện"
]

# Lời khuyên theo chủ đề
LOI_KHUYEN = {
    'tinh_duyen': [
        "Hãy mở lòng, tình yêu sẽ đến khi bạn ít ngờ nhất 💕",
        "Người ấy đang ở rất gần, chỉ chờ bạn nhận ra thôi 🌸",
        "Đừng vội vàng, duyên phận cần thời gian để chín muồi 💗",
        "Hãy là chính mình, người phù hợp sẽ yêu bạn vì điều đó 💖",
        "Tình yêu đích thực không cần phô trương, chỉ cần chân thành 💝",
        "Có thể có chút hiểu lầm, hãy kiên nhẫn lắng nghe nhau 💞",
        "Một mối quan hệ mới đang chờ đón bạn trong thời gian tới 🌹",
        "Người cũ có thể quay lại, nhưng hãy suy nghĩ kỹ trước khi quyết định 💔",
        "Hãy tin vào trực giác của mình, trái tim không bao giờ sai ❤️",
        "Tình cảm của bạn sẽ được đền đáp xứng đáng trong tương lai gần 💐",
    ],
    'su_nghiep': [
        "Cơ hội lớn đang đến, hãy nắm bắt ngay khi có thể 🚀",
        "Sự chăm chỉ của bạn sẽ được đền đáp trong thời gian tới ⭐",
        "Hãy học thêm kỹ năng mới, nó sẽ giúp ích cho bạn 📚",
        "Một dự án mới sẽ mở ra cánh cửa thành công cho bạn 🎯",
        "Đừng sợ thất bại, mỗi lần vấp ngã là một bài học quý 💪",
        "Người dẫn dắt tài ba sẽ xuất hiện giúp bạn thăng tiến 🌟",
        "Hãy tự tin hơn vào khả năng của mình, bạn giỏi hơn bạn nghĩ 🦁",
        "Đầu tư vào bản thân là khoản đầu tư sinh lời nhất 💎",
        "Mối quan hệ công việc sẽ mang lại cho bạn nhiều lợi ích 🤝",
        "Thời điểm chuyển việc đang đến, hãy cân nhắc kỹ 📋",
    ],
    'tai_loc': [
        "Tài lộc đang đến, nhưng hãy chi tiêu khôn ngoan 💰",
        "Một khoản thu nhập bất ngờ đang chờ bạn 🎁",
        "Đầu tư khôn ngoan sẽ sinh lời trong tương lai 📈",
        "Tiết kiệm hôm nay, sung túc ngày mai 💵",
        "Cơ hội kiếm tiền từ sở thích của bạn đang mở ra ✨",
        "Hãy cẩn thận với chi tiêu, tiền vào dễ mà ra cũng dễ ⚠️",
        "Một món quà giá trị sẽ đến từ người thân 💝",
        "Vận may tài chính đang gõ cửa nhà bạn 🏠",
        "Đừng cho vay mượn quá nhiều, giữ tiền cho bản thân 💼",
        "Khoản nợ cũ có thể được giải quyết trong thời gian tới ✅",
    ],
    'suc_khoe': [
        "Sức khỏe của bạn đang tốt, hãy duy trì thói quen lành mạnh 💪",
        "Hãy chú ý đến giấc ngủ, cơ thể cần được nghỉ ngơi 😴",
        "Tập thể dục đều đặn sẽ giúp bạn tràn đầy năng lượng 🏃",
        "Ăn uống lành mạnh, tinh thần sảng khoái 🥗",
        "Đừng thức khuya quá nhiều, sức khỏe là vàng 🌙",
        "Hãy khám sức khỏe định kỳ để yên tâm hơn 🩺",
        "Stress có thể ảnh hưởng, hãy thư giãn nhiều hơn 🧘",
        "Uống đủ nước mỗi ngày, cơ thể sẽ cảm ơn bạn 💧",
        "Hãy dành thời gian cho bản thân nhiều hơn 🌸",
        "Sức khỏe tinh thần quan trọng không kém thể chất 🧠",
    ],
    'hoc_tap': [
        "Sự tập trung cao độ sẽ giúp bạn đạt kết quả tốt 📖",
        "Đừng học vẹt, hãy hiểu sâu vấn đề 🎓",
        "Một người thầy giỏi sẽ xuất hiện trong cuộc đời bạn 👨‍🏫",
        "Kiến thức hôm nay là hành trang ngày mai 🎒",
        "Hãy học từ sai lầm, đó là cách học nhanh nhất 💡",
        "Đam mê sẽ dẫn đường cho bạn đến thành công 🔥",
        "Hãy kiên trì, thành quả không đến trong một sớm một chiều ⏳",
        "Bạn bè cùng tiến sẽ giúp bạn học tốt hơn 👥",
        "Đặt mục tiêu rõ ràng, bạn sẽ đi đúng hướng 🎯",
        "Đọc sách nhiều hơn, mở rộng tầm nhìn 📚",
    ],
}

# Màu may mắn
MAU_MAY_MAN = [
    'Đỏ', 'Cam', 'Vàng', 'Xanh lá', 'Xanh dương',
    'Tím', 'Hồng', 'Trắng', 'Đen', 'Xám',
    'Xanh ngọc', 'Vàng gold', 'Bạc', 'Nâu', 'Be'
]

# Số may mắn
def get_lucky_numbers():
    """3 số may mắn 0-99"""
    return sorted(random.sample(range(0, 100), 3))

# Con giáp may mắn
CON_GIAP = ['Tý', 'Sửu', 'Dần', 'Mão', 'Thìn', 'Tỵ', 'Ngọ', 'Mùi', 'Thân', 'Dậu', 'Tuất', 'Hợi']

# Hướng may mắn
HUONG = ['Đông', 'Tây', 'Nam', 'Bắc', 'Đông Nam', 'Đông Bắc', 'Tây Nam', 'Tây Bắc']

# Giờ hoàng đạo
GIO_HOANG_DAO = [
    'Tý (23h-1h)', 'Sửu (1h-3h)', 'Dần (3h-5h)', 'Mão (5h-7h)',
    'Thìn (7h-9h)', 'Tỵ (9h-11h)', 'Ngọ (11h-13h)', 'Mùi (13h-15h)',
    'Thân (15h-17h)', 'Dậu (17h-19h)', 'Tuất (19h-21h)', 'Hợi (21h-23h)'
]


def boi_vui(chu_de='tinh_duyen', ten=''):
    """
    Trả về kết quả bói vui (fallback khi không có AI).
    chu_de: tinh_duyen | su_nghiep | tai_loc | suc_khoe | hoc_tap
    """
    if chu_de not in LOI_KHUYEN:
        chu_de = 'tinh_duyen'

    return {
        'ten': ten or 'Bạn',
        'chu_de': chu_de,
        'que': random.choice(QUE_BOI),
        'loi_khuyen': random.sample(LOI_KHUYEN[chu_de], min(3, len(LOI_KHUYEN[chu_de]))),
        'mau_may_man': random.choice(MAU_MAY_MAN),
        'so_may_man': get_lucky_numbers(),
        'con_giap': random.choice(CON_GIAP),
        'huong_may_man': random.choice(HUONG),
        'gio_hoang_dao': random.choice(GIO_HOANG_DAO),
        'ngay': datetime.now().strftime('%d/%m/%Y'),
    }


# ═══════════════════════════════════════════════
# THƠ FALLBACK (khi AI lỗi)
# ═══════════════════════════════════════════════
THO_MAU = {
    'tinh_yeu': [
        "Anh gửi em chút nắng chiều\nGió mang theo chút tình yêu ngọt ngào\nDù xa cách biết bao lâu\nTrái tim anh vẫn một màu chờ em.",
        "Em là giấc mộng đêm hè\nLà vầng trăng sáng, là bờ vai êm\nAnh nguyện làm gió bên thềm\nĐưa hương hoa nở dịu êm mỗi ngày.",
    ],
    'que_huong': [
        "Quê hương tôi có con sông\nNước xanh trong vắt, hàng bông trắng ngần\nTuổi thơ theo cánh diều gần\nChiều buông khói bếp, mẹ chờ con về.",
    ],
    'tinh_ban': [
        "Bạn bè như ánh sao trời\nLấp lánh trong tối, sáng ngời niềm tin\nCùng nhau đi khắp hành trình\nBuồn vui chia sẻ, nghĩa tình khó phai.",
    ],
    'cuoc_song': [
        "Cuộc đời như áng mây bay\nLúc bồng bềnh nổi, lúc đầy gió sương\nHãy cười vang khắp nẻo đường\nVì đời chỉ có một lần để yêu.",
    ],
    'thien_nhien': [
        "Mùa xuân chim hót trên cành\nMùa hạ hoa nở thắm xanh nắng vàng\nMùa thu lá úa nhẹ nhàng\nMùa đông tuyết phủ ngỡ ngàng lòng ai.",
    ],
}


def tho_fallback(chu_de='tinh_yeu'):
    """Thơ mẫu khi AI không hoạt động."""
    if chu_de not in THO_MAU:
        chu_de = 'tinh_yeu'

    keywords = {
        'tinh_yeu': 'tình yêu',
        'que_huong': 'quê hương',
        'tinh_ban': 'tình bạn',
        'cuoc_song': 'cuộc sống',
        'thien_nhien': 'thiên nhiên',
    }

    return {
        'chu_de': chu_de,
        'ten_chu_de': keywords.get(chu_de, chu_de),
        'bai_tho': random.choice(THO_MAU[chu_de]),
        'loai': 'thất ngôn bát cú',
    }
