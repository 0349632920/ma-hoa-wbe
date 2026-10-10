"""
Game utilities — Leaderboard, Daily, Rewards, Random, PvP, Meme
"""
import random
import hashlib
from datetime import datetime, timedelta
from crypto_utils import METHODS, ONE_WAY_ONLY


# ═══════════════════════════════════════════════════════════
#  LEVEL SYSTEM
# ═══════════════════════════════════════════════════════════
LEVEL_THRESHOLDS = [
    (0, 1),       # 0-99 điểm → Level 1
    (100, 2),     # 100-249 → Level 2
    (250, 3),     # 250-499 → Level 3
    (500, 4),     # 500-999 → Level 4
    (1000, 5),    # 1000-1999 → Level 5
    (2000, 6),    # 2000-3499 → Level 6
    (3500, 7),    # 3500-5499 → Level 7
    (5500, 8),    # 5500-7999 → Level 8
    (8000, 9),    # 8000-11999 → Level 9
    (12000, 10),  # 12000+ → Level 10
]


def points_to_level(points: int) -> int:
    """Tính level từ điểm."""
    level = 1
    for threshold, lvl in LEVEL_THRESHOLDS:
        if points >= threshold:
            level = lvl
    return level


def level_to_next(points: int) -> dict:
    """Trả về thông tin level hiện tại và level tiếp theo."""
    current_level = points_to_level(points)

    # Tìm ngưỡng tiếp theo
    next_threshold = None
    current_threshold = 0
    for threshold, lvl in LEVEL_THRESHOLDS:
        if lvl == current_level:
            current_threshold = threshold
        if lvl == current_level + 1:
            next_threshold = threshold
            break

    if next_threshold is None:
        # Max level
        return {
            "current_level": current_level,
            "current_points": points,
            "current_threshold": current_threshold,
            "next_threshold": None,
            "progress_pct": 100,
            "points_to_next": 0,
            "is_max": True
        }

    points_in_level = points - current_threshold
    level_range = next_threshold - current_threshold
    progress_pct = round((points_in_level / level_range) * 100, 1)

    return {
        "current_level": current_level,
        "current_points": points,
        "current_threshold": current_threshold,
        "next_threshold": next_threshold,
        "progress_pct": progress_pct,
        "points_to_next": next_threshold - points,
        "is_max": False
    }


# ═══════════════════════════════════════════════════════════
#  DAILY CHALLENGES
# ═══════════════════════════════════════════════════════════
DAILY_CHALLENGES = [
    # (id, method, action, text, expected_pattern, points, description)
    {
        "id": "daily_base64_1",
        "method": "base64",
        "action": "encrypt",
        "text": "Hello World",
        "expected": "SGVsbG8gV29ybGQ=",
        "points": 50,
        "description": "Mã hóa 'Hello World' với Base64"
    },
    {
        "id": "daily_rot13",
        "method": "rot13",
        "action": "encrypt",
        "text": "Python",
        "expected": "Clguba",
        "points": 30,
        "description": "Mã hóa 'Python' với ROT13"
    },
    {
        "id": "daily_morse",
        "method": "morse",
        "action": "encrypt",
        "text": "SOS",
        "expected": "... --- ...",
        "points": 40,
        "description": "Mã hóa 'SOS' với Morse"
    },
    {
        "id": "daily_hex",
        "method": "hex",
        "action": "encrypt",
        "text": "Hi",
        "expected": "48 69",
        "points": 30,
        "description": "Mã hóa 'Hi' với Hex"
    },
    {
        "id": "daily_binary",
        "method": "binary",
        "action": "encrypt",
        "text": "A",
        "expected": "01000001",
        "points": 30,
        "description": "Mã hóa 'A' với Binary"
    },
    {
        "id": "daily_atbash",
        "method": "atbash",
        "action": "encrypt",
        "text": "ABC",
        "expected": "ZYX",
        "points": 40,
        "description": "Mã hóa 'ABC' với Atbash"
    },
    {
        "id": "daily_caesar",
        "method": "caesar",
        "action": "encrypt",
        "text": "Hello",
        "key": "3",
        "expected": "Khoor",
        "points": 40,
        "description": "Mã hóa 'Hello' với Caesar shift 3"
    },
    {
        "id": "daily_reverse",
        "method": "reverse",
        "action": "encrypt",
        "text": "abcde",
        "expected": "edcba",
        "points": 20,
        "description": "Đảo ngược 'abcde'"
    },
    {
        "id": "daily_leet",
        "method": "leet",
        "action": "encrypt",
        "text": "leet",
        "expected": "1337",
        "points": 30,
        "description": "Mã hóa 'leet' với Leet Speak"
    },
    {
        "id": "daily_url",
        "method": "url",
        "action": "encrypt",
        "text": "hello world",
        "expected": "hello%20world",
        "points": 30,
        "description": "URL encode 'hello world'"
    },
]


def get_daily_challenge() -> dict:
    """Lấy challenge của ngày hôm nay (deterministic theo ngày)."""
    today = datetime.now().strftime("%Y-%m-%d")
    # Hash ngày → index ổn định
    hash_val = int(hashlib.md5(today.encode()).hexdigest(), 16)
    idx = hash_val % len(DAILY_CHALLENGES)
    challenge = DAILY_CHALLENGES[idx].copy()
    challenge["date"] = today
    return challenge


# ═══════════════════════════════════════════════════════════
#  ACHIEVEMENTS / REWARDS
# ═══════════════════════════════════════════════════════════
REWARDS = [
    {
        "id": "first_blood",
        "icon": "🥇",
        "name": "First Blood",
        "description": "Hoàn thành daily challenge đầu tiên",
        "points_reward": 100,
        "condition": "daily_count >= 1"
    },
    {
        "id": "week_warrior",
        "icon": "🔥",
        "name": "Week Warrior",
        "description": "Hoàn thành 7 daily challenge",
        "points_reward": 500,
        "condition": "daily_count >= 7"
    },
    {
        "id": "crypto_master",
        "icon": "👑",
        "name": "Crypto Master",
        "description": "Đạt 1000 điểm",
        "points_reward": 200,
        "condition": "points >= 1000"
    },
    {
        "id": "pvp_novice",
        "icon": "⚔️",
        "name": "PvP Novice",
        "description": "Thắng 5 trận PvP",
        "points_reward": 150,
        "condition": "pvp_wins >= 5"
    },
    {
        "id": "pvp_champion",
        "icon": "🏆",
        "name": "PvP Champion",
        "description": "Thắng 20 trận PvP",
        "points_reward": 800,
        "condition": "pvp_wins >= 20"
    },
    {
        "id": "streak_master",
        "icon": "📅",
        "name": "Streak Master",
        "description": "Chuỗi 7 ngày liên tiếp",
        "points_reward": 300,
        "condition": "streak >= 7"
    },
    {
        "id": "meme_lord",
        "icon": "🎨",
        "name": "Meme Lord",
        "description": "Tạo 10 meme",
        "points_reward": 200,
        "condition": "meme_count >= 10"
    },
    {
        "id": "level_5",
        "icon": "⭐",
        "name": "Level 5",
        "description": "Đạt level 5",
        "points_reward": 400,
        "condition": "level >= 5"
    },
]


def check_rewards(game_data: dict) -> list:
    """Kiểm tra user đủ điều kiện nhận reward nào chưa."""
    unlocked = []
    claimed = set(game_data.get("rewards_claimed", []))

    context = {
        "daily_count": len(game_data.get("daily_completed", [])),
        "points": game_data.get("points", 0),
        "pvp_wins": game_data.get("pvp_stats", {}).get("wins", 0),
        "streak": game_data.get("streak", 0),
        "level": points_to_level(game_data.get("points", 0)),
        "meme_count": game_data.get("meme_count", 0),
    }

    for reward in REWARDS:
        if reward["id"] in claimed:
            continue
        # Eval condition đơn giản
        try:
            condition = reward["condition"]
            if eval(condition, {}, context):
                unlocked.append(reward)
        except Exception as e:
            print(f"⚠️ Eval reward error: {e}")

    return unlocked


# ═══════════════════════════════════════════════════════════
#  RANDOM METHOD
# ═══════════════════════════════════════════════════════════
def pick_random_method(exclude_one_way: bool = False, exclude_key: bool = False) -> dict:
    """Chọn ngẫu nhiên 1 phương pháp."""
    methods = list(METHODS.keys())

    if exclude_one_way:
        methods = [m for m in methods if m not in ONE_WAY_ONLY]

    if exclude_key:
        key_methods = {'caesar','affine','vigenere','beaufort','autokey',
                       'playfair','hill','railfence','columnar','xor','aes'}
        methods = [m for m in methods if m not in key_methods]

    method = random.choice(methods)
    return {
        "method": method,
        "name": METHODS[method]
    }


# ═══════════════════════════════════════════════════════════
#  PVP
# ═══════════════════════════════════════════════════════════
# PvP: Mỗi trận đấu gồm 3 challenge
# - Challenge 1: Mã hóa (encrypt)
# - Challenge 2: Giải mã (decrypt)
# - Challenge 3: Đoán phương pháp

def generate_pvp_match() -> dict:
    """Tạo 1 trận PvP với 3 challenge."""
    challenges = []

    # Challenge 1: Mã hóa
    m1 = pick_random_method(exclude_key=False)
    challenges.append({
        "type": "encrypt",
        "method": m1["method"],
        "method_name": m1["name"],
        "text": random.choice(["Hello", "Test", "Secret", "Code", "Game"]),
        "key": "KEY" if m1["method"] in ('vigenere', 'xor') else ""
    })

    # Challenge 2: Giải mã
    m2 = pick_random_method(exclude_one_way=True, exclude_key=False)
    challenges.append({
        "type": "decrypt",
        "method": m2["method"],
        "method_name": m2["name"],
        "text": "",  # Sẽ tạo khi bắt đầu
        "key": ""
    })

    # Challenge 3: Đoán phương pháp
    m3 = pick_random_method(exclude_one_way=True)
    challenges.append({
        "type": "guess",
        "method": m3["method"],
        "method_name": m3["name"],
        "text": random.choice(["Chào bạn", "Xin chào", "Test 123"]),
        "key": ""
    })

    return {
        "id": hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:12],
        "created_at": datetime.now().isoformat(),
        "challenges": challenges
    }


def calculate_pvp_result(player_score: int, opponent_score: int) -> dict:
    """Tính kết quả trận PvP."""
    if player_score > opponent_score:
        return {
            "result": "win",
            "icon": "🏆",
            "message": "Bạn thắng!",
            "points": 100
        }
    elif player_score < opponent_score:
        return {
            "result": "loss",
            "icon": "😢",
            "message": "Bạn thua!",
            "points": 20
        }
    else:
        return {
            "result": "draw",
            "icon": "🤝",
            "message": "Hòa!",
            "points": 50
        }


# ═══════════════════════════════════════════════════════════
#  MEME TEMPLATES
# ═══════════════════════════════════════════════════════════
MEME_TEMPLATES = [
    {
        "id": "drake",
        "name": "Drake Hotline Bling",
        "url": "https://i.imgflip.com/30b1gx.jpg",
        "texts": ["Không dùng Mã Hóa Tool", "Dùng Mã Hóa Tool 🚀"]
    },
    {
        "id": "distracted",
        "name": "Distracted Boyfriend",
        "url": "https://i.imgflip.com/1ur9b0.jpg",
        "texts": ["Tôi", "Code tay", "Mã Hóa Tool ✨"]
    },
    {
        "id": "success",
        "name": "Success Kid",
        "url": "https://i.imgflip.com/1bhk.jpg",
        "texts": ["Encode thành công", "Không bị lỗi"]
    },
    {
        "id": "brain",
        "name": "Expanding Brain",
        "url": "https://i.imgflip.com/1jwhww.jpg",
        "texts": ["Dùng Google", "Dùng tool online", "Dùng Mã Hóa Tool 🧠"]
    },
    {
        "id": "this_is_fine",
        "name": "This is Fine",
        "url": "https://i.imgflip.com/wxica.jpg",
        "texts": ["Quên mật khẩu AES", "Nhưng vẫn còn bình tĩnh"]
    },
]


def generate_meme_template(input_text: str, output_text: str, template_id: str = None) -> dict:
    """Chọn template meme phù hợp."""
    if not template_id:
        template = random.choice(MEME_TEMPLATES)
    else:
        template = next((t for t in MEME_TEMPLATES if t["id"] == template_id), MEME_TEMPLATES[0])

    # Rút gọn text
    def shorten(s, max_len=30):
        s = str(s)
        return s[:max_len] + "..." if len(s) > max_len else s

    return {
        "template": template,
        "texts": [shorten(input_text), shorten(output_text)],
        "generated_at": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════
def init_game_data() -> dict:
    """Tạo game data mặc định cho user mới."""
    return {
        "points": 0,
        "streak": 0,
        "last_daily": None,
        "daily_completed": [],
        "achievements": [],
        "rewards_claimed": [],
        "meme_count": 0,
        "pvp_stats": {
            "wins": 0,
            "losses": 0,
            "draws": 0,
            "total_matches": 0
        },
        "match_history": []
    }


def ensure_game_data(user: dict) -> dict:
    """Đảm bảo user có game data."""
    if "game" not in user:
        user["game"] = init_game_data()
    return user["game"]


def add_points(user: dict, points: int, reason: str = "") -> dict:
    """Cộng điểm cho user."""
    game = ensure_game_data(user)
    game["points"] = game.get("points", 0) + points
    return {
        "points": game["points"],
        "level": points_to_level(game["points"]),
        "added": points,
        "reason": reason
    }


def update_streak(user: dict) -> int:
    """Cập nhật chuỗi ngày liên tiếp."""
    game = ensure_game_data(user)
    today = datetime.now().strftime("%Y-%m-%d")
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

    last = game.get("last_daily")
    if last == today:
        # Đã làm hôm nay rồi
        return game.get("streak", 0)

    if last == yesterday:
        # Liên tiếp
        game["streak"] = game.get("streak", 0) + 1
    else:
        # Đứt chuỗi
        game["streak"] = 1

    game["last_daily"] = today
    return game["streak"]
