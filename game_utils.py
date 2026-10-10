"""
Game utilities — Leaderboard, Daily, Rewards, Random, PvP, Meme
"""
import random
import hashlib
import string
import time
from datetime import datetime, timedelta
from crypto_utils import METHODS, ONE_WAY_ONLY


# ═══════════════════════════════════════════════════════════
#  LEVEL SYSTEM
# ═══════════════════════════════════════════════════════════
LEVEL_THRESHOLDS = [
    (0, 1),
    (100, 2),
    (250, 3),
    (500, 4),
    (1000, 5),
    (2000, 6),
    (3500, 7),
    (5500, 8),
    (8000, 9),
    (12000, 10),
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

    next_threshold = None
    current_threshold = 0
    for threshold, lvl in LEVEL_THRESHOLDS:
        if lvl == current_level:
            current_threshold = threshold
        if lvl == current_level + 1:
            next_threshold = threshold
            break

    if next_threshold is None:
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
#  ⚔️ PVP — NHẬP CHỮ NHANH (3 VÁN × 10 CÂU)
# ═══════════════════════════════════════════════════════════
PVP_ROOMS = {}
ROOM_TTL = 30 * 60  # 30 phút

QUESTIONS_PER_ROUND = 10   # 10 câu / ván
TOTAL_ROUNDS = 3           # 3 ván / trận
POINTS_PER_CORRECT = 100   # Điểm cơ bản mỗi câu đúng
MAX_SPEED_BONUS = 50       # Bonus tối đa cho tốc độ

# Nguồn từ để tạo câu hỏi
PVP_WORDS = [
    "hello", "world", "python", "code", "game", "fast", "type", "quick",
    "speed", "race", "win", "lose", "draw", "match", "player", "arena",
    "champion", "legend", "master", "pro", "elite", "skill", "power",
    "crypto", "cipher", "secret", "encode", "decode", "hack", "secure",
    "keyboard", "mouse", "screen", "monitor", "system", "network",
    "program", "binary", "matrix", "robot", "future", "cyber",
    "tech", "data", "cloud", "server", "client", "kernel", "byte",
    "bit", "logic", "memory", "buffer", "cache", "thread", "process",
    "signal", "packet", "router", "socket", "protocol", "address",
    "port", "firewall", "virus", "encrypt", "decrypt",
    "hash", "salt", "token", "session", "cookie", "login", "logout",
]


def _gen_room_code(length: int = 6) -> str:
    """Tạo mã phòng 6 ký tự không trùng."""
    chars = string.ascii_uppercase + string.digits
    while True:
        code = ''.join(random.choices(chars, k=length))
        if code not in PVP_ROOMS:
            return code


def _gen_questions(count: int) -> list:
    """Tạo `count` câu hỏi random, không lặp từ trong cùng 1 ván."""
    from crypto_utils import (
        base64_encode, rot13, atbash, reverse_str, leet_encode, morse_encode,
        hex_encode, binary_encode, url_encode
    )

    encoder_map = {
        'base64':  base64_encode,
        'rot13':   rot13,
        'atbash':  atbash,
        'reverse': reverse_str,
        'leet':    leet_encode,
        'morse':   morse_encode,
        'hex':     hex_encode,
        'binary':  binary_encode,
        'url':     url_encode,
    }

    # Chọn `count` từ KHÁC NHAU
    words = random.sample(PVP_WORDS, count)

    questions = []
    for word in words:
        method = random.choice(list(encoder_map.keys()))
        encoded = encoder_map[method](word)
        questions.append({
            "word":    word,
            "encoded": encoded,
            "method":  method,
            "display": encoded,
        })
    return questions


def create_pvp_room(host_username: str, host_display: str) -> dict:
    """Tạo phòng PvP mới với 3 ván, mỗi ván 10 câu."""
    cleanup_old_rooms()
    code = _gen_room_code()
    now = time.time()

    # Tạo 3 ván, mỗi ván 10 câu random riêng
    rounds = []
    for r in range(TOTAL_ROUNDS):
        rounds.append({
            "index": r,
            "questions": _gen_questions(QUESTIONS_PER_ROUND),
            "current_index": -1,
            "answers": {},          # { username: { q_index: {...} } }
            "scores": {},           # { username: score }
            "winner": None,         # username thắng ván này
            "question_started_at": None,
            "started_at": None,
        })

    room = {
        "code": code,
        "host": host_username,
        "host_display": host_display,
        "guest": None,
        "guest_display": None,
        "status": "waiting",       # waiting | ready | playing | finished
        "rounds": rounds,
        "current_round": -1,
        "round_wins": {
            host_username: 0,
        },
        "created_at": now,
        "last_activity": now,
        "finished_at": None,
    }
    PVP_ROOMS[code] = room
    return room


def join_pvp_room(code: str, guest_username: str, guest_display: str) -> dict:
    """Guest join phòng."""
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}

    room = PVP_ROOMS[code]

    if room["host"] == guest_username:
        return {"success": False, "error": "Bạn là chủ phòng này!"}

    if room["guest"] is not None and room["guest"] != guest_username:
        return {"success": False, "error": "Phòng đã đầy!"}

    if room["status"] not in ("waiting", "ready"):
        return {"success": False, "error": "Phòng đang chơi!"}

    room["guest"] = guest_username
    room["guest_display"] = guest_display
    room["status"] = "ready"
    room["round_wins"][guest_username] = 0
    room["last_activity"] = time.time()

    return {"success": True, "room": room}


def start_pvp_room(code: str, host_username: str) -> dict:
    """Host bắt đầu trận đấu → bắt đầu ván 1."""
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}

    room = PVP_ROOMS[code]

    if room["host"] != host_username:
        return {"success": False, "error": "Chỉ chủ phòng mới bắt đầu!"}

    if not room["guest"]:
        return {"success": False, "error": "Chưa có đối thủ!"}

    if room["status"] != "ready":
        return {"success": False, "error": "Không thể bắt đầu!"}

    # Bắt đầu ván 1
    room["status"] = "playing"
    room["current_round"] = 0

    r = room["rounds"][0]
    r["current_index"] = 0
    r["question_started_at"] = time.time()
    r["started_at"] = time.time()
    r["answers"] = {
        room["host"]: {},
        room["guest"]: {},
    }
    r["scores"] = {
        room["host"]: 0,
        room["guest"]: 0,
    }

    room["last_activity"] = time.time()
    return {"success": True, "room": room}


def submit_pvp_answer(code: str, username: str, answer: str) -> dict:
    """Nộp đáp án cho câu hỏi hiện tại."""
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}

    room = PVP_ROOMS[code]

    if room["status"] != "playing":
        return {"success": False, "error": "Chưa bắt đầu!"}

    if username not in (room["host"], room["guest"]):
        return {"success": False, "error": "Bạn không ở trong phòng!"}

    round_idx = room["current_round"]
    if round_idx < 0 or round_idx >= TOTAL_ROUNDS:
        return {"success": False, "error": "Ván không hợp lệ!"}

    r = room["rounds"][round_idx]
    q_idx = r["current_index"]

    if q_idx < 0 or q_idx >= QUESTIONS_PER_ROUND:
        return {"success": False, "error": "Câu hỏi không hợp lệ!"}

    # Đã trả lời câu này chưa?
    if q_idx in r["answers"].get(username, {}):
        return {"success": False, "error": "Đã trả lời câu này!"}

    # Tính thời gian
    time_taken = round(time.time() - r["question_started_at"], 2)

    # So sánh đáp án
    correct_answer = r["questions"][q_idx]["word"].lower().strip()
    user_answer = answer.lower().strip()
    correct = (user_answer == correct_answer)

    # Điểm
    points = 0
    if correct:
        speed_bonus = max(0, int(MAX_SPEED_BONUS - time_taken * 2))
        points = POINTS_PER_CORRECT + speed_bonus

    # Lưu đáp án
    r["answers"][username][q_idx] = {
        "answer": answer,
        "correct": correct,
        "time_taken": time_taken,
        "points": points,
    }
    r["scores"][username] = r["scores"].get(username, 0) + points
    room["last_activity"] = time.time()

    # Cả 2 đã trả lời câu này chưa?
    host_answered = q_idx in r["answers"].get(room["host"], {})
    guest_answered = q_idx in r["answers"].get(room["guest"], {})

    if host_answered and guest_answered:
        # Chuyển câu tiếp
        r["current_index"] += 1

        if r["current_index"] >= QUESTIONS_PER_ROUND:
            # Hết ván → xác định người thắng ván
            host_score = r["scores"].get(room["host"], 0)
            guest_score = r["scores"].get(room["guest"], 0)

            if host_score > guest_score:
                r["winner"] = room["host"]
                room["round_wins"][room["host"]] += 1
            elif host_score < guest_score:
                r["winner"] = room["guest"]
                room["round_wins"][room["guest"]] += 1
            else:
                r["winner"] = None  # Hòa ván

            # Kiểm tra đã đủ 3 ván chưa
            if round_idx + 1 >= TOTAL_ROUNDS:
                # Kết thúc trận
                room["status"] = "finished"
                room["finished_at"] = time.time()
            else:
                # Chuẩn bị ván tiếp theo
                room["current_round"] = round_idx + 1
                next_round = room["rounds"][round_idx + 1]
                next_round["current_index"] = 0
                next_round["question_started_at"] = time.time() + 3  # +3s delay
                next_round["started_at"] = time.time() + 3
                next_round["answers"] = {
                    room["host"]: {},
                    room["guest"]: {},
                }
                next_round["scores"] = {
                    room["host"]: 0,
                    room["guest"]: 0,
                }
        else:
            # Câu tiếp theo trong cùng ván
            r["question_started_at"] = time.time()

    return {
        "success": True,
        "correct": correct,
        "points": points,
        "time_taken": time_taken,
        "room": room,
    }


def get_pvp_room(code: str) -> dict:
    """Lấy trạng thái phòng."""
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    return {"success": True, "room": PVP_ROOMS[code]}


def leave_pvp_room(code: str, username: str) -> dict:
    """Rời phòng."""
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": True}

    room = PVP_ROOMS[code]

    if room["host"] == username:
        # Host rời → xóa phòng
        del PVP_ROOMS[code]
        return {"success": True, "destroyed": True}

    if room["guest"] == username:
        # Guest rời → reset phòng
        room["guest"] = None
        room["guest_display"] = None
        room["status"] = "waiting"
        room["current_round"] = -1
        room["round_wins"] = {room["host"]: 0}
        for r in room["rounds"]:
            r["current_index"] = -1
            r["answers"] = {}
            r["scores"] = {}
            r["winner"] = None
            r["question_started_at"] = None
        return {"success": True}

    return {"success": True}


def cleanup_old_rooms():
    """Xóa phòng quá cũ (không hoạt động > 30 phút)."""
    now = time.time()
    to_delete = []
    for code, room in PVP_ROOMS.items():
        if now - room.get("last_activity", 0) > ROOM_TTL:
            to_delete.append(code)
    for code in to_delete:
        del PVP_ROOMS[code]
    return len(to_delete)


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
        return game.get("streak", 0)

    if last == yesterday:
        game["streak"] = game.get("streak", 0) + 1
    else:
        game["streak"] = 1

    game["last_daily"] = today
    return game["streak"]
