"""
Game utilities — Leaderboard, Daily, Rewards, Random, PvP (typing race + AFK), Meme
"""
import random
import hashlib
import string
import time
import os
import json
from datetime import datetime, timedelta
from crypto_utils import METHODS, ONE_WAY_ONLY


# ═══════════════════════════════════════════════════════════
#  LEVEL SYSTEM
# ═══════════════════════════════════════════════════════════
LEVEL_THRESHOLDS = [
    (0, 1), (100, 2), (250, 3), (500, 4), (1000, 5),
    (2000, 6), (3500, 7), (5500, 8), (8000, 9), (12000, 10),
]


def points_to_level(points: int) -> int:
    level = 1
    for threshold, lvl in LEVEL_THRESHOLDS:
        if points >= threshold:
            level = lvl
    return level


def level_to_next(points: int) -> dict:
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
            "current_level": current_level, "current_points": points,
            "current_threshold": current_threshold, "next_threshold": None,
            "progress_pct": 100, "points_to_next": 0, "is_max": True
        }
    points_in_level = points - current_threshold
    level_range = next_threshold - current_threshold
    return {
        "current_level": current_level, "current_points": points,
        "current_threshold": current_threshold, "next_threshold": next_threshold,
        "progress_pct": round((points_in_level / level_range) * 100, 1),
        "points_to_next": next_threshold - points, "is_max": False
    }


# ═══════════════════════════════════════════════════════════
#  DAILY CHALLENGES
# ═══════════════════════════════════════════════════════════
DAILY_CHALLENGES = [
    {"id": "d1", "method": "base64", "action": "encrypt", "text": "Hello World", "expected": "SGVsbG8gV29ybGQ=", "points": 50, "description": "Mã hóa 'Hello World' với Base64"},
    {"id": "d2", "method": "rot13", "action": "encrypt", "text": "Python", "expected": "Clguba", "points": 30, "description": "Mã hóa 'Python' với ROT13"},
    {"id": "d3", "method": "morse", "action": "encrypt", "text": "SOS", "expected": "... --- ...", "points": 40, "description": "Mã hóa 'SOS' với Morse"},
    {"id": "d4", "method": "hex", "action": "encrypt", "text": "Hi", "expected": "48 69", "points": 30, "description": "Mã hóa 'Hi' với Hex"},
    {"id": "d5", "method": "binary", "action": "encrypt", "text": "A", "expected": "01000001", "points": 30, "description": "Mã hóa 'A' với Binary"},
    {"id": "d6", "method": "atbash", "action": "encrypt", "text": "ABC", "expected": "ZYX", "points": 40, "description": "Mã hóa 'ABC' với Atbash"},
    {"id": "d7", "method": "caesar", "action": "encrypt", "text": "Hello", "key": "3", "expected": "Khoor", "points": 40, "description": "Mã hóa 'Hello' với Caesar shift 3"},
    {"id": "d8", "method": "reverse", "action": "encrypt", "text": "abcde", "expected": "edcba", "points": 20, "description": "Đảo ngược 'abcde'"},
    {"id": "d9", "method": "leet", "action": "encrypt", "text": "leet", "expected": "1337", "points": 30, "description": "Mã hóa 'leet' với Leet Speak"},
    {"id": "d10", "method": "url", "action": "encrypt", "text": "hello world", "expected": "hello%20world", "points": 30, "description": "URL encode 'hello world'"},
]


def get_daily_challenge() -> dict:
    today = datetime.now().strftime("%Y-%m-%d")
    hash_val = int(hashlib.md5(today.encode()).hexdigest(), 16)
    idx = hash_val % len(DAILY_CHALLENGES)
    challenge = DAILY_CHALLENGES[idx].copy()
    challenge["date"] = today
    return challenge


# ═══════════════════════════════════════════════════════════
#  REWARDS
# ═══════════════════════════════════════════════════════════
REWARDS = [
    {"id": "first_blood", "icon": "🥇", "name": "First Blood", "description": "Hoàn thành daily đầu tiên", "points_reward": 100, "condition": "daily_count >= 1"},
    {"id": "week_warrior", "icon": "🔥", "name": "Week Warrior", "description": "7 daily challenge", "points_reward": 500, "condition": "daily_count >= 7"},
    {"id": "crypto_master", "icon": "👑", "name": "Crypto Master", "description": "Đạt 1000 điểm", "points_reward": 200, "condition": "points >= 1000"},
    {"id": "pvp_novice", "icon": "⚔️", "name": "PvP Novice", "description": "Thắng 5 trận PvP", "points_reward": 150, "condition": "pvp_wins >= 5"},
    {"id": "pvp_champion", "icon": "🏆", "name": "PvP Champion", "description": "Thắng 20 trận PvP", "points_reward": 800, "condition": "pvp_wins >= 20"},
    {"id": "streak_master", "icon": "📅", "name": "Streak Master", "description": "Chuỗi 7 ngày liên tiếp", "points_reward": 300, "condition": "streak >= 7"},
    {"id": "meme_lord", "icon": "🎨", "name": "Meme Lord", "description": "Tạo 10 meme", "points_reward": 200, "condition": "meme_count >= 10"},
    {"id": "level_5", "icon": "⭐", "name": "Level 5", "description": "Đạt level 5", "points_reward": 400, "condition": "level >= 5"},
]


def check_rewards(game_data: dict) -> list:
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
            if eval(reward["condition"], {}, context):
                unlocked.append(reward)
        except Exception as e:
            print(f"⚠️ Eval reward error: {e}")
    return unlocked


# ═══════════════════════════════════════════════════════════
#  RANDOM METHOD
# ═══════════════════════════════════════════════════════════
def pick_random_method(exclude_one_way: bool = False, exclude_key: bool = False) -> dict:
    methods = list(METHODS.keys())
    if exclude_one_way:
        methods = [m for m in methods if m not in ONE_WAY_ONLY]
    if exclude_key:
        key_methods = {'caesar','affine','vigenere','beaufort','autokey',
                       'playfair','hill','railfence','columnar','xor','aes'}
        methods = [m for m in methods if m not in key_methods]
    method = random.choice(methods)
    return {"method": method, "name": METHODS[method]}


# ═══════════════════════════════════════════════════════════
#  PVP ROOMS
# ═══════════════════════════════════════════════════════════
PVP_ROOMS = {}
FRIENDS_DB = {}
FRIEND_REQUESTS = []

ROOM_TTL = 30 * 60
DEFAULT_QUESTIONS = 10
DEFAULT_ROUNDS = 3
POINTS_PER_CORRECT = 100
MAX_SPEED_BONUS = 50

# ⏰ AFK
AFK_TIMEOUT = 30          # AFK >= 30s → kick
AFK_WARNING_AT = 20       # Cảnh báo sớm 20s
AFK_WARNING_INTERVAL = 10 # Nhắc lại cảnh báo mỗi 10s

# Danh sách từ tiếng Anh để đua gõ
PVP_WORDS = [
    "hello", "world", "code", "game", "fast", "type", "quick", "speed",
    "race", "win", "lose", "draw", "match", "player", "arena", "skill",
    "power", "byte", "bit", "hash", "salt", "token", "port", "packet",
    "socket", "router", "client", "server", "cloud", "data", "matrix",
    "robot", "cyber", "future", "system", "memory", "buffer", "cache",
    "thread", "signal", "network", "kernel", "process", "input", "output",
    "string", "number", "letter", "word", "text", "file", "path", "link",
    "python", "cipher", "secret", "encode", "decode", "secure",
    "monitor", "program", "binary", "legend", "master", "champion",
    "elite", "crypto", "hacker", "developer", "engineer", "algorithm",
    "computer", "keyboard", "function", "variable", "operator",
    "database", "internet", "browser", "website", "application",
    "software", "hardware", "protocol", "security", "firewall",
    "learning", "thinking", "creating", "building", "working",
    "playing", "winning", "typing", "running", "coding", "gaming",
    "hacking", "testing", "writing", "reading", "speaking",
    "encryption", "decryption", "programming", "javascript",
    "typescript", "framework", "structure",
    "connection", "networking", "challenge", "adventure",
    "creative", "carefully", "beautiful", "wonderful",
]


def _gen_room_code(length: int = 6) -> str:
    chars = string.ascii_uppercase + string.digits
    while True:
        code = ''.join(random.choices(chars, k=length))
        if code not in PVP_ROOMS:
            return code


def _gen_questions(count: int) -> list:
    if count > len(PVP_WORDS):
        count = len(PVP_WORDS)
    words = random.sample(PVP_WORDS, count)
    return [{"word": w, "display": w} for w in words]


def load_users_from_db() -> dict:
    """Load users từ DB hoặc JSON."""
    DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
    if DATABASE_URL:
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT username, data FROM users")
                    rows = cur.fetchall()
                    return {row['username']: row['data'] for row in rows}
            finally:
                conn.close()
        except Exception as e:
            print(f"⚠️ Lỗi load users: {e}")
    if not os.path.exists('users.json'):
        return {}
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Lỗi đọc JSON: {e}")
        return {}


def save_user_to_db(username: str, user_data: dict):
    """Lưu user vào DB hoặc JSON."""
    DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
    if DATABASE_URL:
        try:
            import psycopg2
            from psycopg2.extras import Json
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (username, data, updated_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (username)
                        DO UPDATE SET 
                            data = EXCLUDED.data,
                            updated_at = NOW()
                    """, (username, Json(user_data)))
                conn.commit()
                return
            finally:
                conn.close()
        except Exception as e:
            print(f"❌ Lỗi save_user_to_db: {e}")
    try:
        users = load_users_from_db()
        users[username] = user_data
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"❌ Lỗi ghi JSON: {e}")


def _save_afk_match_history(room, winner, loser, users):
    """Lưu lịch sử khi 1 người bị kick vì AFK."""
    try:
        # Winner
        if winner in users:
            game = ensure_game_data(users[winner])
            history = game.get("match_history", [])
            history.insert(0, {
                "opponent": room.get("guest_display") if winner == room["host"] else room.get("host_display"),
                "my_score": room["round_wins"].get(winner, 0),
                "opp_score": 0,
                "my_rounds": room["round_wins"].get(winner, 0),
                "opp_rounds": 0,
                "result": "win",
                "reason": "opponent_afk",
                "time": datetime.now().isoformat(),
            })
            game["match_history"] = history[:20]
            stats = game.setdefault("pvp_stats", {"wins": 0, "losses": 0, "draws": 0, "total_matches": 0})
            stats["wins"] = stats.get("wins", 0) + 1
            stats["total_matches"] = stats.get("total_matches", 0) + 1
            save_user_to_db(winner, users[winner])

        # Loser
        if loser in users:
            game = ensure_game_data(users[loser])
            history = game.get("match_history", [])
            history.insert(0, {
                "opponent": room.get("host_display") if loser == room["guest"] else room.get("guest_display"),
                "my_score": 0,
                "opp_score": room["round_wins"].get(winner, 0),
                "my_rounds": 0,
                "opp_rounds": room["round_wins"].get(winner, 0),
                "result": "loss",
                "reason": "afk",
                "time": datetime.now().isoformat(),
            })
            game["match_history"] = history[:20]
            stats = game.setdefault("pvp_stats", {"wins": 0, "losses": 0, "draws": 0, "total_matches": 0})
            stats["losses"] = stats.get("losses", 0) + 1
            stats["total_matches"] = stats.get("total_matches", 0) + 1
            game["afk_warnings_count"] = game.get("afk_warnings_count", 0) + 1
            save_user_to_db(loser, users[loser])
    except Exception as e:
        print(f"⚠️ Lỗi lưu lịch sử AFK: {e}")


# ─── 1. Danh sách phòng public ───
def list_public_rooms() -> list:
    cleanup_old_rooms()
    result = []
    now = time.time()
    for code, room in PVP_ROOMS.items():
        if not room.get("is_public", True): continue
        if room["status"] not in ("waiting", "ready"): continue
        result.append({
            "code": code,
            "host": room["host"],
            "host_display": room["host_display"],
            "host_level": room.get("host_level", 1),
            "guest": room["guest"],
            "guest_display": room["guest_display"],
            "status": room["status"],
            "rules": room.get("rules", {}),
            "created_at": room["created_at"],
            "age_minutes": round((now - room["created_at"]) / 60, 1),
            "slots": 2,
            "players_count": 1 + (1 if room.get("guest") else 0),
        })
    result.sort(key=lambda x: -x["created_at"])
    return result


def broadcast_player_joined(code: str) -> dict:
    if code not in PVP_ROOMS:
        return {"success": False}
    room = PVP_ROOMS[code]
    return {
        "success": True,
        "message": f"{room['guest_display']} đã vào phòng!",
        "guest": room["guest"],
        "guest_display": room["guest_display"],
    }


# ─── 2. Tạo phòng ───
def create_pvp_room(host_username: str, host_display: str,
                    is_public: bool = True,
                    host_level: int = 1,
                    rules: dict = None) -> dict:
    cleanup_old_rooms()
    code = _gen_room_code()
    now = time.time()

    if rules is None:
        rules = {"rounds": DEFAULT_ROUNDS, "questions_per_round": DEFAULT_QUESTIONS}

    try:
        rules["rounds"] = max(1, min(7, int(rules.get("rounds", DEFAULT_ROUNDS))))
        rules["questions_per_round"] = max(5, min(30, int(rules.get("questions_per_round", DEFAULT_QUESTIONS))))
    except (TypeError, ValueError):
        rules = {"rounds": DEFAULT_ROUNDS, "questions_per_round": DEFAULT_QUESTIONS}

    rounds = []
    for r in range(rules["rounds"]):
        rounds.append({
            "index": r, "questions": [], "current_index": -1,
            "answers": {}, "scores": {}, "winner": None,
            "question_started_at": None, "started_at": None,
        })

    room = {
        "code": code,
        "host": host_username,
        "host_display": host_display,
        "host_level": host_level,
        "guest": None,
        "guest_display": None,
        "guest_level": None,
        "is_public": is_public,
        "rules": rules,
        "status": "waiting",
        "rounds": rounds,
        "current_round": -1,
        "round_wins": {host_username: 0},
        "chat": [],
        "rematch_votes": [],
        "created_at": now,
        "last_activity": now,
        "finished_at": None,
        "afk_warnings": {},
        "last_afk_check": now,
        "left_user": None,
        "left_display": None,
        "heartbeats": {},
        "afk_kick_info": None,
    }
    PVP_ROOMS[code] = room
    return room


# ─── 3. Bạn bè ───
def send_friend_request(from_user: str, to_user: str) -> dict:
    if from_user == to_user:
        return {"success": False, "error": "Không thể kết bạn với chính mình!"}
    if to_user in FRIENDS_DB.get(from_user, []):
        return {"success": False, "error": "Đã là bạn bè!"}
    for req in FRIEND_REQUESTS:
        if req["from"] == from_user and req["to"] == to_user:
            return {"success": False, "error": "Đã gửi lời mời!"}
    for req in FRIEND_REQUESTS:
        if req["from"] == to_user and req["to"] == from_user:
            FRIEND_REQUESTS.remove(req)
            FRIENDS_DB.setdefault(from_user, []).append(to_user)
            FRIENDS_DB.setdefault(to_user, []).append(from_user)
            return {"success": True, "auto_accepted": True, "message": "Đã trở thành bạn bè!"}
    FRIEND_REQUESTS.append({
        "from": from_user, "to": to_user,
        "time": datetime.now().isoformat(),
    })
    return {"success": True, "message": "Đã gửi lời mời kết bạn!"}


def accept_friend_request(username: str, from_user: str) -> dict:
    for req in FRIEND_REQUESTS:
        if req["from"] == from_user and req["to"] == username:
            FRIEND_REQUESTS.remove(req)
            FRIENDS_DB.setdefault(username, []).append(from_user)
            FRIENDS_DB.setdefault(from_user, []).append(username)
            return {"success": True, "message": "Đã chấp nhận lời mời!"}
    return {"success": False, "error": "Không tìm thấy lời mời!"}


def decline_friend_request(username: str, from_user: str) -> dict:
    for req in FRIEND_REQUESTS:
        if req["from"] == from_user and req["to"] == username:
            FRIEND_REQUESTS.remove(req)
            return {"success": True, "message": "Đã từ chối!"}
    return {"success": False, "error": "Không tìm thấy lời mời!"}


def get_friends(username: str) -> list:
    return FRIENDS_DB.get(username, [])


def get_friend_requests(username: str) -> list:
    return [r for r in FRIEND_REQUESTS if r["to"] == username]


def remove_friend(username: str, friend: str) -> dict:
    if friend in FRIENDS_DB.get(username, []):
        FRIENDS_DB[username].remove(friend)
    if username in FRIENDS_DB.get(friend, []):
        FRIENDS_DB[friend].remove(username)
    return {"success": True, "message": "Đã xóa bạn!"}


def invite_friend_to_room(username: str, friend: str, code: str) -> dict:
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Phòng không tồn tại!"}
    room = PVP_ROOMS[code]
    if room["host"] != username and room["guest"] != username:
        return {"success": False, "error": "Bạn không ở trong phòng!"}
    if friend not in FRIENDS_DB.get(username, []):
        return {"success": False, "error": "Không phải bạn bè!"}
    room.setdefault("invites", []).append({
        "friend": friend, "from": username, "code": code,
        "time": datetime.now().isoformat(),
    })
    return {"success": True, "message": f"Đã mời {friend} vào phòng!"}


def get_room_invites(username: str) -> list:
    result = []
    for code, room in PVP_ROOMS.items():
        for inv in room.get("invites", []):
            if inv["friend"] == username:
                result.append({
                    "code": code, "from": inv["from"],
                    "host_display": room["host_display"],
                    "time": inv["time"],
                })
    return result


# ─── 4. Chat ───
def send_chat_message(code: str, username: str, display: str, message: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    if username not in (room["host"], room["guest"]):
        return {"success": False, "error": "Bạn không ở trong phòng!"}
    message = message.strip()[:200]
    if not message:
        return {"success": False, "error": "Tin nhắn trống!"}
    room.setdefault("chat", []).append({
        "user": username, "display": display,
        "message": message, "time": datetime.now().isoformat(),
    })
    room["chat"] = room["chat"][-50:]
    room["last_activity"] = time.time()
    return {"success": True, "message": "Đã gửi!"}


def get_chat_messages(code: str) -> list:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return []
    return PVP_ROOMS[code].get("chat", [])


# ─── 5. Rules ───
def update_room_rules(code: str, username: str, rules: dict) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    if room["host"] != username:
        return {"success": False, "error": "Chỉ chủ phòng mới đổi luật!"}
    if room["status"] != "waiting":
        return {"success": False, "error": "Không thể đổi luật khi đang chơi!"}

    try:
        rounds = int(rules.get("rounds", DEFAULT_ROUNDS))
        questions = int(rules.get("questions_per_round", DEFAULT_QUESTIONS))
    except (TypeError, ValueError):
        return {"success": False, "error": "Giá trị không hợp lệ!"}

    if rounds < 1 or rounds > 7:
        return {"success": False, "error": "Số ván phải từ 1-7!"}
    if questions < 5 or questions > 30:
        return {"success": False, "error": "Số câu phải từ 5-30!"}

    room["rules"] = {"rounds": rounds, "questions_per_round": questions}

    new_rounds = []
    for r in range(rounds):
        if r < len(room["rounds"]):
            new_rounds.append(room["rounds"][r])
        else:
            new_rounds.append({
                "index": r, "questions": [], "current_index": -1,
                "answers": {}, "scores": {}, "winner": None,
                "question_started_at": None, "started_at": None,
            })
    room["rounds"] = new_rounds[:rounds]

    return {"success": True, "message": f"Đã cập nhật: {rounds} ván × {questions} câu",
            "rules": room["rules"]}


# ─── 6. Share link ───
def get_room_share_link(code: str, base_url: str = "") -> str:
    if base_url:
        base_url = base_url.rstrip("/")
        return f"{base_url}/game?join={code}"
    return f"/game?join={code}"


# ─── 8. Xem đối thủ ───
def get_opponent_info(room: dict, username: str, all_users: dict) -> dict:
    opponent = room["guest"] if room["host"] == username else room["host"]
    if not opponent:
        return {}
    user_data = all_users.get(opponent, {})
    game = user_data.get("game", {})
    stats = game.get("pvp_stats", {})
    return {
        "username": opponent,
        "display_name": user_data.get("display_name", opponent),
        "user_id": user_data.get("user_id", "—"),
        "level": points_to_level(game.get("points", 0)),
        "points": game.get("points", 0),
        "pvp_wins": stats.get("wins", 0),
        "pvp_losses": stats.get("losses", 0),
        "total_matches": stats.get("total_matches", 0),
    }


# ─── 9. Kick ───
def kick_guest(code: str, host_username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    if room["host"] != host_username:
        return {"success": False, "error": "Chỉ chủ phòng mới kick!"}
    if not room["guest"]:
        return {"success": False, "error": "Không có guest để kick!"}
    if room["status"] == "playing":
        return {"success": False, "error": "Không thể kick khi đang chơi!"}
    kicked = room["guest"]
    kicked_display = room["guest_display"]
    room["guest"] = None
    room["guest_display"] = None
    room["guest_level"] = None
    room["status"] = "waiting"
    room["current_round"] = -1
    room["round_wins"] = {room["host"]: 0}
    for r in room["rounds"]:
        r["current_index"] = -1
        r["answers"] = {}
        r["scores"] = {}
        r["winner"] = None
        r["question_started_at"] = None
    return {"success": True, "kicked": kicked, "kicked_display": kicked_display,
            "message": f"Đã kick {kicked_display}!"}


# ─── 10. Cleanup ───
def cleanup_old_rooms() -> int:
    now = time.time()
    to_delete = []
    for code, room in PVP_ROOMS.items():
        if now - room.get("last_activity", 0) > ROOM_TTL:
            to_delete.append(code)
    for code in to_delete:
        del PVP_ROOMS[code]
    return len(to_delete)


# ─── 11. Rematch ───
def vote_rematch(code: str, username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    if room["status"] != "finished":
        return {"success": False, "error": "Trận chưa kết thúc!"}
    if username not in (room["host"], room["guest"]):
        return {"success": False, "error": "Bạn không ở trong phòng!"}
    votes = room.setdefault("rematch_votes", [])
    if username not in votes:
        votes.append(username)
    if len(votes) >= 2:
        room["status"] = "ready"
        room["current_round"] = -1
        room["round_wins"] = {room["host"]: 0}
        if room["guest"]:
            room["round_wins"][room["guest"]] = 0
        for r in room["rounds"]:
            r["questions"] = []
            r["current_index"] = -1
            r["answers"] = {}
            r["scores"] = {}
            r["winner"] = None
            r["question_started_at"] = None
            r["started_at"] = None
        room["rematch_votes"] = []
        room["left_user"] = None
        room["left_display"] = None
        room["afk_kick_info"] = None
        room["afk_warnings"] = {}
        room["heartbeats"] = {}
        room["last_activity"] = time.time()
        return {"success": True, "restarted": True, "message": "Cả 2 đồng ý! Trận mới bắt đầu!"}
    return {"success": True, "votes": votes, "message": "Đã vote. Chờ đối thủ..."}


# ─── JOIN / START / SUBMIT ───
def join_pvp_room(code: str, guest_username: str, guest_display: str,
                  guest_level: int = 1) -> dict:
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
    room["guest_level"] = guest_level
    room["status"] = "ready"
    room["round_wins"][guest_username] = 0
    room["last_activity"] = time.time()
    return {"success": True, "room": room}


def start_pvp_room(code: str, host_username: str) -> dict:
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

    rules = room["rules"]
    rounds_count = rules.get("rounds", DEFAULT_ROUNDS)
    questions_count = rules.get("questions_per_round", DEFAULT_QUESTIONS)

    for i in range(rounds_count):
        if i < len(room["rounds"]):
            room["rounds"][i]["questions"] = _gen_questions(questions_count)

    room["status"] = "playing"
    room["current_round"] = 0

    r = room["rounds"][0]
    r["current_index"] = 0
    r["question_started_at"] = time.time()
    r["started_at"] = time.time()
    r["answers"] = {room["host"]: {}, room["guest"]: {}}
    r["scores"] = {room["host"]: 0, room["guest"]: 0}

    room["last_activity"] = time.time()
    room["afk_warnings"] = {}
    room["left_user"] = None
    room["left_display"] = None
    room["heartbeats"] = {
        room["host"]: time.time(),
        room["guest"]: time.time(),
    }
    room["afk_kick_info"] = None
    return {"success": True, "room": room}


def submit_pvp_answer(code: str, username: str, answer: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    if room["status"] != "playing":
        return {"success": False, "error": "Chưa bắt đầu!"}
    if username not in (room["host"], room["guest"]):
        return {"success": False, "error": "Bạn không ở trong phòng!"}

    round_idx = room["current_round"]
    if round_idx < 0 or round_idx >= len(room["rounds"]):
        return {"success": False, "error": "Ván không hợp lệ!"}

    r = room["rounds"][round_idx]
    q_idx = r["current_index"]
    questions_count = room["rules"].get("questions_per_round", DEFAULT_QUESTIONS)

    if q_idx < 0 or q_idx >= len(r["questions"]):
        return {"success": False, "error": "Câu hỏi không hợp lệ!"}
    if q_idx in r["answers"].get(username, {}):
        return {"success": False, "error": "Đã trả lời câu này!"}

    time_taken = round(time.time() - r["question_started_at"], 2)
    correct_answer = r["questions"][q_idx]["word"].lower().strip()
    user_answer = answer.lower().strip()
    correct = (user_answer == correct_answer)

    points = 0
    if correct:
        speed_bonus = max(0, int(MAX_SPEED_BONUS - time_taken * 2))
        points = POINTS_PER_CORRECT + speed_bonus

    r["answers"][username][q_idx] = {
        "answer": answer, "correct": correct,
        "time_taken": time_taken, "points": points,
    }
    r["scores"][username] = r["scores"].get(username, 0) + points
    room["last_activity"] = time.time()
    room.setdefault("heartbeats", {})[username] = time.time()

    host_answered = q_idx in r["answers"].get(room["host"], {})
    guest_answered = q_idx in r["answers"].get(room["guest"], {})

    if host_answered and guest_answered:
        r["current_index"] += 1
        if r["current_index"] >= questions_count:
            host_score = r["scores"].get(room["host"], 0)
            guest_score = r["scores"].get(room["guest"], 0)
            if host_score > guest_score:
                r["winner"] = room["host"]
                room["round_wins"][room["host"]] = room["round_wins"].get(room["host"], 0) + 1
            elif host_score < guest_score:
                r["winner"] = room["guest"]
                room["round_wins"][room["guest"]] = room["round_wins"].get(room["guest"], 0) + 1
            else:
                r["winner"] = None

            rounds_count = room["rules"].get("rounds", DEFAULT_ROUNDS)
            if round_idx + 1 >= rounds_count:
                room["status"] = "finished"
                room["finished_at"] = time.time()
            else:
                room["current_round"] = round_idx + 1
                next_round = room["rounds"][round_idx + 1]
                next_round["current_index"] = 0
                next_round["question_started_at"] = time.time() + 3
                next_round["started_at"] = time.time() + 3
                next_round["answers"] = {room["host"]: {}, room["guest"]: {}}
                next_round["scores"] = {room["host"]: 0, room["guest"]: 0}
        else:
            r["question_started_at"] = time.time()

    return {
        "success": True, "correct": correct, "points": points,
        "time_taken": time_taken, "room": room,
    }


def get_pvp_room(code: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    return {"success": True, "room": PVP_ROOMS[code]}


def leave_pvp_room(code: str, username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": True}
    room = PVP_ROOMS[code]
    if room["host"] == username:
        del PVP_ROOMS[code]
        return {"success": True, "destroyed": True}
    if room["guest"] == username:
        room["guest"] = None
        room["guest_display"] = None
        room["guest_level"] = None
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


# ═══════════════════════════════════════════════════════════
#  🚪 RỜI TRẬN
# ═══════════════════════════════════════════════════════════
def leave_match(code: str, username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": True, "destroyed": True}
    room = PVP_ROOMS[code]

    if room["status"] == "playing":
        opponent = room["guest"] if room["host"] == username else room["host"]
        if opponent:
            room["round_wins"][opponent] = room["round_wins"].get(opponent, 0) + 999
        room["status"] = "finished"
        room["finished_at"] = time.time()
        room["left_user"] = username
        room["left_display"] = room["host_display"] if username == room["host"] else room["guest_display"]
        room["last_activity"] = time.time()
        return {"success": True, "left": True, "room": room,
                "message": f"{room['left_display']} đã rời trận!"}

    return leave_pvp_room(code, username)


# ═══════════════════════════════════════════════════════════
#  ⏰ HEARTBEAT
# ═══════════════════════════════════════════════════════════
def heartbeat(code: str, username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    if username not in (room["host"], room["guest"]):
        return {"success": False, "error": "Bạn không ở trong phòng!"}
    room.setdefault("heartbeats", {})[username] = time.time()
    room["last_activity"] = time.time()
    warnings = room.get("afk_warnings", {})
    if username in warnings:
        del warnings[username]
    return {"success": True, "heartbeat_at": room["heartbeats"][username]}


# ═══════════════════════════════════════════════════════════
#  ⏰ AFK STATUS
# ═══════════════════════════════════════════════════════════
def check_afk_status(code: str, username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    if username not in (room["host"], room["guest"]):
        return {"success": False, "error": "Bạn không ở trong phòng!"}

    now = time.time()
    heartbeats = room.get("heartbeats", {})
    opponent = room["guest"] if room["host"] == username else room["host"]

    my_last = heartbeats.get(username, room.get("created_at", now))
    my_afk = round(now - my_last, 1)

    opp_afk = 999
    if opponent:
        opp_last = heartbeats.get(opponent, room.get("created_at", now))
        opp_afk = round(now - opp_last, 1)

    return {
        "success": True,
        "your_afk_seconds": my_afk,
        "opponent_afk_seconds": opp_afk if opponent else 0,
        "opponent_is_afk": bool(opponent and opp_afk >= AFK_TIMEOUT),
        "opponent_warning": bool(opponent and opp_afk >= AFK_WARNING_AT),
        "afk_timeout": AFK_TIMEOUT,
        "afk_warning_at": AFK_WARNING_AT,
    }


def add_afk_warning(code: str, username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    warnings = room.setdefault("afk_warnings", {})
    user_warnings = warnings.setdefault(username, [])
    now = time.time()
    if not user_warnings or (now - user_warnings[-1]) >= AFK_WARNING_INTERVAL:
        user_warnings.append(now)
        room["last_activity"] = now
        return {"success": True, "warning_added": True, "count": len(user_warnings)}
    return {"success": True, "warning_added": False, "count": len(user_warnings)}


def get_afk_warnings(code: str, username: str) -> dict:
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}
    room = PVP_ROOMS[code]
    warnings = room.get("afk_warnings", {})
    return {
        "success": True,
        "your_warnings": warnings.get(username, []),
        "total_warnings": sum(len(w) for w in warnings.values()),
    }


# ═══════════════════════════════════════════════════════════
#  ⏰ AUTO KICK AFK — Đối thủ AFK >= 30s → kick, requestor thắng
# ═══════════════════════════════════════════════════════════
def check_and_kick_afk(code: str, requestor: str) -> dict:
    """
    Kiểm tra đối thủ có AFK >= 30s không.
    Nếu có → kick đối thủ, requestor thắng trận.
    """
    code = code.upper().strip()
    if code not in PVP_ROOMS:
        return {"success": False, "error": "Không tìm thấy phòng!"}

    room = PVP_ROOMS[code]

    if room["status"] != "playing":
        return {"success": True, "kicked": False}

    if requestor not in (room["host"], room["guest"]):
        return {"success": False, "error": "Bạn không ở trong phòng!"}

    opponent = room["guest"] if room["host"] == requestor else room["host"]
    if not opponent:
        return {"success": True, "kicked": False}

    heartbeats = room.get("heartbeats", {})
    now = time.time()
    opp_last = heartbeats.get(opponent, room.get("created_at", now))
    opp_afk = now - opp_last

    if opp_afk < AFK_TIMEOUT:
        return {
            "success": True,
            "kicked": False,
            "opponent_afk_seconds": round(opp_afk, 1),
        }

    # ═══ ĐỐI THỦ AFK >= 30s → KICK ═══
    opponent_display = (
        room["guest_display"] if room["host"] == requestor else room["host_display"]
    )
    requestor_display = (
        room["host_display"] if room["host"] == requestor else room["guest_display"]
    )

    room["round_wins"][requestor] = room["round_wins"].get(requestor, 0) + 999

    room["status"] = "finished"
    room["finished_at"] = now
    room["afk_kick_info"] = {
        "kicked_user": opponent,
        "kicked_display": opponent_display,
        "winner": requestor,
        "winner_display": requestor_display,
        "afk_seconds": round(opp_afk, 1),
        "time": datetime.now().isoformat(),
    }

    # Lưu lịch sử
    try:
        users = load_users_from_db()
        _save_afk_match_history(room, requestor, opponent, users)
    except Exception as e:
        print(f"⚠️ Lỗi lưu lịch sử AFK kick: {e}")

    return {
        "success": True,
        "kicked": True,
        "kicked_user": opponent,
        "kicked_display": opponent_display,
        "winner": requestor,
        "winner_display": requestor_display,
        "afk_seconds": round(opp_afk, 1),
        "room": room,
    }


# ─── 12. Lịch sử ───
def add_match_to_history(user: dict, opponent_display: str,
                          my_score: int, opp_score: int,
                          my_rounds: int, opp_rounds: int,
                          result: str) -> None:
    game = ensure_game_data(user)
    history = game.get("match_history", [])
    history.insert(0, {
        "opponent": opponent_display,
        "my_score": my_score, "opp_score": opp_score,
        "my_rounds": my_rounds, "opp_rounds": opp_rounds,
        "result": result,
        "time": datetime.now().isoformat(),
    })
    game["match_history"] = history[:20]


# ═══════════════════════════════════════════════════════════
#  MEME
# ═══════════════════════════════════════════════════════════
MEME_TEMPLATES = [
    {"id": "drake", "name": "Drake Hotline Bling", "url": "https://i.imgflip.com/30b1gx.jpg", "texts": ["Không dùng Mã Hóa Tool", "Dùng Mã Hóa Tool 🚀"]},
    {"id": "distracted", "name": "Distracted Boyfriend", "url": "https://i.imgflip.com/1ur9b0.jpg", "texts": ["Tôi", "Code tay", "Mã Hóa Tool ✨"]},
    {"id": "success", "name": "Success Kid", "url": "https://i.imgflip.com/1bhk.jpg", "texts": ["Encode thành công", "Không bị lỗi"]},
    {"id": "brain", "name": "Expanding Brain", "url": "https://i.imgflip.com/1jwhww.jpg", "texts": ["Dùng Google", "Dùng tool online", "Dùng Mã Hóa Tool 🧠"]},
    {"id": "this_is_fine", "name": "This is Fine", "url": "https://i.imgflip.com/wxica.jpg", "texts": ["Quên mật khẩu AES", "Nhưng vẫn còn bình tĩnh"]},
]


def generate_meme_template(input_text: str, output_text: str, template_id: str = None) -> dict:
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
    return {
        "points": 0,
        "streak": 0,
        "last_daily": None,
        "daily_completed": [],
        "achievements": [],
        "rewards_claimed": [],
        "meme_count": 0,
        "pvp_stats": {"wins": 0, "losses": 0, "draws": 0, "total_matches": 0},
        "match_history": [],
        "afk_warnings_count": 0,
    }


def ensure_game_data(user: dict) -> dict:
    if "game" not in user:
        user["game"] = init_game_data()
    return user["game"]


def add_points(user: dict, points: int, reason: str = "") -> dict:
    game = ensure_game_data(user)
    game["points"] = game.get("points", 0) + points
    return {
        "points": game["points"],
        "level": points_to_level(game["points"]),
        "added": points,
        "reason": reason
    }


def update_streak(user: dict) -> int:
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
