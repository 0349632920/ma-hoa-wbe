"""
Database helper — Load/Save mọi thứ lên Supabase
"""
import os
import json
import psycopg2
from psycopg2.extras import Json, RealDictCursor
from contextlib import contextmanager
from datetime import datetime


DATABASE_URL = os.getenv('DATABASE_URL', '').strip()


def has_database() -> bool:
    return bool(DATABASE_URL)


@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════
#  INIT TABLES
# ═══════════════════════════════════════════════════════════
def init_tables():
    if not has_database():
        print("⚠️ Không có DATABASE_URL — dùng JSON local")
        return
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Bảng users
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        data JSONB NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW(),
                        updated_at TIMESTAMP DEFAULT NOW()
                    );
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_users_data 
                    ON users USING GIN (data);
                """)
                # Bảng pvp_rooms
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS pvp_rooms (
                        code TEXT PRIMARY KEY,
                        data JSONB NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW(),
                        updated_at TIMESTAMP DEFAULT NOW()
                    );
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pvp_rooms_updated 
                    ON pvp_rooms (updated_at);
                """)
        print("✅ Đã khởi tạo bảng users + pvp_rooms trên Supabase")
    except Exception as e:
        print(f"❌ Lỗi init_tables: {e}")


# ═══════════════════════════════════════════════════════════
#  USERS
# ═══════════════════════════════════════════════════════════
def load_users() -> dict:
    if has_database():
        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT username, data FROM users")
                    return {row['username']: row['data'] for row in cur.fetchall()}
        except Exception as e:
            print(f"⚠️ Lỗi load users: {e}")

    # Fallback JSON
    if not os.path.exists('users.json'):
        return {}
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_user(username: str, user_data: dict):
    if has_database():
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (username, data, updated_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (username)
                        DO UPDATE SET 
                            data = EXCLUDED.data,
                            updated_at = NOW()
                    """, (username, Json(user_data)))
            return
        except Exception as e:
            print(f"❌ Lỗi save user: {e}")

    # Fallback JSON
    users = load_users()
    users[username] = user_data
    try:
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"❌ Lỗi ghi JSON: {e}")


def save_users(users: dict):
    for username, data in users.items():
        save_user(username, data)


def delete_user(username: str):
    if has_database():
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE username = %s", (username,))
            return
        except Exception as e:
            print(f"❌ Lỗi delete user: {e}")

    users = load_users()
    if username in users:
        del users[username]
        save_users(users)


# ═══════════════════════════════════════════════════════════
#  PVP ROOMS
# ═══════════════════════════════════════════════════════════
def load_all_rooms() -> dict:
    if not has_database():
        return {}
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT code, data FROM pvp_rooms")
                return {row['code']: row['data'] for row in cur.fetchall()}
    except Exception as e:
        print(f"⚠️ Lỗi load rooms: {e}")
        return {}


def load_room(code: str) -> dict:
    if not has_database():
        return None
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT data FROM pvp_rooms WHERE code = %s", (code,))
                row = cur.fetchone()
                return row['data'] if row else None
    except Exception as e:
        print(f"⚠️ Lỗi load room {code}: {e}")
        return None


def save_room(code: str, room_data: dict):
    if not has_database():
        return
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO pvp_rooms (code, data, updated_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (code)
                    DO UPDATE SET 
                        data = EXCLUDED.data,
                        updated_at = NOW()
                """, (code, Json(room_data)))
    except Exception as e:
        print(f"❌ Lỗi save room {code}: {e}")


def delete_room(code: str):
    if not has_database():
        return
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM pvp_rooms WHERE code = %s", (code,))
    except Exception as e:
        print(f"❌ Lỗi delete room {code}: {e}")


def cleanup_old_rooms_db():
    """Xóa phòng cũ > 30 phút."""
    if not has_database():
        return 0
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM pvp_rooms 
                    WHERE updated_at < NOW() - INTERVAL '30 minutes'
                """)
                return cur.rowcount
    except Exception as e:
        print(f"⚠️ Lỗi cleanup rooms: {e}")
        return 0


# ═══════════════════════════════════════════════════════════
#  FRIENDS
# ═══════════════════════════════════════════════════════════
def get_friends(username: str) -> list:
    users = load_users()
    user = users.get(username, {})
    return user.get('friends', [])


def add_friend(username: str, friend: str):
    users = load_users()
    if username in users:
        friends = users[username].get('friends', [])
        if friend not in friends:
            friends.append(friend)
        users[username]['friends'] = friends
        save_user(username, users[username])


def remove_friend(username: str, friend: str):
    users = load_users()
    if username in users:
        friends = users[username].get('friends', [])
        if friend in friends:
            friends.remove(friend)
        users[username]['friends'] = friends
        save_user(username, users[username])


def get_friend_requests(username: str) -> list:
    users = load_users()
    user = users.get(username, {})
    return user.get('friend_requests', [])


def add_friend_request(to_user: str, from_user: str):
    users = load_users()
    if to_user in users:
        pending = users[to_user].get('friend_requests', [])
        for req in pending:
            if req.get('from') == from_user:
                return False
        pending.append({
            'from': from_user,
            'time': datetime.now().isoformat()
        })
        users[to_user]['friend_requests'] = pending
        save_user(to_user, users[to_user])
        return True
    return False


def remove_friend_request(to_user: str, from_user: str):
    users = load_users()
    if to_user in users:
        pending = users[to_user].get('friend_requests', [])
        pending = [r for r in pending if r.get('from') != from_user]
        users[to_user]['friend_requests'] = pending
        save_user(to_user, users[to_user])
