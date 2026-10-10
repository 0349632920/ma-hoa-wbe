"""
Script chuyển data từ users.json lên Supabase
Chạy: python migration.py
"""
import os
import json
import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
USERS_FILE = 'users.json'


def main():
    if not DATABASE_URL:
        print("❌ Thiếu DATABASE_URL trong .env")
        return

    if not os.path.exists(USERS_FILE):
        print(f"❌ Không tìm thấy {USERS_FILE}")
        return

    # Load data cũ
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        users = json.load(f)

    print(f"📦 Tìm thấy {len(users)} users trong {USERS_FILE}")

    # Kết nối Supabase
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cur = conn.cursor()

    # Tạo bảng nếu chưa có
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            data JSONB NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
    """)

    # Insert từng user
    success = 0
    failed = 0
    for username, data in users.items():
        try:
            cur.execute("""
                INSERT INTO users (username, data, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (username)
                DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
            """, (username, Json(data)))
            success += 1
            print(f"  ✅ {username}")
        except Exception as e:
            failed += 1
            print(f"  ❌ {username}: {e}")

    conn.commit()
    cur.close()
    conn.close()

    print(f"\n🎉 Hoàn tất!")
    print(f"   ✅ Thành công: {success}")
    print(f"   ❌ Lỗi: {failed}")


if __name__ == '__main__':
    main()
