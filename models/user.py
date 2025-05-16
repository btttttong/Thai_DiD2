from dataclasses import dataclass
from datetime import datetime
import sqlite3
from typing import Optional, List

@dataclass
class User:
    user_id: str
    public_key: str
    display_name: str
    email: str
    created_at: str = datetime.utcnow().isoformat()
    last_active_at: str = datetime.utcnow().isoformat()

class UserRepository:
    def __init__(self, db_path="users.db"):
        self.conn = sqlite3.connect(db_path)
        self.create_table()

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            display_name TEXT,
            email TEXT,
            created_at TEXT,
            last_active_at TEXT
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def add_user(self, user: User):
        query = """
        INSERT OR REPLACE INTO users (user_id, public_key, display_name, email, created_at, last_active_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        self.conn.execute(query, (user.user_id, user.public_key, user.display_name, user.email, user.created_at, user.last_active_at))
        self.conn.commit()

    def get_user(self, user_id: str) -> Optional[User]:
        cursor = self.conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return User(*row)
        return None

    def get_all_users(self) -> List[User]:
        cursor = self.conn.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        return [User(*row) for row in rows]

    def update_last_active(self, user_id: str):
        query = "UPDATE users SET last_active_at = ? WHERE user_id = ?"
        self.conn.execute(query, (datetime.utcnow().isoformat(), user_id))
        self.conn.commit()

    def close(self):
        self.conn.close()
