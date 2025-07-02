# seed.py
import sqlite3
import bcrypt
import os
from datetime import datetime, timedelta

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "users.db")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def generate_token(length=32) -> str:
    import secrets
    return secrets.token_hex(length)

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT,
            token_expiration TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

    # Verifica se o utilizador admin já existe
    cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        password = hash_password("admin123")
        token = generate_token()
        token_expiration = datetime.now() + timedelta(days=365)

        cursor.execute('''
            INSERT INTO users (username, nome, email, password_hash, token, token_expiration, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            "admin",
            "Administrador",
            "admin@localhost",
            password,
            token,
            token_expiration,
            1
        ))
        print("✅ Utilizador admin criado com sucesso.")
    else:
        print("ℹ️ Utilizador admin já existe.")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()