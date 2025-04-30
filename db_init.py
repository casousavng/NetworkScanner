import os, sqlite3

DB_PATH = os.path.join("data", "rede.db")
SCHEMA  = "schema.sql"

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA, "r") as f:
        conn.executescript(f.read())
    conn.close()
    print(f"🚀 Banco criado em {DB_PATH}")

if __name__ == "__main__":
    init_db()
