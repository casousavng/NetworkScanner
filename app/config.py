from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    SECRET_KEY      = os.getenv("SECRET_KEY")
    ADMIN_USER      = os.getenv("ADMIN_USER")
    ADMIN_PASS      = os.getenv("ADMIN_PASS")
    DB_PATH         = os.path.join("data", "rede.db")
