from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    SECRET_KEY      = os.getenv("SECRET_KEY")
    SUBNET          = os.getenv("SUBNET")
    ROUTER_IP       = os.getenv("ROUTER_IP")
    NVD_API_KEY     = os.getenv("NVD_API_KEY")
    CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS"))
    ADMIN_USER      = os.getenv("ADMIN_USER")
    ADMIN_PASS      = os.getenv("ADMIN_PASS")
    DB_PATH         = os.path.join("data", "rede.db")
