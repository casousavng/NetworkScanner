import sqlite3
from flask import g, current_app
import os
from datetime import datetime

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DB_PATH"],  # <- corrigido aqui
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_app(app):
    app.teardown_appcontext(close_db)

def rename_db():
    db_path = current_app.config.get("DB_PATH", "rede.db")
    router_ip = current_app.config.get("ROUTER_IP", "unknown_ip").replace('.', '-')
    if db_path and os.path.exists(db_path):
        now = datetime.now().strftime('%d-%m-%Y_%H-%M-%S')
        dir_name = os.path.dirname(db_path)
        base_name = f"rede_{router_ip}_{now}.db"
        new_db_path = os.path.join(dir_name, base_name)
        os.rename(db_path, new_db_path)
        print(f"🚀 Base de Dados renomeada para {new_db_path}")
    else:
        print("⚠️ Nenhuma base de dados para renomear.")
