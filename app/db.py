import sqlite3
from flask import g, current_app
import os
from datetime import datetime

# Funções para manipulação da base de dados
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DB_PATH"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

# Função para fechar a base de dados
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

# Função para inicializar a base de dados
def init_app(app):
    app.teardown_appcontext(close_db)

#Função para fazer backup da base de dados
def backup_db(ip_address):
    db_path = current_app.config["DB_PATH"]
    default_backup_dir = os.path.dirname(db_path) or os.getcwd()
    backup_dir = current_app.config.get("BACKUP_DIR", default_backup_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ip = str(ip_address).replace(":", "_").replace("/", "_")
    backup_filename = f"rede_backup_{safe_ip}_{timestamp}.db"
    backup_path = os.path.join(backup_dir, backup_filename)
    with sqlite3.connect(db_path) as conn:
        with sqlite3.connect(backup_path) as backup_conn:
            conn.backup(backup_conn)

