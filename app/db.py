import sqlite3
from flask import g, current_app

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