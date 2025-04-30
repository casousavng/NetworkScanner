
# -*- coding: utf-8 -*-
import threading
import webview
import os
from app import create_app
from app.extensions import socketio
from db_init import init_db

app = create_app()

# Inicializa DB se necessário
db_path = os.path.join("data", "rede.db")
if not os.path.exists(db_path):
    init_db()

# Roda o servidor SocketIO num thread separado
def start_flask():
    socketio.run(app, host="127.0.0.1", port=5005, debug=False, use_reloader=False)

if __name__ == "__main__":
    threading.Thread(target=start_flask, daemon=True).start()
    webview.create_window("Scanner de Rede", "http://127.0.0.1:5005", width=1200, height=800)
    webview.start(gui='cocoa')  # Cocoa é o padrão no macOS


'''
#SCRIPT original que funciona desde o início do projeto.
#This script is the entry point for the Flask application.
#It initializes the Flask app and runs it with SocketIO support.

# -*- coding: utf-8 -*-
from app import create_app
from app.extensions import socketio
import os
from db_init import init_db

app = create_app()

if __name__ == "__main__":


    # Check if the database already exists in the data folder
    db_path = os.path.join("data", "rede.db")
    if not os.path.exists(db_path):
        # Initialize the database if it doesn't exist
        init_db()

    socketio.run(app, host="0.0.0.0", port=5005, debug=True)
'''