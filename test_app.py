# -*- coding: utf-8 -*-
import threading
import webview
import time
from run import app
from app.extensions import socketio
import os
from db_init import init_db

def start_flask():

    db_path = os.path.join("data", "rede.db")
    if not os.path.exists(db_path):
        with app.app_context():
            init_db()

    socketio.run(app, host='127.0.0.1', port=5005, debug=False, use_reloader=False)

if __name__ == '__main__':

    flask_thread = threading.Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()

    time.sleep(1)

    # Aqui abre a janela no macOS
    webview.create_window("Scanner de Rede", "http://127.0.0.1:5005")
    webview.start(gui='cocoa')  # Cocoa é o padrão no macOS