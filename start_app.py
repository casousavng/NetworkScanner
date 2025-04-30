
# -*- coding: utf-8 -*-
import threading
import webview
import time
import requests
from run_tetse import app
from app.extensions import socketio
from app import create_app
from screeninfo import get_monitors
import os
from app.db_init import init_db

app = create_app()

def start_flask():
    print("🚀 A iniciar Flask...")
    socketio.run(app, host='127.0.0.1', port=5005, debug=False, use_reloader=False)

def show_main_app(window):
    if not wait_for_server():
        print("❌ Erro: servidor não respondeu.")
        return

    time.sleep(2)  # tempo da splash

    # Novo tamanho da janela principal
    new_width = 1200
    new_height = 800

    # Obter dimensões do monitor principal
    monitor = get_monitors()[0]
    screen_width = monitor.width
    screen_height = monitor.height

    # Calcular posição centrada
    x = int((screen_width - new_width) / 2)
    y = int((screen_height - new_height) / 2)

    # Redimensionar e mover
    window.resize(new_width, new_height)
    window.move(x, y)

    print("🔁 A carregar interface principal...")
    window.load_url("http://127.0.0.1:5005")

def wait_for_server(url="http://127.0.0.1:5005", timeout=15):
    for _ in range(timeout * 2):
        try:
            r = requests.get(url)
            if r.status_code == 200:
                return True
        except:
            pass
        time.sleep(0.5)
    return False

if __name__ == '__main__':

    # Check if the database already exists in the data folder
    db_path = os.path.join("data", "rede.db")
    if not os.path.exists(db_path):
        with app.app_context():
            init_db()


    flask_thread = threading.Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Load the splash HTML content from the templates folder
    splash_html_path = os.path.join("templates", "splash.html")
    with open(splash_html_path, "r", encoding="utf-8") as file:
        splash_html = file.read()

    # Create the splash window with the loaded HTML content
    splash_window = webview.create_window(
        "A iniciar...",
        html=splash_html,
        width=400,
        height=200,
        x=None,
        y=None,
        frameless=True,
        resizable=False,
        background_color="#1e1e1e",
        text_select=True,
        confirm_close=False,
        transparent=True,
        easy_drag=True,

    )
    webview.start(func=show_main_app, args=(splash_window,), gui='cocoa')