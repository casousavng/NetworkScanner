
# -*- coding: utf-8 -*-
import threading
import webview
import time
import requests
from run import app
from app.extensions import socketio
from screeninfo import get_monitors
import os
from db_init import init_db

#orginal code

def start_flask():
    print("🚀 A iniciar Flask...")
    socketio.run(app, host='127.0.0.1', port=5005, debug=False, use_reloader=False)

''' -> Segunda opção
def start_flask():
    print("🚀 A iniciar Flask...")
    with app.app_context():  # Garante que o contexto da app está ativo
        socketio.run(app, host='127.0.0.1', port=5005, debug=False, use_reloader=False)
'''

'''
def start_flask():
    print("🚀 A iniciar Flask...")
    app.run(host='127.0.0.1', port=5005, debug=False)     
'''  


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

    splash_html = """
    <html>
    <head>
        <style>
            body {
                margin: 0;
                background-color: #1e1e1e;
                color: white;
                font-family: sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }

            .container {
                display: flex;
                flex-direction: column;
                align-items: center;
                animation: fadeIn 1s ease-in-out;
            }

            .spinner {
                border: 6px solid rgba(255, 255, 255, 0.2);
                border-top: 6px solid white;
                border-radius: 50%;
                width: 60px;
                height: 60px;
                animation: spin 1s linear infinite;
            }

            .text {
                margin-top: 20px;
                text-align: center;
                font-size: 1.2em;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            @keyframes fadeIn {
                0% { opacity: 0; transform: scale(0.95); }
                100% { opacity: 1; transform: scale(1); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="spinner"></div>
            <div class="text">A carregar aplicação...</div>
        </div>
    </body>
    </html>
    """

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