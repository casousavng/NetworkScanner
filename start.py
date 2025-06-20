# -*- coding: utf-8 -*-
import threading
import time
import requests
from app.extensions import socketio
from app import create_app
import os
from app.db_init import init_db

app = create_app()

# Inicia o servidor Flask com SocketIO
def start_flask():
    
    print("🚀 A iniciar Flask...")
    socketio.run(app, host='0.0.0.0', port=5002, debug=True, use_reloader=False)

# Espera que o servidor Flask esteja pronto antes de iniciar o SocketIO para evitar problemas de conexão
# def wait_for_server(url="http://0.0.0.0:5002", timeout=15):
#     for _ in range(timeout * 2):
#         try:
#             r = requests.get(url)
#             if r.status_code == 200:
#                 return True
#         except:
#             pass
#         time.sleep(0.5)
#     return False

if __name__ == '__main__':

    # Verifica se o diretório de dados existe, caso contrário, cria-o
    db_path = os.path.join("data", "rede.db")
    if not os.path.exists(db_path):
        with app.app_context():
            init_db()

    # Inicia diretamente o servidor Flask
    start_flask()
