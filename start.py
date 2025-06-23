# -*- coding: utf-8 -*-
from app.extensions import socketio
from app import create_app
import os
from app.db_init import init_db

app = create_app()

# Inicia o servidor Flask com SocketIO
def start_flask():
    
    print("🚀 A iniciar Flask...")
    socketio.run(app, host='0.0.0.0', port=5002, debug=True, use_reloader=False)

if __name__ == '__main__':

    # Verifica se o diretório de dados existe, caso contrário, cria-o
    db_path = os.path.join("data", "rede.db")
    if not os.path.exists(db_path):
        with app.app_context():
            init_db()

    # Inicia diretamente o servidor Flask
    start_flask()
