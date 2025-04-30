from flask import Flask
from flask_socketio import SocketIO
from .config import Config
from .db import init_app as init_db
from .auth import init_app as init_auth
from .routes import init_app as init_routes

from .extensions import socketio

def create_app():
    app = Flask(__name__, static_folder="../static", template_folder="../templates")
    app.config.from_object(Config)
    init_db(app)
    init_auth(app)
    init_routes(app)
    socketio.init_app(app)
    
    return app
