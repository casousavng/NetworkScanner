from flask import redirect, url_for, render_template, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import netifaces

login_manager = LoginManager()

class User(UserMixin):
    def __init__(self, id):
        self.id = id

network = netifaces.ifaddresses(netifaces.gateways()['default'][netifaces.AF_INET][1])[netifaces.AF_INET][0]
gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]

def init_app(app):
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(uid):
        if uid == app.config["ADMIN_USER"]:
            return User(uid)
        return None

    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'POST':
            u = request.form['username']
            p = request.form['password']
            if u == app.config["ADMIN_USER"] and p == app.config["ADMIN_PASS"]:
                user = User(u)
                login_user(user)
                return redirect(url_for('index'))
            flash('Credenciais inválidas', 'danger')
        return render_template('login.html', network=network, router_ip=gateway)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login', network=network, router_ip=gateway))
