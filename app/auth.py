from flask import redirect, url_for, render_template, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import netifaces
from app.user_auth import UserAuth

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
        # Verificar se é o admin do sistema antigo (fallback)
        if uid == app.config.get("ADMIN_USER", "admin"):
            return User(uid)
        
        # Verificar se é um utilizador do novo sistema
        auth = UserAuth()
        # Assumir que o uid é um user_id ou email
        try:
            # Tentar como ID primeiro
            user_id = int(uid)
            # Buscar por ID não está implementado, usar email como fallback
            return User(uid)
        except ValueError:
            # É um email, verificar se existe
            user = auth.get_user_by_email(uid)
            if user and user['is_active']:
                return User(user['id'])
        
        return None


    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'POST':
            # Sistema antigo (fallback) - verificar se não tem token
            if 'token' not in request.form or not request.form['token']:
                username = request.form.get('username', '')
                password = request.form.get('password', '')
                
                if username == app.config.get("ADMIN_USER", "admin") and password == app.config.get("ADMIN_PASS", "admin"):
                    user = User(username)
                    login_user(user)
                    flash('Login realizado com sucesso!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Credenciais inválidas', 'danger')
        
        return render_template('login.html', network=network, router_ip=gateway)
    
    @app.route('/request_token', methods=['POST'])
    def request_token():
        """Etapa 1: Validar credenciais e solicitar token"""
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username e password são obrigatórios', 'danger')
            return redirect(url_for('login'))
        
        auth = UserAuth()
        result = auth.authenticate_with_username_password(username, password)
        
        if result['success']:
            # Gerar novo token
            token_result = auth.generate_and_update_token(username)
            
            if token_result['success']:
                # Tentar enviar por email
                email_result = auth.send_token_by_email(
                    token_result['email'], 
                    token_result['token'], 
                    token_result['nome']
                )
                
                if email_result['success']:
                    flash(f'Token enviado para {token_result["email"]}', 'success')
                    return redirect(url_for('login', step='2', username=username, email=token_result['email']))
                else:
                    # Se email falhar, mostrar token na tela (modo debug)
                    if email_result.get('debug'):
                        flash(f'Token gerado (email falhou): {email_result["token"]}', 'warning')
                        return redirect(url_for('login', step='2', username=username, email=token_result['email']))
                    else:
                        flash(email_result['message'], 'danger')
            else:
                flash(token_result['message'], 'danger')
        else:
            flash(result['message'], 'danger')
        
        return redirect(url_for('login'))
    
    @app.route('/login_with_token', methods=['POST'])
    def login_with_token():
        """Etapa 2: Login com token"""
        username = request.form.get('username', '')
        token = request.form.get('token', '')
        
        if not username or not token:
            flash('Username e token são obrigatórios', 'danger')
            return redirect(url_for('login'))
        
        auth = UserAuth()
        result = auth.authenticate_with_token(username, token)
        
        if result['success']:
            user = User(result['username'])
            login_user(user)
            flash(result['message'], 'success')
            return redirect(url_for('index'))
        else:
            flash(result['message'], 'danger')
            return redirect(url_for('login', step='2', username=username))

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login', network=network, router_ip=gateway))
    
    @app.route('/refresh_token', methods=['POST'])
    @login_required
    def refresh_token():
        email = request.form.get('email', '')
        hours = int(request.form.get('hours', 24))
        
        if not email:
            flash('Email é obrigatório', 'danger')
            return redirect(request.referrer or url_for('index'))
        
        auth = UserAuth()
        result = auth.refresh_token(email, hours)
        
        if result['success']:
            flash(f'Token renovado com sucesso! Novo token: {result["token"]}', 'success')
        else:
            flash(f'Erro ao renovar token: {result["message"]}', 'danger')
        
        return redirect(request.referrer or url_for('index'))
    
    @app.route('/admin/users')
    @login_required
    def admin_users():
        """Página de gestão de utilizadores"""
        auth = UserAuth()
        users = auth.list_users()
        return render_template('admin_users.html', users=users, network=network, router_ip=gateway)
    
    @app.route('/admin/create_user', methods=['POST'])
    @login_required
    def admin_create_user():
        """Criar novo utilizador"""
        nome = request.form.get('nome', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        hours = int(request.form.get('hours', 24))
        
        if not nome or not email or not password:
            flash('Todos os campos são obrigatórios', 'danger')
            return redirect(url_for('admin_users'))
        
        auth = UserAuth()
        result = auth.create_user(nome, email, password, hours)
        
        if result['success']:
            flash(f'Utilizador criado! Token: {result["token"]}', 'success')
        else:
            flash(f'Erro: {result["message"]}', 'danger')
        
        return redirect(url_for('admin_users'))
    
    @app.route('/admin/refresh_user_token', methods=['POST'])
    @login_required
    def admin_refresh_user_token():
        """Renovar token de utilizador"""
        email = request.form.get('email', '')
        hours = int(request.form.get('hours', 24))
        
        auth = UserAuth()
        result = auth.refresh_token(email, hours)
        
        if result['success']:
            flash(f'Token renovado para {email}! Novo token: {result["token"]}', 'success')
        else:
            flash(f'Erro: {result["message"]}', 'danger')
        
        return redirect(url_for('admin_users'))
    
    @app.route('/admin/deactivate_user', methods=['POST'])
    @login_required
    def admin_deactivate_user():
        """Desativar utilizador"""
        email = request.form.get('email', '')
        
        auth = UserAuth()
        result = auth.deactivate_user(email)
        
        if result['success']:
            flash(f'Utilizador {email} desativado!', 'success')
        else:
            flash(f'Erro: {result["message"]}', 'danger')
        
        return redirect(url_for('admin_users'))
