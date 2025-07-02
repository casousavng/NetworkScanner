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
    login_manager.login_view = 'login'  # type: ignore
    login_manager.login_message = '🔒 Por favor, faça login para aceder a esta página.'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(uid):
        # Verificar se é um utilizador do novo sistema
        auth = UserAuth()
        
        # Buscar apenas por username
        user = auth.get_user_by_username(uid)
        if user and user['is_active']:
            return User(user['username'])
        
        return None


    @app.route('/login', methods=['GET','POST'])
    def login():
        # A página de login apenas renderiza o template
        # Todo o processamento é feito pelas rotas /request_token e /login_with_token
        return render_template('login.html', network=network, router_ip=gateway)
    
    @app.route('/request_token', methods=['POST'])
    def request_token():
        """Etapa 1: Validar credenciais e solicitar token"""
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('❌ Username e password são obrigatórios', 'danger')
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
                    # Não mostrar flash aqui, será mostrado na etapa 2
                    return redirect(url_for('login', step='2', username=username, email=token_result['email']))
                else:
                    # Se email falhar, mostrar token na tela (modo debug)
                    if email_result.get('debug'):
                        flash(f'⚠️ Email indisponível. Token: {email_result["token"]}', 'warning')
                        return redirect(url_for('login', step='2', username=username, email=token_result['email']))
                    else:
                        flash(f'❌ {email_result["message"]}', 'danger')
            else:
                flash(f'❌ {token_result["message"]}', 'danger')
        else:
            flash(f'❌ {result["message"]}', 'danger')
        
        return redirect(url_for('login'))
    
    @app.route('/login_with_token', methods=['POST'])
    def login_with_token():
        """Etapa 2: Login com token"""
        username = request.form.get('username', '')
        token = request.form.get('token', '')
        
        if not username or not token:
            flash('❌ Username e token são obrigatórios', 'danger')
            return redirect(url_for('login'))
        
        auth = UserAuth()
        result = auth.authenticate_with_token(username, token)
        
        if result['success']:
            user = User(result['username'])
            login_user(user)
            # Flash de sucesso será exibido na próxima página, não precisa aqui
            return redirect(url_for('index'))
        else:
            flash(f'❌ {result["message"]}', 'danger')
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
        print(f'Usuários retornados: {users}')  # Para debug no console
        return render_template('admin/manage_users.html', users=users, network=network, router_ip=gateway)
    
    @app.route('/admin/create_user', methods=['POST'])
    @login_required
    def admin_create_user():
        """Criar novo utilizador"""
        username = request.form.get('username', '')
        nome = request.form.get('nome', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        hours = int(request.form.get('hours', 24))
        
        if not username or not nome or not email or not password:
            flash('Todos os campos são obrigatórios', 'danger')
            return redirect(url_for('admin_users'))
        
        auth = UserAuth()
        result = auth.create_user(username, nome, email, password, hours)
        
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
