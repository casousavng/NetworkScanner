# -*- coding: utf-8 -*-
"""
Exemplo de integração do sistema de autenticação de utilizadores
"""

from app.user_auth import UserAuth
import os

def demo_authentication():
    """Demonstra como usar o sistema de autenticação"""
    
    print("🔐 Demonstração do Sistema de Autenticação")
    print("=" * 50)
    
    # Inicializar o sistema de autenticação
    auth = UserAuth()
    
    # Listar utilizadores existentes
    print("\n📋 Utilizadores existentes:")
    users = auth.list_users()
    for user in users:
        status = "🟢 Ativo" if user['is_active'] else "🔴 Inativo"
        token_status = "⏰ Válido" if user['token_valid'] else "❌ Expirado"
        print(f"   {user['nome']} ({user['email']}) - {status} - Token: {token_status}")
    
    if users:
        # Usar o primeiro utilizador para demonstração
        user_email = users[0]['email']
        user_data = auth.get_user_by_email(user_email)
        
        if user_data:
            print(f"\n🔍 Dados do utilizador {user_email}:")
            print(f"   Token atual: {user_data['token']}")
            print(f"   Token válido: {'Sim' if user_data['token_valid'] else 'Não'}")
            
            # Demonstrar login com token
            print(f"\n🔐 Tentativa de login com token:")
            # Para o utilizador de teste, sabemos que a password é "admin123"
            result = auth.authenticate_user(user_email, "admin123", user_data['token'])
            
            if result['success']:
                print(f"✅ {result['message']}")
            else:
                print(f"❌ {result['message']}")
            
            # Demonstrar renovação de token
            print(f"\n🔄 Renovando token:")
            token_result = auth.refresh_token(user_email)
            
            if token_result['success']:
                print(f"✅ Token renovado!")
                print(f"   Novo token: {token_result['token']}")
                print(f"   Expira em: {token_result['token_expiration']}")
                
                # Testar login com novo token
                print(f"\n🔐 Login com novo token:")
                new_result = auth.authenticate_user(user_email, "admin123", token_result['token'])
                if new_result['success']:
                    print(f"✅ {new_result['message']}")
                else:
                    print(f"❌ {new_result['message']}")
            else:
                print(f"❌ {token_result['message']}")
        else:
            print(f"❌ Não foi possível obter dados do utilizador")
    
    # Demonstrar criação de novo utilizador
    print(f"\n👤 Criando novo utilizador de teste:")
    new_user_result = auth.create_user(
        nome="Utilizador Teste",
        email="teste@example.com",
        password="teste123",
        token_validity_hours=48  # 2 dias
    )
    
    if new_user_result['success']:
        print(f"✅ {new_user_result['message']}")
        print(f"   Token: {new_user_result['token']}")
        print(f"   Expira em: {new_user_result['token_expiration']}")
        
        # Testar login do novo utilizador
        print(f"\n🔐 Login do novo utilizador:")
        test_result = auth.authenticate_user(
            "teste@example.com", 
            "teste123", 
            new_user_result['token']
        )
        
        if test_result['success']:
            print(f"✅ {test_result['message']}")
        else:
            print(f"❌ {test_result['message']}")
    else:
        print(f"❌ {new_user_result['message']}")

def integration_example():
    """Exemplo de como integrar com uma rota Flask"""
    
    print("\n" + "=" * 50)
    print("📖 Exemplo de Integração com Flask")
    print("=" * 50)
    
    example_code = '''
# Exemplo de como modificar o auth.py existente para usar o novo sistema

from app.user_auth import UserAuth
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_user

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        token = request.form['token']  # Novo campo no formulário
        
        # Usar o novo sistema de autenticação
        auth = UserAuth()
        result = auth.authenticate_user(email, password, token)
        
        if result['success']:
            # Login bem-sucedido
            user = User(result['user_id'])
            login_user(user)
            flash(result['message'], 'success')
            return redirect(url_for('index'))
        else:
            flash(result['message'], 'danger')
    
    return render_template('login.html')

# Rota para renovar token
@app.route('/refresh_token', methods=['POST'])
@login_required
def refresh_token():
    email = request.form['email']
    auth = UserAuth()
    result = auth.refresh_token(email)
    
    if result['success']:
        flash(f"Token renovado! Novo token: {result['token']}", 'success')
    else:
        flash(result['message'], 'danger')
    
    return redirect(url_for('profile'))
'''
    
    print(example_code)
    
    # Mostrar estrutura do formulário de login
    html_example = '''
<!-- Exemplo de formulário de login atualizado (login.html) -->
<form method="POST">
    <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" name="email" class="form-control" required>
    </div>
    
    <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" name="password" class="form-control" required>
    </div>
    
    <div class="form-group">
        <label for="token">Token de Acesso:</label>
        <input type="text" name="token" class="form-control" required 
               placeholder="Insira o seu token de acesso">
        <small class="form-text text-muted">
            O token é fornecido quando a sua conta é criada ou renovado.
        </small>
    </div>
    
    <button type="submit" class="btn btn-primary">Login</button>
</form>
'''
    
    print("\n📝 Estrutura do formulário HTML:")
    print(html_example)

if __name__ == "__main__":
    demo_authentication()
    integration_example()
