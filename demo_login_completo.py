# -*- coding: utf-8 -*-
"""
🔐 Sistema de Login com Token por Email - NetworkScanner
========================================================

Este documento demonstra como usar o novo sistema de autenticação em duas etapas:

1. Username + Password → Gera token e envia por email
2. Token → Faz login no sistema

CREDENCIAIS DE TESTE:
Username: admin
Password: admin123
Email: admin@networkscanner.com

FLUXO DE LOGIN:
1. Aceder a http://localhost:5002
2. Na tab "Login Seguro":
   - Inserir username: admin
   - Inserir password: admin123
   - Clicar "Solicitar Token por Email"
3. O sistema irá:
   - Validar as credenciais
   - Gerar um novo token
   - Tentar enviar por email (se falhar, mostra na tela)
   - Redirecionar para a Etapa 2
4. Na Etapa 2:
   - Inserir o token recebido
   - Clicar "Fazer Login"
   - Acesso concedido!

"""

from app.user_auth import UserAuth

def demo_complete_flow():
    """Demonstração completa do fluxo de autenticação"""
    
    print("🔐 Demonstração do Sistema de Login com Token")
    print("=" * 60)
    
    auth = UserAuth()
    
    # Mostrar utilizadores disponíveis
    print("\n👥 Utilizadores disponíveis:")
    users = auth.list_users()
    for user in users:
        status = "🟢 Ativo" if user['is_active'] else "🔴 Inativo"
        print(f"   Username: {user.get('username', 'N/A')} | Nome: {user['nome']} | Email: {user['email']} | {status}")
    
    print("\n📋 Credenciais de teste:")
    print("   Username: admin")
    print("   Password: admin123")
    print("   Email: admin@networkscanner.com")
    
    # Simular Etapa 1
    print("\n🔑 Etapa 1: Validação de credenciais")
    result1 = auth.authenticate_with_username_password('admin', 'admin123')
    
    if result1['success']:
        print(f"   ✅ {result1['message']}")
        print(f"   👤 Nome: {result1['nome']}")
        print(f"   📧 Email: {result1['email']}")
        
        # Gerar token
        print("\n🎟️  Gerando token de acesso...")
        token_result = auth.generate_and_update_token('admin')
        
        if token_result['success']:
            print(f"   ✅ Token gerado: {token_result['token']}")
            print(f"   ⏰ Expira em: {token_result['token_expiration']}")
            
            # Simular envio de email
            print("\n📨 Simulando envio de email...")
            email_result = auth.send_token_by_email(
                result1['email'], 
                token_result['token'], 
                result1['nome']
            )
            
            if email_result['success']:
                print(f"   ✅ {email_result['message']}")
            else:
                print(f"   ⚠️  {email_result['message']}")
                if email_result.get('debug'):
                    print(f"   🔍 Token para login manual: {email_result['token']}")
            
            # Simular Etapa 2
            print("\n🔓 Etapa 2: Login com token")
            result2 = auth.authenticate_with_token('admin', token_result['token'])
            
            if result2['success']:
                print(f"   ✅ {result2['message']}")
                print(f"   🎉 Acesso concedido ao sistema!")
            else:
                print(f"   ❌ {result2['message']}")
        
        else:
            print(f"   ❌ Erro ao gerar token: {token_result['message']}")
    
    else:
        print(f"   ❌ {result1['message']}")
    
    print("\n" + "=" * 60)
    print("🌐 Para testar no browser:")
    print("   1. Aceder a http://localhost:5002")
    print("   2. Usar as credenciais de teste")
    print("   3. Seguir o fluxo de 2 etapas")
    print("=" * 60)

def create_test_user():
    """Criar utilizador adicional para teste"""
    auth = UserAuth()
    
    result = auth.create_user(
        username="user1",
        nome="João Silva",
        email="joao@teste.com",
        password="teste123",
        token_validity_hours=48
    )
    
    if result['success']:
        print("👤 Utilizador de teste criado:")
        print(f"   Username: user1")
        print(f"   Password: teste123")
        print(f"   Email: joao@teste.com")
        print(f"   Token inicial: {result['token']}")
    else:
        print(f"❌ Erro ao criar utilizador: {result['message']}")

if __name__ == "__main__":
    demo_complete_flow()
    
    print("\n" + "="*60)
    print("🆕 Criar utilizador adicional para teste? (s/n)")
    resposta = input().lower()
    if resposta == 's':
        create_test_user()
