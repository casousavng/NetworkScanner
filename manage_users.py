#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de gestão de utilizadores para NetworkScanner
Permite criar, listar, renovar tokens e gerir utilizadores
"""

import argparse
import sys
import os
from app.user_auth import UserAuth
from datetime import datetime

def format_user_info(user):
    """Formatar informações do utilizador para exibição"""
    status = "🟢 Ativo" if user['is_active'] else "🔴 Inativo"
    token_status = "⏰ Válido" if user['token_valid'] else "❌ Expirado"
    
    return f"""
ID: {user['id']}
Nome: {user['nome']}
Email: {user['email']}
Status: {status}
Token: {token_status}
Criado: {user['created_at']}
Último login: {user['last_login'] or 'Nunca'}
"""

def list_users(auth):
    """Listar todos os utilizadores"""
    users = auth.list_users()
    
    if not users:
        print("📝 Nenhum utilizador encontrado.")
        return
    
    print(f"\n📋 Total de utilizadores: {len(users)}")
    print("=" * 60)
    
    for user in users:
        print(format_user_info(user))
        print("-" * 60)

def create_user(auth, nome, email, password, hours=24):
    """Criar um novo utilizador"""
    print(f"👤 Criando utilizador: {nome} ({email})")
    
    result = auth.create_user(nome, email, password, hours)
    
    if result['success']:
        print(f"✅ {result['message']}")
        print(f"📋 Detalhes:")
        print(f"   ID: {result['user_id']}")
        print(f"   Token: {result['token']}")
        print(f"   Expira em: {result['token_expiration']}")
        
        # Salvar token em arquivo para referência
        token_file = f"token_{email.replace('@', '_').replace('.', '_')}.txt"
        with open(token_file, 'w') as f:
            f.write(f"Email: {email}\n")
            f.write(f"Password: {password}\n")
            f.write(f"Token: {result['token']}\n")
            f.write(f"Expira em: {result['token_expiration']}\n")
        
        print(f"💾 Credenciais salvas em: {token_file}")
    else:
        print(f"❌ {result['message']}")

def refresh_token(auth, email, hours=24):
    """Renovar token de um utilizador"""
    print(f"🔄 Renovando token para: {email}")
    
    result = auth.refresh_token(email, hours)
    
    if result['success']:
        print(f"✅ Token renovado!")
        print(f"   Novo token: {result['token']}")
        print(f"   Expira em: {result['token_expiration']}")
        
        # Atualizar arquivo de token se existir
        token_file = f"token_{email.replace('@', '_').replace('.', '_')}.txt"
        if os.path.exists(token_file):
            # Ler conteúdo existente
            with open(token_file, 'r') as f:
                lines = f.readlines()
            
            # Atualizar token e expiração
            with open(token_file, 'w') as f:
                for line in lines:
                    if line.startswith('Token:'):
                        f.write(f"Token: {result['token']}\n")
                    elif line.startswith('Expira em:'):
                        f.write(f"Expira em: {result['token_expiration']}\n")
                    else:
                        f.write(line)
            
            print(f"💾 Arquivo atualizado: {token_file}")
    else:
        print(f"❌ {result['message']}")

def get_user_info(auth, email):
    """Obter informações de um utilizador específico"""
    user = auth.get_user_by_email(email)
    
    if user:
        print(f"\n🔍 Informações do utilizador: {email}")
        print("=" * 50)
        
        status = "🟢 Ativo" if user['is_active'] else "🔴 Inativo"
        token_status = "⏰ Válido" if user['token_valid'] else "❌ Expirado"
        
        print(f"ID: {user['id']}")
        print(f"Nome: {user['nome']}")
        print(f"Email: {user['email']}")
        print(f"Status: {status}")
        print(f"Token: {user['token']}")
        print(f"Token Status: {token_status}")
        print(f"Token expira: {user['token_expiration']}")
    else:
        print(f"❌ Utilizador {email} não encontrado!")

def test_login(auth, email, password, token):
    """Testar login de um utilizador"""
    print(f"🔐 Testando login para: {email}")
    
    result = auth.authenticate_user(email, password, token)
    
    if result['success']:
        print(f"✅ {result['message']}")
    else:
        print(f"❌ {result['message']}")

def deactivate_user(auth, email):
    """Desativar um utilizador"""
    print(f"🔴 Desativando utilizador: {email}")
    
    result = auth.deactivate_user(email)
    
    if result['success']:
        print(f"✅ {result['message']}")
    else:
        print(f"❌ {result['message']}")

def main():
    parser = argparse.ArgumentParser(description='Gestão de Utilizadores do NetworkScanner')
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponíveis')
    
    # Comando: listar utilizadores
    subparsers.add_parser('list', help='Listar todos os utilizadores')
    
    # Comando: criar utilizador
    create_parser = subparsers.add_parser('create', help='Criar novo utilizador')
    create_parser.add_argument('nome', help='Nome do utilizador')
    create_parser.add_argument('email', help='Email do utilizador')
    create_parser.add_argument('password', help='Password do utilizador')
    create_parser.add_argument('--hours', type=int, default=24, help='Validade do token em horas (padrão: 24)')
    
    # Comando: renovar token
    refresh_parser = subparsers.add_parser('refresh', help='Renovar token de utilizador')
    refresh_parser.add_argument('email', help='Email do utilizador')
    refresh_parser.add_argument('--hours', type=int, default=24, help='Validade do token em horas (padrão: 24)')
    
    # Comando: informações do utilizador
    info_parser = subparsers.add_parser('info', help='Mostrar informações de utilizador')
    info_parser.add_argument('email', help='Email do utilizador')
    
    # Comando: testar login
    test_parser = subparsers.add_parser('test', help='Testar login de utilizador')
    test_parser.add_argument('email', help='Email do utilizador')
    test_parser.add_argument('password', help='Password do utilizador')
    test_parser.add_argument('token', help='Token do utilizador')
    
    # Comando: desativar utilizador
    deactivate_parser = subparsers.add_parser('deactivate', help='Desativar utilizador')
    deactivate_parser.add_argument('email', help='Email do utilizador')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Inicializar sistema de autenticação
    auth = UserAuth()
    
    print("🔐 Gestão de Utilizadores do NetworkScanner")
    print("=" * 50)
    
    # Executar comando
    if args.command == 'list':
        list_users(auth)
    
    elif args.command == 'create':
        create_user(auth, args.nome, args.email, args.password, args.hours)
    
    elif args.command == 'refresh':
        refresh_token(auth, args.email, args.hours)
    
    elif args.command == 'info':
        get_user_info(auth, args.email)
    
    elif args.command == 'test':
        test_login(auth, args.email, args.password, args.token)
    
    elif args.command == 'deactivate':
        deactivate_user(auth, args.email)

if __name__ == "__main__":
    main()
