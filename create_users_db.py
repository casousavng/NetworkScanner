# -*- coding: utf-8 -*-
"""
Script para criar e gerir base de dados de utilizadores
Inclui nome, password codificada, email e token com expiração
"""

import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta
import os
import sys

def create_users_table(db_path):
    """Cria a tabela de utilizadores se não existir"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Criar tabela de utilizadores
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT,
            token_expiration TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Tabela de utilizadores criada com sucesso!")

def hash_password(password):
    """Codifica a password usando bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verifica se a password está correta"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_token():
    """Gera um token seguro"""
    return secrets.token_urlsafe(32)

def create_user(db_path, nome, email, password, token_validity_hours=24):
    """Cria um novo utilizador"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Verificar se o email já existe
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        print(f"❌ Erro: Email {email} já existe!")
        conn.close()
        return False
    
    # Gerar password hash e token
    password_hash = hash_password(password)
    token = generate_token()
    token_expiration = datetime.now() + timedelta(hours=token_validity_hours)
    
    # Inserir utilizador
    cursor.execute('''
        INSERT INTO users (nome, email, password_hash, token, token_expiration)
        VALUES (?, ?, ?, ?, ?)
    ''', (nome, email, password_hash, token, token_expiration))
    
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    
    print(f"✅ Utilizador criado com sucesso!")
    print(f"   ID: {user_id}")
    print(f"   Nome: {nome}")
    print(f"   Email: {email}")
    print(f"   Token: {token}")
    print(f"   Token expira em: {token_expiration.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return True

def authenticate_user(db_path, email, password, token):
    """Autentica um utilizador verificando email, password e token"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, nome, password_hash, token, token_expiration, is_active 
        FROM users WHERE email = ?
    ''', (email,))
    
    user = cursor.fetchone()
    
    if not user:
        print("❌ Email não encontrado!")
        conn.close()
        return False
    
    user_id, nome, password_hash, stored_token, token_expiration, is_active = user
    
    # Verificar se o utilizador está ativo
    if not is_active:
        print("❌ Utilizador desativado!")
        conn.close()
        return False
    
    # Verificar password
    if not verify_password(password, password_hash):
        print("❌ Password incorreta!")
        conn.close()
        return False
    
    # Verificar token
    if stored_token != token:
        print("❌ Token inválido!")
        conn.close()
        return False
    
    # Verificar se o token não expirou
    token_exp_datetime = datetime.fromisoformat(token_expiration)
    if datetime.now() > token_exp_datetime:
        print("❌ Token expirado!")
        conn.close()
        return False
    
    # Atualizar último login
    cursor.execute('''
        UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
    ''', (user_id,))
    conn.commit()
    conn.close()
    
    print(f"✅ Login bem-sucedido! Bem-vindo, {nome}!")
    return True

def refresh_token(db_path, email, token_validity_hours=24):
    """Renova o token de um utilizador"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    new_token = generate_token()
    new_expiration = datetime.now() + timedelta(hours=token_validity_hours)
    
    cursor.execute('''
        UPDATE users SET token = ?, token_expiration = ?
        WHERE email = ?
    ''', (new_token, new_expiration, email))
    
    if cursor.rowcount > 0:
        conn.commit()
        print(f"✅ Token renovado para {email}")
        print(f"   Novo token: {new_token}")
        print(f"   Expira em: {new_expiration.strftime('%Y-%m-%d %H:%M:%S')}")
        conn.close()
        return new_token
    else:
        print(f"❌ Utilizador {email} não encontrado!")
        conn.close()
        return None

def list_users(db_path):
    """Lista todos os utilizadores"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, nome, email, token, token_expiration, created_at, last_login, is_active
        FROM users ORDER BY id
    ''')
    
    users = cursor.fetchall()
    conn.close()
    
    if not users:
        print("📝 Nenhum utilizador encontrado.")
        return
    
    print("\n📋 Lista de Utilizadores:")
    print("-" * 100)
    for user in users:
        user_id, nome, email, token, token_exp, created_at, last_login, is_active = user
        status = "🟢 Ativo" if is_active else "🔴 Inativo"
        token_status = "⏰ Válido" if datetime.now() < datetime.fromisoformat(token_exp) else "❌ Expirado"
        
        print(f"ID: {user_id} | {nome} | {email}")
        print(f"   Status: {status} | Token: {token_status}")
        print(f"   Criado: {created_at} | Último login: {last_login or 'Nunca'}")
        print(f"   Token expira: {token_exp}")
        print("-" * 100)

def main():
    """Função principal para demonstrar o sistema"""
    # Caminho para a base de dados
    db_path = os.path.join("data", "users.db")
    
    # Criar diretório data se não existir
    os.makedirs("data", exist_ok=True)
    
    print("🔐 Sistema de Gestão de Utilizadores")
    print("=" * 50)
    
    # Criar tabela
    create_users_table(db_path)
    
    # Criar utilizador de teste
    print("\n👤 Criando utilizador de teste...")
    success = create_user(
        db_path=db_path,
        nome="Admin",
        email="admin@networkscanner.com",
        password="admin123",
        token_validity_hours=24
    )
    
    if success:
        print("\n🔍 Listando utilizadores:")
        list_users(db_path)
        
        # Demonstrar autenticação
        print("\n🔐 Testando autenticação...")
        
        # Obter o token do utilizador criado
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT token FROM users WHERE email = ?", ("admin@networkscanner.com",))
        token = cursor.fetchone()[0]
        conn.close()
        
        # Testar login com credenciais corretas
        print("\n✅ Teste com credenciais corretas:")
        authenticate_user(db_path, "admin@networkscanner.com", "admin123", token)
        
        # Testar login com password errada
        print("\n❌ Teste com password errada:")
        authenticate_user(db_path, "admin@networkscanner.com", "senha_errada", token)
        
        # Testar login com token errado
        print("\n❌ Teste com token errado:")
        authenticate_user(db_path, "admin@networkscanner.com", "admin123", "token_invalido")

if __name__ == "__main__":
    main()
