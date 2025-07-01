# -*- coding: utf-8 -*-
"""
Módulo de autenticação de utilizadores para integração com a aplicação Flask
"""

import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta
from flask import current_app
import os

class UserAuth:
    """Classe para gestão de autenticação de utilizadores"""
    
    def __init__(self, db_path=None):
        if db_path is None:
            # Tentar usar o contexto Flask se disponível, senão usar caminho padrão
            try:
                main_db_dir = os.path.dirname(current_app.config.get("DB_PATH", "data/rede.db"))
                self.db_path = os.path.join(main_db_dir, "users.db")
            except RuntimeError:
                # Fora do contexto Flask, usar caminho padrão
                self.db_path = os.path.join("data", "users.db")
        else:
            self.db_path = db_path
        
        # Criar diretório se não existir
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Inicializa a base de dados de utilizadores"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
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
        
        # Adicionar coluna username se não existir (para compatibilidade com BD existente)
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN username TEXT UNIQUE')
        except sqlite3.OperationalError:
            pass  # Coluna já existe
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Codifica a password usando bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password, password_hash):
        """Verifica se a password está correta"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def generate_token(self):
        """Gera um token seguro"""
        return secrets.token_urlsafe(32)
    
    def create_user(self, username, nome, email, password, token_validity_hours=24):
        """Cria um novo utilizador"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Verificar se o email já existe
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                return {"success": False, "message": f"Email {email} já existe!"}
            
            # Verificar se o username já existe
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return {"success": False, "message": f"Username {username} já existe!"}
            
            # Gerar password hash e token
            password_hash = self.hash_password(password)
            token = self.generate_token()
            token_expiration = datetime.now() + timedelta(hours=token_validity_hours)
            
            # Inserir utilizador
            cursor.execute('''
                INSERT INTO users (username, nome, email, password_hash, token, token_expiration)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, nome, email, password_hash, token, token_expiration))
            
            conn.commit()
            user_id = cursor.lastrowid
            
            return {
                "success": True,
                "message": "Utilizador criado com sucesso!",
                "user_id": user_id,
                "token": token,
                "token_expiration": token_expiration.isoformat()
            }
            
        except Exception as e:
            return {"success": False, "message": f"Erro ao criar utilizador: {str(e)}"}
        finally:
            conn.close()
    
    def authenticate_user(self, email, password, token=None):
        """Autentica um utilizador"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, nome, password_hash, token, token_expiration, is_active 
                FROM users WHERE email = ?
            ''', (email,))
            
            user = cursor.fetchone()
            
            if not user:
                return {"success": False, "message": "Email não encontrado!"}
            
            user_id, nome, password_hash, stored_token, token_expiration, is_active = user
            
            # Verificar se o utilizador está ativo
            if not is_active:
                return {"success": False, "message": "Utilizador desativado!"}
            
            # Verificar password
            if not self.verify_password(password, password_hash):
                return {"success": False, "message": "Password incorreta!"}
            
            # Se foi fornecido um token, verificá-lo
            if token:
                if stored_token != token:
                    return {"success": False, "message": "Token inválido!"}
                
                # Verificar se o token não expirou
                token_exp_datetime = datetime.fromisoformat(token_expiration)
                if datetime.now() > token_exp_datetime:
                    return {"success": False, "message": "Token expirado!"}
            
            # Atualizar último login
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            conn.commit()
            
            return {
                "success": True,
                "message": f"Login bem-sucedido! Bem-vindo, {nome}!",
                "user_id": user_id,
                "nome": nome,
                "email": email,
                "token": stored_token
            }
            
        except Exception as e:
            return {"success": False, "message": f"Erro na autenticação: {str(e)}"}
        finally:
            conn.close()
    
    def get_user_by_email(self, email):
        """Obtém informações do utilizador por email"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, nome, email, token, token_expiration, is_active
                FROM users WHERE email = ?
            ''', (email,))
            
            user = cursor.fetchone()
            
            if user:
                user_id, nome, email, token, token_expiration, is_active = user
                return {
                    "id": user_id,
                    "nome": nome,
                    "email": email,
                    "token": token,
                    "token_expiration": token_expiration,
                    "is_active": bool(is_active),
                    "token_valid": datetime.now() < datetime.fromisoformat(token_expiration) if token_expiration else False
                }
            return None
            
        except Exception as e:
            print(f"Erro ao obter utilizador: {str(e)}")
            return None
        finally:
            conn.close()
    
    def refresh_token(self, email, token_validity_hours=24):
        """Renova o token de um utilizador"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            new_token = self.generate_token()
            new_expiration = datetime.now() + timedelta(hours=token_validity_hours)
            
            cursor.execute('''
                UPDATE users SET token = ?, token_expiration = ?
                WHERE email = ? AND is_active = 1
            ''', (new_token, new_expiration, email))
            
            if cursor.rowcount > 0:
                conn.commit()
                return {
                    "success": True,
                    "token": new_token,
                    "token_expiration": new_expiration.isoformat()
                }
            else:
                return {"success": False, "message": "Utilizador não encontrado ou inativo!"}
                
        except Exception as e:
            return {"success": False, "message": f"Erro ao renovar token: {str(e)}"}
        finally:
            conn.close()
    
    def deactivate_user(self, email):
        """Desativa um utilizador"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE users SET is_active = 0 WHERE email = ?
            ''', (email,))
            
            if cursor.rowcount > 0:
                conn.commit()
                return {"success": True, "message": "Utilizador desativado!"}
            else:
                return {"success": False, "message": "Utilizador não encontrado!"}
                
        except Exception as e:
            return {"success": False, "message": f"Erro ao desativar utilizador: {str(e)}"}
        finally:
            conn.close()
    
    def list_users(self):
        """Lista todos os utilizadores"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, nome, email, created_at, last_login, is_active, token_expiration
                FROM users ORDER BY id
            ''')
            
            users = cursor.fetchall()
            result = []
            
            for user in users:
                user_id, nome, email, created_at, last_login, is_active, token_exp = user
                result.append({
                    "id": user_id,
                    "nome": nome,
                    "email": email,
                    "created_at": created_at,
                    "last_login": last_login,
                    "is_active": bool(is_active),
                    "token_valid": datetime.now() < datetime.fromisoformat(token_exp) if token_exp else False
                })
            
            return result
            
        except Exception as e:
            print(f"Erro ao listar utilizadores: {str(e)}")
            return []
        finally:
            conn.close()
    
    def get_user_by_username(self, username):
        """Obtém informações do utilizador por username"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, username, nome, email, password_hash, token, token_expiration, is_active
                FROM users WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            
            if user:
                user_id, username, nome, email, password_hash, token, token_expiration, is_active = user
                return {
                    "id": user_id,
                    "username": username,
                    "nome": nome,
                    "email": email,
                    "password_hash": password_hash,
                    "token": token,
                    "token_expiration": token_expiration,
                    "is_active": bool(is_active),
                    "token_valid": datetime.now() < datetime.fromisoformat(token_expiration) if token_expiration else False
                }
            return None
            
        except Exception as e:
            print(f"Erro ao obter utilizador por username: {str(e)}")
            return None
        finally:
            conn.close()
    
    def authenticate_with_username_password(self, username, password):
        """Autentica utilizador com username e password (Etapa 1)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, username, nome, email, password_hash, is_active 
                FROM users WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            
            if not user:
                return {"success": False, "message": "Username não encontrado!"}
            
            user_id, username, nome, email, password_hash, is_active = user
            
            # Verificar se o utilizador está ativo
            if not is_active:
                return {"success": False, "message": "Utilizador desativado!"}
            
            # Verificar password
            if not self.verify_password(password, password_hash):
                return {"success": False, "message": "Password incorreta!"}
            
            return {
                "success": True,
                "message": "Credenciais válidas!",
                "user_id": user_id,
                "username": username,
                "nome": nome,
                "email": email
            }
            
        except Exception as e:
            return {"success": False, "message": f"Erro na autenticação: {str(e)}"}
        finally:
            conn.close()
    
    def generate_and_update_token(self, username, token_validity_hours=24):
        """Gera novo token para um utilizador"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Buscar utilizador
            cursor.execute('''
                SELECT id, username, nome, email, is_active 
                FROM users WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            
            if not user:
                return {"success": False, "message": "Utilizador não encontrado!"}
            
            user_id, username, nome, email, is_active = user
            
            if not is_active:
                return {"success": False, "message": "Utilizador desativado!"}
            
            # Gerar novo token
            new_token = self.generate_token()
            new_expiration = datetime.now() + timedelta(hours=token_validity_hours)
            
            # Atualizar token na base de dados
            cursor.execute('''
                UPDATE users SET token = ?, token_expiration = ?
                WHERE username = ?
            ''', (new_token, new_expiration, username))
            
            conn.commit()
            
            return {
                "success": True,
                "message": "Token gerado com sucesso!",
                "user_id": user_id,
                "username": username,
                "nome": nome,
                "email": email,
                "token": new_token,
                "token_expiration": new_expiration.isoformat()
            }
            
        except Exception as e:
            return {"success": False, "message": f"Erro ao gerar token: {str(e)}"}
        finally:
            conn.close()
    
    def authenticate_with_token(self, username, token):
        """Autentica utilizador com username e token (Etapa 2)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, username, nome, email, token, token_expiration, is_active 
                FROM users WHERE username = ?
            ''', (username,))
            
            user = cursor.fetchone()
            
            if not user:
                return {"success": False, "message": "Username não encontrado!"}
            
            user_id, username, nome, email, stored_token, token_expiration, is_active = user
            
            # Verificar se o utilizador está ativo
            if not is_active:
                return {"success": False, "message": "Utilizador desativado!"}
            
            # Verificar token
            if stored_token != token:
                return {"success": False, "message": "Token inválido!"}
            
            # Verificar se o token não expirou
            if token_expiration:
                token_exp_datetime = datetime.fromisoformat(token_expiration)
                if datetime.now() > token_exp_datetime:
                    return {"success": False, "message": "Token expirado!"}
            
            # Atualizar último login
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            conn.commit()
            
            return {
                "success": True,
                "message": f"Login bem-sucedido! Bem-vindo, {nome}!",
                "user_id": user_id,
                "username": username,
                "nome": nome,
                "email": email
            }
            
        except Exception as e:
            return {"success": False, "message": f"Erro na autenticação: {str(e)}"}
        finally:
            conn.close()
    
    def send_token_by_email(self, email, token, nome):
        """Envia token por email usando o sistema de email existente"""
        try:
            from app.mail import send_access_token_email
            
            # Usar a função específica para envio de token
            send_access_token_email(email, token, nome, 24)
            return {"success": True, "message": f"Token enviado para {email}"}
            
        except Exception as e:
            # Se o envio de email falhar, retornar o token para debug
            print(f"Erro ao enviar email: {str(e)}")
            return {
                "success": False, 
                "message": f"Erro ao enviar email. Token: {token}", 
                "token": token,
                "debug": True
            }
