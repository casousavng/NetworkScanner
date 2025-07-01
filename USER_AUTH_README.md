# Sistema de Autenticação de Utilizadores - NetworkScanner

Este sistema implementa uma autenticação segura baseada em utilizador, password e token para o NetworkScanner.

## Características

- **Passwords Codificadas**: Utiliza bcrypt para hash seguro das passwords
- **Tokens com Expiração**: Tokens seguros gerados automaticamente com data de expiração
- **Base de Dados SQLite**: Armazenamento local dos dados dos utilizadores
- **Gestão Completa**: Scripts para criar, listar, renovar tokens e gerir utilizadores

## Ficheiros Criados

1. **`create_users_db.py`** - Script inicial para criar a base de dados e utilizador de teste
2. **`app/user_auth.py`** - Módulo principal de autenticação
3. **`manage_users.py`** - Script de gestão de utilizadores
4. **`demo_auth.py`** - Demonstração do sistema

## Estrutura da Base de Dados

A tabela `users` contém:
- `id` - ID único do utilizador
- `nome` - Nome completo
- `email` - Email único (usado como username)
- `password_hash` - Password codificada com bcrypt
- `token` - Token de acesso atual
- `token_expiration` - Data/hora de expiração do token
- `created_at` - Data de criação da conta
- `last_login` - Último login realizado
- `is_active` - Status da conta (ativo/inativo)

## Utilização

### 1. Utilizador de Teste Criado

Foi criado um utilizador de teste com as seguintes credenciais:

```
Email: admin@networkscanner.com
Password: admin123
Token: [gerado automaticamente - verificar com manage_users.py info]
```

### 2. Scripts de Gestão

#### Listar utilizadores:
```bash
python manage_users.py list
```

#### Criar novo utilizador:
```bash
python manage_users.py create "Nome Completo" "email@exemplo.com" "password123" --hours 48
```

#### Renovar token:
```bash
python manage_users.py refresh "email@exemplo.com" --hours 24
```

#### Informações de utilizador:
```bash
python manage_users.py info "email@exemplo.com"
```

#### Testar login:
```bash
python manage_users.py test "email@exemplo.com" "password" "token"
```

#### Desativar utilizador:
```bash
python manage_users.py deactivate "email@exemplo.com"
```

### 3. Integração com Flask

Para integrar com o sistema Flask existente, modifique o `app/auth.py`:

```python
from app.user_auth import UserAuth
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_user

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        token = request.form['token']  # Novo campo
        
        # Usar o novo sistema
        auth = UserAuth()
        result = auth.authenticate_user(email, password, token)
        
        if result['success']:
            user = User(result['user_id'])
            login_user(user)
            flash(result['message'], 'success')
            return redirect(url_for('index'))
        else:
            flash(result['message'], 'danger')
    
    return render_template('login.html')
```

### 4. Formulário de Login Atualizado

Atualize o template `templates/login.html` para incluir o campo token:

```html
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
```

## Segurança

- As passwords são sempre armazenadas com hash bcrypt
- Os tokens são gerados usando `secrets.token_urlsafe()` (criptograficamente seguros)
- Tokens têm expiração configurável
- Verificação de múltiplos fatores: email + password + token
- Possibilidade de desativar utilizadores sem apagar dados

## Fluxo de Autenticação

1. **Criação de Conta**: Admin cria conta com nome, email e password
2. **Token Gerado**: Sistema gera token seguro com expiração
3. **Login**: Utilizador fornece email, password e token
4. **Verificação**: Sistema valida todos os três elementos
5. **Acesso**: Se válido, utilizador é autenticado no sistema

## Manutenção

- Tokens podem ser renovados sem alterar password
- Utilizadores podem ser temporariamente desativados
- Histórico de logins é mantido
- Base de dados é criada automaticamente se não existir

## Exemplo de Uso Programático

```python
from app.user_auth import UserAuth

# Inicializar
auth = UserAuth()

# Criar utilizador
result = auth.create_user("João Silva", "joao@empresa.com", "minhapassword", 24)

# Autenticar
result = auth.authenticate_user("joao@empresa.com", "minhapassword", "token_do_utilizador")

# Renovar token
result = auth.refresh_token("joao@empresa.com", 48)
```

Este sistema garante uma autenticação robusta e segura para o NetworkScanner, mantendo os dados dos utilizadores protegidos e fornecendo flexibilidade na gestão de acessos.
