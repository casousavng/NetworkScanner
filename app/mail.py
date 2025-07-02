from flask_mail import Mail, Message
from flask import current_app
from markupsafe import escape
import ipaddress

mail = Mail()

def init_mail(app):
    mail.init_app(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def count_ports(port_range: str):
    try:
        start, end = map(int, port_range.split('-'))
        return end - start + 1 if start <= end else 1
    except:
        return None

def count_ips(ip_list):
    total = 0
    for ip in ip_list:
        ip = ip.strip()

        # Caso 1: CIDR, tipo "192.168.1.0/30"
        if '/' in ip:
            try:
                network = ipaddress.ip_network(ip, strict=False)
                total += network.num_addresses
            except ValueError:
                total += 1

        # Caso 2: IP-IP range, tipo "192.168.1.100-192.168.2.5"
        elif '-' in ip and '.' in ip.split('-')[1]:
            try:
                start_str, end_str = ip.split('-')
                start_ip = ipaddress.IPv4Address(start_str)
                end_ip = ipaddress.IPv4Address(end_str)
                if end_ip >= start_ip:
                    total += int(end_ip) - int(start_ip) + 1
                else:
                    total += 1
            except ValueError:
                total += 1

        # Caso 3: final alternado, tipo "192.168.1.100-105"
        elif '-' in ip:
            try:
                base, final = ip.rsplit('.', 1)
                start, end = map(int, final.split('-'))
                if end >= start:
                    total += end - start + 1
                else:
                    total += 1
            except:
                total += 1

        # Caso 4: IP único
        else:
            total += 1

    return total

def send_issue_report(data, recipient_email):
    from email.utils import make_msgid

    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    issue_text = data.get('issue', '').strip().replace('\r\n', '\n').replace('\r', '\n')
    screenshot = data.get('screenshot')  # objeto FileStorage do Flask

    plain_text = (
        f"Nome: {name}\n"
        f"Email: {email}\n\n"
        "Problema reportado:\n"
        f"{issue_text}\n\n"
        "Por favor, verifique e tome as medidas necessárias."
    )

    issue_html = escape(issue_text).replace('\n', '<br>')

    msg = Message(
        subject="🛠️ Novo Problema Reportado - NetworkScanner",
        sender="scanner@networkscanner.com",
        recipients=[recipient_email]
    )
    msg.body = plain_text

    if screenshot and screenshot.filename != '':
        screenshot.seek(0)
        file_data = screenshot.read()
        content_id = make_msgid(domain="networkscanner.com")
        msg.attach(
            filename=screenshot.filename,
            content_type=screenshot.content_type,
            data=file_data,
            disposition='inline',
            headers={'Content-ID': content_id}
        )

        # Adiciona a imagem inline no HTML usando o Content-ID (sem os <>)
        html_text = f"""
        <h2 style="color: #e74c3c;">🛠️ Problema Reportado</h2>
        <p><strong>Nome:</strong> {escape(name)}<br>
        <strong>Email:</strong> {escape(email)}</p>
        <p><strong>Descrição:</strong></p>
        <blockquote style="background-color: #f9f9f9; border-left: 4px solid #e74c3c; padding: 10px;">
            {issue_html}
        </blockquote>
        <p><strong>Imagem Anexada:</strong></p>
        <img src="cid:{content_id[1:-1]}" alt="Imagem Anexada" style="max-width: 100%; height: auto; border: 1px solid #ddd; padding: 5px;">
        <p style="margin-top: 20px; font-size: 0.9em; color: #7f8c8d;">
            Este problema foi enviado por um utilizador do sistema NetworkScanner.
        </p>
        """
    else:
        # Caso não tenha anexo, HTML normal
        html_text = f"""
        <h2 style="color: #e74c3c;">🛠️ Problema Reportado</h2>
        <p><strong>Nome:</strong> {escape(name)}<br>
        <strong>Email:</strong> {escape(email)}</p>
        <p><strong>Descrição:</strong></p>
        <blockquote style="background-color: #f9f9f9; border-left: 4px solid #e74c3c; padding: 10px;">
            {issue_html}
        </blockquote>
        <p style="margin-top: 20px; font-size: 0.9em; color: #7f8c8d;">
            Este problema foi enviado por um utilizador do sistema NetworkScanner.
        </p>
        """

    msg.html = html_text

    mail.send(msg)


def send_scan_start_email(recipient_email, scan_params):
    """
    Envia um email a indicar o início de um scan e os parâmetros utilizados.
    """
    ips = scan_params.get("ips", [])
    port_range = scan_params.get("port_range", "N/A")
    n_ips = count_ips(ips)
    n_ports = count_ports(port_range)

    ip_text = "1 IP" if n_ips == 1 else f"{n_ips} IPs"
    port_text = (
        "1 porta" if n_ports == 1 else f"{n_ports} portas"
        if n_ports else port_range
    )

    msg = Message(
        subject="🚀 Início de Scan - NetworkScanner",
        sender="scanner@networkscanner.com",
        recipients=[recipient_email]
    )
    
    msg.body = (
        "O scan foi iniciado com os seguintes parâmetros:\n\n"
        f"- Intervalo de Portas: {port_range} ({port_text})\n"
        f"- IPs a analisar: {ip_text}\n\n"
        "Lista de IPs:\n" + "\n".join(ips)
    )

    ip_list_html = "".join(f"<li>{ip}</li>" for ip in ips)

    msg.html = f"""
    <h2 style="color: #2980b9;">🚀 Scan Iniciado</h2>
    <p><strong>Intervalo de Portas:</strong> {port_range} ({port_text})</p>
    <p><strong>IPs a analisar:</strong> {ip_text}</p>
    <h4>Lista ou Intervalo de IPs:</h4>
    <ul>
        {ip_list_html}
    </ul>
    <p style="margin-top: 20px; font-size: 0.9em; color: #95a5a6;">
        Está a decorrer um novo scan na sua rede através do NetworkScanner.
    </p>
    """

    mail.send(msg)

def send_scan_completed_email(recipient_email, data):
    """
    Envia um email a indicar que o scan foi concluído e inclui detalhes.
    """
    scan_id = data.get("scan_id", "N/A")
    duration = data.get("duration", "N/A")
    port_range = data.get("port_range", "N/A")
    ips = data.get("ips", [])
    n_ips = count_ips(ips)
    n_ports = count_ports(port_range)

    ip_text = "1 IP ativo" if n_ips == 1 else f"{n_ips} IPs ativos"
    port_text = (
        "1 porta" if n_ports == 1 else f"{n_ports} portas"
        if n_ports else port_range
    )

    msg = Message(
        subject=f"✅ Scan #{scan_id} Concluído com Sucesso - NetworkScanner",
        sender="scanner@networkscanner.com",
        recipients=[recipient_email]
    )

    msg.body = (
        f"O scan #{scan_id} foi concluído com sucesso!\n\n"
        f"- Duração: {duration}\n"
        f"- Intervalo de Portas: {port_range} ({port_text})\n"
        f"- IPs Ativos Encontrados: {ip_text}\n\n"
        f"Lista de IPs:\n" + "\n".join(ips)
    )

    ip_list_html = "".join(f"<li>{ip}</li>" for ip in ips)

    msg.html = f"""
    <h2 style="color: #2c3e50;">🔍 Scan #{scan_id} Concluído com Sucesso</h2>
    <p><strong>Duração:</strong> {duration}</p>
    <p><strong>Intervalo de Portas:</strong> {port_range} ({port_text})</p>
    <p><strong>IPs Ativos Encontrados:</strong> {ip_text}</p>
    <h4>Lista ou Intervalo de IPs:</h4>
    <ul>
        {ip_list_html}
    </ul>
    <hr>
    <p style="font-size: 0.9em; color: #7f8c8d;">
        Este email foi gerado automaticamente pelo sistema NetworkScanner.
    </p>
    """

    mail.send(msg)

def send_report_email(to_email, csv_path):
    """
    Envia um email com o relatório CSV em anexo para o email especificado.
    """
    

    with current_app.app_context():
        msg = Message(
            subject="📊 Relatório CSV - NetworkScanner",
            sender="scanner@networkscanner.com",
            recipients=[to_email]
        )

        with open(csv_path, "rb") as f:
            csv_data = f.read()

        filename = csv_path.split('/')[-1] if '/' in csv_path else csv_path
        msg.attach(filename, "text/csv", csv_data)

        msg.body = (
            "Segue em anexo o relatório CSV solicitado.\n\n"
            "Este relatório foi gerado automaticamente pelo sistema NetworkScanner."
        )

        msg.html = f"""
        <h2 style="color: #16a085;">📊 Relatório CSV Gerado</h2>
        <p>Segue em anexo o relatório CSV solicitado.</p>
        <p style="margin-top: 20px; font-size: 0.9em; color: #7f8c8d;">
            Este relatório foi gerado automaticamente pelo sistema NetworkScanner.
        </p>
        """

        mail.send(msg)

def send_access_token_email(recipient_email, token, user_name, token_expiration_hours=24):
    """
    Envia um email com o token de acesso para autenticação no sistema.
    """
    msg = Message(
        subject="🔐 Token de Acesso - NetworkScanner",
        sender="scanner@networkscanner.com",
        recipients=[recipient_email]
    )
    
    # Texto simples
    msg.body = f"""
Olá {user_name},

Foi solicitado um token de acesso para o NetworkScanner.

SEU TOKEN DE ACESSO:
{token}

INSTRUÇÕES:
1. Aceda à página de login do NetworkScanner
2. Insira o seu username e password
3. Quando solicitado, insira o token acima no campo "Token de Acesso"
4. Clique em "Fazer Login"

IMPORTANTE:
- Este token é válido por {token_expiration_hours} horas
- Não partilhe este token com ninguém
- Se não solicitou este token, ignore este email

---
NetworkScanner Security System
Gerado automaticamente em {current_app.config.get('SERVER_NAME', 'localhost')}
"""

    # HTML formatado
    msg.html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f9f9f9; padding: 20px;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2 style="color: #2c3e50; text-align: center; margin-bottom: 30px;">
                🔐 Token de Acesso - NetworkScanner
            </h2>
            
            <p style="color: #34495e; font-size: 16px;">Olá <strong>{escape(user_name)}</strong>,</p>
            
            <p style="color: #34495e;">Foi solicitado um token de acesso para o NetworkScanner.</p>
            
            <div style="background-color: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; text-align: center;">
                <h3 style="color: #e74c3c; margin-bottom: 10px;">SEU TOKEN DE ACESSO:</h3>
                <div id="tokenContainer" style="font-family: 'Courier New', monospace; font-size: 18px; font-weight: bold; 
                           background-color: #34495e; color: white; padding: 15px; border-radius: 5px; 
                           letter-spacing: 2px; word-break: break-all; margin-bottom: 15px; position: relative;">
                    {token}
                </div>
                <button onclick="copyToken()" id="copyBtn" 
                        style="background-color: #3498db; color: white; border: none; padding: 10px 20px; 
                               border-radius: 5px; cursor: pointer; font-size: 14px; font-weight: bold;
                               transition: background-color 0.3s; margin-right: 10px;">
                    📋 Copiar Token
                </button>
                <button onclick="selectToken()" 
                        style="background-color: #2ecc71; color: white; border: none; padding: 10px 20px; 
                               border-radius: 5px; cursor: pointer; font-size: 14px; font-weight: bold;
                               transition: background-color 0.3s;">
                    ✏️ Selecionar Token
                </button>
                <script>
                    function copyToken() {{
                        const tokenText = '{token}';
                        
                        // Método 1: Clipboard API (navegadores modernos)
                        if (navigator.clipboard && navigator.clipboard.writeText) {{
                            navigator.clipboard.writeText(tokenText).then(function() {{
                                document.getElementById('copyBtn').innerHTML = '✅ Copiado!';
                                document.getElementById('copyBtn').style.backgroundColor = '#27ae60';
                                setTimeout(function() {{
                                    document.getElementById('copyBtn').innerHTML = '📋 Copiar Token';
                                    document.getElementById('copyBtn').style.backgroundColor = '#3498db';
                                }}, 2000);
                            }}).catch(function() {{
                                fallbackCopy();
                            }});
                        }} else {{
                            fallbackCopy();
                        }}
                    }}
                    
                    function fallbackCopy() {{
                        // Método 2: Fallback para clientes de email mais antigos
                        const textArea = document.createElement('textarea');
                        textArea.value = '{token}';
                        textArea.style.position = 'fixed';
                        textArea.style.opacity = '0';
                        document.body.appendChild(textArea);
                        textArea.focus();
                        textArea.select();
                        
                        try {{
                            const successful = document.execCommand('copy');
                            if (successful) {{
                                document.getElementById('copyBtn').innerHTML = '✅ Copiado!';
                                document.getElementById('copyBtn').style.backgroundColor = '#27ae60';
                                setTimeout(function() {{
                                    document.getElementById('copyBtn').innerHTML = '📋 Copiar Token';
                                    document.getElementById('copyBtn').style.backgroundColor = '#3498db';
                                }}, 2000);
                            }} else {{
                                alert('Token: {token}\\n\\nPor favor, copie manualmente este token.');
                            }}
                        }} catch (err) {{
                            alert('Token: {token}\\n\\nPor favor, copie manualmente este token.');
                        }}
                        
                        document.body.removeChild(textArea);
                    }}
                    
                    function selectToken() {{
                        const tokenContainer = document.getElementById('tokenContainer');
                        if (window.getSelection && document.createRange) {{
                            const range = document.createRange();
                            range.selectNodeContents(tokenContainer);
                            const selection = window.getSelection();
                            selection.removeAllRanges();
                            selection.addRange(range);
                        }} else if (document.selection && document.body.createTextRange) {{
                            const range = document.body.createTextRange();
                            range.moveToElementText(tokenContainer);
                            range.select();
                        }}
                        
                        // Feedback visual
                        tokenContainer.style.backgroundColor = '#e74c3c';
                        setTimeout(function() {{
                            tokenContainer.style.backgroundColor = '#34495e';
                        }}, 1000);
                    }}
                    
                    // Hover effects
                    document.addEventListener('DOMContentLoaded', function() {{
                        const copyBtn = document.getElementById('copyBtn');
                        const selectBtn = document.querySelectorAll('button')[1];
                        
                        copyBtn.addEventListener('mouseenter', function() {{
                            if (this.innerHTML === '📋 Copiar Token') {{
                                this.style.backgroundColor = '#2980b9';
                            }}
                        }});
                        
                        copyBtn.addEventListener('mouseleave', function() {{
                            if (this.innerHTML === '📋 Copiar Token') {{
                                this.style.backgroundColor = '#3498db';
                            }}
                        }});
                        
                        selectBtn.addEventListener('mouseenter', function() {{
                            this.style.backgroundColor = '#27ae60';
                        }});
                        
                        selectBtn.addEventListener('mouseleave', function() {{
                            this.style.backgroundColor = '#2ecc71';
                        }});
                    }});
                </script>
            </div>
            
            <div style="background-color: #e8f4fd; padding: 15px; border-left: 4px solid #3498db; margin: 20px 0;">
                <h4 style="color: #2980b9; margin-top: 0;">📋 INSTRUÇÕES:</h4>
                <ol style="color: #34495e; margin: 0;">
                    <li>Aceda à página de login do NetworkScanner</li>
                    <li>Insira o seu <strong>username</strong> e <strong>password</strong></li>
                    <li>Quando solicitado, insira o token acima no campo "Token de Acesso"
                        <br><small style="color: #7f8c8d;">💡 <em>Dica: Use os botões "Copiar Token" ou "Selecionar Token" acima para facilitar</em></small>
                    </li>
                    <li>Clique em "<strong>Fazer Login</strong>"</li>
                </ol>
                
                <noscript>
                    <div style="background-color: #fff3cd; padding: 10px; border-radius: 5px; margin-top: 15px; border-left: 3px solid #ffc107;">
                        <strong>⚠️ JavaScript Desativado:</strong><br>
                        <small>Os botões de copiar não funcionam. Selecione manualmente o token acima e copie-o (Ctrl+C / Cmd+C).</small>
                    </div>
                </noscript>
            </div>
            
            <div style="background-color: #fdf2e9; padding: 15px; border-left: 4px solid #f39c12; margin: 20px 0;">
                <h4 style="color: #e67e22; margin-top: 0;">⚠️ IMPORTANTE:</h4>
                <ul style="color: #34495e; margin: 0;">
                    <li>Este token é válido por <strong>{token_expiration_hours} horas</strong></li>
                    <li><strong>Não partilhe</strong> este token com ninguém</li>
                    <li>Se não solicitou este token, <strong>ignore este email</strong></li>
                </ul>
            </div>
            
            <hr style="border: none; border-top: 1px solid #bdc3c7; margin: 30px 0;">
            
            <p style="color: #7f8c8d; font-size: 12px; text-align: center; margin: 0;">
                NetworkScanner Security System<br>
                Gerado automaticamente em {escape(current_app.config.get('SERVER_NAME', 'localhost'))}
            </p>
        </div>
    </div>
    """

    mail.send(msg)