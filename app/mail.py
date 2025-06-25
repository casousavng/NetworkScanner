from flask_mail import Mail, Message
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