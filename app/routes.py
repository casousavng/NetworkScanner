from http.client import HTTPException
import os
import signal
import csv
import io
import json
import ipaddress
import netifaces
import markdown2
import re
from datetime import datetime, timedelta

from flask import (
    render_template,
    request,
    flash,
    redirect,
    url_for,
    jsonify,
    send_file,
)
from flask_login import login_required
from smtplib import SMTPServerDisconnected
from google.api_core.exceptions import ResourceExhausted
from flask import render_template, g
from werkzeug.exceptions import HTTPException, Forbidden, NotFound, InternalServerError

from .mail import send_issue_report, send_report_email, allowed_file, MAX_FILE_SIZE
from .ai import fazer_pergunta
from .db import get_db
from .scan import scan_and_store
from .extensions import socketio
from .graph import build_network_data
from .csv_files import generate_csv_simple, generate_csv_full

import plotly

# Obtém a rede local e o IP do router (gateway) usando netifaces
network = netifaces.ifaddresses(netifaces.gateways()['default'][netifaces.AF_INET][1])[netifaces.AF_INET][0]
gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]

def init_app(app):

    # Rota para iniciar o scan
    @app.route('/scan', methods=['GET', 'POST'])
    @login_required
    def do_scan():
        if request.method == 'POST':
            scan_type = request.form.get("scan_type")  # 'all' ou 'specific' ou 'range'
            ip_range = request.form.get("ip_range", "").strip()

            # Definir intervalo de IP com base na escolha
            if scan_type == "all":
                # Obter a rede local automaticamente
                iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
                net = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
                # Obter o IP do router (gateway padrão)
                ip = net['addr']
                mask = net['netmask']
                # Calcular o CIDR
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                ip_range = str(network)
            elif scan_type == "specific":
                if not ip_range:
                    return render_template("new_scan.html", error="Por favor, insira um IP válido.")
            elif scan_type == "range":
                ip_start = request.form.get("ip_start", "").strip()
                ip_end = request.form.get("ip_end", "").strip()
                ip_range = ip_start + "-" + ip_end.split('.')[-1]
            else:
                return render_template("new_scan.html", error="Opção inválida de scan.")
            
            port_range = request.form.get("port_range", "").strip()
            if port_range == "":
                port_range = "1-65535"
            
            # Chamar o scan com o IP ou range definido
            scan_and_store([ip_range], port_range)  # Passa como lista para a função

        return redirect(url_for('index'))  # Redireciona para a página inicial após o scan

    # Rota para a página inicial
    @app.route('/')
    @login_required
    def index():
        fig_data = build_network_data()
        graphJSON = json.dumps(fig_data, cls=plotly.utils.PlotlyJSONEncoder)

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT start_time, end_time FROM scan_status ORDER BY start_time DESC LIMIT 1")
        row = cur.fetchone()

        if row and row['end_time'] is None:
            scan_progress = 1
        else:
            scan_progress = 0

        return render_template('index.html', graphJSON=graphJSON, scan_progress=scan_progress, network=network, router_ip=gateway)
    
    # Rota para a API que retorna informações detalhadas sobre um dispositivo específico
    @app.route('/api/device/<ip>')
    @login_required
    def api_device(ip):
        db = get_db()
        cur = db.cursor()

        # Buscar info básica do dispositivo
        cur.execute("SELECT hostname, mac, vendor, last_seen FROM devices WHERE ip=?", (ip,))
        dev = cur.fetchone()
        if not dev:
            return jsonify(error="Não encontrado"), 404

        data = dict(ip=ip, **dev)

        # Buscar portas + info de vulnerabilidades associadas
        cur.execute("""
            SELECT id, port, service, product, version, state
            FROM ports
            WHERE ip=?
        """, (ip,))
        
        ports = []
        for pid, port, svc, prod, ver, state in cur.fetchall():
            # Buscar CVEs associados à porta
            cur.execute("""
                SELECT cve_id, description, cvss, reference
                FROM cves
                WHERE port_id=?
            """, (pid,))
            cves = [{
                "id": cve_id,
                "description": description,
                "cvss": cvss,
                "reference": reference
            } for cve_id, description, cvss, reference in cur.fetchall()]

            # Buscar IDs das vulnerabilidades desta porta
            cur.execute("SELECT id FROM vulnerabilities WHERE port_id=?", (pid,))
            vuln_ids = [row[0] for row in cur.fetchall()]

            # Buscar EDBs associados a essas vulnerabilidades
            edb_list = []
            if vuln_ids:
                cur.execute(
                    f"""
                    SELECT ebd_id, reference_url, severity
                    FROM edbs
                    WHERE vulnerability_id IN ({','.join(['?']*len(vuln_ids))}) AND ebd_id IS NOT NULL
                    """,
                    vuln_ids
                )
                edb_list = [
                    {
                        "id": row[0],
                        "reference": row[1],
                        "severity": row[2]  # ou None, se não existir
                    }
                    for row in cur.fetchall()
                ]

            ports.append({
                "port": port,
                "service": svc,
                "product": prod,
                "version": ver,
                "state": state,
                "cves": cves,
                "edb": edb_list
            })

        data["ports"] = ports

        return jsonify(data)

    # Rota para listar todos os dispositivos na base de dados
    @app.route('/devices')
    @login_required
    def list_devices():
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT * FROM devices")
        return render_template('devices.html', devices=cur.fetchall(), network=network, router_ip=gateway)
    
    # Rota para a página de assistente de IA
    @app.route('/ai_assist', methods=['GET', 'POST'])
    @login_required
    def ai_assist():
        db = get_db()
        cur = db.cursor()

        # Obter todos os dispositivos
        cur.execute("SELECT ip, mac, hostname FROM devices ORDER BY last_seen DESC")
        devices = [(row['ip'], row['mac'], row['hostname']) for row in cur.fetchall()]

        # Vai buscar todos os IPs com pelo menos uma porta aberta
        cur.execute("SELECT DISTINCT ip FROM ports WHERE state='open'")
        ips_com_portas_abertas = set(row['ip'] for row in cur.fetchall())

        # Só passa para o template os dispositivos com portas abertas
        ips = [(ip, mac, hostname) for ip, mac, hostname in devices if ip in ips_com_portas_abertas]

        resposta = ""
        resposta_ia = ""
        ip_escolhido = ""
        mensagem_erro_quota = None

        if request.method == 'POST':
            ip_escolhido = request.form.get("ip")

            # Obter dados de portas + CVEs + EDBs associados ao IP selecionado
            cur.execute("""
                SELECT p.port, p.service, p.version, c.cve_id, c.description, c.cvss,
                    e.ebd_id, e.reference_url, e.severity
                FROM ports p
                LEFT JOIN cves c ON p.id = c.port_id
                LEFT JOIN vulnerabilities v ON v.port_id = p.id
                LEFT JOIN edbs e ON e.vulnerability_id = v.id
                WHERE p.ip=?
            """, (ip_escolhido,))

            rows = cur.fetchall()

            if not rows:
                resposta = (
                    "Não foram detetadas portas abertas, serviços vulneráveis, CVEs ou EDBs neste dispositivo.<br>"
                    "Recomenda-se manter o dispositivo atualizado e monitorizar regularmente para garantir a segurança."
                )
            else:
                contexto = f"Foi detetado um dispositivo com o IP {ip_escolhido}. As seguintes portas estão abertas:\n"
                tem_cves = False
                tem_ebds = False
                tem_portas = len(rows) > 0

                for row in rows:
                    contexto += f"- Porta {row['port']}: {row['service']} {row['version']}\n"
                    if row['cve_id']:
                        tem_cves = True
                        contexto += f"  > CVE: {row['cve_id']} (CVSS {row['cvss']}): {row['description']}\n"
                    if row['ebd_id']:
                        tem_ebds = True
                        contexto += f"  > EDB: {row['ebd_id']} - {row['reference_url']}\n"

                contexto += "\nCom base nesta informação, quais as principais recomendações para mitigar as vulnerabilidades detetadas?"

                try:
                    # CHAMAR A IA COM OS FLAGS CORRETOS
                    resposta_raw = fazer_pergunta(contexto, tem_cves=tem_cves, tem_edbs=tem_ebds, tem_portas_abertas=tem_portas)
                    resposta_ia = markdown2.markdown(resposta_raw)
                except ResourceExhausted as e:
                    # Podes tentar extrair retry_delay do erro se disponível, senão colocar um valor fixo
                    retry_time = 5  # Ajusta conforme necessário
                    mensagem_erro_quota = (
                        f"Quota excedida! Por favor, espere {retry_time} minutos e tente novamente."
                    )

        return render_template(
            "ai_assist.html",
            ips=ips,
            ip_escolhido=ip_escolhido,
            resposta=resposta,
            resposta_ia=resposta_ia,
            mensagem_erro_quota=mensagem_erro_quota,
            network=network,
            router_ip=gateway
        )
    
    # Rota para a página de novo scan
    @app.route('/new_scan')
    @login_required
    def new_scan():
        
        return render_template('new_scan.html', network=network, router_ip=gateway)

    # Rota para a página de sobre
    @app.route('/about')
    def about():
        return render_template('about.html', network=network, router_ip=gateway)

    # Rota para a página de ajuda
    @app.route('/help')
    @login_required
    def help():
        return render_template('help.html', network=network, router_ip=gateway)

    # Rota para a página de reportar problemas
    @app.route('/report', methods=['GET', 'POST'])
    @login_required
    def report_issue():
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip()
            issue_text = request.form.get('issue', '').strip()
            screenshot = request.files.get('screenshot')

            if not name or not email or not issue_text:
                flash('Por favor, preencha todos os campos antes de enviar.', 'report_warning')
                return redirect(url_for('report_issue'))

            if screenshot and screenshot.filename != '':
                if not allowed_file(screenshot.filename):
                    flash('Formato de ficheiro não permitido. Use apenas JPG, PNG ou GIF.', 'report_error')
                    return redirect(url_for('report_issue'))

                screenshot.seek(0, 2)
                file_size = screenshot.tell()
                screenshot.seek(0)

                if file_size > MAX_FILE_SIZE:
                    flash('Ficheiro demasiado grande. Tamanho máximo: 2 MB.', 'report_error')
                    return redirect(url_for('report_issue'))

            issue_data = {
                'name': name,
                'email': email,
                'issue': issue_text,
                'screenshot': screenshot,
            }

            try:
                send_issue_report(issue_data, "report@networkscanner.com")
                flash("Obrigado por reportar o problema. Entraremos em contacto em breve.", "report_success")
                return redirect(url_for('report_issue'))
            except SMTPServerDisconnected as e:
                print(f"Erro SMTPServerDisconnected: {e}")
                flash("Ocorreu um erro ao enviar o email. Por favor, tente novamente mais tarde.", "report_error")
                return redirect(url_for('report_issue'))
            except Exception as e:
                print(f"Erro inesperado: {e}")
                flash("Ocorreu um erro inesperado. Por favor, tente novamente mais tarde.", "report_error")
                return redirect(url_for('report_issue'))

        return render_template('report_issue.html', network=network, router_ip=gateway)

    # Rota para a página de agradecimento (INATIVA)
    @app.route('/thankyou')
    @login_required
    def thank_you():
        return render_template('thankyou.html', network=network, router_ip=gateway)

    # Rota para exibir o histórico de scans  
    @app.route('/history')
    @login_required
    def history():
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM scans ORDER BY ts DESC")
        scans = cur.fetchall()

        # Buscar estatísticas já guardadas
        ids = [scan["id"] for scan in scans]
        scan_stats = []
        for scan in scans:
            cur.execute("SELECT * FROM scans WHERE id=?", (scan["id"],))
            stats = cur.fetchone()
            if stats:
                scan_stats.append(dict(stats))
            else:
                # Se não existir, podes calcular ou deixar vazio
                scan_stats.append({
                    "id": scan["id"],
                    "ts": scan["ts"],
                    "duration": scan["duration"],
                    "n_ips": 0,
                    "n_ports": 0,
                    "n_open_ports": 0,
                    "n_cves": 0,
                    "n_edbs": 0
                })

        return render_template('history.html', scans=scans, scan_stats=scan_stats, network=network, router_ip=gateway)

    # Rota para exibir as vulnerabilidades por dispositivo
    @app.route('/vuln_by_device')
    @login_required
    def vuln_by_device():
        db = get_db()
        cur = db.cursor()

        # Buscar dispositivos com CVEs ou EDBs
        cur.execute("""
            SELECT DISTINCT d.ip, d.hostname
            FROM devices d
            JOIN ports p ON d.ip = p.ip
            JOIN vulnerabilities v ON v.port_id = p.id
            LEFT JOIN cves c ON c.port_id = p.id
            LEFT JOIN edbs e ON e.vulnerability_id = v.id
            WHERE c.cve_id IS NOT NULL OR e.ebd_id IS NOT NULL
        """)
        devices = cur.fetchall()

        device_vulns = {}

        for device in devices:
            ip = device['ip']
            hostname = device['hostname']

            cur.execute("""
                SELECT p.port, p.protocol, p.state, p.service, p.product, p.version,
                    c.cve_id, c.description AS cve_desc, c.cvss,
                    e.ebd_id, e.ebds AS edb_desc, e.severity, e.reference_url
                FROM ports p
                LEFT JOIN vulnerabilities v ON v.port_id = p.id
                LEFT JOIN cves c ON c.port_id = p.id
                LEFT JOIN edbs e ON e.vulnerability_id = v.id
                WHERE p.ip = ? AND (c.cve_id IS NOT NULL OR e.ebd_id IS NOT NULL)
            """, (ip,))
            rows = cur.fetchall()

            vulns_rows = []
            seen_entries = set()  # Para evitar duplicados

            for row in rows:
                port_str = f"{row['port']}/{row['protocol']}"

                # CVE
                if row['cve_id']:
                    cve_key = (port_str, 'CVE', row['cve_id'])
                    if cve_key not in seen_entries:
                        seen_entries.add(cve_key)
                        vulns_rows.append({
                            'port': port_str,
                            'state': row['state'],
                            'service': row['service'],
                            'product': row['product'],
                            'version': row['version'],
                            'vuln_type': 'CVE',
                            'vuln_id': row['cve_id'],
                            'description': row['cve_desc'] or '-',
                            'cvss': row['cvss'] or '-',
                            'severity': '-',
                            'reference_url': None
                        })

                # EDB
                if row['ebd_id'] and row['edb_desc']:
                    pattern = r'(CVE-\d{4}-\d+|EDB-ID:\d+)\s[\d\.]+\shttps?://[^\s]+(?:\s\*EXPLOIT\*)?'
                    matches = re.finditer(pattern, row['edb_desc'])

                    edb_desc_found = False
                    for match in matches:
                        full_desc = match.group(0)
                        edb_key = (port_str, 'EDB', row['ebd_id'], full_desc)
                        if edb_key not in seen_entries:
                            seen_entries.add(edb_key)
                            vulns_rows.append({
                                'port': port_str,
                                'state': row['state'],
                                'service': row['service'],
                                'product': row['product'],
                                'version': row['version'],
                                'vuln_type': 'Exploit-DB',
                                'vuln_id': row['ebd_id'],
                                'description': full_desc,
                                'cvss': '-',
                                'severity': row['severity'] or '-',
                                'reference_url': row['reference_url']
                            })
                            edb_desc_found = True

                    if not edb_desc_found:
                        edb_key = (port_str, 'EDB', row['ebd_id'], row['edb_desc'])
                        if edb_key not in seen_entries:
                            seen_entries.add(edb_key)
                            vulns_rows.append({
                                'port': port_str,
                                'state': row['state'],
                                'service': row['service'],
                                'product': row['product'],
                                'version': row['version'],
                                'vuln_type': 'Exploit-DB',
                                'vuln_id': row['ebd_id'],
                                'description': row['edb_desc'],
                                'cvss': '-',
                                'severity': row['severity'] or '-',
                                'reference_url': row['reference_url']
                            })

            if vulns_rows:
                device_vulns[ip] = {
                    'hostname': hostname,
                    'vulnerabilities': vulns_rows
                }

        return render_template(
            'vuln_by_device.html',
            device_vulns=device_vulns,
            network=network,
            router_ip=gateway
        )

    # Rota para exibir os relatórios
    @app.route('/reports')
    @login_required
    def reports():
        return render_template('reports.html', network=network, router_ip=gateway)

    # Rota para exportar os dispositivos em formato CSV
    @app.route('/export/csv/devices')
    @login_required
    def export_csv_devices():
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT * FROM devices")
        rows = cur.fetchall()
        si = io.StringIO(); cw = csv.writer(si)
        cw.writerow(rows[0].keys())
        for r in rows: cw.writerow(r)
        return send_file(io.BytesIO(si.getvalue().encode()),
                         mimetype='text/csv',
                         download_name='devices.csv')

    # Rota para exportar os dispositivos com informações completas em formato CSV
    @app.route('/export/csv/devices/full')
    @login_required
    def export_csv_devices_full():
        db = get_db()
        cur = db.cursor()
        # Buscar todos os dispositivos
        cur.execute("SELECT * FROM devices")
        devices = cur.fetchall()

        # Cabeçalho CSV
        header = [
            "ip", "hostname", "mac", "vendor", "last_seen",
            "port", "service", "product", "version", "state",
            "cve_id", "cve_description", "cvss", "cve_reference",
            "ebd_id", "ebd_reference_url", "ebd_severity"
        ]

        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(header)

        # Para evitar duplicados, vamos usar um set para guardar tuplos já escritos
        linhas_escritas = set()

        for dev in devices:
            ip = dev["ip"]
            # Buscar portas do dispositivo
            cur.execute("SELECT id, port, service, product, version, state FROM ports WHERE ip=?", (ip,))
            ports = cur.fetchall()
            if not ports:
                linha = (dev["ip"], dev["hostname"], dev["mac"], dev["vendor"], dev["last_seen"], "", "", "", "", "", "", "", "", "", "", "", "")
                if linha not in linhas_escritas:
                    cw.writerow(linha)
                    linhas_escritas.add(linha)
                continue
            for port_row in ports:
                port_id = port_row["id"]
                # Buscar CVEs da porta
                cur.execute("SELECT cve_id, description, cvss, reference FROM cves WHERE port_id=?", (port_id,))
                cves = cur.fetchall()
                # Buscar vulnerabilidades da porta
                cur.execute("SELECT id FROM vulnerabilities WHERE port_id=?", (port_id,))
                vuln_ids = [row[0] for row in cur.fetchall()]
                edbs = []
                if vuln_ids:
                    cur.execute(
                        f"SELECT ebd_id, reference_url, severity FROM edbs WHERE vulnerability_id IN ({','.join(['?']*len(vuln_ids))}) AND ebd_id IS NOT NULL",
                        vuln_ids
                    )
                    edbs = cur.fetchall()
                # Se não houver CVEs nem EDBs, escreve só info da porta
                if not cves and not edbs:
                    linha = (
                        dev["ip"], dev["hostname"], dev["mac"], dev["vendor"], dev["last_seen"],
                        port_row["port"], port_row["service"], port_row["product"], port_row["version"], port_row["state"],
                        "", "", "", "", "", "", ""
                    )
                    if linha not in linhas_escritas:
                        cw.writerow(linha)
                        linhas_escritas.add(linha)
                # Para cada CVE, escreve linha
                for cve in cves or [None]:
                    cve_id = cve["cve_id"] if cve else ""
                    cve_desc = cve["description"] if cve else ""
                    cvss = cve["cvss"] if cve else ""
                    cve_ref = cve["reference"] if cve else ""
                    # Para cada EDB, escreve linha
                    if edbs:
                        for edb in edbs:
                            linha = (
                                dev["ip"], dev["hostname"], dev["mac"], dev["vendor"], dev["last_seen"],
                                port_row["port"], port_row["service"], port_row["product"], port_row["version"], port_row["state"],
                                cve_id, cve_desc, cvss, cve_ref,
                                edb["ebd_id"], edb["reference_url"], edb["severity"]
                            )
                            if linha not in linhas_escritas:
                                cw.writerow(linha)
                                linhas_escritas.add(linha)
                    else:
                        linha = (
                            dev["ip"], dev["hostname"], dev["mac"], dev["vendor"], dev["last_seen"],
                            port_row["port"], port_row["service"], port_row["product"], port_row["version"], port_row["state"],
                            cve_id, cve_desc, cvss, cve_ref,
                            "", "", ""
                        )
                        if linha not in linhas_escritas:
                            cw.writerow(linha)
                            linhas_escritas.add(linha)
                # Se não houver CVEs mas houver EDBs
                if not cves and edbs:
                    for edb in edbs:
                        linha = (
                            dev["ip"], dev["hostname"], dev["mac"], dev["vendor"], dev["last_seen"],
                            port_row["port"], port_row["service"], port_row["product"], port_row["version"], port_row["state"],
                            "", "", "", "",
                            edb["ebd_id"], edb["reference_url"], edb["severity"]
                        )
                        if linha not in linhas_escritas:
                            cw.writerow(linha)
                            linhas_escritas.add(linha)

        return send_file(
            io.BytesIO(si.getvalue().encode()),
            mimetype='text/csv',
            download_name='devices_full.csv'
        )
    
    # Rota para enviar CSV por email
    @app.route('/send_email_csv', methods=['POST'])
    def send_email_csv():
        email = request.form.get('email')
        report_type = request.form.get('type')

        if not email:
            flash("O email é obrigatório", "danger")
            return redirect(url_for('relatorios'))

        if report_type == 'simple':
            csv_path = generate_csv_simple()
        elif report_type == 'full':
            csv_path = generate_csv_full()
        else:
            flash('Tipo de relatório inválido.', 'danger')
            return redirect(url_for('relatorios'))

        try:
            send_report_email(email, csv_path)
            flash(f'Relatório {report_type.upper()} enviado para {email}', 'success')
        except Exception as e:
            flash(f'Erro ao enviar email: {str(e)}', 'danger')

        return redirect(url_for('reports'))

    # Rota para encerrar o servidor Flask (usada para testes com webview)
    @app.route('/shutdown', methods=['POST'])
    @login_required
    def shutdown():
        os.kill(os.getpid(), signal.SIGINT)
        return 'A encerrar o servidor Flask...'
        
    # Rotas para tratamento de erros
    #@app.errorhandler(404)
    def handle_404(e):
        print("Erro interno:", e) 
        return render_template("error.html", error=e, network=network, router_ip=gateway), 404

    @app.errorhandler(403)
    def handle_403(e):
        print("Erro interno:", e) 
        return render_template("error.html", error=e, network=network, router_ip=gateway), 403

    #@app.errorhandler(500)
    def handle_500(e):
        print("Erro interno:", e) 
        return render_template("error.html", error=e, network=network, router_ip=gateway), 500

    #@app.errorhandler(Exception)
    def handle_exception(e):
        # Se for HTTPException (como 404, etc), deixa o handler específico lidar
        print("Erro interno:", e) # Log do erro para debug
        if isinstance(e, HTTPException):
            return render_template("error.html", error=e, network=network, router_ip=gateway), e.code

        # Se for erro inesperado (ex: ZeroDivisionError, etc)
        return render_template("error.html", error=e, network=network, router_ip=gateway), 500
    
    # Rota para o WebSocket
    @socketio.on('connect')
    def ws_connect():
        print("WS client conectado")

    # ===== GESTÃO DE UTILIZADORES =====

    @app.route('/configuration')
    @login_required
    def configuration():
        """Painel de administração"""
        return render_template('configuration.html', network=network, router_ip=gateway)
    
    @app.route('/admin/users')
    @login_required
    def manage_users():
        """Página de gestão de utilizadores"""
        from .user_auth import UserAuth
        auth = UserAuth()
        users = auth.list_users()
        return render_template('admin/manage_users.html', users=users, network=network, router_ip=gateway)
    
    @app.route('/admin/users/create', methods=['GET', 'POST'])
    @login_required
    def create_user():
        """Criar novo utilizador"""
        if request.method == 'POST':
            from .user_auth import UserAuth
            auth = UserAuth()
            
            username = request.form.get('username', '').strip()
            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            hours = int(request.form.get('hours', 24))
            
            if not username or not nome or not email or not password:
                flash('Todos os campos são obrigatórios.', 'danger')
                return render_template('admin/create_user.html', network=network, router_ip=gateway)
            
            result = auth.create_user(username, nome, email, password, hours)
            
            if result['success']:
                flash(f"Utilizador criado com sucesso! Token: {result['token']}", 'success')
                return redirect(url_for('manage_users'))
            else:
                flash(result['message'], 'danger')
        
        return render_template('admin/create_user.html', network=network, router_ip=gateway)
    
    @app.route('/admin/users/<email>/refresh', methods=['POST'])
    @login_required
    def refresh_user_token(email):
        """Renovar token de utilizador"""
        from .user_auth import UserAuth
        auth = UserAuth()
        
        hours = int(request.form.get('hours', 24))
        result = auth.refresh_token(email, hours)
        
        if result['success']:
            flash(f"Token renovado! Novo token: {result['token']}", 'success')
        else:
            flash(result['message'], 'danger')
        
        return redirect(url_for('manage_users'))
    
    @app.route('/admin/users/<email>/deactivate', methods=['POST'])
    @login_required
    def deactivate_user(email):
        """Desativar utilizador"""
        from .user_auth import UserAuth
        auth = UserAuth()
        
        result = auth.deactivate_user(email)
        
        if result['success']:
            flash(result['message'], 'success')
        else:
            flash(result['message'], 'danger')
        
        return redirect(url_for('manage_users'))
    
    @app.route('/admin/users/<email>/activate', methods=['POST'])
    @login_required
    def activate_user(email):
        """Ativar utilizador"""
        from .user_auth import UserAuth
        auth = UserAuth()
        
        result = auth.activate_user(email)
        
        if result['success']:
            flash(result['message'], 'success')
        else:
            flash(result['message'], 'danger')
        
        return redirect(url_for('manage_users'))
    
    @app.route('/admin/users/<email>')
    @login_required
    def user_details(email):
        """Detalhes de um utilizador específico"""
        from .user_auth import UserAuth
        auth = UserAuth()
        
        user = auth.get_user_by_email(email)
        if not user:
            flash('Utilizador não encontrado.', 'danger')
            return redirect(url_for('manage_users'))
        
        
        user = auth.get_user_by_email(email)
        now = datetime.utcnow()

        if user and user.get('token_expiration'):
            token_exp = user['token_expiration']
            if isinstance(token_exp, str):
                user['token_expiration'] = datetime.fromisoformat(token_exp)

        return render_template('admin/user_details.html', user=user, network=network, router_ip=gateway, now=now)    
    
    @app.route('/admin/init-users-db')
    @login_required
    def init_users_db():
        """Inicializar base de dados de utilizadores"""
        from .user_auth import UserAuth
        try:
            auth = UserAuth()
            flash('Base de dados de utilizadores inicializada com sucesso!', 'success')
        except Exception as e:
            flash(f'Erro ao inicializar base de dados: {str(e)}', 'danger')
        
        return redirect(url_for('manage_users'))

