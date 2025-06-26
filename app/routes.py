import os
import signal
import csv
import io
import json
import ipaddress
import netifaces
import markdown2

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

from .mail import send_issue_report, allowed_file, MAX_FILE_SIZE
from .ai import fazer_pergunta
from .db import get_db
from .scan import scan_and_store
from .extensions import socketio
from .graph import build_network_data

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
                flash('Por favor, preencha todos os campos antes de enviar.', 'warning')
                return redirect(url_for('report_issue'))

            if screenshot and screenshot.filename != '':
                if not allowed_file(screenshot.filename):
                    flash('Formato de ficheiro não permitido. Use apenas JPG, PNG ou GIF.', 'danger')
                    return redirect(url_for('report_issue'))

                screenshot.seek(0, 2)  # move para o fim do ficheiro
                file_size = screenshot.tell()
                screenshot.seek(0)  # volta ao início para leitura posterior

                if file_size > MAX_FILE_SIZE:
                    flash('Ficheiro demasiado grande. Tamanho máximo: 2 MB.', 'danger')
                    return redirect(url_for('report_issue'))

            issue_data = {
                'name': name,
                'email': email,
                'issue': issue_text,
                'screenshot': screenshot,
            }

            try:
                send_issue_report(issue_data, "report@networkscanner.com")
                flash("Obrigado por reportar o problema. Entraremos em contacto em breve.", "success")
                return redirect(url_for('report_issue')) # Redireciona para a mesma página após o envio podemos optar para encaminhar para uma página de agradecimento
            except SMTPServerDisconnected as e:
                print(f"Erro SMTPServerDisconnected: {e}")
                flash("Ocorreu um erro ao enviar o email. Por favor, tente novamente mais tarde.", "danger")
                return redirect(url_for('report_issue'))
            except Exception as e:
                print(f"Erro inesperado: {e}")
                flash("Ocorreu um erro inesperado. Por favor, tente novamente mais tarde.", "danger")
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

        # Obter apenas dispositivos com CVEs ou ExploitDBs associados
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

            # Buscar vulnerabilidades com CVE ou EBD
            cur.execute("""
                SELECT p.port, p.service, p.product, p.version,
                    c.cve_id, c.description, c.cvss,
                    e.ebd_id, e.reference_url, e.severity
                FROM ports p
                JOIN vulnerabilities v ON v.port_id = p.id
                LEFT JOIN cves c ON c.port_id = p.id
                LEFT JOIN edbs e ON e.vulnerability_id = v.id
                WHERE p.ip = ? AND (c.cve_id IS NOT NULL OR e.ebd_id IS NOT NULL)
            """, (ip,))
            vulns = cur.fetchall()

            if vulns:
                device_vulns[ip] = {
                    'hostname': hostname,
                    'vulnerabilities': vulns
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
    # Rota para encerrar o servidor Flask (usada para testes com webview)
    @app.route('/shutdown', methods=['POST'])
    @login_required
    def shutdown():
        os.kill(os.getpid(), signal.SIGINT)
        return 'A encerrar o servidor Flask...'

    # Rota para o WebSocket
    @socketio.on('connect')
    def ws_connect():
        print("WS client conectado")

