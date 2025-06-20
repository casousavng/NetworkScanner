import os
import signal
import csv
import io
import json
import ipaddress
import netifaces
from dotenv import load_dotenv

from flask import (
    Flask,
    app,
    render_template,
    request,
    flash,
    redirect,
    url_for,
    jsonify,
    send_file,
)
from flask_login import login_required

from .mail import mail, init_mail, send_issue_report
from .ai import fazer_pergunta, formatar_resposta_markdown_para_html
from .db import get_db
from .scan import scan_and_store
from .extensions import socketio
from .graph import build_network_data

import plotly

# Função para inicializar as rotas da aplicação Flask
# Esta função é chamada no início da aplicação para configurar as rotas

def init_app(app):

    # Rota para iniciar o scan
    # Permite escolher entre scan completo, específico ou intervalo de IPs
    # Também permite escolher o intervalo de portas a escanear
    # Após o scan, redireciona para a página inicial
    # e atualiza o mapa de rede com os novos dados
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam iniciar scans
    # A rota aceita tanto GET (para exibir o formulário) quanto POST (para processar o formulário e iniciar o scan)
    # O scan é feito em background usando a função scan_and_store, que armazena os resultados no banco de dados
    # A função também atualiza o status do scan na tabela scan_status, que é usada para mostrar o progresso do scan na página inicial
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
            # print(f"IP Range para scan: {ip_range}")
            scan_and_store([ip_range], port_range)  # Passa como lista para a função

        return redirect(url_for('index'))  # Redireciona para a página inicial após o scan

    # Rota para a página inicial
    # Exibe o mapa de rede com os dados mais recentes
    # Também verifica o status do último scan e exibe o progresso
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função build_network_data é chamada para construir os dados do gráfico usando Plotly
    # Os dados do gráfico são convertidos para JSON usando o PlotlyJSONEncoder
    # O status do scan é verificado na tabela scan_status, e se o último scan ainda estiver em andamento (end_time é None), o progresso é definido como 1 (em andamento), caso contrário, é definido como 0 (concluído)
    # Os dados do gráfico e o progresso do scan são passados para o template index.html para renderização
    # A rota também usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar a página
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

        return render_template('index.html', graphJSON=graphJSON, scan_progress=scan_progress)
    
    # Rota para a API que retorna informações detalhadas sobre um dispositivo específico
    # A rota aceita um parâmetro IP e retorna informações sobre o dispositivo, incluindo portas abertas
    # e vulnerabilidades associadas, no formato JSON
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função busca informações do dispositivo na tabela devices e suas portas na tabela ports
    # Para cada porta, busca as CVEs associadas na tabela cves e as vulnerabilidades na tabela vulnerabilities
    # Também busca os EDBs associados às vulnerabilidades, se existirem
    # Os dados são organizados em um dicionário e retornados como JSON
    # Se o dispositivo não for encontrado, retorna um erro 404
    # A função usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função get_db é usada para obter a conexão com o banco de dados SQLite
    # A consulta SQL é feita usando parâmetros para evitar injeção de SQL
    # A resposta JSON inclui o IP do dispositivo, hostname, MAC, vendor, last_seen
    # e uma lista de portas com suas informações, incluindo CVEs e EDBs associados
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
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função busca todos os dispositivos na tabela devices e os exibe em um template
    # A consulta SQL é feita sem parâmetros, retornando todos os dispositivos
    # Os dados são passados para o template devices.html, que renderiza uma tabela com os dispositivos
    # A função usa o decorator login_required para garantir que apenas utilizadores autenticados
    # possam acessar a lista de dispositivos
    @app.route('/devices')
    @login_required
    def list_devices():
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT * FROM devices")
        return render_template('devices.html', devices=cur.fetchall())
    
    # Rota para a página de assistente de IA
    # Permite ao utilizador selecionar um dispositivo e obter recomendações de segurança
    # A rota aceita tanto GET (para exibir o formulário) quanto POST (para processar o formulário e obter recomendações)
    # A função busca todos os dispositivos na tabela devices e verifica quais têm portas abertas
    # Se o utilizador selecionar um dispositivo, busca as portas abertas
    # e as vulnerabilidades associadas, incluindo CVEs e EDBs
    # A função constrói um contexto para a IA com as informações do dispositivo e suas portas
    # e chama a função fazer_pergunta para obter recomendações de segurança
    # A resposta da IA é formatada de Markdown para HTML usando a função formatar_resposta_markdown_para_html
    # Os dados dos dispositivos e a resposta da IA são passados para o template ai_assist.html
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função get_db é usada para obter a conexão com o banco de dados SQLite
    # A consulta SQL é feita usando parâmetros para evitar injeção de SQL
    # A resposta inclui uma lista de dispositivos com portas abertas, o IP selecionado pelo utilizador,
    # a resposta da IA e uma mensagem de resposta, se aplicável
    @app.route('/ai_assist', methods=['GET', 'POST'])
    @login_required
    def ai_assist():
        db = get_db()
        cur = db.cursor()

        # Obter todos os dispositivos
        cur.execute("SELECT ip, mac, hostname FROM devices ORDER BY last_seen DESC")
        devices = [ (row['ip'], row['mac'], row['hostname']) for row in cur.fetchall() ]

        # Vai buscar todos os IPs com pelo menos uma porta aberta
        cur.execute("SELECT DISTINCT ip FROM ports WHERE state='open'")
        ips_com_portas_abertas = set(row['ip'] for row in cur.fetchall())

        # Só passa para o template os dispositivos com portas abertas
        ips = [ (ip, mac, hostname) for ip, mac, hostname in devices if ip in ips_com_portas_abertas ]

        resposta = ""
        resposta_ia = ""
        ip_escolhido = ""

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
                resposta = "Não foram detetadas portas abertas, serviços vulneráveis, CVEs ou EDBs neste dispositivo.<br>"
                resposta += "Recomenda-se manter o dispositivo atualizado e monitorizar regularmente para garantir a segurança."
            else:
                # Construir contexto da pergunta para a IA
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

                # CHAMAR A IA COM OS FLAGS CORRETOS
                resposta_raw = fazer_pergunta(contexto, tem_cves=tem_cves, tem_edbs=tem_ebds, tem_portas_abertas=tem_portas)
                resposta_ia = formatar_resposta_markdown_para_html(resposta_raw)

        return render_template(
            "ai_assist.html",
            ips=ips,
            ip_escolhido=ip_escolhido,
            resposta=resposta,
            resposta_ia=resposta_ia
        )
    
    # Rota para a página de novo scan
    # Exibe um formulário para iniciar um novo scan
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # O formulário permite escolher entre scan completo, específico ou intervalo de IPs
    # Também permite escolher o intervalo de portas a escanear
    # Após o scan, redireciona para a página inicial
    # A rota usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar   
    @app.route('/new_scan')
    @login_required
    def new_scan():
        return render_template('new_scan.html')

    # Rota para a página de sobre
    # Exibe informações sobre a aplicação, como versão, autor e descrição
    # A função renderiza o template about.html, que exibe as informações sobre a aplicação
    # A rota usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar
    @app.route('/about')
    def about():
        return render_template('about.html')

    # Rota para a página de ajuda
    # Exibe informações de ajuda sobre como usar a aplicação

    # A função renderiza o template help.html, que exibe as informações de ajuda
    # A rota usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar
    @app.route('/help')
    @login_required
    def help():
        return render_template('help.html')

    # Rota para a página de reportar problema
    # Exibe um formulário para reportar problemas ou bugs na aplicação
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função renderiza o template report_issue.html, que exibe o formulário de reportar problema
    # A rota usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar
    @app.route('/report', methods=['GET', 'POST'])
    @login_required
    def report_issue():
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip()
            issue_text = request.form.get('issue', '').strip()

            if not name or not email or not issue_text:
                flash('Por favor, preencha todos os campos antes de enviar.', 'warning')
                return redirect(url_for('report_issue'))

            # Monta a mensagem para o email
            message = f"Nome: {name}\nEmail: {email}\n\nProblema reportado:\n{issue_text}"

            send_issue_report(message, "report@networkscanner.com")
            flash('Obrigado por reportar o problema. Entraremos em contacto em breve.', 'success')
            return redirect(url_for('thank_you'))

        return render_template('report_issue.html')  # Teu formulário

    # Rota para a página de agradecimento
    # Exibe uma mensagem de agradecimento após o utilizador reportar um problema
    @app.route('/thankyou')
    @login_required
    def thank_you():
        return render_template('thankyou.html')

    # Rota para exibir o histórico de scans
    # Exibe uma lista de todos os scans realizados, ordenados por data
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função busca os scans na tabela scans e os exibe em um template
    # A consulta SQL é feita para obter todos os scans ordenados pela data mais recente
    # Os dados são passados para o template history.html, que renderiza uma tabela com os scans
    # A função usa o decorator login_required para garantir que apenas utilizadores autenticados
    # possam acessar o histórico de scans    
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
                    "n_ips": 0,
                    "n_ports": 0,
                    "n_open_ports": 0,
                    "n_cves": 0,
                    "n_edbs": 0
                })

        return render_template('history.html', scans=scans, scan_stats=scan_stats)
    
    # Rota para exportar os dispositivos em formato CSV
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função busca todos os dispositivos na tabela devices e os exporta para um arquivo CSV
    # Os dados são escritos em um objeto StringIO, que é convertido para BytesIO
    # e enviado como um arquivo para download
    # O arquivo é enviado com o tipo MIME 'text/csv' e o nome 'devices.csv'
    # A função usa o decorator login_required para garantir que apenas utilizadores autenticados
    # possam acessar a exportação de dispositivos
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
    # A rota é protegida por login_required para garantir que apenas utilizadores autenticados possam acessar
    # A função busca todos os dispositivos na tabela devices e suas portas, CVEs e EDBs associadas
    # Os dados são organizados em um formato tabular e escritos em um objeto StringIO
    # O CSV resultante inclui informações detalhadas sobre cada dispositivo,
    # incluindo IP, hostname, MAC, vendor, last_seen, portas abertas, serviços,
    # produtos, versões, estados, CVEs e EDBs associadas
    # O arquivo é enviado como um download com o nome 'devices_full.csv'
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
    # Rota para encerrar o servidor Flask
    # Esta rota é usada para encerrar o servidor Flask de forma controlada

    # A função usa o método os.kill para enviar um sinal SIGINT ao processo atual
    # Isso simula o pressionamento de Ctrl+C no terminal, encerrando o servidor Flask
    # A função também pode renomear a base de dados antes de encerrar, se necessário
    # A rota retorna uma mensagem indicando que o servidor está sendo encerrado
    # A função usa o decorator login_required para garantir que apenas utilizadores autenticados possam acessar
    @app.route('/shutdown', methods=['POST'])
    @login_required
    def shutdown():
        os.kill(os.getpid(), signal.SIGINT)
        return 'A encerrar o servidor Flask...'


    # Rota para o WebSocket
    # Esta rota é usada para estabelecer uma conexão WebSocket com o cliente
    # A função ws_connect é chamada quando um cliente se conecta ao WebSocket
    # A função imprime uma mensagem no console indicando que um cliente WebSocket se conectou
    # A rota usa o decorator socketio.on para registrar a função ws_connect como um manipulador de eventos de conexão WebSocket
    # Isso permite que o servidor Flask receba mensagens do cliente e envie mensagens de volta
    # A função ws_connect pode ser expandida para enviar mensagens de status ou atualizações para o cliente
    # A rota usa o decorator socketio.on para registrar a função ws_connect como um manipulador de eventos de conexão WebSocket
    # Isso permite que o servidor Flask receba mensagens do cliente e envie mensagens de volta
    # A função ws_connect pode ser expandida para enviar mensagens de status ou atualizações para o cliente
    # A função ws_connect é chamada automaticamente quando um cliente se conecta ao WebSocket
    # A função pode ser usada para enviar mensagens de status ou atualizações para o cliente
    @socketio.on('connect')
    def ws_connect():
        print("WS client conectado")

