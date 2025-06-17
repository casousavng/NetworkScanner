from flask import render_template, jsonify, send_file
from flask_login import login_required
from flask import Blueprint, render_template, request
from .ai import fazer_pergunta
from .ai import formatar_resposta_markdown_para_html
from .db import get_db
from .db import rename_db
from .scan import scan_and_store

import csv, io
from .extensions import socketio
from .graph import build_network_data
import plotly
import json
from flask import redirect, url_for
from flask import request
import os
import signal
from datetime import datetime
import netifaces
import ipaddress


def init_app(app):
    
    # @app.route('/scan', methods=['GET', 'POST'])
    # @login_required
    # def do_scan():
    #     scan_and_store(app)  # Realiza o scan
    #     return render_template('index.html')
    #     #return jsonify({"status": "Scan concluído"})  # Resposta JSON

    @app.route('/scan', methods=['GET', 'POST'])
    @login_required
    def do_scan():
        print("Iniciando NOVO scan...")
        if request.method == 'POST':
            scan_type = request.form.get("scan_type")  # 'all' ou 'specific' ou 'range'
            print(f"Scan Type: {scan_type}")
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
            
            # Chamar o scan com o IP ou range definido
            print(f"IP Range para scan: {ip_range}")
            scan_and_store([ip_range])  # Passa como lista para a função

            return redirect(url_for('index'))

        return render_template('new_scan.html')

    @app.route('/')
    @login_required
    def index():
        fig_data = build_network_data()
        graphJSON = json.dumps(fig_data, cls=plotly.utils.PlotlyJSONEncoder)
        return render_template('index.html', graphJSON=graphJSON)
    

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
            SELECT id, port, service, version, state
            FROM ports
            WHERE ip=?
        """, (ip,))
        
        ports = []
        for pid, port, svc, ver, state in cur.fetchall():
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
                "version": ver,
                "state": state,
                "cves": cves,
                "edb": edb_list
            })

        data["ports"] = ports

        return jsonify(data)

    @app.route('/devices')
    @login_required
    def list_devices():
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT * FROM devices")
        return render_template('devices.html', devices=cur.fetchall())
    

    @app.route('/ai_assist', methods=['GET', 'POST'])
    def ai_assist():
        db = get_db()
        cur = db.cursor()

        # Obter todos os IPs detetados
        cur.execute("SELECT ip FROM devices ORDER BY last_seen DESC")
        ips = [row['ip'] for row in cur.fetchall()]

        resposta = ""
        resposta_ia = ""
        ip_escolhido = ""

        if request.method == 'POST':
            ip_escolhido = request.form.get("ip")

            # Obter dados de portas + CVEs associados ao IP selecionado
            cur.execute("""
                SELECT p.port, p.service, p.version, c.cve_id, c.description, c.cvss
                FROM ports p
                LEFT JOIN cves c ON p.id = c.port_id
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
                tem_portas = len(rows) > 0

                for row in rows:
                    contexto += f"- Porta {row['port']}: {row['service']} {row['version']}\n"
                    if row['cve_id']:
                        tem_cves = True
                        contexto += f"  > CVE: {row['cve_id']} (CVSS {row['cvss']}): {row['description']}\n"

                contexto += "\nCom base nesta informação, quais as principais recomendações para mitigar as vulnerabilidades detetadas?"

                # CHAMAR A IA COM OS FLAGS CORRETOS
                resposta_raw = fazer_pergunta(contexto, tem_cves=tem_cves, tem_edbs=False, tem_portas=tem_portas)
                resposta_ia = formatar_resposta_markdown_para_html(resposta_raw)

        return render_template(
            "ai_assist.html",
            ips=ips,
            ip_escolhido=ip_escolhido,
            resposta=resposta,
            resposta_ia=resposta_ia
        )
  
    @app.route('/settings')
    @login_required
    def settings():
        return render_template('settings.html')
    
    @app.route('/new_scan')
    @login_required
    def new_scan():
        return render_template('new_scan.html')

    @app.route('/about')
    @login_required
    def about():
        return render_template('about.html')

    @app.route('/help')
    @login_required
    def help():
        return render_template('help.html')

    @app.route('/report-issue')
    @login_required
    def report_issue():
        return render_template('report_issue.html')

    @app.route('/history')
    @login_required
    def history():
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT * FROM scans ORDER BY ts DESC")
        return render_template('history.html', scans=cur.fetchall())
        

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
    
    @app.route('/shutdown', methods=['POST'])
    def shutdown():
        # Renomeia a base de dados antes de encerrar apenas para DEBUG
        #rename_db()  
        # Aqui usamos o método de sinal para encerrar o Flask
        os.kill(os.getpid(), signal.SIGINT)
        return 'A encerrar o servidor Flask...'

    @socketio.on('connect')
    def ws_connect():
        print("WS client conectado")

    @app.route('/api/edb-info')
    @login_required
    def edb_info():
        db = get_db()
        cur = db.cursor()
        cur.execute("""
            SELECT d.ip, p.port, v.id AS vuln_id, e.ebd_id, e.reference_url
            FROM devices d
            JOIN ports p ON p.ip = d.ip
            JOIN vulnerabilities v ON v.port_id = p.id
            JOIN edbs e ON e.vulnerability_id = v.id;
        """)
        rows = cur.fetchall()
        return jsonify([dict(row) for row in rows])
