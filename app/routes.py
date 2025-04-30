from flask import render_template, jsonify, send_file
from flask_login import login_required
from .db import get_db
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


def init_app(app):
    
    @app.route('/scan')
    @login_required
    def do_scan():
        scan_and_store(app)  # Realiza o scan
        return jsonify({"status": "Scan concluído"})  # Resposta JSON
    

    @app.route('/')
    @login_required
    def index():
        fig_data = build_network_data()
        graphJSON = json.dumps(fig_data, cls=plotly.utils.PlotlyJSONEncoder)
        return render_template('index.html', graphJSON=graphJSON)
    

    @app.route('/api/device/<ip>')
    @login_required
    def api_device(ip):
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT hostname, mac, vendor, last_seen FROM devices WHERE ip=?", (ip,))
        dev = cur.fetchone()
        if not dev: 
            return jsonify(error="Não encontrado"), 404
        data = dict(ip=ip, **dev)
        
        # Alteração na consulta para incluir o estado da porta
        cur.execute("""
            SELECT id, port, service, version, state FROM ports WHERE ip=?
        """, (ip,))
        ports = []
        for pid, port, svc, ver, state in cur.fetchall():
            cur.execute("SELECT cve_id, description FROM cves WHERE port_id=?", (pid,))
            cves = [{"id": c, "description": d} for c, d in cur.fetchall()]
            ports.append({
                "port": port,
                "service": svc,
                "version": ver,
                "state": state,  # Agora inclui o estado da porta
                "cves": cves
            })
        data["ports"] = ports
        return jsonify(data)

    @app.route('/devices')
    @login_required
    def list_devices():
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT * FROM devices")
        return render_template('devices.html', devices=cur.fetchall())

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
        # Aqui usamos o método de sinal para encerrar o Flask
        os.kill(os.getpid(), signal.SIGINT)
        return 'A encerrar o servidor Flask...'

    @socketio.on('connect')
    def ws_connect():
        print("WS client conectado")
