# -*- coding: utf-8 -*-
import subprocess
import xml.etree.ElementTree as ET
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from .db import get_db, backup_db
import re
import netifaces
import ipaddress
from .mail import send_scan_start_email, send_scan_completed_email
from .update_descriptions import update_descriptions

# Função para obter o gateway padrão da máquina
def get_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    return default_gateway

# Função para escanear e armazenar informações de rede
def scan_and_store(active_ips, port_range):

    start_time = time.time()

    db = get_db()
    cur = db.cursor()

    cur.execute("DELETE FROM scan_status;")
    cur.execute("INSERT INTO scan_status (start_time) VALUES (CURRENT_TIMESTAMP);")
    db.commit()

    print("⚡ Iniciando varredura")
    print(f"🌐 IPs ativos: {active_ips}")

    # Envia email a indicar o início do scan
    send_scan_start_email("scan@networkscanner.com", {"ips": active_ips, "port_range": port_range})

    # Atualiza os scripts do Nmap
    print("🔄 Atualizando base de dados de scripts do Nmap...")
    try:
        subprocess.run(["nmap", "--script-updatedb"], check=True)
        print("✅ Scripts do Nmap atualizados com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro ao atualizar scripts do Nmap: {e}")

    def _scan_ip(ip):
        print(f"🔬 Varrendo IP: {ip}")
        print(f"🔍 Varredura de portas: {port_range}")
        args = [
            "nmap", "-sS", "-sV", "--script", "vuln", "-T4",
            "-p", port_range, "-oX", "-", ip
        ]  # Usa port_range fornecido como argumento
        try:
            res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return ET.fromstring(res.stdout)
        except subprocess.CalledProcessError as e:
            print(f"❌ Erro ao escanear {ip}: {e}")
            print(f"Stderr: {e.stderr.decode()}")
            return None

    with ThreadPoolExecutor(max_workers=10) as exe:
        roots = [r for r in exe.map(_scan_ip, active_ips) if r is not None]

    # Cria novo scan na tabela scans
    cur.execute("INSERT INTO scans (ts) VALUES (CURRENT_TIMESTAMP)")
    scan_id = cur.lastrowid
    print(f"📥 Novo registo criado em 'scans' (ID: {scan_id})")

    def get_vendor(mac):
        if not mac:
            return ""
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=10)
            return r.text if r.status_code == 200 else ""
        except Exception as e:
            print(f"Erro vendor {mac}: {e}")
            return ""

    cves_detectados = []

    for root in roots:
        for host in root.findall("host"):
            addr_tag = host.find("address[@addrtype='ipv4']")
            if addr_tag is None:
                continue

            ip = addr_tag.attrib["addr"]
            print(f"➡️ IP detectado: {ip}")

            mac_tag = host.find("address[@addrtype='mac']")
            mac = mac_tag.attrib["addr"] if mac_tag is not None else ""
            hn = host.find("hostnames/hostname")
            hostname = hn.attrib["name"] if hn is not None else ip
            vendor = get_vendor(mac)

            # Insere ou atualiza device
            cur.execute("""
              INSERT INTO devices(ip, hostname, mac, vendor, scan_id)
              VALUES (?, ?, ?, ?, ?)
              ON CONFLICT(ip) DO UPDATE SET
                  hostname = excluded.hostname,
                  mac = excluded.mac,
                  vendor = excluded.vendor,
                  last_seen = CURRENT_TIMESTAMP,
                  scan_id = excluded.scan_id
            """, (ip, hostname, mac, vendor, scan_id))

            for p in host.findall(".//port"):
                portid = int(p.attrib["portid"])
                protocol = p.attrib.get("protocol", "tcp")
                state_tag = p.find("state")
                state = state_tag.attrib["state"] if state_tag is not None else "unknown"

                if state not in ("open", "filtered"):
                    continue

                svc = p.find("service")
                product = svc.attrib.get("product", "") if svc is not None else ""
                name = svc.attrib.get("name", "") if svc is not None else ""
                ver = svc.attrib.get("version", "") if svc is not None else ""

                print(f"  💡 Porta {portid}/{protocol} ({state}): {name} {ver} (Produto: {product})")

                # Insere ou atualiza port
                cur.execute("""
                INSERT INTO ports(ip, port, protocol, state, service, version, product, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, port, protocol) DO UPDATE SET
                    state = excluded.state,
                    service = excluded.service,
                    version = excluded.version,
                    product = excluded.product,
                    scan_id = excluded.scan_id
                """, (ip, portid, protocol, state, name, ver, product, scan_id))

                cur.execute("SELECT id FROM ports WHERE ip = ? AND port = ? AND protocol = ?", (ip, portid, protocol))
                pid_row = cur.fetchone()
                if not pid_row:
                    continue

                pid = pid_row[0]

                for script in p.findall("script"):
                    script_id = script.attrib.get("id", "unknown")
                    output = script.attrib.get("output", "").strip()
                    if not output:
                        continue

                    print(f"    🧪 Script: {script_id}")
                    print(f"    📄 Output: {output}")

                    cur.execute("""
                        INSERT INTO vulnerabilities (port_id, script_id, description)
                        VALUES (?, ?, ?)
                        ON CONFLICT(port_id, script_id) DO NOTHING
                    """, (pid, script_id, output))

                    for elem in script.findall("elem"):
                        cve_text = elem.text or ""
                        if "CVE" in cve_text:
                            print(f"    🛡️ CVE detectado: {cve_text}")

                            cur.execute("""
                                INSERT INTO cves(port_id, cve_id, description)
                                VALUES (?, ?, ?)
                                ON CONFLICT(port_id, cve_id) DO NOTHING
                            """, (pid, cve_text, f"Detectado pelo script {script_id}"))

                            cur.execute("""
                                INSERT INTO vulnerabilities (port_id, cve_id, script_id, description)
                                VALUES (?, ?, ?, ?)
                                ON CONFLICT(port_id, cve_id) DO NOTHING
                            """, (pid, cve_text, script_id, f"Detectado pelo script {script_id}"))

                            cves_detectados.append((pid, cve_text))

    # Extrai CVEs e EDBs das descrições das vulnerabilidades
    def extract_cves_from_description():
        cur.execute("SELECT port_id, description FROM vulnerabilities WHERE description LIKE '%CVE%'")
        rows = cur.fetchall()
        # Regex para CVE e CVSS (ignora o link)
        pattern = re.compile(
            r'(CVE-\d{4}-\d+)[\t ]+([0-9.]+)',
            re.IGNORECASE
        )

        for port_id, description in rows:
            if not description:
                continue
            for match in pattern.finditer(description):
                cve_id = match.group(1)
                cvss = match.group(2)
                desc = ""  # Sera preenchido com script proprio
                link = f"https://vulners.com/cve/{cve_id}"
                cur.execute("""
                    INSERT INTO cves(port_id, cve_id, description, cvss, reference)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(port_id, cve_id) DO UPDATE SET
                        cvss = excluded.cvss,
                        reference = excluded.reference,
                        description = excluded.description
                """, (
                    port_id,
                    cve_id,
                    desc,
                    cvss,
                    link
                ))

    # Extrai EDBs das descrições das vulnerabilidades
    def extract_ebds_from_description():
        cur.execute("SELECT id, description FROM vulnerabilities WHERE description LIKE '%EDB-ID:%'")
        rows = cur.fetchall()

        pattern = re.compile(
            r'EDB-ID:(\d+)[\t ]+([0-9.]+)[\t ]+(https?://[^\s]+)',
            re.IGNORECASE
        )

        for vuln_id, description in rows:
            if not description:
                continue
            for match in pattern.finditer(description):
                edb_id = f"EDB-ID:{match.group(1)}"
                severity = match.group(2)
                ebds = "" # será preenchido com script proprio
                url = match.group(3)

                cur.execute("""
                    INSERT INTO edbs(vulnerability_id, ebd_id, severity, ebds, reference_url)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(vulnerability_id, ebd_id) DO UPDATE SET
                        severity = excluded.severity,
                        ebds = excluded.ebds,
                        reference_url = excluded.reference_url
                """, (
                    vuln_id,
                    edb_id,
                    severity,
                    ebds,
                    url
                ))
    
    def save_scan_stats(scan_id, ts, active_ips, port_range):
        cur = db.cursor()

        # Função para expandir IPs de intervalos tipo '192.168.1.108-110'
        def expand_ip_range(ip_range_str):
            if '-' not in ip_range_str:
                return [ip_range_str]  # IP único
            base, range_part = ip_range_str.rsplit('.', 1)
            start, end = map(int, range_part.split('-'))
            return [f"{base}.{i}" for i in range(start, end + 1)]

        # Conta o número real de IPs com base em active_ips
        def count_ips(active_ips_list):
            total = 0
            for ip_entry in active_ips_list:
                ip_entry = ip_entry.strip()
                # Verifica se é um range CIDR (ex: 192.168.1.0/24)
                if '/' in ip_entry:
                    try:
                        net = ipaddress.ip_network(ip_entry, strict=False)
                        total += net.num_addresses
                    except ValueError:
                        pass  # ignora entradas inválidas
                elif '-' in ip_entry:
                    base, range_part = ip_entry.rsplit('.', 1)
                    try:
                        start, end = map(int, range_part.split('-'))
                        if end >= start:
                            total += (end - start + 1)
                    except ValueError:
                        pass  # ignora entradas inválidas
                else:
                    total += 1
            return total

        n_ips = count_ips(active_ips)

        # Número de portas abertas
        cur.execute("SELECT COUNT(*) AS n_open_ports FROM ports WHERE scan_id=? AND state='open'", (scan_id,))
        n_open_ports = cur.fetchone()["n_open_ports"] or 0

        # Número de CVEs
        cur.execute("""
            SELECT COUNT(DISTINCT cve_id) AS n_cves
            FROM cves
            WHERE port_id IN (SELECT id FROM ports WHERE scan_id=?)
        """, (scan_id,))
        n_cves = cur.fetchone()["n_cves"] or 0

        # Número de EDBs
        cur.execute("""
            SELECT COUNT(DISTINCT ebd_id) AS n_edbs
            FROM edbs
            WHERE vulnerability_id IN (
                SELECT id FROM vulnerabilities WHERE port_id IN (SELECT id FROM ports WHERE scan_id=?)
            ) AND ebd_id IS NOT NULL
        """, (scan_id,))
        n_edbs = cur.fetchone()["n_edbs"] or 0

        # Número de portas no intervalo
        if "-" in port_range:
            try:
                start, end = map(int, port_range.split("-"))
                n_ports = end - start + 1 if end >= start else 0
            except ValueError:
                n_ports = 0
        else:
            n_ports = 1

        # Guarda estatísticas na base de dados
        cur.execute("""
            UPDATE scans SET
                n_ips = ?, n_ports = ?, n_open_ports = ?, n_cves = ?, n_edbs = ?
            WHERE id = ?
        """, (n_ips, n_ports, n_open_ports, n_cves, n_edbs, scan_id))
        db.commit()
        
    extract_cves_from_description()
    extract_ebds_from_description()
    save_scan_stats(scan_id, time.strftime('%Y-%m-%d %H:%M:%S'), active_ips, port_range)
        
    # Atualiza o status do scan
    cur.execute("UPDATE scan_status SET end_time = CURRENT_TIMESTAMP WHERE end_time IS NULL;")
    db.commit()
    
    # Mostra o tempo decorrido e atualiza a duração do scan na tabela scans
    elapsed = round(time.time() - start_time, 2)
    hours, rem = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(rem, 60)
    duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    print(f"✅ Varredura finalizada em {hours} horas, {minutes} minutos e {seconds} segundos")

    send_scan_completed_email("scan@networkscanner.com", {
        "ips": active_ips,
        "port_range": port_range,
        "scan_id": scan_id,
        "duration": duration_str,
        "n_ips": len(active_ips)
    })

    cur.execute("UPDATE scans SET duration = ? WHERE id = ?", (duration_str, scan_id))
    db.commit()

    update_descriptions()  # Atualiza descrições de CVEs e EDBs a partir da BD

    # Realiza backup da base de dados a cada scan
    print("🔄 Realizando backup da base de dados...")
    backup_db(get_default_gateway())