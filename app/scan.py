# -*- coding: utf-8 -*-
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from .db import get_db
from .extensions import socketio


def scan_and_store(app):
    start_time = time.time()
    print("⚡ Iniciando varredura")

    # Atualiza os scripts do Nmap
    print("🔄 Atualizando base de dados de scripts do Nmap...")
    try:
        subprocess.run(["nmap", "--script-updatedb"], check=True)
        print("✅ Scripts do Nmap atualizados com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro ao atualizar scripts do Nmap: {e}")

    # Define a rede a escanear
    net = ipaddress.ip_network("192.168.6.0/24")
    ip_list = [str(ip) for ip in net.hosts()]
    print(f"🔢 De: {ip_list[0]} até {ip_list[-1]}")

    # ---------- Fase 1: Descoberta de Hosts Ativos ----------
    def _ping_scan():
        print("🔍 Executando ping scan...")
        args = ["nmap", "-sn", "-oX", "-", str(net)]
        res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
        root = ET.fromstring(res.stdout)
        active_ips = []
        for host in root.findall("host"):
            addr = host.find("address[@addrtype='ipv4']")
            if addr is not None:
                active_ips.append(addr.attrib["addr"])
        return active_ips

    active_ips = _ping_scan()
    print(f"✅ IPs ativos encontrados: {active_ips}")

    # ---------- Fase 2: Varredura de portas com script vuln ----------
    def _scan_ip(ip):
        print(f"🔬 Escaneando IP: {ip}")
        args = ["nmap", "-sS", "-sV", "--script", "vuln", "-T4", "-p", "1-1000", "-oX", "-", ip]
        try:
            res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return ET.fromstring(res.stdout)
        except subprocess.CalledProcessError as e:
            print(f"❌ Erro ao escanear {ip}: {e}")
            print(f"Stderr: {e.stderr.decode()}")
            return None

    with ThreadPoolExecutor(max_workers=10) as exe:
        roots = list(exe.map(_scan_ip, active_ips))
        roots = [r for r in roots if r is not None]

    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO scans DEFAULT VALUES")
    print("📥 Novo registo criado em 'scans'")

    def get_vendor(mac):
        if not mac:
            return ""
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=10)
            return r.text if r.status_code == 200 else ""
        except Exception as e:
            print(f"Erro vendor {mac}: {e}")
            return ""

    total_ips = 0
    for root in roots:
        for host in root.findall("host"):
            addr_tag = host.find("address[@addrtype='ipv4']")
            if addr_tag is None:
                continue

            ip = addr_tag.attrib["addr"]
            total_ips += 1
            print(f"➡️ IP detectado: {ip}")

            mac_tag = host.find("address[@addrtype='mac']")
            mac = mac_tag.attrib["addr"] if mac_tag is not None else ""
            hn = host.find("hostnames/hostname")
            hostname = hn.attrib["name"] if hn is not None else ip
            vendor = get_vendor(mac)

            # Guardar device
            cur.execute("""
              INSERT INTO devices(ip,hostname,mac,vendor)
              VALUES(?,?,?,?)
              ON CONFLICT(ip) DO UPDATE SET
                hostname=excluded.hostname,
                mac=excluded.mac,
                vendor=excluded.vendor,
                last_seen=CURRENT_TIMESTAMP
            """, (ip, hostname, mac, vendor))

            # Portas e serviços
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

                cur.execute("""
                INSERT INTO ports(ip, port, protocol, state, service, version, product)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, port, protocol) DO UPDATE SET
                    state = excluded.state,
                    service = excluded.service,
                    version = excluded.version,
                    product = excluded.product
                """, (ip, portid, protocol, state, name, ver, product))

                cur.execute("SELECT id FROM ports WHERE ip=? AND port=? AND protocol=?", (ip, portid, protocol))
                pid_row = cur.fetchone()
                if not pid_row:
                    print(f"⚠️ Port ID não encontrado para {ip}:{portid}/{protocol}")
                    continue

                pid = pid_row[0]

                # Extrair CVEs do script "vuln"
                script = p.find("script[@id='vuln']")
                if script is not None:
                    found_cves = 0
                    for elem in script.findall("elem"):
                        cve_text = elem.text or ""
                        if "CVE" in cve_text:
                            print(f"    🛡️ CVE detectado: {cve_text}")
                            found_cves += 1
                            cur.execute("""
                                INSERT INTO cves(port_id, cve_id, description)
                                VALUES (?, ?, ?)
                                ON CONFLICT(port_id, cve_id) DO NOTHING
                            """, (pid, cve_text, "Detectado por Nmap (vuln script)"))
                    if found_cves == 0:
                        print("    ⚠️ Script 'vuln' executado mas sem CVEs detectados.")
                else:
                    print("    ℹ️ Script 'vuln' não executado ou sem resultados.")

    db.commit()
    print(f"✅ Varredura concluída. {total_ips} IPs com serviços detectados.")

    # Tempo total
    elapsed_time = time.time() - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    print(f"⏱️ Tempo total da varredura: {int(minutes)} minutos e {int(seconds)} segundos")

    socketio.emit('new_scan', {'message': 'Novo scan concluído.'}, to=None)