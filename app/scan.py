

# -*- coding: utf-8 -*-
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from .db import get_db
from .nvd import fetch_cves
from .extensions import socketio

def scan_and_store(app):

    start_time = time.time()
    print("⚡ Iniciando varredura")

    net = ipaddress.ip_network("192.168.1.0/24")  # Exemplo para testar a rede local
    #net = ipaddress.ip_network("192.168.1.217")  # Exemplo para testar um IP específico
    
    #net = ipaddress.ip_network(app.config["SUBNET"], strict=False) #Exemplo para testar a rede local a partir da configuração
    
    ip_list = [str(ip) for ip in net.hosts()]
    #print(f"🔍 IPs a escanear (ping): {ip_list}") #lista completa de ips (muitos valores)
    print(f"🔢 De: {ip_list[0]}"+" ate " + ip_list[-1])


    # ---------- Fase 1: Descoberta de Hosts Ativos ----------
    def _ping_scan():
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

    # ---------- Fase 2: Varredura de portas 1-10000 ----------
    def _scan_ip(ip):
        args = ["nmap", "-sS", "-sV", "-T4", "-p", "1-1000", "-oX", "-", ip] 
        res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
        return ET.fromstring(res.stdout)

    with ThreadPoolExecutor(max_workers=20) as exe:
        roots = list(exe.map(_scan_ip, active_ips))

    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO scans DEFAULT VALUES")
    print("📥 Novo registo criado em 'scans'")

    # ---------- Função de Vendor ----------
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

            # Insere na DB
            cur.execute("""
              INSERT INTO devices(ip,hostname,mac,vendor)
              VALUES(?,?,?,?)
              ON CONFLICT(ip) DO UPDATE SET
                hostname=excluded.hostname,
                mac=excluded.mac,
                vendor=excluded.vendor,
                last_seen=CURRENT_TIMESTAMP
            """, (ip, hostname, mac, vendor))

            # Portas e Serviços
            for p in root.findall(".//port"):
                portid = int(p.attrib["portid"])
                protocol = p.attrib.get("protocol", "tcp")

                state_tag = p.find("state")
                state = state_tag.attrib["state"] if state_tag is not None else "unknown"

                if state not in ("open", "filtered"):
                    continue  # ignora portas closed ou unrecognized

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
                pid = cur.fetchone()[0]

                if name:
                    cves = fetch_cves(name, ver)
                    for cve in cves:
                        cur.execute("""
                        INSERT INTO cves(port_id, cve_id, description)
                        VALUES (?, ?, ?)
                        ON CONFLICT(port_id, cve_id) DO UPDATE SET
                            description = excluded.description
                        """, (pid, cve["id"], cve["description"]))

    db.commit()
    print(f"✅ Varredura concluída. {total_ips} IPs com serviços detectados.")

    # Calcula o tempo total da varredura
    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    print(f"⏱️ Tempo total da varredura: {int(minutes)} minutos e {int(seconds)} segundos")
    
    socketio.emit('new_scan', {'message': 'Novo scan concluído.'}, to=None)









# versao original e completa do scan.py
'''

import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from .db import get_db
from .nvd import fetch_cves
from .extensions import socketio
def scan_and_store(app):
    print("⚡ Iniciando varredura")
    start_time = time.time()

    # Carrega a rede inteira a partir da variável de configuração da aplicação
    net = ipaddress.ip_network("192.168.1.0/24")  # ip limitado para teste

    # Gera uma lista de todos os IPs na sub-rede, excluindo o endereço de rede e o de broadcast
    ip_list = [str(ip) for ip in net.hosts()]
    print(f"🔍 IPs a escanear: {ip_list}")

    def _scan_ip(ip):
        # Executa o nmap para cada IP
        # args = ["nmap", "-T5", "-sV", "-p 1-10000", "-oX", "-", ip] # parametros originais: nmap -sV -oX - <ip>
        args = ["sudo", "nmap", "-sS", "-sV", "-T4", "-p", "1-10000", "-oX", "-", ip]
        res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
        return ET.fromstring(res.stdout)

    # Usa múltiplos threads para escanear os IPs de forma paralela
    with ThreadPoolExecutor(max_workers=20) as exe:
        roots = list(exe.map(_scan_ip, ip_list))

    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO scans DEFAULT VALUES")
    print("📥 Inserido novo registo em 'scans'")

    total_ips = 0

    # Função para obter o vendor do MAC
    def get_vendor(mac):
        if not mac:
            return ""
        url = f"https://api.macvendors.com/{mac}"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                return r.text
            else:
                print(f"Erro ao obter vendor para {mac}: Status {r.status_code}")
                return ""
        except requests.exceptions.RequestException as e:
            print(f"Erro ao obter vendor para {mac}: {e}")
            return ""

    # Processa os resultados do Nmap
    for root in roots:
        for host in root.findall("host"):
            addr_tag = host.find("address[@addrtype='ipv4']")
            if addr_tag is None:
                print("⚠️ Host sem IP IPv4, ignorado.")
                continue

            ip = addr_tag.attrib["addr"]
            total_ips += 1
            print(f"➡️ Encontrado IP: {ip}")

            mac_tag = host.find("address[@addrtype='mac']")
            mac = mac_tag.attrib["addr"] if mac_tag is not None else ""
            hn = host.find("hostnames/hostname")
            hostname = hn.attrib["name"] if hn is not None else ip

            # Adiciona o MAC à lista para obter o vendor
            vendor = get_vendor(mac)

            # Insere os dados do dispositivo na base de dados
            cur.execute("""
              INSERT INTO devices(ip,hostname,mac,vendor)
              VALUES(?,?,?,?)
              ON CONFLICT(ip) DO UPDATE SET
                hostname=excluded.hostname,
                mac=excluded.mac,
                vendor=excluded.vendor,
                last_seen=CURRENT_TIMESTAMP
            """, (ip, hostname, mac, vendor))

            # Escaneia as portas abertas no dispositivo
            for p in root.findall(".//port"):
                portid = int(p.attrib["portid"])
                svc = p.find("service")
                product = svc.attrib.get("product", "") if svc is not None else ""
                name = svc.attrib.get("name", "") if svc is not None else ""
                ver = svc.attrib.get("version", "") if svc is not None else ""
                print(f"  💡 Porta {portid}: {name} {ver} (Produto: {product})")
                cur.execute("""
                INSERT INTO ports(ip, port, service, version, product)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip, port) DO UPDATE SET
                    service = excluded.service,
                    version = excluded.version,
                    product = excluded.product
                """, (ip, portid, name, ver, product))

                cur.execute("SELECT id FROM ports WHERE ip=? AND port=?", (ip, portid))
                pid = cur.fetchone()[0]

                # Insere os CVEs encontrados para o serviço na porta
                if name:
                    cves = fetch_cves(name, ver)  # Aqui você chama a função fetch_cves
                    for cve in cves:
                        cur.execute("""
                        INSERT INTO cves(port_id, cve_id, description)
                        VALUES (?, ?, ?)
                        ON CONFLICT(port_id, cve_id) DO UPDATE SET
                            description = excluded.description
                        """, (pid, cve["id"], cve["description"]))

    # Confirma as alterações na base de dados
    db.commit()
    print(f"✅ Varredura concluída. {total_ips} IPs encontrados.")
    # Calcula o tempo total da varredura
    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    print(f"⏱️ Tempo total da varredura: {int(minutes)} minutos e {int(seconds)} segundos")
    
    # Emite um evento para indicar que a varredura terminou
    socketio.emit('new_scan', {'message': 'Novo scan concluído.'}, to=None)

'''