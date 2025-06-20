# -*- coding: utf-8 -*-
import subprocess
import xml.etree.ElementTree as ET
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from .db import get_db
import re
import netifaces

# Função para obter o gateway padrão da máquina
# Utiliza a biblioteca netifaces para obter as rotas de rede e extrai o gateway padrão
# Retorna o endereço IP do gateway padrão
# Exemplo de uso: get_default_gateway()
# Pode ser útil para determinar a rede local ou para configurar o scan de rede
# Certifique-se de que a biblioteca netifaces está instalada no ambiente Python
# Você pode instalar com: pip install netifaces
# A função assume que o gateway padrão está configurado para IPv4 (AF_INET)
# Se não houver gateway padrão configurado, a função pode gerar um erro
# É recomendado tratar exceções caso o gateway não esteja disponível ou a rede não esteja configurada
# A função retorna o endereço IP do gateway padrão como uma string
# Exemplo de retorno: '192.168.1.1'
def get_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    return default_gateway

# Função para escanear e armazenar informações de rede
# Esta função realiza um scan de rede usando o Nmap e armazena os resultados no banco de dados
# Recebe uma lista de IPs ativos e um intervalo de portas a serem escaneadas
# A função atualiza os scripts do Nmap antes de iniciar o scan
# Utiliza a biblioteca subprocess para executar comandos do Nmap e processar os resultados
# Os resultados do scan são armazenados em tabelas no banco de dados, incluindo dispositivos, ports, vulnerabilities e cves
# A função também extrai informações de CVEs e EDBs a partir das descrições das vulnerabilidades
# O scan é realizado em paralelo usando ThreadPoolExecutor para melhorar a performance
# A função registra o tempo de início e fim do scan, bem como o tempo total de execução
# Exemplo de uso: scan_and_store(['192.168.1.1'], '1-1000')
def scan_and_store(active_ips, port_range):

    start_time = time.time()

    db = get_db()
    cur = db.cursor()

    cur.execute("DELETE FROM scan_status;")
    cur.execute("INSERT INTO scan_status (start_time) VALUES (CURRENT_TIMESTAMP);")
    db.commit()

    print("⚡ Iniciando varredura")

    # Atualiza os scripts do Nmap
    print("🔄 Atualizando base de dados de scripts do Nmap...")
    try:
        subprocess.run(["nmap", "--script-updatedb"], check=True)
        print("✅ Scripts do Nmap atualizados com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro ao atualizar scripts do Nmap: {e}")

    def _scan_ip(ip):
        print(f"🔬 Escaneando IP: {ip}")
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
    cur.execute("INSERT INTO scans DEFAULT VALUES")
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
                desc = "Detectado na descrição da vulnerabilidade"
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
    # Regex para EDB-ID, CVSS e URL
    # O regex procura por padrões como "EDB-ID:12345 7.5 https://www.exploit-db.com/exploits/12345"
    # O EDB-ID é capturado como um grupo, seguido por um número de CVSS e uma URL
    # A função insere ou atualiza os registros na tabela edbs
    # Se o EDB-ID já existir para o mesmo port_id, ele atualiza os campos severity, ebds e reference
    # A descrição é definida como "Detectado na descrição da vulnerabilidade"
    # A URL é extraída do padrão e armazenada no campo reference_url
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
                    "Detectado na descrição da vulnerabilidade",
                    url
                ))

    extract_cves_from_description()
    extract_ebds_from_description()
    # Atualiza o status do scan
    cur.execute("UPDATE scan_status SET end_time = CURRENT_TIMESTAMP WHERE end_time IS NULL;")
    db.commit()
    elapsed = round(time.time() - start_time, 2)
    print(f"✅ Varredura finalizada em {elapsed} segundos")