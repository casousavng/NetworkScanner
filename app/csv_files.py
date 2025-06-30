import io
import csv
import tempfile
from .db import get_db

def generate_csv_simple():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM devices")
    rows = cur.fetchall()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(rows[0].keys())
    for r in rows:
        cw.writerow(r)
    
    # Salvar num arquivo temporário
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    tmp_file.write(si.getvalue().encode('utf-8'))
    tmp_file.close()

    return tmp_file.name


def generate_csv_full():
    db = get_db()
    cur = db.cursor()
    devices = cur.execute("SELECT * FROM devices").fetchall()

    header = [
        "ip", "hostname", "mac", "vendor", "last_seen",
        "port", "service", "product", "version", "state",
        "cve_id", "cve_description", "cvss", "cve_reference",
        "ebd_id", "ebd_reference_url", "ebd_severity"
    ]

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(header)

    linhas_escritas = set()

    for dev in devices:
        ip = dev["ip"]
        ports = cur.execute("SELECT id, port, service, product, version, state FROM ports WHERE ip=?", (ip,)).fetchall()
        if not ports:
            linha = (dev["ip"], dev["hostname"], dev["mac"], dev["vendor"], dev["last_seen"], "", "", "", "", "", "", "", "", "", "", "", "")
            if linha not in linhas_escritas:
                cw.writerow(linha)
                linhas_escritas.add(linha)
            continue
        for port_row in ports:
            port_id = port_row["id"]
            cves = cur.execute("SELECT cve_id, description, cvss, reference FROM cves WHERE port_id=?", (port_id,)).fetchall()
            vuln_ids = [row[0] for row in cur.execute("SELECT id FROM vulnerabilities WHERE port_id=?", (port_id,)).fetchall()]
            edbs = []
            if vuln_ids:
                edbs = cur.execute(
                    f"SELECT ebd_id, reference_url, severity FROM edbs WHERE vulnerability_id IN ({','.join(['?']*len(vuln_ids))}) AND ebd_id IS NOT NULL",
                    vuln_ids
                ).fetchall()

            if not cves and not edbs:
                linha = (
                    dev["ip"], dev["hostname"], dev["mac"], dev["vendor"], dev["last_seen"],
                    port_row["port"], port_row["service"], port_row["product"], port_row["version"], port_row["state"],
                    "", "", "", "", "", "", ""
                )
                if linha not in linhas_escritas:
                    cw.writerow(linha)
                    linhas_escritas.add(linha)

            for cve in cves or [None]:
                cve_id = cve["cve_id"] if cve else ""
                cve_desc = cve["description"] if cve else ""
                cvss = cve["cvss"] if cve else ""
                cve_ref = cve["reference"] if cve else ""

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

    # Salvar no arquivo temporário
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    tmp_file.write(si.getvalue().encode('utf-8'))
    tmp_file.close()

    return tmp_file.name