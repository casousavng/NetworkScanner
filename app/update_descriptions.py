import os
import requests
import gzip
import shutil
import json
import sqlite3
import csv

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/" # URL base para os feeds NVD (CVEs)
YEARS = list(range(2002, 2026))  # de 2002 até 2025
DB_PATH = os.path.join("data", "rede.db")
DATA_DIR = "cve_edb_data"
EBD_CSV_PATH = "cve_edb_data/files_exploits.csv" # Caminho do CSV de EBDs

os.makedirs(DATA_DIR, exist_ok=True)

def download_and_extract_feeds():
    for year in YEARS:
        gz_filename = f"nvdcve-2.0-{year}.json.gz"
        json_filename = gz_filename[:-3]
        gz_path = os.path.join(DATA_DIR, gz_filename)
        json_path = os.path.join(DATA_DIR, json_filename)

        # ✅ Se o JSON já existe, pula tudo (nem baixa)
        if os.path.exists(json_path):
            print(f"{json_filename} já existe. Ignorando download e extração.")
            continue

        url = BASE_URL + gz_filename

        # Baixar o .gz
        print(f"Baixando {gz_filename}...")
        r = requests.get(url, stream=True)
        r.raise_for_status()
        with open(gz_path, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

        # Extrair para JSON
        print(f"Extraindo {gz_filename}...")
        with gzip.open(gz_path, 'rb') as f_in:
            with open(json_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        # ✅ Apagar o .gz depois de extrair
        try:
            os.remove(gz_path)
            print(f"✔ Apagado {gz_filename}")
        except Exception as e:
            print(f"❌ Erro ao apagar {gz_filename}: {e}")

def build_cve_description_index():
    print("Construindo índice de descrições CVE...")
    cve_descriptions = {}
    for year in YEARS:
        json_path = os.path.join(DATA_DIR, f"nvdcve-2.0-{year}.json")
        if not os.path.exists(json_path):
            continue
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        cve_descriptions[cve_id] = d.get("value")
                        break
    print(f"Total de CVEs indexados: {len(cve_descriptions)}")
    return cve_descriptions

def build_ebd_description_index():
    print("Construindo índice de descrições EBD...")
    ebd_descriptions = {}
    if not os.path.exists(EBD_CSV_PATH):
        print(f"❌ Arquivo {EBD_CSV_PATH} não encontrado.")
        return ebd_descriptions

    with open(EBD_CSV_PATH, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            raw_id = row.get("id", "").strip()
            desc = row.get("description", "").strip()
            if raw_id and desc:
                ebd_id = f"EDB-ID:{raw_id}"
                ebd_descriptions[ebd_id] = desc
    print(f"Total de EBDs indexados: {len(ebd_descriptions)}")
    return ebd_descriptions

def update_cves_table(cve_desc_map):
    print("Atualizando descrições na tabela 'cves'...")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT port_id, cve_id FROM cves")
    rows = cur.fetchall()
    total = 0

    for port_id, cve_id in rows:
        desc = cve_desc_map.get(cve_id, "Descrição não disponível.")
        cur.execute("""
            UPDATE cves SET description = ? WHERE port_id = ? AND cve_id = ?
        """, (desc, port_id, cve_id))
        if cur.rowcount > 0:
            print(f"✔ CVE atualizado: {cve_id}")
            total += 1

    conn.commit()
    conn.close()
    print(f"✔ Atualização CVEs completa. Total: {total}")

def update_edbs_table(ebd_desc_map):
    print("Atualizando descrições na tabela 'edbs'...")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT vulnerability_id, ebd_id FROM edbs")
    rows = cur.fetchall()
    total = 0

    for vulnerability_id, ebd_id in rows:
        desc = ebd_desc_map.get(ebd_id, "Descrição não disponível.")
        cur.execute("""
            UPDATE edbs SET ebds = ? WHERE vulnerability_id = ? AND ebd_id = ?
        """, (desc, vulnerability_id, ebd_id))
        if cur.rowcount > 0:
            print(f"✔ EBD atualizado: {ebd_id}")
            total += 1

    conn.commit()
    conn.close()
    print(f"✔ Atualização EBDs completa. Total: {total}")

def update_descriptions():
    print("Iniciando atualização de descrições CVE e EBD...")
    download_and_extract_feeds()
    print("✅ Feeds baixados e extraídos com sucesso.")
    cve_desc_map = build_cve_description_index()
    ebd_desc_map = build_ebd_description_index()
    print("✅ Índices de descrições construídos com sucesso.")
    update_cves_table(cve_desc_map)
    update_edbs_table(ebd_desc_map)

    def main():
        update_descriptions()

    if __name__ == "__main__":
        main()