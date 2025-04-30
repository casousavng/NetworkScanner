import json, time
import requests
from flask import current_app
from .db import get_db

def fetch_cves(service, version, max_results=3):
    db = get_db()
    cur = db.cursor()
    ttl = current_app.config["CACHE_TTL_HOURS"] * 3600

    cur.execute("""
      SELECT result_json, strftime('%s', fetched_at) AS ts
      FROM cve_cache WHERE service=? AND version=?
    """, (service, version))
    row = cur.fetchone()
    now = time.time()
    if row and now - float(row["ts"]) < ttl:
        return json.loads(row["result_json"])

    params = {
      "keywordSearch": f"{service} {version}".strip(),
      "apiKey": current_app.config["NVD_API_KEY"],
      "resultsPerPage": max_results
    }
    try:
        resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params=params, timeout=10)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        cves = [{"id": v["cve"]["id"],
                 "description": v["cve"]["descriptions"][0]["value"]}
                for v in items]
    except:
        cves = []

    cur.execute("""
      INSERT INTO cve_cache(service,version,result_json,fetched_at)
      VALUES(?,?,?,CURRENT_TIMESTAMP)
      ON CONFLICT(service,version) DO UPDATE SET
        result_json=excluded.result_json,
        fetched_at=CURRENT_TIMESTAMP
    """, (service, version, json.dumps(cves)))
    db.commit()
    return cves
