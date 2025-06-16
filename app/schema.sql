-- Active: 1746029370379@@127.0.0.1@3306
-- Tabela de dispositivos na rede
CREATE TABLE IF NOT EXISTS devices (
  ip        TEXT PRIMARY KEY,
  hostname  TEXT,
  mac       TEXT,
  vendor    TEXT,
  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de portas com suporte a protocolo e estado
CREATE TABLE IF NOT EXISTS ports (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ip       TEXT,
  port     INTEGER,
  protocol TEXT DEFAULT 'tcp',          -- 'tcp' ou 'udp'
  state    TEXT DEFAULT 'open',         -- 'open', 'filtered', etc.
  service  TEXT,
  product  TEXT,
  version  TEXT,
  UNIQUE(ip, port, protocol),
  FOREIGN KEY(ip) REFERENCES devices(ip)
);

-- Índice único para facilitar buscas e garantir integridade
CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_ip_port_protocol
ON ports(ip, port, protocol);

-- Tabela de vulnerabilidades (CVEs)
CREATE TABLE IF NOT EXISTS cves (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  port_id     INTEGER,
  cve_id      TEXT,
  description TEXT,
  UNIQUE(port_id, cve_id),
  FOREIGN KEY(port_id) REFERENCES ports(id)
);

-- Histórico de varreduras
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cache para evitar chamadas repetidas à API de CVEs
CREATE TABLE IF NOT EXISTS cve_cache (
  service     TEXT,
  version     TEXT,
  result_json TEXT,
  fetched_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(service, version)
);

CREATE TABLE scripts_result (
    port_id INTEGER,
    script_id TEXT,
    output TEXT,
    PRIMARY KEY (port_id, script_id),
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id INTEGER,
    cve_id TEXT,
    script_id TEXT,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    reference TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (port_id) REFERENCES ports(id),
    UNIQUE (port_id, script_id)
);

-- Tabela de referências de exploits criadas depois

CREATE TABLE vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  port_id INTEGER,
  script_id TEXT,
  description TEXT,
  has_cve BOOLEAN,
  UNIQUE(port_id, script_id)
);

CREATE TABLE cves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id INTEGER,
  cve_id TEXT,
  severity TEXT,
  cvss TEXT,
  reference_url TEXT,
  FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE edbs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id INTEGER,
  ebd_id TEXT,
  severity TEXT,
  ebds TEXT,
  reference_url TEXT,
  FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
);

CREATE UNIQUE INDEX idx_edbs_unique ON edbs(vulnerability_id, ebd_id);
LEFT JOIN edbs e ON p.id = e.port_id

CREATE TABLE exploit_refs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT,
  source TEXT,
  reference_url TEXT
  );



INSERT INTO cves (id, port_id, cve_id, description) VALUES
(1, 2, 'CVE-2020-1234', 'Descrição genérica do CVE-2020-1234.');

INSERT INTO vulnerabilities (port_id, cve_id, severity, cvss_score, description, reference) VALUES
(2, 1, 'HIGH', 8.7, 'Vulnerabilidade que permite acesso não autorizado.', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1234');



ALTER TABLE devices
ADD COLUMN scan_id INTEGER;
ALTER TABLE ports ADD COLUMN scan_id INTEGER;






-- Dispositivos na rede
CREATE TABLE devices (
  ip        TEXT PRIMARY KEY,
  hostname  TEXT,
  mac       TEXT,
  vendor    TEXT,
  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  scan_id   INTEGER,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

-- Histórico de varreduras
CREATE TABLE scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Portas encontradas
CREATE TABLE ports (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ip       TEXT,
  port     INTEGER,
  protocol TEXT DEFAULT 'tcp',
  state    TEXT DEFAULT 'open',
  service  TEXT,
  product  TEXT,
  version  TEXT,
  UNIQUE(ip, port, protocol),
  FOREIGN KEY(ip) REFERENCES devices(ip)
);

CREATE UNIQUE INDEX idx_ports_ip_port_protocol
ON ports(ip, port, protocol);

-- Vulnerabilidades por porta (CVEs)
CREATE TABLE vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  port_id INTEGER,
  script_id TEXT,
  description TEXT,
  has_cve BOOLEAN,
  severity TEXT,
  cvss_score REAL,
  reference TEXT,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (port_id, script_id),
  FOREIGN KEY (port_id) REFERENCES ports(id)
);

-- CVEs detalhados
CREATE TABLE cves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id INTEGER,
  cve_id TEXT,
  severity TEXT,
  cvss TEXT,
  reference_url TEXT,
  FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
);

-- Scripts do Nmap
CREATE TABLE scripts_result (
  port_id INTEGER,
  script_id TEXT,
  output TEXT,
  PRIMARY KEY (port_id, script_id),
  FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
);

-- Exploits relacionados a CVEs
CREATE TABLE exploit_refs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT,
  source TEXT,
  reference_url TEXT
);

-- Cache de resultados de CVE para evitar chamadas repetidas
CREATE TABLE cve_cache (
  service     TEXT,
  version     TEXT,
  result_json TEXT,
  fetched_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(service, version)
);

SELECT p.ip, COUNT(v.id) as vuln_count
FROM ports p
LEFT JOIN vulnerabilities v ON v.port_id = p.id
GROUP BY p.ip