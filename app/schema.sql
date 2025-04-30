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