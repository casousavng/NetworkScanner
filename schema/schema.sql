CREATE TABLE ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INTEGER,
    protocol TEXT DEFAULT 'tcp', -- 'tcp' ou 'udp'
    state TEXT DEFAULT 'open', -- 'open', 'filtered', etc.
    service TEXT,
    product TEXT,
    version TEXT,
    scan_id INTEGER,
    UNIQUE (ip, port, protocol),
    FOREIGN KEY (ip) REFERENCES devices (ip)
);

CREATE TABLE devices (
    ip TEXT PRIMARY KEY,
    hostname TEXT,
    mac TEXT,
    vendor TEXT,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scan_id INTEGER
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
    FOREIGN KEY (port_id) REFERENCES ports (id),
    UNIQUE (port_id, script_id)
);

CREATE TABLE cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id INTEGER,
    cve_id TEXT,
    description TEXT,
    cvss REAL,
    reference TEXT,
    UNIQUE (port_id, cve_id),
    FOREIGN KEY (port_id) REFERENCES ports (id)
);

CREATE TABLE edbs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER,
    ebd_id TEXT,
    severity TEXT,
    ebds TEXT,
    reference_url TEXT,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id),
    UNIQUE (vulnerability_id, ebd_id)
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration INTEGER, 
    n_ips INTEGER DEFAULT 0,
    n_ports INTEGER DEFAULT 0,
    n_open_ports INTEGER DEFAULT 0,
    n_cves INTEGER DEFAULT 0,
    n_edbs INTEGER DEFAULT 0
);

CREATE TABLE scan_status (
    id SERIAL PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP
);

