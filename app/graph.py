import networkx as nx
import plotly.graph_objs as go
from .db import get_db
from flask import current_app

def build_network_data():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip, hostname, vendor FROM devices")
    rows = cur.fetchall()

    G = nx.Graph()
    router = current_app.config["ROUTER_IP"]
    G.add_node(router, label="Router", type="router")
    for r in rows:
        ip, host, vendor = r["ip"], r["hostname"], r["vendor"]
        if ip == router:
            continue
        G.add_node(ip, label=f"{host}<br>{ip}<br>{vendor}", type="device")
        G.add_edge(router, ip)

    # Obter número de portas abertas por IP
    cur.execute("""
        SELECT ip, COUNT(*) as open_ports
        FROM ports
        WHERE state='open'
        GROUP BY ip
    """)
    open_ports_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    # Obter número de vulnerabilidades por IP
    cur.execute("""
        SELECT p.ip, COUNT(v.id) as vuln_count
        FROM ports p
        LEFT JOIN vulnerabilities v ON v.port_id = p.id
        GROUP BY p.ip
    """)
    vuln_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    MIN_SIZE = 20
    MAX_SIZE = 45
    MAX_VULN = 45  # limite máximo de vulnerabilidades para escala

    pos = nx.spring_layout(G, seed=42)
    edge_traces = []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_traces.append(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode='lines',
            hoverinfo='none', line=dict(width=1, color='gray'),
            showlegend=False
        ))

    node_x, node_y, node_text, node_custom = [], [], [], []
    node_colors = []
    node_sizes = []

    for n in G.nodes():
        node_x.append(pos[n][0])
        node_y.append(pos[n][1])
        node_text.append(G.nodes[n]["label"])
        node_custom.append(n)

        if G.nodes[n]["type"] == "router":
            node_colors.append('#888888')  # Cinzento para o router
            node_sizes.append(50)          # Tamanho fixo para o router
        else:
            open_ports = open_ports_by_ip.get(n, 0)
            vuln_count = vuln_by_ip.get(n, 0)

            if open_ports == 0 and vuln_count == 0:
                node_colors.append('#00cc00')  # verde sólido
            elif open_ports <= 5 and vuln_count == 0:
                node_colors.append('#ffcc00')  # amarelo sólido
            else:
                node_colors.append('#cc0000')  # vermelho sólido

            if vuln_count == 0:
                size = MIN_SIZE
            else:
                capped_vuln = min(vuln_count, MAX_VULN)
                normalized_size = MIN_SIZE + (MAX_SIZE - MIN_SIZE) * (capped_vuln / MAX_VULN)
                size = 2 * round(normalized_size / 2)

            node_sizes.append(size)

    node_trace = go.Scatter(
        x=node_x, y=node_y, text=node_text,
        mode='markers', hoverinfo='text',
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=2, color='black')
        ),
        customdata=node_custom,
        showlegend=False
    )

    data = edge_traces + [node_trace]

    layout = go.Layout(
        showlegend=False,
        xaxis=dict(
            showgrid=True,
            zeroline=False,
            showticklabels=False
        ),
        yaxis=dict(
            showgrid=True,
            zeroline=False,
            showticklabels=False,
        ),
        dragmode=False
    )

    return dict(data=data, layout=layout)