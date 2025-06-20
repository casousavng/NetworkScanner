import networkx as nx
import plotly.graph_objs as go
from .db import get_db
from .scan import get_default_gateway

def build_network_data():

    router = get_default_gateway()
    print(f"IP do router: {router}")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip, hostname, vendor FROM devices")
    rows = cur.fetchall()

    G = nx.Graph()

    if rows:
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

    cur.execute("""
        SELECT ip, COUNT(*) as filtered_ports
        FROM ports
        WHERE state='filtered'
        GROUP BY ip
    """)
    filtered_ports_by_ip = {row[0]: row[1] for row in cur.fetchall()}
    open_ports_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    # Obter número de vulnerabilidades por IP
    cur.execute("""
        SELECT p.ip, COUNT(v.id) as vuln_count
        FROM ports p
        LEFT JOIN vulnerabilities v ON v.port_id = p.id
        GROUP BY p.ip
    """)
    vuln_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    # Obter a gravidade máxima das vulnerabilidades por IP
    cur.execute("""
        SELECT p.ip, MAX(v.cvss_score) as max_cvss
        FROM ports p
        LEFT JOIN vulnerabilities v ON v.port_id = p.id
        GROUP BY p.ip
    """)
    max_cvss_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    MIN_SIZE = 20
    MAX_SIZE = 45
    MAX_VULN = 45  # limite máximo de vulnerabilidades para escala

    pos = nx.spring_layout(G, seed=42)
    edge_traces = []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        # Se um dos nós for o router, aplica linha tracejada
        if G.nodes[u]["type"] == "router" or G.nodes[v]["type"] == "router":
            line_style = dict(width=1, color='gray', dash='dot')  # 'dot', 'dash', 'dashdot'
        else:
            line_style = dict(width=1, color='gray')
        edge_traces.append(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode='lines',
            hoverinfo='none', line=line_style,
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
            node_colors.append("#0037FF")  # Azul para o router
            node_sizes.append(50)          # Tamanho fixo para o router
        else:
            open_ports = open_ports_by_ip.get(n, 0)
            filtered_ports = filtered_ports_by_ip.get(n, 0)
            vuln_count = vuln_by_ip.get(n, 0)
            max_cvss = max_cvss_by_ip.get(n, 0)

            safe_cvss = max_cvss if max_cvss is not None else 0

            match True:
                case _ if vuln_count >= 1 and safe_cvss >= 7:
                    node_colors.append("#ff0000")  # vermelho sólido
                case _ if vuln_count >= 1:
                    node_colors.append("#ffb300")  # laranja sólido
                case _ if open_ports > 0 or filtered_ports > 0:
                    node_colors.append("#fff700")  # amarelo sólido
                case _:
                    node_colors.append("#00cc00")  # verde sólido

            if vuln_count == 0:
                size = MIN_SIZE
            else:
                capped_vuln = min(vuln_count, MAX_VULN)
                normalized_size = MIN_SIZE + (MAX_SIZE - MIN_SIZE) * (capped_vuln / MAX_VULN)
                size = 2 * round(normalized_size / 2)

            min_size = 20
            max_size = 45
            max_ports = 10
            size = min_size + (max_size - min_size) * min(open_ports, max_ports) / max_ports
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