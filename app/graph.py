import networkx as nx
import plotly.graph_objs as go
from .db import get_db
from .scan import get_default_gateway

def build_network_data():
    router = get_default_gateway()

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

    # Contar portas abertas por IP
    cur.execute("""
        SELECT ip, COUNT(*) as open_ports
        FROM ports
        WHERE state='open'
        GROUP BY ip
    """)
    open_ports_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    # Contar CVEs por IP (através da tabela cves ligada às portas)
    cur.execute("""
        SELECT p.ip, COUNT(c.id) as cves_count
        FROM ports p
        LEFT JOIN cves c ON c.port_id = p.id
        GROUP BY p.ip
    """)
    cves_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    # Contar EDBs por IP (através da tabela edbs ligada às vulnerabilidades e portas)
    cur.execute("""
        SELECT p.ip, COUNT(e.id) as edbs_count
        FROM ports p
        LEFT JOIN vulnerabilities v ON v.port_id = p.id
        LEFT JOIN edbs e ON e.vulnerability_id = v.id
        GROUP BY p.ip
    """)
    edbs_by_ip = {row[0]: row[1] for row in cur.fetchall()}

    MIN_SIZE = 20
    MAX_SIZE = 45
    MAX_PORTS = 30
    MAX_VULN = 20  # soma CVEs + EDBs para escalonar tamanho

    pos = nx.spring_layout(G, seed=42)
    edge_traces = []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        if G.nodes[u]["type"] == "router" or G.nodes[v]["type"] == "router":
            line_style = dict(width=1, color='gray', dash='dot')
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
            node_colors.append("#0037FF")
            node_sizes.append(50)
            continue

        open_ports = open_ports_by_ip.get(n, 0)
        cves_count = cves_by_ip.get(n, 0) or 0
        edbs_count = edbs_by_ip.get(n, 0) or 0
        total_vuln = cves_count + edbs_count

        if open_ports == 0:
            color = "#00cc00"  # verde pequeno
            size = MIN_SIZE
        else:
            # Tem portas abertas
            if total_vuln == 0:
                color = "#fff700"  # amarelo
                size = MIN_SIZE + (MAX_SIZE - MIN_SIZE) * min(open_ports, MAX_PORTS) / MAX_PORTS
            elif 5 < total_vuln <= 10:
                color = "#ffb300"  # laranja
                vuln_scaled = min(total_vuln, MAX_VULN)
                size = MIN_SIZE + (MAX_SIZE - MIN_SIZE) * vuln_scaled / MAX_VULN
            elif total_vuln > 10:
                color = "#ff0000"  # vermelho
                size = MAX_SIZE
            else:
                # Se tiver vulnerabilidades entre 1 e 5
                color = "#fff700"
                vuln_scaled = min(total_vuln, MAX_VULN)
                size = MIN_SIZE + (MAX_SIZE - MIN_SIZE) * vuln_scaled / MAX_VULN

        size = 2 * round(size / 2)
        node_colors.append(color)
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

    data = edge_traces + [node_trace] if G.nodes else []

    annotations = []

    if not rows:
        annotations.append(dict(
            text="Realize primeiro o Scan para visualizar o mapa de rede...",
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=24, color="gray"),
            align="center"
        ))

    layout = go.Layout(
        showlegend=False,
        xaxis=dict(showgrid=True, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=True, zeroline=False, showticklabels=False),
        dragmode=False,
        annotations=annotations
    )

    return dict(data=data, layout=layout)