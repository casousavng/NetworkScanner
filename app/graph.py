import networkx as nx
import plotly.graph_objs as go
from .db import get_db
from flask import current_app

def build_network_data():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ip,hostname,vendor FROM devices")
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

    pos = nx.spring_layout(G, seed=42)
    edge_traces = []
    node_x, node_y, node_text, node_custom = [], [], [], []
    node_colors = []  # Lista para armazenar a cor dos nós

    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_traces.append(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode='lines',
            hoverinfo='none', line=dict(width=1, color='gray')
        ))

    for n in G.nodes():
        node_x.append(pos[n][0])
        node_y.append(pos[n][1])
        node_text.append(G.nodes[n]["label"])
        node_custom.append(n)

        # Definindo a cor com base no tipo de nó
        if G.nodes[n]["type"] == "router":
            node_colors.append('#FF7F7F')  # Cor vermelho claro para o router
        else:
            node_colors.append('#0d6efd')  # Cor azul claro para os dispositivos

    node_trace = go.Scatter(
        x=node_x, y=node_y, text=node_text,
        mode='markers', hoverinfo='text',
        marker=dict(size=20, color=node_colors),  # Aplicando as cores
        customdata=node_custom
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
        dragmode=False  # Desativa a interação de drag (arrastar)
    )

    return dict(data=data, layout=layout)