"""
SPARK — Smart Protection & Anomaly Recognition Kernel
ECU Communication Network Graph

Interactive NetworkX + Plotly graph visualization showing:
- ECU nodes (CAN IDs) with dynamic sizing based on traffic volume
- Edge weights representing communication density
- Color coding: green (normal), red (threat), orange (warning)
"""

import plotly.graph_objects as go
import networkx as nx
import streamlit as st
import numpy as np
from typing import Dict, List
from collections import Counter, defaultdict
import time

# Known ECU names for display
ECU_NAMES: Dict[str, str] = {
    '0x000': 'HIGHEST_PRIORITY',
    '0x0A0': 'Engine RPM',
    '0x0A1': 'Engine Temp',
    '0x0B0': 'Vehicle Speed',
    '0x0B1': 'Wheel Speed',
    '0x130': 'Steering Angle',
    '0x131': 'Steering Torque',
    '0x164': 'Brake Pressure',
    '0x18E': 'Throttle',
    '0x1A0': 'ABS Status',
    '0x1F5': 'Gear Position',
    '0x260': 'Airbag',
    '0x2C0': 'Door Status',
    '0x316': 'RPM Gauge',
    '0x329': 'Fuel Level',
    '0x380': 'Climate Ctrl',
    '0x3B0': 'Lighting',
    '0x43F': 'Drive Gear',
    '0x545': 'Odometer',
    '0x580': 'Battery',
    '0x5A0': 'Tire Pressure',
    '0x620': 'Infotainment',
    '0x6F1': 'Diag Request',
    '0x700': 'Diag Response',
    '0x7DF': 'OBD Broadcast',
}


def render_network_graph(verdicts: List[Dict]) -> None:
    """Render interactive ECU communication topology graph."""
    st.markdown('<div class="panel-title">🌐 ECU Communication Topology</div>', unsafe_allow_html=True)

    if not verdicts or len(verdicts) < 5:
        st.info("Accumulating network data...")
        return

    # Build network graph
    G = nx.Graph()

    # Count messages per CAN ID and track their classifications
    id_counts = Counter()
    id_threats = defaultdict(int)
    id_classifications = defaultdict(lambda: Counter())

    for v in verdicts:
        can_id = v.get('can_id_hex', '0x000')
        classification = v.get('classification', 'Normal')
        id_counts[can_id] += 1
        id_classifications[can_id][classification] += 1
        if classification != 'Normal':
            id_threats[can_id] += 1

    # Add nodes
    all_ids = list(id_counts.keys())
    for cid in all_ids:
        G.add_node(cid, weight=id_counts[cid], threats=id_threats.get(cid, 0))

    # Add edges (simulate communication between nearby IDs)
    for i, id1 in enumerate(all_ids):
        for id2 in all_ids[i+1:min(i+4, len(all_ids))]:
            weight = min(id_counts[id1], id_counts[id2]) * 0.1
            if weight > 1:
                G.add_edge(id1, id2, weight=weight)

    # Layout
    if len(G.nodes()) > 0:
        pos = nx.spring_layout(G, k=2.5, iterations=50, seed=42)
    else:
        return

    # Create traces
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.8, color='rgba(0, 212, 255, 0.15)'),
        hoverinfo='none',
        mode='lines'
    )

    # Node attributes
    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]
    node_sizes = []
    node_colors = []
    node_text = []
    node_labels = []

    max_count = max(id_counts.values()) if id_counts else 1

    for node in G.nodes():
        count = id_counts.get(node, 1)
        threats = id_threats.get(node, 0)
        name = ECU_NAMES.get(node, node)

        # Dynamic sizing
        size = max(15, min(60, 15 + (count / max_count) * 45))
        node_sizes.append(size)

        # Color: red for threats, orange for targets, green for normal
        threat_ratio = threats / max(count, 1)
        if threat_ratio > 0.5:
            node_colors.append('#DC2626')
        elif threat_ratio > 0.1:
            node_colors.append('#F97316')
        elif node == '0x000':
            node_colors.append('#DC2626')
        elif node in ('0x316', '0x43F'):
            node_colors.append('#F59E0B')
        else:
            node_colors.append('#10B981')

        # Hover text
        classifications = dict(id_classifications.get(node, {}))
        class_str = ', '.join([f"{k}: {v}" for k, v in classifications.items()])
        node_text.append(
            f"<b>{name}</b><br>"
            f"ID: {node}<br>"
            f"Messages: {count:,}<br>"
            f"Threats: {threats:,}<br>"
            f"{class_str}"
        )
        node_labels.append(f"{node}")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        hovertext=node_text,
        text=node_labels,
        textposition='top center',
        textfont=dict(size=8, color='#94A3B8', family='JetBrains Mono'),
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=2, color='rgba(0,0,0,0.5)'),
            opacity=0.9,
        )
    )

    # Compose figure
    fig = go.Figure(data=[edge_trace, node_trace])

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(17,24,39,0.3)',
        font=dict(family='Inter, sans-serif', color='#94A3B8'),
        height=400,
        showlegend=False,
        hovermode='closest',
        margin=dict(l=0, r=0, t=10, b=0),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        annotations=[dict(
            text=f"<b>{len(G.nodes())}</b> Active ECU Nodes",
            xref='paper', yref='paper',
            x=0.01, y=0.99,
            showarrow=False,
            font=dict(size=10, color='#00D4FF', family='JetBrains Mono'),
        )],
    )

    st.plotly_chart(fig, use_container_width=True, key=f"graph_{time.time()}")
