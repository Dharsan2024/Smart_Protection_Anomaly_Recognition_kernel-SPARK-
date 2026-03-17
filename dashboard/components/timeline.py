"""
SPARK — Smart Protection & Anomaly Recognition Kernel
Attack Timeline & Distribution Charts

Real-time Plotly visualizations:
- Traffic timeline (messages over time)
- Attack type distribution (pie/bar)
- Payload entropy heatmap
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import streamlit as st
import pandas as pd
import numpy as np
from typing import Dict, List
from collections import Counter
import time


# Color palette for attack types
ATTACK_COLORS: Dict[str, str] = {
    'Normal': '#10B981',
    'DoS': '#DC2626',
    'Fuzzy': '#F97316',
    'Spoofing': '#EF4444',
    'Replay': '#F59E0B',
    'Anomaly': '#8B5CF6',
}

PLOTLY_LAYOUT = dict(
    paper_bgcolor='rgba(0,0,0,0)',
    plot_bgcolor='rgba(17,24,39,0.4)',
    font=dict(family='Inter, sans-serif', color='#94A3B8', size=11),
    margin=dict(l=40, r=20, t=40, b=30),
    xaxis=dict(
        gridcolor='rgba(255,255,255,0.04)',
        zerolinecolor='rgba(255,255,255,0.06)',
    ),
    yaxis=dict(
        gridcolor='rgba(255,255,255,0.04)',
        zerolinecolor='rgba(255,255,255,0.06)',
    ),
    legend=dict(
        bgcolor='rgba(0,0,0,0)',
        bordercolor='rgba(0,212,255,0.2)',
        font=dict(size=10),
    ),
)


def render_traffic_timeline(verdicts: List[Dict]) -> None:
    """Render real-time traffic timeline chart."""
    st.markdown('<div class="panel-title">📈 Live Traffic Timeline</div>', unsafe_allow_html=True)

    if not verdicts:
        st.info("Waiting for traffic data...")
        return

    df = pd.DataFrame(verdicts)
    df['time'] = pd.to_datetime(df['timestamp'], unit='s')

    # Group by second and classification
    df['second'] = df['time'].dt.floor('1s')
    timeline = df.groupby(['second', 'classification']).size().reset_index(name='count')

    fig = go.Figure()

    for label, color in ATTACK_COLORS.items():
        data = timeline[timeline['classification'] == label]
        if len(data) > 0:
            fig.add_trace(go.Scatter(
                x=data['second'],
                y=data['count'],
                mode='lines',
                name=label,
                line=dict(color=color, width=2 if label == 'Normal' else 3),
                fill='tozeroy' if label != 'Normal' else None,
                fillcolor=f"rgba{tuple(int(color.lstrip('#')[i:i+2], 16) for i in (0, 2, 4)) + (0.1,)}" if label != 'Normal' else None,
                opacity=0.9,
            ))

    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=300,
        title=None,
        showlegend=True,
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        hovermode='x unified',
    )

    st.plotly_chart(fig, use_container_width=True, key=f"timeline_{time.time()}")


def render_attack_distribution(threat_counts: Dict[str, int]) -> None:
    """Render attack type distribution as a donut chart."""
    st.markdown('<div class="panel-title">🎯 Attack Distribution</div>', unsafe_allow_html=True)

    # Filter out zero counts
    labels = [k for k, v in threat_counts.items() if v > 0]
    values = [v for v in threat_counts.values() if v > 0]
    colors = [ATTACK_COLORS.get(l, '#64748B') for l in labels]

    if not labels:
        st.info("No traffic data yet...")
        return

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color='#0A0E1A', width=2)),
        textinfo='label+percent',
        textfont=dict(size=11, color='#E2E8F0'),
        hoverinfo='label+value+percent',
        pull=[0.05 if l != 'Normal' else 0 for l in labels],
    )])

    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=300,
        showlegend=False,
        annotations=[dict(
            text='<b>SPARK</b>',
            x=0.5, y=0.5,
            font_size=14,
            font_color='#00D4FF',
            font_family='Orbitron',
            showarrow=False
        )],
    )

    st.plotly_chart(fig, use_container_width=True, key=f"dist_{time.time()}")


def render_attack_bars(threat_counts: Dict[str, int]) -> None:
    """Render attack counts as horizontal bar chart."""
    st.markdown('<div class="panel-title">📊 Threat Classification Breakdown</div>', unsafe_allow_html=True)

    attack_only = {k: v for k, v in threat_counts.items() if k != 'Normal' and v > 0}

    if not attack_only:
        st.markdown("""
        <div style="text-align: center; padding: 2rem; color: #10B981;">
            <div style="font-size: 2rem;">✅</div>
            <div style="font-family: 'Inter'; font-size: 0.9rem; margin-top: 0.5rem;">
                All Clear — No Threats Detected
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    labels = list(attack_only.keys())
    values = list(attack_only.values())
    colors = [ATTACK_COLORS.get(l, '#64748B') for l in labels]

    fig = go.Figure(data=[go.Bar(
        y=labels,
        x=values,
        orientation='h',
        marker=dict(
            color=colors,
            line=dict(color='rgba(0,0,0,0.3)', width=1),
        ),
        text=[f'{v:,}' for v in values],
        textposition='outside',
        textfont=dict(color='#E2E8F0', size=11),
    )])

    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=250,
        showlegend=False,
        xaxis_title='Count',
    )

    st.plotly_chart(fig, use_container_width=True, key=f"bars_{time.time()}")


def render_can_id_frequency(verdicts: List[Dict]) -> None:
    """Render CAN ID frequency analysis."""
    st.markdown('<div class="panel-title">📡 CAN ID Frequency Analysis</div>', unsafe_allow_html=True)

    if not verdicts:
        st.info("Collecting data...")
        return

    id_counts = Counter([v.get('can_id_hex', '0x000') for v in verdicts])
    top_ids = id_counts.most_common(15)

    ids = [x[0] for x in top_ids]
    counts = [x[1] for x in top_ids]

    # Color code: known attack IDs
    colors = []
    for cid in ids:
        if cid == '0x000':
            colors.append('#DC2626')  # DoS indicator
        elif cid in ('0x316', '0x43F'):
            colors.append('#F59E0B')  # Spoof targets
        else:
            colors.append('#00D4FF')

    fig = go.Figure(data=[go.Bar(
        x=ids,
        y=counts,
        marker=dict(color=colors, line=dict(color='rgba(0,0,0,0.3)', width=1)),
        text=counts,
        textposition='outside',
        textfont=dict(color='#94A3B8', size=10),
    )])

    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=280,
        showlegend=False,
        xaxis_title='CAN ID',
        yaxis_title='Frequency',
        xaxis=dict(
            **PLOTLY_LAYOUT['xaxis'],
            tickangle=-45,
            tickfont=dict(family='JetBrains Mono', size=10),
        ),
    )

    st.plotly_chart(fig, use_container_width=True, key=f"freq_{time.time()}")
