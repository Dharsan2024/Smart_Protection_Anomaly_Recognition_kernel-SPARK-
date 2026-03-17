"""
SPARK — Smart Protection & Anomaly Recognition Kernel
Live KPI Metric Cards Component

Displays real-time key performance indicators:
- Packets/sec throughput
- Total messages analyzed
- Threats detected
- System health / model status
"""

import streamlit as st
from typing import Dict


def render_metrics(stats: Dict, threat_summary: Dict) -> None:
    """Render the top-row KPI metric cards."""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
        <div class="metric-card info">
            <div class="metric-value">{stats.get('messages_per_second', 0):,.0f}</div>
            <div class="metric-label">📡 Packets / Second</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        total = threat_summary.get('total_analyzed', 0)
        if total >= 1_000_000:
            display = f"{total / 1_000_000:.1f}M"
        elif total >= 1_000:
            display = f"{total / 1_000:.1f}K"
        else:
            display = str(total)
        st.markdown(f"""
        <div class="metric-card info">
            <div class="metric-value">{display}</div>
            <div class="metric-label">📊 Total Analyzed</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        threats = threat_summary.get('total_threats', 0)
        card_class = "danger" if threats > 0 else "safe"
        st.markdown(f"""
        <div class="metric-card {card_class}">
            <div class="metric-value" style="color: {'#EF4444' if threats > 0 else '#10B981'}">{threats:,}</div>
            <div class="metric-label">🛡️ Threats Detected</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        ratio = threat_summary.get('threat_ratio', 0) * 100
        card_class = "danger" if ratio > 10 else ("warning" if ratio > 2 else "safe")
        st.markdown(f"""
        <div class="metric-card {card_class}">
            <div class="metric-value">{ratio:.1f}%</div>
            <div class="metric-label">⚡ Threat Ratio</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        level = threat_summary.get('threat_level', 'INITIALIZING')
        color = threat_summary.get('threat_color', '#64748B')
        st.markdown(f"""
        <div class="metric-card {'danger' if 'CRITICAL' in level else ('warning' if level in ['ELEVATED','HIGH'] else 'safe')}">
            <div class="metric-value" style="color: {color}; font-size: 1.3rem;">{level}</div>
            <div class="metric-label">🔒 Threat Level</div>
        </div>
        """, unsafe_allow_html=True)
