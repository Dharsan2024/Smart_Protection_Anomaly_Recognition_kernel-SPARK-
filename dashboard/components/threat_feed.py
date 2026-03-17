"""
SPARK — Smart Protection & Anomaly Recognition Kernel
Real-Time Threat Alert Feed

Auto-scrolling threat alert feed with severity color coding
and detailed threat information.
"""

import streamlit as st
import time
from typing import Dict, List
from datetime import datetime


SEVERITY_STYLES = {
    'CRITICAL': {'bg': 'rgba(220,38,38,0.1)', 'border': '#DC2626', 'icon': '🚨', 'text': '#EF4444'},
    'HIGH': {'bg': 'rgba(249,115,22,0.1)', 'border': '#F97316', 'icon': '⚠️', 'text': '#F97316'},
    'MEDIUM': {'bg': 'rgba(139,92,246,0.1)', 'border': '#8B5CF6', 'icon': '🔍', 'text': '#8B5CF6'},
    'LOW': {'bg': 'rgba(245,158,11,0.1)', 'border': '#F59E0B', 'icon': '📋', 'text': '#F59E0B'},
    'SAFE': {'bg': 'rgba(16,185,129,0.03)', 'border': '#10B981', 'icon': '✅', 'text': '#10B981'},
}


def render_threat_feed(verdicts: List[Dict], max_display: int = 15) -> None:
    """Render the real-time threat alert feed."""
    st.markdown('<div class="panel-title">🔔 Live Threat Intelligence Feed</div>', unsafe_allow_html=True)

    if not verdicts:
        st.markdown("""
        <div style="text-align: center; padding: 2rem; color: #64748B; font-family: 'Inter';">
            <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">📡</div>
            Awaiting incoming CAN bus traffic...
        </div>
        """, unsafe_allow_html=True)
        return

    # Show only threats and occasional normal samples
    threats_only = [v for v in verdicts if v.get('classification') != 'Normal']
    display_verdicts = threats_only[-max_display:] if threats_only else verdicts[-5:]

    # Build alert HTML
    alerts_html = '<div style="max-height: 400px; overflow-y: auto; padding-right: 0.5rem;">'

    for v in reversed(display_verdicts):
        severity = v.get('severity', 'SAFE')
        style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES['SAFE'])

        ts = v.get('timestamp', 0)
        time_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3] if ts > 0 else '--:--:--'

        can_id = v.get('can_id_hex', '0x???')
        classification = v.get('classification', 'Unknown')
        confidence = v.get('confidence', 0)

        alerts_html += f"""
        <div style="
            display: flex;
            align-items: flex-start;
            gap: 0.8rem;
            padding: 0.7rem 1rem;
            margin-bottom: 0.4rem;
            border-radius: 8px;
            background: {style['bg']};
            border-left: 3px solid {style['border']};
            font-family: 'Inter', sans-serif;
            transition: all 0.2s ease;
        ">
            <div style="font-size: 1.1rem; margin-top: 0.1rem;">{style['icon']}</div>
            <div style="flex: 1;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="
                        font-size: 0.8rem;
                        font-weight: 600;
                        color: {style['text']};
                        font-family: 'JetBrains Mono', monospace;
                    ">{classification.upper()}</span>
                    <span style="
                        font-size: 0.65rem;
                        color: #64748B;
                        font-family: 'JetBrains Mono', monospace;
                    ">{time_str}</span>
                </div>
                <div style="
                    font-size: 0.72rem;
                    color: #94A3B8;
                    margin-top: 0.2rem;
                    line-height: 1.4;
                ">
                    CAN ID: <span style="color: #00D4FF; font-family: 'JetBrains Mono';">{can_id}</span>
                    &nbsp;|&nbsp;
                    Confidence: <span style="color: {style['text']};">{confidence:.1%}</span>
                    &nbsp;|&nbsp;
                    Severity: <span style="font-weight: 600; color: {style['text']};">{severity}</span>
                </div>
            </div>
        </div>
        """

    alerts_html += '</div>'
    st.markdown(alerts_html, unsafe_allow_html=True)


def render_alert_summary(threat_counts: Dict[str, int]) -> None:
    """Render a compact alert summary bar."""
    total_threats = sum(v for k, v in threat_counts.items() if k != 'Normal')

    if total_threats == 0:
        st.markdown("""
        <div style="
            text-align: center;
            padding: 1rem;
            background: rgba(16,185,129,0.08);
            border: 1px solid rgba(16,185,129,0.2);
            border-radius: 12px;
            color: #10B981;
            font-family: 'Inter';
            font-size: 0.85rem;
        ">
            ✅ <b>System Secure</b> — No active threats detected
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1rem;
            background: rgba(220,38,38,0.08);
            border: 1px solid rgba(220,38,38,0.2);
            border-radius: 12px;
            color: #EF4444;
            font-family: 'Inter';
            font-size: 0.85rem;
            animation: pulse 2s ease-in-out infinite;
        ">
            🚨 <b>{total_threats:,} Active Threats</b> — Immediate investigation recommended
        </div>
        """, unsafe_allow_html=True)
