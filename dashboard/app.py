"""
SPARK — Smart Protection & Anomaly Recognition Kernel
Main SOC Dashboard Application

Real-time CAN Bus Intrusion Detection Security Operations Center.
Run with: streamlit run dashboard/app.py
"""

import os
import sys
import time
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from engine.simulator import CANBusSimulator
from engine.detector import DetectionEngine
from engine.attacker import get_attack_profiles
from dashboard.components.metrics import render_metrics
from dashboard.components.timeline import (
    render_traffic_timeline, render_attack_distribution,
    render_attack_bars, render_can_id_frequency
)
from dashboard.components.network_graph import render_network_graph
from dashboard.components.threat_feed import render_threat_feed, render_alert_summary
from dashboard.components.ai_analyst import render_ai_analyst

# ═══════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════
st.set_page_config(
    page_title="SPARK — CAN Bus IDS",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load custom CSS
css_path = os.path.join(os.path.dirname(__file__), 'styles', 'theme.css')
if os.path.exists(css_path):
    with open(css_path) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Scan line effect
st.markdown('<div class="scan-line"></div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# SESSION STATE INITIALIZATION
# ═══════════════════════════════════════════════════════
def init_session_state() -> None:
    """Initialize all session state variables."""
    if 'simulator' not in st.session_state:
        # Try to find dataset
        dataset_path = os.path.join(project_root, 'data', 'spark_can_dataset.csv')
        if not os.path.exists(dataset_path):
            dataset_path = None

        st.session_state.simulator = CANBusSimulator(
            dataset_path=dataset_path,
            speed_multiplier=1.0
        )

    if 'detector' not in st.session_state:
        models_dir = os.path.join(project_root, 'models', 'saved')
        st.session_state.detector = DetectionEngine(models_dir)

    if 'is_running' not in st.session_state:
        st.session_state.is_running = False

    if 'verdicts' not in st.session_state:
        st.session_state.verdicts = []

    if 'auto_refresh' not in st.session_state:
        st.session_state.auto_refresh = True

    if 'refresh_rate' not in st.session_state:
        st.session_state.refresh_rate = 2

    if 'messages_processed' not in st.session_state:
        st.session_state.messages_processed = 0


init_session_state()

# Get references
simulator: CANBusSimulator = st.session_state.simulator
detector: DetectionEngine = st.session_state.detector


# ═══════════════════════════════════════════════════════
# MESSAGE PROCESSING CALLBACK
# ═══════════════════════════════════════════════════════
def process_message(msg) -> None:
    """Callback: analyze each incoming CAN message."""
    msg_dict = msg.to_dict()
    verdict = detector.analyze_message(msg_dict)
    st.session_state.verdicts.append(verdict.to_dict())

    # Keep verdict list manageable
    if len(st.session_state.verdicts) > 5000:
        st.session_state.verdicts = st.session_state.verdicts[-3000:]

    st.session_state.messages_processed += 1


# Register callback if not already done
if not simulator._callbacks:
    simulator.register_callback(process_message)


# ═══════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════
st.markdown("""
<div class="spark-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <div class="spark-title">⚡ SPARK</div>
            <div class="spark-subtitle">Smart Protection & Anomaly Recognition Kernel</div>
        </div>
        <div style="text-align: right;">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #64748B;">
                CAN BUS INTRUSION DETECTION SYSTEM
            </div>
            <div style="font-family: 'Orbitron', sans-serif; font-size: 0.95rem; color: #00D4FF; letter-spacing: 2px;">
                SECURITY OPERATIONS CENTER
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# SIDEBAR — CONTROLS
# ═══════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; margin-bottom: 1.5rem;">
        <div style="font-family: 'Orbitron'; font-size: 1.3rem; color: #00D4FF; font-weight: 700;">
            ⚡ SPARK
        </div>
        <div style="font-size: 0.7rem; color: #64748B; letter-spacing: 2px; text-transform: uppercase;">
            Control Console
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # System Controls
    st.markdown("### 🎛️ System Controls")

    col_start, col_stop = st.columns(2)
    with col_start:
        if st.button("▶️ START", use_container_width=True, key="btn_start"):
            if not st.session_state.is_running:
                simulator.start()
                st.session_state.is_running = True
                st.rerun()

    with col_stop:
        if st.button("⏹️ STOP", use_container_width=True, key="btn_stop"):
            if st.session_state.is_running:
                simulator.stop()
                st.session_state.is_running = False
                st.rerun()

    # Status indicator
    if st.session_state.is_running:
        st.markdown("""
        <div style="
            text-align: center; padding: 0.5rem;
            background: rgba(16,185,129,0.1);
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 8px; color: #10B981;
            font-family: 'Orbitron'; font-size: 0.75rem;
            animation: pulse 2s ease-in-out infinite;
        ">● SYSTEM ACTIVE</div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="
            text-align: center; padding: 0.5rem;
            background: rgba(100,116,139,0.1);
            border: 1px solid rgba(100,116,139,0.3);
            border-radius: 8px; color: #64748B;
            font-family: 'Orbitron'; font-size: 0.75rem;
        ">○ SYSTEM IDLE</div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Attack Simulation
    st.markdown("### 🎯 Attack Simulation")

    attack_profiles = get_attack_profiles()
    attack_type = st.selectbox(
        "Attack Vector",
        options=list(attack_profiles.keys()),
        format_func=lambda x: f"{attack_profiles[x]['icon']} {attack_profiles[x]['name']}"
    )

    col_dur, col_int = st.columns(2)
    with col_dur:
        duration = st.slider("Duration (s)", 2, 30, 8)
    with col_int:
        intensity = st.slider("Intensity", 1, 100, 50)

    if st.button(f"🚀 LAUNCH {attack_type.upper()} ATTACK", use_container_width=True, key="btn_attack"):
        if st.session_state.is_running:
            simulator.inject_attack(attack_type, duration=duration, intensity=intensity)
            st.toast(f"🚨 {attack_type} attack launched!", icon="🚨")
        else:
            st.warning("Start the system first!")

    # Show attack profile info
    profile = attack_profiles.get(attack_type, {})
    st.markdown(f"""
    <div style="
        margin-top: 0.5rem; padding: 0.8rem;
        background: rgba(220,38,38,0.05);
        border: 1px solid rgba(220,38,38,0.1);
        border-radius: 8px;
        font-size: 0.72rem; color: #94A3B8;
        font-family: 'Inter';
        line-height: 1.5;
    ">
        <b style="color: {profile.get('color', '#EF4444')};">{profile.get('name', '')}</b><br>
        {profile.get('description', '')}
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Dashboard Settings
    st.markdown("### ⚙️ Dashboard Settings")

    st.session_state.auto_refresh = st.checkbox("Auto Refresh", value=st.session_state.auto_refresh)
    st.session_state.refresh_rate = st.slider("Refresh (sec)", 1, 10, st.session_state.refresh_rate)

    st.markdown("---")

    # Model Status
    st.markdown("### 🧠 AI Models Status")

    models_info = [
        ("XGBoost", detector.xgb_model is not None),
        ("Random Forest", detector.rf_model is not None),
        ("Isolation Forest", detector.iso_model is not None),
    ]

    for name, loaded in models_info:
        icon = "🟢" if loaded else "🔴"
        status = "Active" if loaded else "Not Loaded"
        color = "#10B981" if loaded else "#EF4444"
        st.markdown(f"""
        <div style="
            display: flex; justify-content: space-between; align-items: center;
            padding: 0.4rem 0.6rem; margin-bottom: 0.3rem;
            background: rgba(255,255,255,0.02); border-radius: 6px;
            font-family: 'Inter'; font-size: 0.75rem;
        ">
            <span style="color: #E2E8F0;">{icon} {name}</span>
            <span style="color: {color}; font-family: 'JetBrains Mono'; font-size: 0.65rem;">{status}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # System Info
    st.markdown(f"""
    <div style="
        text-align: center; padding: 0.8rem;
        font-family: 'JetBrains Mono'; font-size: 0.65rem;
        color: #475569; line-height: 1.8;
    ">
        SPARK v1.0.0<br>
        CAN Bus IDS Engine<br>
        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        Python {sys.version.split()[0]}
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# MAIN DASHBOARD CONTENT
# ═══════════════════════════════════════════════════════

# Get current data
stats = simulator.get_stats()
threat_summary = detector.get_threat_summary()
verdicts = st.session_state.verdicts

# ── ROW 1: KPI Metrics ──
render_metrics(stats, threat_summary)

st.markdown("<div style='height: 0.8rem;'></div>", unsafe_allow_html=True)

# ── Alert Summary ──
render_alert_summary(threat_summary.get('counts', {}))

st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

# ── ROW 2: Main Visualization Area ──
tab1, tab2, tab3, tab4 = st.tabs([
    "📈 Traffic Timeline",
    "🌐 Network Topology",
    "🎯 Threat Analysis",
    "📊 Deep Analytics"
])

with tab1:
    col_timeline, col_dist = st.columns([2, 1])
    with col_timeline:
        render_traffic_timeline(verdicts[-500:])
    with col_dist:
        render_attack_distribution(threat_summary.get('counts', {}))

with tab2:
    col_graph, col_feed = st.columns([2, 1])
    with col_graph:
        render_network_graph(verdicts[-300:])
    with col_feed:
        render_threat_feed(verdicts, max_display=12)

with tab3:
    render_ai_analyst(threat_summary.get('counts', {}), verdicts)

    st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

    col_bars, col_freq = st.columns(2)
    with col_bars:
        render_attack_bars(threat_summary.get('counts', {}))
    with col_freq:
        render_can_id_frequency(verdicts[-200:])

with tab4:
    # Deep analytics tab with raw data view and additional metrics
    st.markdown('<div class="panel-title">🔬 Deep Packet Analysis</div>', unsafe_allow_html=True)

    if verdicts:
        df = pd.DataFrame(verdicts[-100:])
        display_cols = ['can_id_hex', 'classification', 'confidence', 'severity', 'details']
        available_cols = [c for c in display_cols if c in df.columns]

        if available_cols:
            st.dataframe(
                df[available_cols].style.apply(
                    lambda x: ['background-color: rgba(220,38,38,0.1)' if v != 'Normal' else ''
                              for v in x] if x.name == 'classification' else ['' for _ in x],
                    axis=0
                ),
                use_container_width=True,
                height=400,
            )

        # Classification distribution metrics
        st.markdown('<div class="panel-title">📉 Session Statistics</div>', unsafe_allow_html=True)

        stat_cols = st.columns(4)
        all_verdicts_df = pd.DataFrame(verdicts) if verdicts else pd.DataFrame()

        with stat_cols[0]:
            avg_conf = all_verdicts_df['confidence'].mean() if len(all_verdicts_df) > 0 else 0
            st.metric("Avg Confidence", f"{avg_conf:.2%}")

        with stat_cols[1]:
            unique_ids = all_verdicts_df['can_id'].nunique() if len(all_verdicts_df) > 0 else 0
            st.metric("Unique CAN IDs", unique_ids)

        with stat_cols[2]:
            elapsed = stats.get('elapsed_seconds', 0)
            st.metric("Uptime", f"{elapsed:.0f}s")

        with stat_cols[3]:
            st.metric("Buffer Size", f"{len(verdicts):,}")
    else:
        st.info("Start the system and wait for traffic data to populate analytics.")


# ═══════════════════════════════════════════════════════
# AUTO-REFRESH
# ═══════════════════════════════════════════════════════
if st.session_state.auto_refresh and st.session_state.is_running:
    time.sleep(st.session_state.refresh_rate)
    st.rerun()
