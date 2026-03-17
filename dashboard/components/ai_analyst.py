"""
SPARK — Smart Protection & Anomaly Recognition Kernel
AI Threat Analysis Panel

Generates detailed, human-readable threat explanations
and mitigation strategies using pattern-based analysis.
"""

import streamlit as st
from typing import Dict, List
from datetime import datetime


# Threat intelligence knowledge base
THREAT_INTEL: Dict[str, Dict] = {
    'DoS': {
        'title': 'Denial of Service (DoS) Attack',
        'mechanism': 'The attacker is exploiting the CAN bus arbitration mechanism by flooding the network with highest-priority CAN ID 0x000. This mechanism abuses the Carrier Sense Multiple Access with Collision Resolution (CSMA/CR) protocol.',
        'impact': [
            'All legitimate ECUs are unable to transmit messages',
            'Critical safety systems (ABS, ESC, Airbags) lose communication',
            'Vehicle may enter degraded "limp mode" or lose power steering',
            'Manufacturing line PLCs may halt, causing production stoppage'
        ],
        'mitigation': [
            'Enable CAN bus message rate limiting on gateway ECU',
            'Implement hardware-based ID filtering on critical bus segments',
            'Deploy automotive firewall (e.g., Argus, Upstream) at OBD-II port',
            'Activate anomaly-based IDS alerting for ID frequency spikes',
            'Isolate compromised network segment via domain controller'
        ],
        'severity_score': 9.5,
        'cve_refs': ['CVE-2022-26269', 'CVE-2023-29389'],
        'mitre_technique': 'T0800 - Denial of Service',
    },
    'Fuzzy': {
        'title': 'Fuzzy Injection (Flooding) Attack',
        'mechanism': 'The attacker is injecting massive volumes of messages with randomized CAN IDs and random payload data. This creates high Shannon entropy across the bus, causing unpredictable behavior in multiple vehicle subsystems simultaneously.',
        'impact': [
            'Chaotic behavior across multiple ECUs',
            'Random gauge fluctuations and false sensor readings',
            'Potential unintended actuator activation',
            'System stability degradation across the entire CAN network'
        ],
        'mitigation': [
            'Implement CAN ID whitelist filtering at hardware level',
            'Deploy payload range validation for known ECU data fields',
            'Enable entropy-based anomaly detection threshold monitoring',
            'Activate bus-off detection and automatic bus recovery procedures',
            'Review and restrict physical access to OBD-II and diagnostic ports'
        ],
        'severity_score': 8.0,
        'cve_refs': ['CVE-2019-12797'],
        'mitre_technique': 'T0803 - Fuzzing / Data Injection',
    },
    'Spoofing': {
        'title': 'ECU Spoofing / Impersonation Attack',
        'mechanism': 'The attacker is targeting specific known CAN IDs (RPM gauge: 0x316, Drive gear: 0x43F) and injecting fabricated payload data with values far outside the normal operational range. The receiving ECUs accept the high-frequency spoofed data over legitimate transmissions.',
        'impact': [
            'Targeted mechanical or display malfunctions',
            'False RPM readings could mask engine over-rev condition',
            'Invalid gear position data could cause transmission damage',
            'Driver loss-of-trust in vehicle instrumentation',
            'Safety-critical decisions based on falsified sensor data'
        ],
        'mitigation': [
            'Implement Message Authentication Codes (MAC) using AUTOSAR SecOC',
            'Deploy signal-level validation comparing physical sensors to CAN data',
            'Enable time-based message interval monitoring per CAN ID',
            'Implement rolling counter verification on safety-critical messages',
            'Deploy deep packet inspection on gateway nodes'
        ],
        'severity_score': 9.0,
        'cve_refs': ['CVE-2020-8539', 'CVE-2023-29389'],
        'mitre_technique': 'T0856 - Spoofing',
    },
    'Replay': {
        'title': 'Replay Attack',
        'mechanism': 'The attacker has captured a sequence of legitimate CAN bus traffic and is re-injecting it at an incorrect temporal alignment. Individual packets appear structurally valid, but the sequence is contextually malicious, designed to bypass payload-based anomaly detection.',
        'impact': [
            'Circumvents traditional payload anomaly detection',
            'Can trigger outdated vehicle states or commands',
            'May cause unexpected vehicle behavior in different driving context',
            'Extremely difficult to detect without temporal analysis'
        ],
        'mitigation': [
            'Implement timestamp-based freshness validation on messages',
            'Deploy LSTM-based temporal sequence analysis (active in SPARK)',
            'Enable rolling counter / sequence number verification per ECU',
            'Implement challenge-response authentication for critical commands',
            'Deploy cryptographic nonce-based message freshness guarantees'
        ],
        'severity_score': 8.5,
        'cve_refs': ['CVE-2021-22156'],
        'mitre_technique': 'T0882 - Replay Attack',
    },
}


def render_ai_analyst(threat_counts: Dict[str, int], verdicts: List[Dict]) -> None:
    """Render the AI threat analysis panel with detailed explanations."""
    st.markdown('<div class="panel-title">🤖 AI Threat Analyst — SPARK Intelligence</div>', unsafe_allow_html=True)

    # Find the most significant active threat
    active_threats = {k: v for k, v in threat_counts.items() if k != 'Normal' and v > 0}

    if not active_threats:
        st.markdown("""
        <div style="
            background: rgba(16,185,129,0.06);
            border: 1px solid rgba(16,185,129,0.2);
            border-radius: 12px;
            padding: 1.5rem;
            font-family: 'Inter', sans-serif;
        ">
            <div style="color: #10B981; font-weight: 600; font-size: 1rem; margin-bottom: 0.5rem;">
                ✅ SPARK AI Analysis: All Systems Nominal
            </div>
            <div style="color: #94A3B8; font-size: 0.85rem; line-height: 1.6;">
                The AI detection engine is actively monitoring all CAN bus traffic. No anomalous patterns 
                have been detected. All ECU communication frequencies, payload entropy values, and 
                inter-arrival times are within expected operational parameters.
            </div>
            <div style="color: #64748B; font-size: 0.75rem; margin-top: 0.8rem; font-family: 'JetBrains Mono';">
                Analysis Timestamp: {timestamp} | Models: XGBoost + Isolation Forest Active
            </div>
        </div>
        """.format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')), unsafe_allow_html=True)
        return

    # Analyze the dominant threat
    dominant_threat = max(active_threats, key=active_threats.get)
    intel = THREAT_INTEL.get(dominant_threat, {})

    if not intel:
        return

    # Build analysis HTML
    impact_html = ''.join([f'<li style="margin-bottom: 0.3rem;">{i}</li>' for i in intel.get('impact', [])])
    mitigation_html = ''.join([f'<li style="margin-bottom: 0.3rem;">{m}</li>' for m in intel.get('mitigation', [])])
    cve_html = ' | '.join([f'<span style="color: #F97316;">{c}</span>' for c in intel.get('cve_refs', [])])

    st.markdown(f"""
    <div style="
        background: rgba(220,38,38,0.04);
        border: 1px solid rgba(220,38,38,0.15);
        border-radius: 12px;
        padding: 1.5rem;
        font-family: 'Inter', sans-serif;
    ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <div style="color: #EF4444; font-weight: 700; font-size: 1rem;">
                🚨 {intel['title']}
            </div>
            <div style="
                background: rgba(220,38,38,0.2);
                color: #EF4444;
                padding: 0.2rem 0.8rem;
                border-radius: 20px;
                font-size: 0.7rem;
                font-weight: 600;
                font-family: 'Orbitron';
            ">
                SEVERITY: {intel.get('severity_score', 'N/A')}/10
            </div>
        </div>
        
        <div style="color: #E2E8F0; font-size: 0.85rem; line-height: 1.6; margin-bottom: 1rem;">
            <b>Mechanism:</b> {intel['mechanism']}
        </div>
        
        <div style="margin-bottom: 1rem;">
            <div style="color: #F97316; font-weight: 600; font-size: 0.8rem; margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 1px;">
                ⚡ Impact Assessment
            </div>
            <ul style="color: #94A3B8; font-size: 0.8rem; line-height: 1.6; padding-left: 1.2rem; margin: 0;">
                {impact_html}
            </ul>
        </div>
        
        <div style="margin-bottom: 1rem;">
            <div style="color: #10B981; font-weight: 600; font-size: 0.8rem; margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 1px;">
                🛡️ Recommended Mitigations
            </div>
            <ul style="color: #94A3B8; font-size: 0.8rem; line-height: 1.6; padding-left: 1.2rem; margin: 0;">
                {mitigation_html}
            </ul>
        </div>
        
        <div style="
            display: flex;
            gap: 1.5rem;
            padding-top: 0.8rem;
            border-top: 1px solid rgba(255,255,255,0.06);
            font-size: 0.7rem;
            color: #64748B;
            font-family: 'JetBrains Mono';
        ">
            <span>MITRE ATT&CK: <span style="color: #8B5CF6;">{intel.get('mitre_technique', 'N/A')}</span></span>
            <span>CVE References: {cve_html}</span>
            <span>Detected: <span style="color: #F59E0B;">{active_threats.get(dominant_threat, 0):,} instances</span></span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Show other active threats
    other_threats = {k: v for k, v in active_threats.items() if k != dominant_threat}
    if other_threats:
        st.markdown(f"""
        <div style="
            margin-top: 0.8rem;
            padding: 0.8rem 1rem;
            background: rgba(139,92,246,0.06);
            border: 1px solid rgba(139,92,246,0.15);
            border-radius: 8px;
            font-family: 'Inter';
            font-size: 0.8rem;
            color: #94A3B8;
        ">
            <b style="color: #8B5CF6;">Additional Active Threats:</b> {', '.join([f'{k} ({v:,} instances)' for k, v in other_threats.items()])}
        </div>
        """, unsafe_allow_html=True)
