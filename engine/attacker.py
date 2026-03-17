"""
SPARK — Smart Protection & Anomaly Recognition Kernel
Attack Injection Engine

Provides configurable attack patterns for CAN bus simulation:
DoS, Fuzzy, Spoofing, and Replay attacks.
"""

import time
import logging
import numpy as np
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


ATTACK_PROFILES: Dict[str, Dict] = {
    'DoS': {
        'name': 'Denial of Service',
        'description': 'Floods the CAN bus with highest-priority ID 0x000, preventing legitimate ECU communication',
        'severity': 'CRITICAL',
        'icon': '🚨',
        'color': '#DC2626',
        'rate_multiplier': 50,  # 50x normal rate
    },
    'Fuzzy': {
        'name': 'Fuzzy Injection',
        'description': 'Injects random CAN IDs with random payloads causing chaotic subsystem behavior',
        'severity': 'HIGH',
        'icon': '⚠️',
        'color': '#F97316',
        'rate_multiplier': 20,
    },
    'Spoofing': {
        'name': 'ECU Spoofing',
        'description': 'Fabricates payloads on known ECU IDs (RPM 0x316, Gear 0x43F) causing targeted malfunctions',
        'severity': 'CRITICAL',
        'icon': '🚨',
        'color': '#EF4444',
        'rate_multiplier': 10,
    },
    'Replay': {
        'name': 'Replay Attack',
        'description': 'Re-injects captured normal traffic at wrong timestamps, bypassing payload anomaly detection',
        'severity': 'HIGH',
        'icon': '⚠️',
        'color': '#F59E0B',
        'rate_multiplier': 5,
    },
}


def get_attack_profiles() -> Dict:
    """Return all available attack profiles."""
    return ATTACK_PROFILES


def get_attack_description(attack_type: str) -> str:
    """Get a detailed description of the attack type."""
    profile = ATTACK_PROFILES.get(attack_type, {})
    return profile.get('description', 'Unknown attack type')
