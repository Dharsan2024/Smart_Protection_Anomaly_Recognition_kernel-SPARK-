"""
SPARK — Smart Protection & Anomaly Recognition Kernel
Synthetic CAN Bus Dataset Generator

Generates realistic CAN bus traffic with labeled attack scenarios:
- Normal: Standard ECU communication patterns
- DoS: High-priority ID flooding (0x000)
- Fuzzy: Random IDs with high-entropy payloads
- Spoofing: Manipulated payloads on known IDs
- Replay: Captured normal sequences replayed out of context
"""

import os
import sys
import numpy as np
import pandas as pd
from typing import Tuple, List, Dict
import logging
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- CAN Bus Configuration ---
NORMAL_CAN_IDS: List[int] = [
    0x0A0, 0x0A1, 0x0B0, 0x0B1, 0x130, 0x131,
    0x164, 0x18E, 0x1A0, 0x1F5, 0x260, 0x2C0,
    0x316, 0x329, 0x380, 0x3B0, 0x43F, 0x545,
    0x580, 0x5A0, 0x620, 0x6F1, 0x700, 0x7DF
]

# ECU payload patterns (typical byte ranges for specific IDs)
ECU_PROFILES: Dict[int, Dict] = {
    0x0A0: {"name": "Engine_RPM",      "base": [0x00, 0x00, 0x1A, 0x50, 0x00, 0x00, 0x00, 0x00], "var": 15},
    0x0A1: {"name": "Engine_Temp",     "base": [0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 10},
    0x0B0: {"name": "Vehicle_Speed",   "base": [0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 20},
    0x0B1: {"name": "Wheel_Speed",     "base": [0x00, 0x3C, 0x3C, 0x3C, 0x3C, 0x00, 0x00, 0x00], "var": 15},
    0x130: {"name": "Steering_Angle",  "base": [0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 25},
    0x131: {"name": "Steering_Torque", "base": [0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 10},
    0x164: {"name": "Brake_Pressure",  "base": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 30},
    0x18E: {"name": "Throttle_Pos",    "base": [0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 20},
    0x1A0: {"name": "ABS_Status",      "base": [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00], "var": 5},
    0x1F5: {"name": "Gear_Position",   "base": [0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 3},
    0x260: {"name": "Airbag_Status",   "base": [0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00], "var": 2},
    0x2C0: {"name": "Door_Status",     "base": [0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 5},
    0x316: {"name": "RPM_Gauge",       "base": [0x05, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 20},
    0x329: {"name": "Fuel_Level",      "base": [0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 5},
    0x380: {"name": "Climate_Ctrl",    "base": [0x16, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00], "var": 8},
    0x3B0: {"name": "Lighting",        "base": [0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 3},
    0x43F: {"name": "Drive_Gear",      "base": [0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 4},
    0x545: {"name": "Odometer",        "base": [0x00, 0x01, 0xE2, 0x40, 0x00, 0x00, 0x00, 0x00], "var": 2},
    0x580: {"name": "Battery_Volt",    "base": [0x00, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 5},
    0x5A0: {"name": "Tire_Pressure",   "base": [0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00], "var": 3},
    0x620: {"name": "Infotainment",    "base": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 15},
    0x6F1: {"name": "Diagnostic_Req",  "base": [0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 5},
    0x700: {"name": "Diagnostic_Resp", "base": [0x06, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 5},
    0x7DF: {"name": "OBD_Broadcast",   "base": [0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00], "var": 3},
}

# Transmission frequencies (messages per second) for each ECU
ECU_FREQUENCIES: Dict[int, float] = {
    0x0A0: 100.0, 0x0A1: 10.0,  0x0B0: 100.0, 0x0B1: 50.0,
    0x130: 50.0,  0x131: 50.0,  0x164: 50.0,  0x18E: 100.0,
    0x1A0: 20.0,  0x1F5: 10.0,  0x260: 2.0,   0x2C0: 5.0,
    0x316: 100.0, 0x329: 1.0,   0x380: 2.0,   0x3B0: 5.0,
    0x43F: 10.0,  0x545: 1.0,   0x580: 10.0,  0x5A0: 2.0,
    0x620: 5.0,   0x6F1: 0.5,   0x700: 0.5,   0x7DF: 0.5,
}


def generate_normal_payload(can_id: int, rng: np.random.Generator) -> List[int]:
    """Generate a realistic payload for a given CAN ID based on ECU profile."""
    profile = ECU_PROFILES.get(can_id, {"base": [0]*8, "var": 10})
    base = np.array(profile["base"], dtype=np.int16)
    variation = rng.integers(-profile["var"], profile["var"] + 1, size=8)
    payload = np.clip(base + variation, 0, 255).astype(np.uint8)
    return payload.tolist()


def generate_normal_traffic(n_messages: int, rng: np.random.Generator) -> pd.DataFrame:
    """Generate normal CAN bus traffic following realistic ECU patterns."""
    logger.info(f"Generating {n_messages:,} normal traffic messages...")

    # Weight IDs by their frequency
    total_freq = sum(ECU_FREQUENCIES.values())
    weights = [ECU_FREQUENCIES[cid] / total_freq for cid in NORMAL_CAN_IDS]

    ids = rng.choice(NORMAL_CAN_IDS, size=n_messages, p=weights)

    # Generate timestamps with realistic inter-arrival times
    base_iat = 0.0001  # 100µs base
    iats = rng.exponential(base_iat, size=n_messages)
    timestamps = np.cumsum(iats)

    payloads = np.array([generate_normal_payload(cid, rng) for cid in ids])

    df = pd.DataFrame({
        'Timestamp': timestamps,
        'CAN_ID': ids,
        'DLC': 8,
        'Data0': payloads[:, 0], 'Data1': payloads[:, 1],
        'Data2': payloads[:, 2], 'Data3': payloads[:, 3],
        'Data4': payloads[:, 4], 'Data5': payloads[:, 5],
        'Data6': payloads[:, 6], 'Data7': payloads[:, 7],
        'Label': 'Normal'
    })
    return df


def generate_dos_attack(n_messages: int, start_time: float, rng: np.random.Generator) -> pd.DataFrame:
    """Generate DoS attack: flooding with highest-priority ID 0x000."""
    logger.info(f"Generating {n_messages:,} DoS attack messages...")

    # DoS floods at extremely high rate
    iats = rng.exponential(0.00002, size=n_messages)  # ~50kHz flood
    timestamps = start_time + np.cumsum(iats)

    payloads = rng.integers(0, 256, size=(n_messages, 8))

    df = pd.DataFrame({
        'Timestamp': timestamps,
        'CAN_ID': 0x000,
        'DLC': 8,
        'Data0': payloads[:, 0], 'Data1': payloads[:, 1],
        'Data2': payloads[:, 2], 'Data3': payloads[:, 3],
        'Data4': payloads[:, 4], 'Data5': payloads[:, 5],
        'Data6': payloads[:, 6], 'Data7': payloads[:, 7],
        'Label': 'DoS'
    })
    return df


def generate_fuzzy_attack(n_messages: int, start_time: float, rng: np.random.Generator) -> pd.DataFrame:
    """Generate Fuzzy attack: random IDs with high-entropy random payloads."""
    logger.info(f"Generating {n_messages:,} Fuzzy attack messages...")

    ids = rng.integers(0x000, 0x800, size=n_messages)
    iats = rng.exponential(0.00005, size=n_messages)
    timestamps = start_time + np.cumsum(iats)

    # Fully random payloads => high entropy
    payloads = rng.integers(0, 256, size=(n_messages, 8))

    df = pd.DataFrame({
        'Timestamp': timestamps,
        'CAN_ID': ids,
        'DLC': rng.choice([4, 5, 6, 7, 8], size=n_messages),
        'Data0': payloads[:, 0], 'Data1': payloads[:, 1],
        'Data2': payloads[:, 2], 'Data3': payloads[:, 3],
        'Data4': payloads[:, 4], 'Data5': payloads[:, 5],
        'Data6': payloads[:, 6], 'Data7': payloads[:, 7],
        'Label': 'Fuzzy'
    })
    return df


def generate_spoofing_attack(n_messages: int, start_time: float, rng: np.random.Generator) -> pd.DataFrame:
    """Generate Spoofing attack: fake payloads on RPM (0x316) and Gear (0x43F) IDs."""
    logger.info(f"Generating {n_messages:,} Spoofing attack messages...")

    target_ids = [0x316, 0x43F]
    ids = rng.choice(target_ids, size=n_messages)

    iats = rng.exponential(0.0001, size=n_messages)
    timestamps = start_time + np.cumsum(iats)

    # Spoofed payloads: abnormal values far outside normal range
    payloads = np.zeros((n_messages, 8), dtype=int)
    for i in range(n_messages):
        if ids[i] == 0x316:  # RPM — inject dangerously high values
            payloads[i] = [0xFF, 0xFF, rng.integers(0, 256),
                           rng.integers(0, 256), 0x00, 0x00, 0x00, 0x00]
        else:  # Gear — inject invalid gear positions
            payloads[i] = [0x00, rng.integers(0x08, 0xFF),
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    df = pd.DataFrame({
        'Timestamp': timestamps,
        'CAN_ID': ids,
        'DLC': 8,
        'Data0': payloads[:, 0], 'Data1': payloads[:, 1],
        'Data2': payloads[:, 2], 'Data3': payloads[:, 3],
        'Data4': payloads[:, 4], 'Data5': payloads[:, 5],
        'Data6': payloads[:, 6], 'Data7': payloads[:, 7],
        'Label': 'Spoofing'
    })
    return df


def generate_replay_attack(normal_df: pd.DataFrame, n_messages: int,
                           start_time: float, rng: np.random.Generator) -> pd.DataFrame:
    """Generate Replay attack: re-inject captured normal sequences at wrong time."""
    logger.info(f"Generating {n_messages:,} Replay attack messages...")

    # Sample a contiguous sequence from normal traffic
    max_start = len(normal_df) - n_messages
    if max_start <= 0:
        start_idx = 0
        n_messages = min(n_messages, len(normal_df))
    else:
        start_idx = rng.integers(0, max_start)

    replayed = normal_df.iloc[start_idx:start_idx + n_messages].copy()

    # Shift timestamps to replay moment with slight timing drift
    original_duration = replayed['Timestamp'].max() - replayed['Timestamp'].min()
    if original_duration > 0:
        normalized_ts = (replayed['Timestamp'].values - replayed['Timestamp'].values[0]) / original_duration
    else:
        normalized_ts = np.linspace(0, 1, n_messages)

    drift = rng.uniform(0.95, 1.05)
    replayed['Timestamp'] = start_time + normalized_ts * original_duration * drift
    replayed['Label'] = 'Replay'

    return replayed.reset_index(drop=True)


def compute_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute derived features: InterArrivalTime, PayloadEntropy, ByteMean, ByteStd."""
    logger.info("Computing derived features...")

    data_cols = [f'Data{i}' for i in range(8)]

    # Inter-Arrival Time per CAN ID
    df = df.sort_values('Timestamp').reset_index(drop=True)
    df['InterArrivalTime'] = df.groupby('CAN_ID')['Timestamp'].diff().fillna(0.0)

    # Payload entropy (Shannon entropy of byte values)
    payload_array = df[data_cols].values.astype(np.float64)

    def row_entropy(row: np.ndarray) -> float:
        """Calculate Shannon entropy of a single payload."""
        counts = np.bincount(row.astype(int), minlength=256)
        probs = counts[counts > 0] / len(row)
        return -np.sum(probs * np.log2(probs + 1e-10))

    df['PayloadEntropy'] = np.apply_along_axis(row_entropy, 1, payload_array)

    # Byte statistics
    df['ByteMean'] = payload_array.mean(axis=1)
    df['ByteStd'] = payload_array.std(axis=1)

    return df


def generate_full_dataset(total_normal: int = 400000,
                          attack_size: int = 25000,
                          seed: int = 42) -> pd.DataFrame:
    """Generate the complete SPARK dataset with all attack types."""
    rng = np.random.default_rng(seed)

    # Generate normal traffic
    normal_df = generate_normal_traffic(total_normal, rng)
    max_time = normal_df['Timestamp'].max()

    # Generate attack traffic
    dos_df = generate_dos_attack(attack_size, max_time + 1.0, rng)
    fuzzy_df = generate_fuzzy_attack(attack_size, max_time + 5.0, rng)
    spoof_df = generate_spoofing_attack(attack_size, max_time + 10.0, rng)
    replay_df = generate_replay_attack(normal_df, attack_size, max_time + 15.0, rng)

    # Combine all traffic
    full_df = pd.concat([normal_df, dos_df, fuzzy_df, spoof_df, replay_df],
                        ignore_index=True)

    # Sort by timestamp to simulate realistic traffic flow
    full_df = full_df.sort_values('Timestamp').reset_index(drop=True)

    # Compute derived features
    full_df = compute_features(full_df)

    logger.info(f"Dataset generated: {len(full_df):,} total messages")
    logger.info(f"Label distribution:\n{full_df['Label'].value_counts().to_string()}")

    return full_df


def main() -> None:
    """Generate and save the SPARK CAN bus dataset."""
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "synthetic_can_data.csv")

    df = generate_full_dataset()
    df.to_csv(output_path, index=False)
    logger.info(f"Dataset saved to: {output_path}")
    logger.info(f"Shape: {df.shape}")
    logger.info(f"Columns: {list(df.columns)}")


if __name__ == "__main__":
    main()
