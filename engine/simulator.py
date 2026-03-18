"""
SPARK — Smart Protection & Anomaly Recognition Kernel
CAN Bus Traffic Simulator

Software-based CAN bus simulator for Windows.
Streams normal CAN traffic from the synthetic dataset
and supports real-time attack injection.
"""

import os
import sys
import time
import json
import threading
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Callable
from collections import deque

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CANMessage:
    """Represents a single CAN bus message."""

    def __init__(self, timestamp: float, can_id: int, dlc: int,
                 data: List[int], label: str = "Normal",
                 source: str = "ECU") -> None:
        self.timestamp = timestamp
        self.can_id = can_id
        self.dlc = dlc
        self.data = data[:8]  # Ensure max 8 bytes
        self.label = label
        self.source = source
        
    @property
    def can_id_hex(self) -> str:
        return f"0x{self.can_id:03X}"

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': round(self.timestamp, 6),
            'can_id': self.can_id,
            'can_id_hex': f"0x{self.can_id:03X}",
            'dlc': self.dlc,
            'data': self.data,
            'label': self.label,
            'source': self.source
        }

    def __repr__(self) -> str:
        data_hex = ' '.join(f'{b:02X}' for b in self.data)
        return f"[{self.timestamp:.6f}] 0x{self.can_id:03X} [{self.dlc}] {data_hex} ({self.label})"


class CANBusSimulator:
    """
    Software-based CAN bus simulator.
    Streams CAN messages to a shared buffer accessible by the detection engine.
    """

    def __init__(self, dataset_path: Optional[str] = None, speed_multiplier: float = 1.0) -> None:
        self.speed_multiplier = speed_multiplier
        self.message_buffer: deque = deque(maxlen=50000)
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._attack_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._callbacks: List[Callable] = []
        self.quarantined_ids = set()

        # Statistics
        self.stats = {
            'total_messages': 0,
            'messages_per_second': 0,
            'normal_count': 0,
            'attack_count': 0,
            'start_time': 0,
        }

        # Attack state
        self.attack_active = False
        self.attack_type: Optional[str] = None
        self.attacker_quarantined = False

        # Load dataset
        self.dataset: Optional[pd.DataFrame] = None
        if dataset_path and os.path.exists(dataset_path):
            self._load_dataset(dataset_path)

        # ECU profiles for live generation
        self._rng = np.random.default_rng(42)
        self._ecu_ids = [
            0x0A0, 0x0A1, 0x0B0, 0x0B1, 0x130, 0x131,
            0x164, 0x18E, 0x1A0, 0x1F5, 0x260, 0x2C0,
            0x316, 0x329, 0x380, 0x3B0, 0x43F, 0x545
        ]

    def _load_dataset(self, path: str) -> None:
        """Load the CAN bus dataset for replay."""
        logger.info(f"Loading dataset: {path}")
        self.dataset = pd.read_csv(path)
        logger.info(f"Loaded {len(self.dataset):,} messages")

    def register_callback(self, callback: Callable) -> None:
        """Register a callback function for new messages."""
        self._callbacks.append(callback)

    def _notify_callbacks(self, message: CANMessage) -> None:
        """Notify all registered callbacks of a new message."""
        for cb in self._callbacks:
            try:
                cb(message)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def _generate_live_message(self) -> CANMessage:
        """Generate a single live normal CAN message."""
        can_id = self._rng.choice(self._ecu_ids)
        data = self._rng.integers(0, 256, size=8).tolist()
        return CANMessage(
            timestamp=time.time(),
            can_id=int(can_id),
            dlc=8,
            data=data,
            label="Normal",
            source="ECU_SIM"
        )

    def _stream_dataset(self) -> None:
        """Stream messages from the loaded dataset."""
        if self.dataset is None:
            return

        normal_data = self.dataset[self.dataset['Label'] == 'Normal']
        data_cols = [f'Data{i}' for i in range(8)]
        idx = 0

        while self.is_running:
            if idx >= len(normal_data):
                idx = 0  # Loop dataset

            row = normal_data.iloc[idx]
            msg = CANMessage(
                timestamp=time.time(),
                can_id=int(row['CAN_ID']),
                dlc=int(row['DLC']),
                data=[int(row[c]) for c in data_cols],
                label="Normal",
                source="DATASET"
            )

            self._push_message(msg)
            idx += 1
            time.sleep(0.001 / self.speed_multiplier)  # ~1000 msg/sec base

    def _stream_live(self) -> None:
        """Generate and stream live CAN messages."""
        while self.is_running:
            msg = self._generate_live_message()
            self._push_message(msg)
            time.sleep(0.001 / self.speed_multiplier)

    def _push_message(self, msg: CANMessage) -> None:
        """Push a message to the buffer and update stats."""
        # KILL SWITCH: Drop if quarantined
        if msg.can_id_hex in self.quarantined_ids:
            return
        # PORT ISOLATION: Drop if attacker is physically quarantined at the gateway
        if getattr(self, 'attacker_quarantined', False) and msg.source == "ATTACKER":
            return
            
        with self._lock:
            self.message_buffer.append(msg)
            self.stats['total_messages'] += 1
            if msg.label == 'Normal':
                self.stats['normal_count'] += 1
            else:
                self.stats['attack_count'] += 1

        self._notify_callbacks(msg)

    def start(self) -> None:
        """Start the CAN bus simulator."""
        if self.is_running:
            return

        self.is_running = True
        self.stats['start_time'] = time.time()

        if self.dataset is not None:
            self._thread = threading.Thread(target=self._stream_dataset, daemon=True)
        else:
            self._thread = threading.Thread(target=self._stream_live, daemon=True)

        self._thread.start()
        logger.info("CAN Bus Simulator started.")

    def stop(self) -> None:
        """Stop the simulator."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("CAN Bus Simulator stopped.")

    def inject_attack(self, attack_type: str, duration: float = 5.0,
                      intensity: int = 100) -> None:
        """Inject an attack into the CAN bus stream."""
        if self._attack_thread and self._attack_thread.is_alive():
            logger.warning("Attack already in progress")
            return

        self.attack_active = True
        self.attack_type = attack_type

        def _run_attack():
            logger.info(f"Injecting {attack_type} attack for {duration}s...")
            end_time = time.time() + duration
            rng = np.random.default_rng()

            while time.time() < end_time and self.is_running:
                if attack_type == "DoS":
                    msg = CANMessage(
                        timestamp=time.time(),
                        can_id=0x000,
                        dlc=8,
                        data=rng.integers(0, 256, size=8).tolist(),
                        label="DoS",
                        source="ATTACKER"
                    )
                elif attack_type == "Fuzzy":
                    msg = CANMessage(
                        timestamp=time.time(),
                        can_id=int(rng.integers(0, 0x800)),
                        dlc=int(rng.choice([4, 5, 6, 7, 8])),
                        data=rng.integers(0, 256, size=8).tolist(),
                        label="Fuzzy",
                        source="ATTACKER"
                    )
                elif attack_type == "Spoofing":
                    target_id = int(rng.choice([0x316, 0x43F]))
                    msg = CANMessage(
                        timestamp=time.time(),
                        can_id=target_id,
                        dlc=8,
                        data=[0xFF, 0xFF] + rng.integers(0, 256, size=6).tolist(),
                        label="Spoofing",
                        source="ATTACKER"
                    )
                elif attack_type == "Replay":
                    # Replay uses a normal-looking ID but with temporal anomaly
                    msg = CANMessage(
                        timestamp=time.time(),
                        can_id=int(rng.choice([0x0A0, 0x0B0, 0x316])),
                        dlc=8,
                        data=rng.integers(0, 100, size=8).tolist(),
                        label="Replay",
                        source="ATTACKER"
                    )
                else:
                    break

                self._push_message(msg)
                time.sleep(max(0.0001, 0.001 / intensity))

            self.attack_active = False
            self.attack_type = None
            self.attacker_quarantined = False  # Reset for next attack cycle
            logger.info(f"{attack_type} attack completed.")

        self._attack_thread = threading.Thread(target=_run_attack, daemon=True)
        self._attack_thread.start()
        
    def quarantine_id(self, can_id_hex: str) -> None:
        """Blocks a specific CAN ID from processing (Kill Switch)"""
        self.quarantined_ids.add(can_id_hex)
        logger.warning(f"KILL SWITCH ACTIVATED: CAN ID {can_id_hex} is now quarantined.")
        
    def quarantine_attacker_port(self) -> None:
        """Physically isolates the attacking module entirely."""
        self.attacker_quarantined = True
        logger.warning("AUTO-IPS ACTIVATED: Full attacker port isolation enforced.")
        
    def clear_quarantine(self) -> None:
        """Restores full flow"""
        self.quarantined_ids.clear()
        self.attacker_quarantined = False

    def get_recent_messages(self, count: int = 100) -> List[Dict]:
        """Get the most recent messages from the buffer."""
        with self._lock:
            messages = list(self.message_buffer)[-count:]
        return [m.to_dict() for m in messages]

    def get_stats(self) -> Dict:
        """Get current simulator statistics."""
        elapsed = max(time.time() - self.stats['start_time'], 1)
        return {
            **self.stats,
            'messages_per_second': round(self.stats['total_messages'] / elapsed, 1),
            'elapsed_seconds': round(elapsed, 1),
            'attack_active': self.attack_active,
            'attack_type': self.attack_type
        }
