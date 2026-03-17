# ⚡ SPARK — Smart Protection & Anomaly Recognition Kernel

<div align="center">

### 🛡️ AI-Powered CAN Bus Intrusion Detection System
### Real-Time Security Operations Center Dashboard

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-ML-006600?style=for-the-badge)](https://xgboost.ai)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.18-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)](https://tensorflow.org)

</div>

---

## 🎯 Overview

**SPARK** is an advanced AI-driven Intrusion Detection System (IDS) specifically engineered for Controller Area Network (CAN) bus security. It provides real-time threat detection, classification, and visualization through a premium industrial SOC (Security Operations Center) dashboard.

The system employs a **dual-layer AI detection engine**:
- **Layer 1 — Spatial Analysis**: XGBoost ensemble classifier for ultra-fast known attack classification
- **Layer 2 — Anomaly Detection**: Isolation Forest for zero-day threat identification
- **Layer 3 — Temporal Analysis**: LSTM Autoencoder for sequence-based replay/impersonation detection

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SPARK WEB FRONTEND                        │
│            (Vanilla JS + WebSockets + ApexCharts)            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ Live KPIs│ │ Timeline │ │ Feed +   │ │  AI Analyst   │  │
│  │  Metrics │ │  Charts  │ │ Topology │ │  (MITRE ATT&CK)│ │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
├─────────────────────────────────────────────────────────────┤
│              FASTAPI BACKEND & AI THREAT ENGINE              │
│  ┌──────────────┐ ┌────────────────┐ ┌─────────────────┐   │
│  │   XGBoost    │ │ Isolation      │ │ LSTM Autoencoder│   │
│  │  Classifier  │ │ Forest         │ │  (Temporal)     │   │
│  └──────────────┘ └────────────────┘ └─────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│           CAN BUS SIMULATION ENGINE                          │
│  ┌──────────────┐ ┌────────────────┐ ┌─────────────────┐   │
│  │  Normal ECU  │ │ Attack Inject  │ │ Message Buffer  │   │
│  │  Simulator   │ │ (DoS/Fuzzy/..) │ │  & Callbacks    │   │
│  └──────────────┘ └────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate Synthetic CAN Dataset
```bash
python data/generate_dataset.py
```

### 3. Train ML Models
```bash
python models/train_models.py
```

### 4. (Optional) Train LSTM Autoencoder
```bash
python models/train_lstm.py
```

### 5. Launch the Web Application (Two Terminals Required)

**Terminal 1 (Backend API):**
```bash
uvicorn backend.api:app --host 0.0.0.0 --port 8000
```

**Terminal 2 (Frontend UI):**
```bash
cd frontend
python -m http.server 3000
```
*Then open your browser to `http://localhost:3000`*

## 🎮 Usage

1. Click **▶️ START** in the sidebar to begin CAN bus simulation
2. Monitor real-time traffic in the **Traffic Timeline** tab
3. View ECU network topology in the **Network Topology** tab
4. Select an attack type and click **🚀 LAUNCH ATTACK** to simulate threats
5. Watch the AI engine detect and classify threats in real-time
6. Review detailed threat intelligence in the **Threat Analysis** tab

## 🛡️ Attack Types Detected

| Attack | Severity | Description |
|--------|----------|-------------|
| **DoS** | 🔴 CRITICAL | Floods bus with highest-priority ID 0x000 |
| **Fuzzy** | 🟠 HIGH | Random IDs with high-entropy payloads |
| **Spoofing** | 🔴 CRITICAL | Fabricated payloads on known ECU IDs |
| **Replay** | 🟠 HIGH | Re-injected captured traffic sequences |

## 📊 AI Models

| Model | Type | Purpose |
|-------|------|---------|
| **XGBoost** | Supervised | Primary real-time attack classifier |
| **Random Forest** | Supervised | Ensemble backup classifier |
| **Isolation Forest** | Unsupervised | Zero-day anomaly detection |
| **LSTM Autoencoder** | Semi-supervised | Temporal sequence anomaly detection |

## 📁 Project Structure

```
can/
├── data/                    # Dataset generation & storage
├── models/                  # ML training scripts & saved models
├── engine/                  # CAN bus simulation & AI detection
├── backend/                 # FastAPI WebSocket server (api.py)
├── frontend/                # Custom HTML/JS/CSS Web UI
│   ├── index.html           # Main View
│   ├── app.js               # WebSocket + Chart Logic
│   └── styles.css           # Premium Glassmorphism Theme
├── dashboard/               # (Legacy Streamlit Dashboard)
├── requirements.txt
├── AGENTS.md               # Architecture specification
└── README.md
```

## 🔧 Tech Stack

- **Python 3.10+** — Core runtime
- **FastAPI + WebSockets** — Backend application server
- **Vanilla JS + HTML + CSS** — Performance-focused frontend
- **ApexCharts** — Real-time live data visualizations
- **XGBoost / Scikit-Learn** — ML classifiers
- **TensorFlow/Keras** — LSTM Autoencoder
- **Pandas / NumPy** — Data processing

## 📜 License

MIT License — Built for educational and research purposes.

---

<div align="center">

**⚡ SPARK** — *Securing the Future of Connected Vehicles*

</div>
