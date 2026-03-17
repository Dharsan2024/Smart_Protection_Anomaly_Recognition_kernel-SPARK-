# SPARK — Smart Protection & Anomaly Recognition Kernel

## Tech Stack
- Python 3.10+
- Streamlit (Dashboard/UI)
- Pandas, NumPy (Data Processing)
- Scikit-Learn, XGBoost (ML Classification)
- TensorFlow/Keras (LSTM Autoencoder)
- Plotly, NetworkX (Visualization)

## Architecture Rules
- Strict separation: `data/`, `models/`, `engine/`, `dashboard/`
- All models serialized to `models/saved/`
- Dashboard reads from shared state in `engine/`
- No external API dependencies for core functionality
- Windows-compatible (no vcan/SocketCAN — pure software simulation)

## Coding Standards
- Type hints on all functions
- Docstrings on all modules and classes
- Error handling with graceful fallbacks
- Consistent logging via Python `logging` module
