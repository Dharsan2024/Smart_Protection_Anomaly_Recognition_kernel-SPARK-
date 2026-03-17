"""
SPARK — Smart Protection & Anomaly Recognition Kernel
LSTM Autoencoder Training

Semi-supervised anomaly detection: trains an LSTM Autoencoder
exclusively on normal CAN bus traffic to detect zero-day attacks
via reconstruction error thresholding.
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import logging
from typing import Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SEQUENCE_LENGTH = 50  # Rolling window size
FEATURE_COLS = [
    'CAN_ID', 'DLC',
    'Data0', 'Data1', 'Data2', 'Data3',
    'Data4', 'Data5', 'Data6', 'Data7',
    'InterArrivalTime', 'PayloadEntropy', 'ByteMean', 'ByteStd'
]


def create_sequences(data: np.ndarray, seq_length: int = SEQUENCE_LENGTH) -> np.ndarray:
    """Create rolling window sequences from time-series data."""
    sequences = []
    for i in range(len(data) - seq_length):
        sequences.append(data[i:i + seq_length])
    return np.array(sequences)


def normalize_data(data: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Min-max normalize features to [0, 1]."""
    d_min = data.min(axis=0)
    d_max = data.max(axis=0)
    d_range = d_max - d_min
    d_range[d_range == 0] = 1.0
    normalized = (data - d_min) / d_range
    return normalized, d_min, d_max


def build_lstm_autoencoder(seq_length: int, n_features: int):
    """Build LSTM Autoencoder model for sequence anomaly detection."""
    try:
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
    except ImportError:
        logger.error("TensorFlow not installed. Install with: pip install tensorflow")
        sys.exit(1)

    # Encoder
    inputs = keras.Input(shape=(seq_length, n_features))
    encoded = layers.LSTM(64, activation='relu', return_sequences=True)(inputs)
    encoded = layers.LSTM(32, activation='relu', return_sequences=False)(encoded)

    # Bottleneck
    bottleneck = layers.RepeatVector(seq_length)(encoded)

    # Decoder
    decoded = layers.LSTM(32, activation='relu', return_sequences=True)(bottleneck)
    decoded = layers.LSTM(64, activation='relu', return_sequences=True)(decoded)
    outputs = layers.TimeDistributed(layers.Dense(n_features))(decoded)

    model = keras.Model(inputs, outputs)
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=0.001),
                  loss='mse')

    logger.info(f"LSTM Autoencoder built: {model.count_params():,} parameters")
    return model


def main() -> None:
    """Train LSTM Autoencoder on normal CAN bus traffic."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, "data", "synthetic_can_data.csv")
    save_dir = os.path.join(base_dir, "models", "saved")
    os.makedirs(save_dir, exist_ok=True)

    if not os.path.exists(data_path):
        logger.error(f"Dataset not found. Run data/generate_dataset.py first.")
        sys.exit(1)

    # Load and filter normal traffic only
    df = pd.read_csv(data_path)
    normal_df = df[df['Label'] == 'Normal'].copy()
    logger.info(f"Normal samples: {len(normal_df):,}")

    # Extract and normalize features
    X = normal_df[FEATURE_COLS].values.astype(np.float32)
    X_norm, d_min, d_max = normalize_data(X)

    # Save normalization params
    joblib.dump({'min': d_min, 'max': d_max}, os.path.join(save_dir, 'lstm_norm_params.pkl'))

    # Create sequences
    sequences = create_sequences(X_norm, SEQUENCE_LENGTH)
    logger.info(f"Sequences created: {sequences.shape}")

    # Train/validation split
    split = int(0.85 * len(sequences))
    X_train, X_val = sequences[:split], sequences[split:]

    # Build and train model
    model = build_lstm_autoencoder(SEQUENCE_LENGTH, len(FEATURE_COLS))

    import tensorflow as tf
    history = model.fit(
        X_train, X_train,
        epochs=5,
        batch_size=128,
        validation_data=(X_val, X_val),
        callbacks=[
            tf.keras.callbacks.EarlyStopping(patience=3, restore_best_weights=True),
            tf.keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=2)
        ],
        verbose=1
    )

    # Calculate threshold from validation reconstruction error
    val_pred = model.predict(X_val, verbose=0)
    val_mse = np.mean(np.power(X_val - val_pred, 2), axis=(1, 2))

    threshold = np.mean(val_mse) + 2.5 * np.std(val_mse)
    logger.info(f"Anomaly threshold: {threshold:.6f}")
    logger.info(f"Val MSE — Mean: {np.mean(val_mse):.6f}, Std: {np.std(val_mse):.6f}")

    # Save model and threshold
    model_path = os.path.join(save_dir, 'lstm_autoencoder.keras')
    model.save(model_path)
    joblib.dump({'threshold': threshold, 'mean_mse': float(np.mean(val_mse)),
                 'std_mse': float(np.std(val_mse))},
                os.path.join(save_dir, 'lstm_threshold.pkl'))

    logger.info(f"LSTM Autoencoder saved to {model_path}")
    logger.info("Training complete!")


if __name__ == "__main__":
    main()
