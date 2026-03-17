"""
SPARK — Smart Protection & Anomaly Recognition Kernel
ML Model Training Pipeline

Trains XGBoost, Random Forest, and Isolation Forest models
on the synthetic CAN bus dataset for real-time intrusion detection.
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import logging
from typing import Tuple, Dict, Any

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, accuracy_score, precision_score, recall_score
)
from sklearn.ensemble import RandomForestClassifier, IsolationForest

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


FEATURE_COLS = [
    'CAN_ID', 'DLC',
    'Data0', 'Data1', 'Data2', 'Data3',
    'Data4', 'Data5', 'Data6', 'Data7',
    'InterArrivalTime', 'PayloadEntropy', 'ByteMean', 'ByteStd'
]

LABEL_COL = 'Label'


def load_dataset(data_path: str) -> Tuple[pd.DataFrame, pd.Series, LabelEncoder]:
    """Load and prepare the CAN bus dataset for training."""
    logger.info(f"Loading dataset from {data_path}...")
    df = pd.read_csv(data_path)

    # Encode labels
    le = LabelEncoder()
    df['LabelEncoded'] = le.fit_transform(df[LABEL_COL])

    logger.info(f"Dataset shape: {df.shape}")
    logger.info(f"Classes: {dict(zip(le.classes_, le.transform(le.classes_)))}")
    logger.info(f"Distribution:\n{df[LABEL_COL].value_counts().to_string()}")

    X = df[FEATURE_COLS].values
    y = df['LabelEncoded'].values

    return df, pd.Series(y), le


def train_xgboost(X_train: np.ndarray, y_train: np.ndarray,
                  X_test: np.ndarray, y_test: np.ndarray,
                  le: LabelEncoder) -> Any:
    """Train XGBoost classifier for multi-class CAN attack detection."""
    try:
        from xgboost import XGBClassifier
    except ImportError:
        logger.warning("XGBoost not available, skipping...")
        return None

    logger.info("Training XGBoost classifier...")

    model = XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective='multi:softprob',
        num_class=len(le.classes_),
        eval_metric='mlogloss',
        random_state=42,
        n_jobs=-1,
        verbosity=0
    )

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')

    logger.info(f"XGBoost — Accuracy: {acc:.4f}, F1-Score: {f1:.4f}")
    logger.info(f"\n{classification_report(y_test, y_pred, target_names=le.classes_)}")

    return model


def train_random_forest(X_train: np.ndarray, y_train: np.ndarray,
                        X_test: np.ndarray, y_test: np.ndarray,
                        le: LabelEncoder) -> RandomForestClassifier:
    """Train Random Forest classifier as ensemble backup."""
    logger.info("Training Random Forest classifier...")

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')

    logger.info(f"Random Forest — Accuracy: {acc:.4f}, F1-Score: {f1:.4f}")
    logger.info(f"\n{classification_report(y_test, y_pred, target_names=le.classes_)}")

    return model


def train_isolation_forest(X_normal: np.ndarray) -> IsolationForest:
    """Train Isolation Forest for unsupervised anomaly detection."""
    logger.info("Training Isolation Forest anomaly detector...")

    model = IsolationForest(
        n_estimators=150,
        max_samples='auto',
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_normal)
    logger.info("Isolation Forest trained on normal traffic patterns.")

    return model


def save_models(models: Dict[str, Any], le: LabelEncoder, save_dir: str) -> None:
    """Serialize all trained models to disk."""
    os.makedirs(save_dir, exist_ok=True)

    for name, model in models.items():
        if model is not None:
            path = os.path.join(save_dir, f"{name}.pkl")
            joblib.dump(model, path)
            logger.info(f"Saved {name} → {path}")

    le_path = os.path.join(save_dir, "label_encoder.pkl")
    joblib.dump(le, le_path)
    logger.info(f"Saved label_encoder → {le_path}")

    # Save feature columns
    fc_path = os.path.join(save_dir, "feature_columns.pkl")
    joblib.dump(FEATURE_COLS, fc_path)
    logger.info(f"Saved feature_columns → {fc_path}")


def main() -> None:
    """Full training pipeline."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, "data", "synthetic_can_data.csv")
    save_dir = os.path.join(base_dir, "models", "saved")

    if not os.path.exists(data_path):
        logger.error(f"Dataset not found at {data_path}. Run data/generate_dataset.py first.")
        sys.exit(1)

    df, y, le = load_dataset(data_path)
    X = df[FEATURE_COLS].values

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y.values, test_size=0.2, random_state=42, stratify=y.values
    )

    logger.info(f"Train: {X_train.shape[0]:,}, Test: {X_test.shape[0]:,}")

    # Train all models
    xgb_model = train_xgboost(X_train, y_train, X_test, y_test, le)
    rf_model = train_random_forest(X_train, y_train, X_test, y_test, le)

    # Isolation Forest on normal data only
    normal_mask = y.values == le.transform(['Normal'])[0]
    X_normal = X[normal_mask]
    iso_model = train_isolation_forest(X_normal)

    # Save all models
    models = {
        "xgboost_classifier": xgb_model,
        "random_forest_classifier": rf_model,
        "isolation_forest": iso_model,
    }
    save_models(models, le, save_dir)

    logger.info("All models trained and saved successfully!")


if __name__ == "__main__":
    main()
