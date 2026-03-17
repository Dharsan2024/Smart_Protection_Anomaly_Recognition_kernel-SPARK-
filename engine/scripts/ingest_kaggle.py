import os
import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

def preprocess_kaggle_dataset(raw_csv_path: str, output_csv_path: str, attack_type: str, max_rows: int = 50000):
    """
    Converts raw Kaggle CAN datasets (DoS, Fuzzy, etc.) into the SPARK synthetic format.
    Kaggle Format: Timestamp, CAN_ID (Hex), DLC, Data0...Data7, Label (R=Normal, T=Attack)
    SPARK Format: Timestamp, CAN_ID (Int), DLC, Data0...Data7, Label (Attack Type)
    """
    logger.info(f"Processing {raw_csv_path}...")
    
    # Kaggle CSVs don't have headers.
    col_names = ['Timestamp', 'CAN_ID_Hex', 'DLC', 'Data0', 'Data1', 'Data2', 'Data3', 'Data4', 'Data5', 'Data6', 'Data7', 'Label']
    
    # We only take a subset to keep the simulator snappy, but ensure we grab a mix of R and T
    df = pd.read_csv(raw_csv_path, names=col_names, nrows=max_rows * 2, dtype=str)
    
    # 1. Clean missing data
    df = df.dropna()
    
    # 2. Convert CAN_ID from Hex string to Integer
    df['CAN_ID'] = df['CAN_ID_Hex'].apply(lambda x: int(str(x), 16) if isinstance(x, str) else 0)
    
    # 3. Convert Data columns from Hex string to Integer
    data_cols = [f'Data{i}' for i in range(8)]
    for col in data_cols:
        df[col] = df[col].apply(lambda x: int(str(x), 16) if isinstance(x, str) and str(x).isalnum() else 0)
        
    # 4. Convert DLC and Timestamp
    df['DLC'] = pd.to_numeric(df['DLC'], errors='coerce').fillna(8).astype(int)
    df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
    
    # 5. Map Labels ('R' -> 'Normal', 'T' -> attack_type)
    df['Label'] = df['Label'].map({'R': 'Normal', 'T': attack_type}).fillna('Normal')
    
    # --- Feature Engineering ---
    logger.info("Calculating derived features...")
    
    # Inter-Arrival Time (IAT)
    # Note: Kaggle datasets are usually sorted by timestamp per file.
    df = df.sort_values('Timestamp')
    df['InterArrivalTime'] = df.groupby('CAN_ID')['Timestamp'].diff().fillna(0)
    
    # Payload Stats
    data_df = df[data_cols].astype(int)
    df['ByteMean'] = data_df.mean(axis=1)
    df['ByteStd'] = data_df.std(axis=1).fillna(0)
    
    # Entropy
    def calc_entropy(row):
        counts = np.bincount(row, minlength=256)
        probs = counts[counts > 0] / 8
        return -np.sum(probs * np.log2(probs + 1e-10))
    
    df['PayloadEntropy'] = data_df.apply(calc_entropy, axis=1)
    
    # --- Finalize ---
    final_cols = ['Timestamp', 'CAN_ID', 'DLC'] + data_cols + [
        'InterArrivalTime', 'PayloadEntropy', 'ByteMean', 'ByteStd', 'Label'
    ]
    df_clean = df[final_cols].head(max_rows)
    
    df_clean.to_csv(output_csv_path, index=False)
    logger.info(f"Saved {len(df_clean)} rows to {output_csv_path}")
    
    # Print distribution
    logger.info(df_clean['Label'].value_counts())

if __name__ == "__main__":
    kaggle_dir = r"c:\Users\GOHUL KANNAN\Downloads\can\KAGGLE DATASET AND MODELS"
    output_dir = r"c:\Users\GOHUL KANNAN\Downloads\can\data"
    
    os.makedirs(output_dir, exist_ok=True)
    
    # We will merge DoS and Fuzzy datasets to create a robust mixed dataset
    # 1. Process DoS
    dos_path = os.path.join(kaggle_dir, "DoS_dataset.csv")
    dos_out = os.path.join(output_dir, "kaggle_dos.csv")
    preprocess_kaggle_dataset(dos_path, dos_out, "DoS", max_rows=20000)
    
    # 2. Process Fuzzy
    fuzzy_path = os.path.join(kaggle_dir, "Fuzzy_dataset.csv")
    fuzzy_out = os.path.join(output_dir, "kaggle_fuzzy.csv")
    preprocess_kaggle_dataset(fuzzy_path, fuzzy_out, "Fuzzy", max_rows=15000)
    
    # 3. Process Gear
    gear_path = os.path.join(kaggle_dir, "gear_dataset.csv")
    gear_out = os.path.join(output_dir, "kaggle_gear.csv")
    preprocess_kaggle_dataset(gear_path, gear_out, "Spoofing", max_rows=15000)
    
    # 4. Process RPM
    rpm_path = os.path.join(kaggle_dir, "RPM_dataset.csv")
    rpm_out = os.path.join(output_dir, "kaggle_rpm.csv")
    preprocess_kaggle_dataset(rpm_path, rpm_out, "Spoofing", max_rows=15000)
    
    # 5. Combine into the master synthetic_can_data.csv that SPARK expects
    df_dos = pd.read_csv(dos_out)
    df_fuzzy = pd.read_csv(fuzzy_out)
    df_gear = pd.read_csv(gear_out)
    df_rpm = pd.read_csv(rpm_out)
    
    master_df = pd.concat([df_dos, df_fuzzy, df_gear, df_rpm]).sample(frac=1).reset_index(drop=True)
    
    # Ensure it's sorted by timestamp roughly
    master_df = master_df.sort_values(by='Timestamp').reset_index(drop=True)
    
    master_path = os.path.join(output_dir, "synthetic_can_data.csv")
    master_df.to_csv(master_path, index=False)
    logger.info(f"MASTER DATASET SAVED to {master_path} with {len(master_df)} total records.")
    logger.info(master_df['Label'].value_counts())
