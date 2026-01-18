"""
Convert Custom Dataset (Data.csv) for Autoencoder Training
Healthcare Cyber-Resilience Platform

This script:
1. Reads Data.csv (CICIDS format or similar)
2. Preprocesses and normalizes features
3. Saves as training_data.npy (keeps original normal_data.npy intact)
4. Optionally trains the model

To restore OLD dataset:
  - Just delete training_data.npy
  - The system will use normal_data.npy as fallback
"""

import pandas as pd
import numpy as np
import os

# Configuration
CSV_FILE = "Data.csv"
OUTPUT_FILE = "training_data.npy"  # Different from normal_data.npy!
BACKUP_FILE = "normal_data.npy"    # Original stays untouched

# Selected features for the autoencoder (10 most relevant for anomaly detection)
SELECTED_FEATURES = [
    ' Flow Duration',
    ' Total Fwd Packets',
    ' Total Backward Packets',
    'Total Length of Fwd Packets',
    ' Flow Bytes/s',
    ' Flow Packets/s',
    ' Fwd Packet Length Mean',
    ' Packet Length Mean',
    ' Average Packet Size',
    ' Down/Up Ratio'
]

# Fallback if above features not found - use first 10 numeric columns
FALLBACK_MODE = True

def clean_data(df):
    """Clean and preprocess the dataframe."""
    # Remove spaces from column names
    df.columns = df.columns.str.strip()
    
    # Replace infinity with NaN, then fill NaN with column median
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Select only numeric columns
    numeric_df = df.select_dtypes(include=[np.number])
    
    # Fill NaN with column median
    numeric_df = numeric_df.fillna(numeric_df.median())
    
    return numeric_df

def normalize_data(data):
    """Normalize data to 0-1 range using min-max scaling."""
    min_vals = data.min(axis=0)
    max_vals = data.max(axis=0)
    
    # Avoid division by zero
    ranges = max_vals - min_vals
    ranges[ranges == 0] = 1
    
    normalized = (data - min_vals) / ranges
    return np.clip(normalized, 0, 1)

def main():
    print("=" * 60)
    print("CUSTOM DATASET CONVERTER")
    print("=" * 60)
    
    # Check if CSV exists
    if not os.path.exists(CSV_FILE):
        print(f"ERROR: {CSV_FILE} not found!")
        return
    
    print(f"\nReading {CSV_FILE}...")
    
    # Read CSV with error handling for large files
    try:
        df = pd.read_csv(CSV_FILE, low_memory=False)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return
    
    print(f"Loaded: {len(df)} samples, {len(df.columns)} columns")
    
    # Check for Label column
    if ' Label' in df.columns or 'Label' in df.columns:
        label_col = ' Label' if ' Label' in df.columns else 'Label'
        labels = df[label_col].value_counts()
        print(f"\nLabel distribution:")
        for label, count in labels.items():
            print(f"  {label}: {count}")
        
        # Filter to only BENIGN (normal) traffic for training
        benign_mask = df[label_col].str.upper().str.strip() == 'BENIGN'
        normal_df = df[benign_mask]
        print(f"\nUsing {len(normal_df)} BENIGN samples for training")
    else:
        normal_df = df
        print("No Label column found - using all data")
    
    # Clean data
    print("\nCleaning data...")
    numeric_df = clean_data(normal_df)
    
    # Select features
    print("\nSelecting features...")
    available_features = []
    
    # Strip spaces from column names for matching
    clean_columns = {col.strip(): col for col in numeric_df.columns}
    
    for feat in SELECTED_FEATURES:
        clean_feat = feat.strip()
        if clean_feat in clean_columns:
            available_features.append(clean_columns[clean_feat])
    
    if len(available_features) >= 5:
        print(f"Found {len(available_features)} matching features")
        selected_df = numeric_df[available_features]
    else:
        print(f"Using fallback: first 10 numeric columns")
        cols = list(numeric_df.columns)[:10]
        selected_df = numeric_df[cols]
        print(f"Selected columns: {cols}")
    
    # Convert to numpy array
    data = selected_df.values.astype(np.float32)
    
    # Handle any remaining NaN/Inf
    data = np.nan_to_num(data, nan=0.0, posinf=1.0, neginf=0.0)
    
    # Normalize
    print("\nNormalizing data...")
    normalized_data = normalize_data(data)
    
    # Sample if too large (for faster training)
    MAX_SAMPLES = 10000
    if len(normalized_data) > MAX_SAMPLES:
        print(f"Sampling {MAX_SAMPLES} from {len(normalized_data)} samples...")
        indices = np.random.choice(len(normalized_data), MAX_SAMPLES, replace=False)
        normalized_data = normalized_data[indices]
    
    print(f"\nFinal dataset shape: {normalized_data.shape}")
    print(f"  Min: {normalized_data.min():.4f}")
    print(f"  Max: {normalized_data.max():.4f}")
    print(f"  Mean: {normalized_data.mean():.4f}")
    
    # Save
    np.save(OUTPUT_FILE, normalized_data)
    print(f"\nSaved to: {OUTPUT_FILE}")
    print(f"File size: {os.path.getsize(OUTPUT_FILE)} bytes")
    
    print("\n" + "=" * 60)
    print("SUCCESS! Your custom dataset is ready.")
    print("=" * 60)
    print(f"\nFiles:")
    print(f"  - {OUTPUT_FILE} : Your custom data (NEW)")
    print(f"  - {BACKUP_FILE} : Original data (BACKUP)")
    print(f"\nNext step:")
    print(f"  .\\venv\\Scripts\\python.exe train_from_custom.py")
    print("=" * 60)

if __name__ == "__main__":
    main()
