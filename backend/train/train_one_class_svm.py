import pandas as pd
import numpy as np
from sklearn.svm import OneClassSVM
import joblib
import os
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Paths from env or defaults
MODEL_STORAGE_PATH = os.getenv('MODEL_STORAGE_PATH', 'backend/models')
DATASET_BASE_PATH = os.getenv('DATASET_BASE_PATH', 'backend/datasets')

def load_network_dataset():
    """Load and validate network dataset"""
    try:
        network_df = pd.read_csv(f'{DATASET_BASE_PATH}/network/network_anomalies.csv')
        required_cols = ['avg_packet_size', 'connection_count', 'duration_seconds', 'failed_connections']
        if not all(col in network_df.columns for col in required_cols):
            raise ValueError(f"Network dataset missing required columns: {required_cols}")
        logging.info("Network dataset loaded successfully")
        return network_df
    except Exception as e:
        logging.error(f"Error loading network dataset: {e}")
        raise

def train_one_class_svm():
    """Train OneClassSVM for anomaly detection"""
    logging.info("Starting OneClassSVM training")

    network_df = load_network_dataset()

    # Use the features
    X = network_df[['avg_packet_size', 'connection_count', 'duration_seconds', 'failed_connections']].values

    # Train
    ocsvm = OneClassSVM(kernel='rbf', nu=0.1)  # nu is upper bound on fraction of outliers
    ocsvm.fit(X)

    # Save
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    joblib.dump(ocsvm, f'{MODEL_STORAGE_PATH}/one_class_svm.pkl')

    logging.info("OneClassSVM model trained and saved successfully")

if __name__ == "__main__":
    train_one_class_svm()