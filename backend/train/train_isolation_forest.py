import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os
import time
from utils import setup_logging, TrainingTimer, calculate_anomaly_metrics, save_metrics, plot_anomaly_scores, plot_training_time, generate_report

# Paths from env or defaults
MODEL_STORAGE_PATH = os.getenv('MODEL_STORAGE_PATH', 'models')
DATASET_BASE_PATH = os.getenv('DATASET_BASE_PATH', 'datasets')

def load_network_dataset(logger):
    """Load and validate network dataset"""
    try:
        network_df = pd.read_csv(f'{DATASET_BASE_PATH}/network/network_anomalies.csv')
        required_cols = ['avg_packet_size', 'connection_count', 'duration_seconds', 'failed_connections']
        if not all(col in network_df.columns for col in required_cols):
            raise ValueError(f"Network dataset missing required columns: {required_cols}")
        logger.info("Network dataset loaded successfully")
        return network_df
    except Exception as e:
        logger.error(f"Error loading network dataset: {e}")
        raise

def train_isolation_forest():
    """Train IsolationForest for anomaly detection"""
    logger = setup_logging('train_isolation_forest')
    timer = TrainingTimer(logger)

    timer.start()
    logger.info("Starting IsolationForest training")

    network_df = load_network_dataset(logger)

    # Use the features
    X = network_df[['avg_packet_size', 'connection_count', 'duration_seconds', 'failed_connections']].values

    # Train
    iforest = IsolationForest(random_state=42, contamination=0.1)  # Assume 10% anomalies
    iforest.fit(X)
    timer.log_progress("Model trained")

    # Scores
    scores = iforest.decision_function(X)

    # Metrics
    metrics = calculate_anomaly_metrics(scores, logger)
    metrics['training_duration'] = timer.elapsed()

    # Save metrics
    save_metrics(metrics, 'train_isolation_forest')

    # Plots
    plot_anomaly_scores(scores, 'train_isolation_forest')
    plot_training_time(timer.elapsed(), 'train_isolation_forest')

    # Save model
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    model_path = f'{MODEL_STORAGE_PATH}/isolation_forest.pkl'
    joblib.dump(iforest, model_path)

    # Report
    end_time = time.time()
    start_time = timer.start_time
    graph_paths = [
        'training_artifacts/graphs/individual/train_isolation_forest_anomaly_scores.png',
        'training_artifacts/graphs/individual/train_isolation_forest_training_time.png'
    ]
    generate_report('train_isolation_forest', 'IsolationForest', ['network'], time.ctime(start_time), time.ctime(end_time), timer.elapsed(), metrics, model_path, graph_paths)

    logger.info("IsolationForest model trained and saved successfully")

if __name__ == "__main__":
    train_isolation_forest()