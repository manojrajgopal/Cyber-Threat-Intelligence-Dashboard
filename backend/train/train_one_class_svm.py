import pandas as pd
import numpy as np
from sklearn.svm import OneClassSVM
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

def train_one_class_svm():
    """Train OneClassSVM for anomaly detection"""
    logger = setup_logging('train_one_class_svm')
    timer = TrainingTimer(logger)

    timer.start()
    logger.info("Starting OneClassSVM training")

    network_df = load_network_dataset(logger)

    # Use the features
    X = network_df[['avg_packet_size', 'connection_count', 'duration_seconds', 'failed_connections']].values

    # Train
    ocsvm = OneClassSVM(kernel='rbf', nu=0.1)  # nu is upper bound on fraction of outliers
    ocsvm.fit(X)
    timer.log_progress("Model trained")

    # Scores
    scores = ocsvm.decision_function(X)

    # Metrics
    metrics = calculate_anomaly_metrics(scores, logger)
    metrics['training_duration'] = timer.elapsed()

    # Save metrics
    save_metrics(metrics, 'train_one_class_svm')

    # Plots
    plot_anomaly_scores(scores, 'train_one_class_svm')
    plot_training_time(timer.elapsed(), 'train_one_class_svm')

    # Save model
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    model_path = f'{MODEL_STORAGE_PATH}/one_class_svm.pkl'
    joblib.dump(ocsvm, model_path)

    # Report
    end_time = time.time()
    start_time = timer.start_time
    graph_paths = [
        'training_artifacts/graphs/individual/train_one_class_svm_anomaly_scores.png',
        'training_artifacts/graphs/individual/train_one_class_svm_training_time.png'
    ]
    generate_report('train_one_class_svm', 'OneClassSVM', ['network'], time.ctime(start_time), time.ctime(end_time), timer.elapsed(), metrics, model_path, graph_paths)

    logger.info("OneClassSVM model trained and saved successfully")

if __name__ == "__main__":
    train_one_class_svm()