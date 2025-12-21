import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
import joblib
import os
import time
from utils import setup_logging, TrainingTimer, calculate_classification_metrics, save_metrics, plot_confusion_matrix, plot_training_time, generate_report

# Paths from env or defaults
MODEL_STORAGE_PATH = os.getenv('MODEL_STORAGE_PATH', 'models')
DATASET_BASE_PATH = os.getenv('DATASET_BASE_PATH', 'datasets')

def load_datasets(logger):
    """Load and validate datasets"""
    datasets = {}
    try:
        url_df = pd.read_csv(f'{DATASET_BASE_PATH}/url/malicious_url.csv')
        if 'status' not in url_df.columns:
            raise ValueError("URL dataset missing 'status' column")
        url_df['is_malicious'] = url_df['status']
        url_df = url_df.drop('status', axis=1)
        datasets['url'] = url_df

        ip_df = pd.read_csv(f'{DATASET_BASE_PATH}/ip/malicious_ips.csv')
        if 'is_malicious' not in ip_df.columns:
            raise ValueError("IP dataset missing 'is_malicious' column")
        datasets['ip'] = ip_df

        domain_df = pd.read_csv(f'{DATASET_BASE_PATH}/domain/malicious_domains.csv')
        if 'is_malicious' not in domain_df.columns:
            raise ValueError("Domain dataset missing 'is_malicious' column")
        datasets['domain'] = domain_df

        hash_df = pd.read_csv(f'{DATASET_BASE_PATH}/hash/malware_hashes.csv')
        if 'is_malicious' not in hash_df.columns:
            raise ValueError("Hash dataset missing 'is_malicious' column")
        datasets['hash'] = hash_df

        logger.info("Datasets loaded successfully")
        return datasets
    except Exception as e:
        logger.error(f"Error loading datasets: {e}")
        raise

def engineer_features(df, name):
    """Feature engineering for each dataset"""
    if name == 'url':
        df['url_length'] = df['url'].apply(len)
        df['num_dots'] = df['url'].apply(lambda x: x.count('.'))
        df['has_https'] = df['url'].apply(lambda x: 1 if 'https' in x else 0)
        df['has_http'] = df['url'].apply(lambda x: 1 if 'http' in x else 0)
        df = df.drop('url', axis=1)
    elif name == 'ip':
        ip_parts = df['ip'].str.split('.', expand=True).astype(float)
        df = pd.concat([df, ip_parts], axis=1)
        df = df.drop('ip', axis=1)
        df = df.drop(['risk_score', 'source'], axis=1, errors='ignore')
    elif name == 'domain':
        df['domain_length'] = df['domain'].apply(len)
        df['num_dots'] = df['domain'].apply(lambda x: x.count('.'))
        df = df.drop('domain', axis=1)
        df = df.drop(['risk_score', 'source'], axis=1, errors='ignore')
    elif name == 'hash':
        df['hash_length'] = df['hash'].apply(len)
        le = LabelEncoder()
        df['hash_type_encoded'] = le.fit_transform(df['hash_type'])
        df = df.drop(['hash', 'hash_type', 'risk_score', 'source'], axis=1, errors='ignore')
    return df

def train_ensemble_threat_model():
    """Train Ensemble model using VotingClassifier with RF and LR"""
    logger = setup_logging('train_ensemble')
    timer = TrainingTimer(logger)

    timer.start()
    logger.info("Starting Ensemble Threat Model training")

    datasets = load_datasets(logger)

    # Process each dataset
    processed_dfs = []
    for name in ['url', 'ip', 'domain', 'hash']:
        df = engineer_features(datasets[name], name)
        processed_dfs.append(df)
        logger.info(f"Processed {name} dataset")

    # Combine
    combined_df = pd.concat(processed_dfs, ignore_index=True)
    logger.info("Datasets combined")

    # Prepare data
    X = combined_df.drop('is_malicious', axis=1)
    y = combined_df['is_malicious']

    # Handle missing values
    X = X.fillna(0)

    # Convert column names to strings
    X.columns = X.columns.astype(str)

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    logger.info("Data scaled")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # Define base models
    rf = RandomForestClassifier(random_state=42, n_estimators=100)
    lr = LogisticRegression(random_state=42, max_iter=1000)

    # Ensemble
    ensemble = VotingClassifier(estimators=[('rf', rf), ('lr', lr)], voting='soft')
    ensemble.fit(X_train, y_train)
    timer.log_progress("Ensemble model trained")

    # Predict on test
    y_pred = ensemble.predict(X_test)

    # Metrics
    metrics = calculate_classification_metrics(y_test, y_pred, logger)
    metrics['training_duration'] = timer.elapsed()

    # Save metrics
    save_metrics(metrics, 'train_ensemble')

    # Plots
    plot_confusion_matrix(np.array(metrics['confusion_matrix']), 'train_ensemble')
    plot_training_time(timer.elapsed(), 'train_ensemble')

    # Save model
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    model_path = f'{MODEL_STORAGE_PATH}/ensemble_threat_model.pkl'
    joblib.dump(ensemble, model_path)

    # Report
    end_time = time.time()
    start_time = timer.start_time
    graph_paths = [
        'training_artifacts/graphs/individual/train_ensemble_confusion_matrix.png',
        'training_artifacts/graphs/individual/train_ensemble_training_time.png'
    ]
    generate_report('train_ensemble', 'VotingClassifier', ['url', 'ip', 'domain', 'hash'], time.ctime(start_time), time.ctime(end_time), timer.elapsed(), metrics, model_path, graph_paths)

    logger.info("Ensemble Threat Model trained and saved successfully")

if __name__ == "__main__":
    train_ensemble_threat_model()