import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Paths from env or defaults
MODEL_STORAGE_PATH = os.getenv('MODEL_STORAGE_PATH', 'backend/models')
DATASET_BASE_PATH = os.getenv('DATASET_BASE_PATH', 'backend/datasets')

def load_datasets():
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

        logging.info("Datasets loaded successfully")
        return datasets
    except Exception as e:
        logging.error(f"Error loading datasets: {e}")
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

def train_random_forest():
    """Train RandomForestClassifier"""
    logging.info("Starting RandomForest training")

    datasets = load_datasets()

    # Process each dataset
    processed_dfs = []
    for name in ['url', 'ip', 'domain', 'hash']:
        df = engineer_features(datasets[name], name)
        processed_dfs.append(df)

    # Combine
    combined_df = pd.concat(processed_dfs, ignore_index=True)

    # Prepare data
    X = combined_df.drop('is_malicious', axis=1)
    y = combined_df['is_malicious']

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # Train
    rf = RandomForestClassifier(random_state=42, n_estimators=100)
    rf.fit(X_train, y_train)

    # Save
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    joblib.dump(rf, f'{MODEL_STORAGE_PATH}/random_forest.pkl')

    logging.info("RandomForest model trained and saved successfully")

if __name__ == "__main__":
    train_random_forest()