"""
ENHANCED IP MODEL TRAINING
==========================
Production-grade IP address risk scoring with robust validation
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report, roc_auc_score
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import os
import time
import warnings
import socket
import struct
import ipaddress
warnings.filterwarnings('ignore')

# Import from your utils
from utils import setup_logging, TrainingTimer, calculate_classification_metrics, save_metrics, plot_confusion_matrix, plot_training_time, generate_report

# Paths
MODEL_STORAGE_PATH = os.getenv('MODEL_STORAGE_PATH', 'models')
DATASET_BASE_PATH = os.getenv('DATASET_BASE_PATH', 'datasets')

def load_ip_dataset(logger):
    """Load and validate IP dataset with dataset extension"""
    try:
        df = pd.read_csv(f'{DATASET_BASE_PATH}/ip/malicious_ips.csv')
        
        # Validate required columns
        required_columns = ['ip', 'is_malicious']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Dataset missing required column: {col}")
        
        # Remove duplicates
        initial_count = len(df)
        df = df.drop_duplicates(subset=['ip'])
        final_count = len(df)
        logger.info(f"Removed {initial_count - final_count} duplicate IPs.")
        
        logger.info(f"IP dataset loaded successfully. Shape: {df.shape}")
        
        # Detailed class analysis
        class_dist = df['is_malicious'].value_counts()
        logger.info(f"Class distribution:\n{class_dist}")
        logger.info(f"Benign IPs: {class_dist.get(0, 0)} ({class_dist.get(0, 0)/len(df)*100:.1f}%)")
        logger.info(f"Malicious IPs: {class_dist.get(1, 0)} ({class_dist.get(1, 0)/len(df)*100:.1f}%)")
        
        # If dataset is too small, extend it
        if len(df) < 1000:
            logger.info("Dataset is small. Extending with synthetic data...")
            df = extend_ip_dataset(df, logger, target_size=2000)
        
        return df
    except Exception as e:
        logger.error(f"Error loading IP dataset: {e}")
        raise

def extend_ip_dataset(df, logger, target_size=2000):
    """Extend IP dataset with realistic synthetic data"""
    logger.info("Generating synthetic IP data for better model generalization...")
    
    synthetic_ips = []
    
    # Generate realistic IP ranges
    ip_ranges = [
        # Known malicious IP ranges (from threat intelligence)
        ('5.188.86.0', '5.188.86.255', 0.8),  # Malicious C2
        ('45.9.148.0', '45.9.148.255', 0.85),  # Spam
        ('185.220.101.0', '185.220.101.255', 0.9),  # Tor exit
        ('91.199.112.0', '91.199.112.255', 0.75),  # Scanner
        
        # Benign IP ranges
        ('8.8.8.0', '8.8.8.255', 0.1),  # Google DNS
        ('1.1.1.0', '1.1.1.255', 0.05),  # Cloudflare
        ('208.67.222.0', '208.67.222.255', 0.1),  # OpenDNS
        ('74.125.0.0', '74.125.255.255', 0.15),  # Google
        
        # Mixed ranges
        ('192.168.0.0', '192.168.255.255', 0.3),  # Private - mostly benign
        ('10.0.0.0', '10.255.255.255', 0.25),  # Private
        ('172.16.0.0', '172.31.255.255', 0.2),  # Private
        
        # IoT ranges (mixed)
        ('192.0.2.0', '192.0.2.255', 0.6),  # Test - often abused
        ('203.0.113.0', '203.0.113.255', 0.55),  # Test
        ('198.51.100.0', '198.51.100.255', 0.5),  # Test
    ]
    
    sources = ['abuseipdb', 'otx', 'internal_analysis', 'virustotal', 'alienvault', 'shodan']
    
    for ip_start, ip_end, malicious_ratio in ip_ranges:
        start_int = int(ipaddress.IPv4Address(ip_start))
        end_int = int(ipaddress.IPv4Address(ip_end))

        # Generate multiple IPs from this range
        num_ips = min(50, (target_size - len(df) - len(synthetic_ips)) // len(ip_ranges))

        for _ in range(num_ips):
            ip_int = np.random.randint(start_int, end_int, dtype=np.uint32)
            ip_str = str(ipaddress.IPv4Address(int(ip_int)))
            
            # Determine if malicious based on ratio
            is_malicious = 1 if np.random.random() < malicious_ratio else 0
            
            # Generate realistic risk score
            if is_malicious:
                risk_score = np.random.uniform(0.6, 1.0)
            else:
                risk_score = np.random.uniform(0.0, 0.4)
            
            source = np.random.choice(sources)
            
            synthetic_ips.append({
                'ip': ip_str,
                'is_malicious': is_malicious,
                'risk_score': round(risk_score, 2),
                'source': source
            })
    
    # Add specific malicious patterns
    malicious_patterns = [
        # DDoS botnets
        ('185.143.223.', 1, 0.95, 'ddos_tracker'),
        ('23.129.64.', 1, 0.9, 'ddos_tracker'),
        ('5.188.210.', 1, 0.85, 'malware_c2'),
        
        # Cryptominers
        ('95.179.168.', 1, 0.8, 'mining_pool'),
        ('144.76.239.', 1, 0.75, 'mining_pool'),
        
        # Benign CDNs
        ('104.16.', 0, 0.1, 'cloudflare'),
        ('151.101.', 0, 0.05, 'fastly'),
        ('13.107.', 0, 0.08, 'microsoft'),
    ]
    
    for pattern, is_malicious, base_risk, source in malicious_patterns:
        num_pattern_ips = 20
        for i in range(num_pattern_ips):
            last_octet = np.random.randint(1, 254)
            ip_str = f"{pattern}{last_octet}"
            
            # Add some randomness
            risk_variation = np.random.uniform(-0.1, 0.1)
            risk_score = max(0, min(1, base_risk + risk_variation))
            
            synthetic_ips.append({
                'ip': ip_str,
                'is_malicious': is_malicious,
                'risk_score': round(risk_score, 2),
                'source': source
            })
    
    # Create DataFrame
    synthetic_df = pd.DataFrame(synthetic_ips)
    
    # Combine with original
    extended_df = pd.concat([df, synthetic_df], ignore_index=True)
    
    # Remove duplicates again
    extended_df = extended_df.drop_duplicates(subset=['ip'])
    
    logger.info(f"Extended dataset from {len(df)} to {len(extended_df)} rows")
    logger.info(f"Final class distribution: {extended_df['is_malicious'].value_counts().to_dict()}")
    
    return extended_df

def ip_to_int(ip):
    """Convert IP address to integer"""
    try:
        return int(ipaddress.IPv4Address(ip))
    except:
        return 0

def engineer_features(df, logger):
    """Feature engineering for IP addresses - REALISTIC features"""
    logger.info("Starting IP feature engineering...")
    
    original_count = len(df)
    
    # Remove invalid IPs
    def is_valid_ip(ip_str):
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except:
            return False
    
    df = df[df['ip'].apply(is_valid_ip)]
    logger.info(f"Removed {original_count - len(df)} invalid IPs")
    
    # Remove risk_score and source columns to prevent data leakage
    columns_to_drop = ['risk_score', 'source']
    for col in columns_to_drop:
        if col in df.columns:
            df = df.drop(col, axis=1)
            logger.info(f"Removed '{col}' column to prevent data leakage")
    
    # 1. BASIC OCTET FEATURES
    octets = df['ip'].str.split('.', expand=True).astype(float)
    df = pd.concat([df, octets], axis=1)
    
    df = df.rename(columns={0: 'octet1', 1: 'octet2', 2: 'octet3', 3: 'octet4'})
    
    # 2. IP AS INTEGER
    df['ip_int'] = df['ip'].apply(ip_to_int)
    
    # 3. NETWORK CLASS AND CATEGORIES
    def get_ip_class(octet1):
        if octet1 <= 127:
            return 'A'
        elif octet1 <= 191:
            return 'B'
        elif octet1 <= 223:
            return 'C'
        elif octet1 <= 239:
            return 'D'
        else:
            return 'E'
    
    df['ip_class'] = df['octet1'].apply(get_ip_class)
    df['is_class_a'] = (df['octet1'] <= 127).astype(int)
    df['is_class_b'] = ((df['octet1'] >= 128) & (df['octet1'] <= 191)).astype(int)
    df['is_class_c'] = ((df['octet1'] >= 192) & (df['octet1'] <= 223)).astype(int)
    
    # 4. PRIVATE IP RANGES (RFC 1918)
    df['is_private'] = (
        ((df['octet1'] == 10) |
         ((df['octet1'] == 172) & (df['octet2'] >= 16) & (df['octet2'] <= 31)) |
         ((df['octet1'] == 192) & (df['octet2'] == 168)))
    ).astype(int)
    
    # 5. RESERVED AND SPECIAL RANGES
    df['is_loopback'] = (df['octet1'] == 127).astype(int)
    df['is_link_local'] = ((df['octet1'] == 169) & (df['octet2'] == 254)).astype(int)
    df['is_multicast'] = ((df['octet1'] >= 224) & (df['octet1'] <= 239)).astype(int)
    df['is_reserved'] = ((df['octet1'] >= 240) & (df['octet1'] <= 255)).astype(int)
    
    # 6. DOCUMENTATION/TEST RANGES (RFC 5737)
    df['is_test_net'] = (
        ((df['octet1'] == 192) & (df['octet2'] == 0) & (df['octet3'] == 2)) |  # 192.0.2.0/24
        ((df['octet1'] == 198) & (df['octet2'] == 51) & (df['octet3'] == 100)) |  # 198.51.100.0/24
        ((df['octet1'] == 203) & (df['octet2'] == 0) & (df['octet3'] == 113))  # 203.0.113.0/24
    ).astype(int)
    
    # 7. OCTET PATTERNS AND DISTRIBUTION
    df['octet_sum'] = df['octet1'] + df['octet2'] + df['octet3'] + df['octet4']
    df['octet_mean'] = df['octet_sum'] / 4
    df['octet_std'] = df[['octet1', 'octet2', 'octet3', 'octet4']].std(axis=1)
    
    # 8. BITWISE FEATURES
    df['octet1_high_bit'] = (df['octet1'] >= 128).astype(int)
    df['octet4_low_bit'] = (df['octet4'] < 128).astype(int)
    
    # 9. REPETITION AND PATTERN DETECTION
    df['octets_equal'] = ((df['octet1'] == df['octet2']) & 
                          (df['octet2'] == df['octet3']) & 
                          (df['octet3'] == df['octet4'])).astype(int)
    
    df['has_consecutive_octets'] = (
        (df['octet1'] + 1 == df['octet2']) |
        (df['octet2'] + 1 == df['octet3']) |
        (df['octet3'] + 1 == df['octet4'])
    ).astype(int)
    
    # 10. SUSPICIOUS OCTET VALUES
    df['has_zero_octet'] = ((df['octet1'] == 0) | 
                           (df['octet2'] == 0) | 
                           (df['octet3'] == 0) | 
                           (df['octet4'] == 0)).astype(int)
    
    df['has_255_octet'] = ((df['octet1'] == 255) | 
                          (df['octet2'] == 255) | 
                          (df['octet3'] == 255) | 
                          (df['octet4'] == 255)).astype(int)
    
    # 11. COMMON MALICIOUS PATTERNS
    # Common in botnets: ending in .1, .254, etc.
    common_malicious_ends = [1, 254, 100, 200, 66, 88, 99]
    df['has_suspicious_end'] = df['octet4'].isin(common_malicious_ends).astype(int)
    
    # 12. OCTET ENTROPY (randomness measure)
    def calculate_octet_entropy(row):
        octets = [row['octet1'], row['octet2'], row['octet3'], row['octet4']]
        values, counts = np.unique(octets, return_counts=True)
        probs = counts / len(octets)
        return -np.sum(probs * np.log2(probs))
    
    df['octet_entropy'] = df.apply(calculate_octet_entropy, axis=1)
    
    # 13. IP GEOGRAPHICAL HINTS (based on first octet)
    # Common regions for malicious IPs
    df['is_european_range'] = ((df['octet1'] >= 77) & (df['octet1'] <= 95)).astype(int)
    df['is_asian_range'] = ((df['octet1'] >= 58) & (df['octet1'] <= 61)).astype(int)
    df['is_american_range'] = ((df['octet1'] >= 3) & (df['octet1'] <= 56)).astype(int)
    
    # 14. BINARY PATTERN FEATURES
    df['octet1_binary_ones'] = df['octet1'].apply(lambda x: bin(int(x)).count('1'))
    df['octet4_binary_ones'] = df['octet4'].apply(lambda x: bin(int(x)).count('1'))
    
    # 15. OCTET RATIOS AND DIFFERENCES
    df['octet_ratio_1_4'] = df.apply(
        lambda row: row['octet1'] / row['octet4'] if row['octet4'] > 0 else 0, axis=1
    )
    df['octet_diff_1_4'] = abs(df['octet1'] - df['octet4'])
    
    # 16. SEQUENTIAL PATTERNS
    df['is_sequential_up'] = (
        (df['octet1'] < df['octet2']) & 
        (df['octet2'] < df['octet3']) & 
        (df['octet3'] < df['octet4'])
    ).astype(int)
    
    df['is_sequential_down'] = (
        (df['octet1'] > df['octet2']) & 
        (df['octet2'] > df['octet3']) & 
        (df['octet3'] > df['octet4'])
    ).astype(int)
    
    # 17. NETWORK BOUNDARY DETECTION
    df['is_network_boundary'] = (
        (df['octet4'] == 0) |  # Network address
        (df['octet4'] == 255) |  # Broadcast
        (df['octet4'] == 1) |  # Common gateway
        (df['octet4'] == 254)  # Common gateway
    ).astype(int)
    
    # DROP ORIGINAL IP COLUMN
    df = df.drop('ip', axis=1)
    
    # Also drop the string IP class column for now (we have dummy variables)
    if 'ip_class' in df.columns:
        df = df.drop('ip_class', axis=1)
    
    logger.info(f"Feature engineering completed. Total features: {df.shape[1]}")
    logger.info(f"Feature columns: {list(df.columns)}")
    
    # Check for any NaN values
    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        logger.warning(f"Found {nan_count} NaN values in features. Filling with 0.")
        df = df.fillna(0)
    
    return df

def validate_model_performance(y_true, y_pred, y_prob, logger):
    """Comprehensive model performance validation"""
    logger.info("\n" + "=" * 60)
    logger.info("COMPREHENSIVE MODEL VALIDATION")
    logger.info("=" * 60)
    
    # Basic metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall: {recall:.4f}")
    logger.info(f"F1-Score: {f1:.4f}")
    
    # Check for overfitting indicators
    if accuracy > 0.98:
        logger.warning("⚠️  HIGH ACCURACY WARNING: Model accuracy > 98% - potential overfitting!")
        logger.warning("   This may indicate data leakage or unrealistic dataset separation.")
    
    if precision == 1.0 and recall == 1.0:
        logger.warning("⚠️  PERFECT SCORES WARNING: Precision and recall both at 100%")
        logger.warning("   This is extremely rare in real-world cybersecurity applications.")
    
    # ROC-AUC if probabilities are available
    if y_prob is not None and len(y_prob.shape) > 1:
        try:
            roc_auc = roc_auc_score(y_true, y_prob[:, 1])
            logger.info(f"ROC-AUC Score: {roc_auc:.4f}")
        except:
            logger.info("ROC-AUC Score: Not available")
    
    # Confusion matrix analysis
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    logger.info(f"\nConfusion Matrix Details:")
    logger.info(f"True Negatives:  {tn}")
    logger.info(f"False Positives: {fp}")
    logger.info(f"False Negatives: {fn}")
    logger.info(f"True Positives:  {tp}")
    
    # Calculate rates
    if tn + fp > 0:
        fpr = fp / (tn + fp)
        logger.info(f"False Positive Rate: {fpr:.4f}")
    
    if tp + fn > 0:
        fnr = fn / (tp + fn)
        logger.info(f"False Negative Rate: {fnr:.4f}")
    
    # Performance warnings
    if fp == 0 and fn == 0:
        logger.warning("⚠️  NO ERRORS DETECTED: Model made zero classification errors")
        logger.warning("   This is highly suspicious for this type of problem.")
    
    if fpr == 0:
        logger.warning("⚠️  ZERO FALSE POSITIVES: All benign IPs correctly classified")
        logger.warning("   Real-world models typically have some false positives.")
    
    if fnr == 0:
        logger.warning("⚠️  ZERO FALSE NEGATIVES: All malicious IPs detected")
        logger.warning("   This is unrealistic for IP classification.")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm,
        'true_negatives': tn,
        'false_positives': fp,
        'false_negatives': fn,
        'true_positives': tp
    }

def train_ip_model():
    """Train IP model with multiple algorithms and robust validation"""
    logger = setup_logging('train_ip')
    timer = TrainingTimer(logger)
    
    timer.start()
    logger.info("=" * 60)
    logger.info("STARTING IP MODEL TRAINING WITH ROBUST VALIDATION")
    logger.info("=" * 60)
    
    # Load and extend dataset
    df = load_ip_dataset(logger)
    
    # Engineer features (without data leakage)
    df = engineer_features(df, logger)
    
    # Final NaN check
    if df.isnull().any().any():
        logger.warning(f"Final NaN check: Found {df.isnull().sum().sum()} NaN values. Filling with 0.")
        df = df.fillna(0)
    
    # Prepare features and target
    X = df.drop('is_malicious', axis=1)
    y = df['is_malicious']
    
    logger.info(f"Final dataset shape - X: {X.shape}, y: {y.shape}")
    logger.info(f"Class distribution: {y.value_counts().to_dict()}")
    logger.info(f"Total features: {len(X.columns)}")
    
    # Ensure column names are strings
    X.columns = X.columns.astype(str)
    
    # Feature selection to reduce dimensionality
    logger.info("Performing feature selection...")
    selector = SelectKBest(f_classif, k=min(20, X.shape[1]))
    X_selected = selector.fit_transform(X, y)
    selected_features = X.columns[selector.get_support()].tolist()
    logger.info(f"Selected {len(selected_features)} features: {selected_features}")
    
    # Scale features
    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_selected)
    
    # Split data with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Additional validation split
    X_train_final, X_val, y_train_final, y_val = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
    )
    
    logger.info(f"\nData Split Summary:")
    logger.info(f"Train set (final): {X_train_final.shape[0]} samples")
    logger.info(f"Validation set: {X_val.shape[0]} samples")
    logger.info(f"Test set: {X_test.shape[0]} samples")
    logger.info(f"Total samples: {X_train_final.shape[0] + X_val.shape[0] + X_test.shape[0]}")
    
    # Calculate class weights
    class_weights = compute_class_weight('balanced', classes=np.unique(y_train_final), y=y_train_final)
    class_weight_dict = {0: class_weights[0], 1: class_weights[1]}
    logger.info(f"Class weights: {class_weight_dict}")
    
    # Define models with regularization to prevent overfitting
    models = {
        'logistic_regression': {
            'model': LogisticRegression(random_state=42, max_iter=2000, class_weight='balanced'),
            'params': {
                'C': [0.001, 0.01, 0.1, 1, 10],
                'penalty': ['l2'],
                'solver': ['lbfgs', 'saga'],
                'max_iter': [2000]
            }
        },
        'random_forest': {
            'model': RandomForestClassifier(random_state=42, n_estimators=100, class_weight='balanced_subsample'),
            'params': {
                'n_estimators': [50, 100, 150],
                'max_depth': [5, 10, 15, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'max_features': ['sqrt', 'log2', 0.3, 0.5],
                'bootstrap': [True, False]
            }
        },
        'gradient_boosting': {
            'model': GradientBoostingClassifier(random_state=42, n_estimators=100),
            'params': {
                'n_estimators': [50, 100, 150],
                'learning_rate': [0.001, 0.01, 0.05, 0.1],
                'max_depth': [3, 4, 5, 6],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'subsample': [0.7, 0.8, 0.9],
                'max_features': ['sqrt', 'log2', None]
            }
        },
        'svc': {
            'model': SVC(random_state=42, probability=True, class_weight='balanced', max_iter=100000),
            'params': {
                'C': [0.1, 1, 10, 100],
                'kernel': ['linear', 'rbf'],
                'gamma': ['scale', 'auto', 0.001, 0.01, 0.1],
                'max_iter': [100000],
                'tol': [1e-4, 1e-3]
            }
        }
    }
    
    best_model = None
    best_accuracy = 0
    best_name = ''
    best_params = None
    model_results = {}
    
    logger.info("\n" + "=" * 60)
    logger.info("STARTING MODEL TRAINING WITH 10-FOLD CROSS VALIDATION")
    logger.info("=" * 60)
    
    # Use Stratified K-Fold for better validation
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    
    for name, config in models.items():
        logger.info(f"\nTraining {name}...")
        
        try:
            # Perform cross-validation
            cv_scores = cross_val_score(
                config['model'], X_train_final, y_train_final, 
                cv=cv, scoring='f1', n_jobs=-1
            )
            logger.info(f"  Cross-validation F1 scores (10-fold): Mean={cv_scores.mean():.4f}, Std={cv_scores.std():.4f}")
            
            # Grid search with more conservative settings
            grid = GridSearchCV(
                config['model'], 
                config['params'], 
                cv=5, 
                scoring='f1',
                n_jobs=-1,
                verbose=0,
                error_score='raise'
            )
            
            grid.fit(X_train_final, y_train_final)
            
            # Validation set evaluation
            y_pred_val = grid.predict(X_val)
            val_acc = accuracy_score(y_val, y_pred_val)
            val_f1 = f1_score(y_val, y_pred_val, zero_division=0)
            
            # Test set evaluation
            y_pred_test = grid.predict(X_test)
            test_acc = accuracy_score(y_test, y_pred_test)
            
            # Get probabilities for ROC-AUC
            y_prob_test = None
            if hasattr(grid.best_estimator_, 'predict_proba'):
                y_prob_test = grid.best_estimator_.predict_proba(X_test)
            
            # Calculate metrics
            precision = precision_score(y_test, y_pred_test, zero_division=0)
            recall = recall_score(y_test, y_pred_test, zero_division=0)
            f1 = f1_score(y_test, y_pred_test, zero_division=0)
            
            model_results[name] = {
                'train_accuracy': grid.score(X_train_final, y_train_final),
                'validation_accuracy': val_acc,
                'validation_f1': val_f1,
                'test_accuracy': test_acc,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'best_params': grid.best_params_,
                'cv_mean_f1': cv_scores.mean(),
                'cv_std_f1': cv_scores.std()
            }
            
            logger.info(f"{name} Results:")
            logger.info(f"  Best Parameters: {grid.best_params_}")
            logger.info(f"  Training Accuracy: {model_results[name]['train_accuracy']:.4f}")
            logger.info(f"  Validation Accuracy: {val_acc:.4f} (F1: {val_f1:.4f})")
            logger.info(f"  Testing Accuracy: {test_acc:.4f}")
            logger.info(f"  Precision: {precision:.4f}")
            logger.info(f"  Recall: {recall:.4f}")
            logger.info(f"  F1-Score: {f1:.4f}")
            
            # Check for overfitting
            train_test_diff = model_results[name]['train_accuracy'] - test_acc
            if train_test_diff > 0.1:
                logger.warning(f"  ⚠️  Potential overfitting: Train-Test difference = {train_test_diff:.4f}")
            
            # Select best model based on validation F1 score
            if val_f1 > best_accuracy:
                best_accuracy = val_f1
                best_model = grid.best_estimator_
                best_name = name
                best_params = grid.best_params_
                logger.info(f"  *** New Best Model! (Validation F1: {val_f1:.4f}) ***")
                
        except Exception as e:
            logger.error(f"Error training {name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            continue
    
    logger.info("\n" + "=" * 60)
    logger.info("MODEL PERFORMANCE SUMMARY")
    logger.info("=" * 60)
    
    # Display all model results
    for name, results in model_results.items():
        logger.info(f"{name.upper():25} Val F1: {results['validation_f1']:.4f} | "
                   f"Test Acc: {results['test_accuracy']:.4f} | "
                   f"Precision: {results['precision']:.4f} | "
                   f"Recall: {results['recall']:.4f} | "
                   f"F1: {results['f1']:.4f}")
    
    logger.info(f"\nBest model: {best_name}")
    logger.info(f"Best validation F1: {best_accuracy:.4f}")
    logger.info(f"Best parameters: {best_params}")
    
    # Comprehensive final evaluation
    logger.info("\n" + "=" * 60)
    logger.info("FINAL COMPREHENSIVE EVALUATION")
    logger.info("=" * 60)
    
    # Predict on test set
    y_pred = best_model.predict(X_test)
    y_prob = None
    if hasattr(best_model, 'predict_proba'):
        y_prob = best_model.predict_proba(X_test)
    
    # Detailed classification report
    report = classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'])
    logger.info(f"\nClassification Report:\n{report}")
    
    # Comprehensive validation
    metrics = validate_model_performance(y_test, y_pred, y_prob, logger)
    
    # Add additional metrics
    metrics['training_duration'] = timer.elapsed()
    metrics['best_model'] = best_name
    metrics['best_parameters'] = str(best_params)
    metrics['selected_features'] = selected_features
    metrics['feature_importance'] = {}
    
    # Get feature importance if available
    if hasattr(best_model, 'feature_importances_'):
        importances = best_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        logger.info("\nFeature Importance (Top 10):")
        for i in range(min(10, len(importances))):
            feature_name = selected_features[indices[i]] if i < len(selected_features) else f"Feature_{indices[i]}"
            importance_value = importances[indices[i]]
            logger.info(f"  {i+1:2}. {feature_name:30}: {importance_value:.4f}")
            metrics['feature_importance'][feature_name] = float(importance_value)
    
    # Save metrics
    save_metrics(metrics, 'train_ip')
    
    # Plot results
    plot_confusion_matrix(metrics['confusion_matrix'], 'train_ip')
    plot_training_time(timer.elapsed(), 'train_ip')
    
    # Save model, scaler, selector, and feature names
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    model_path = f'{MODEL_STORAGE_PATH}/ip_model.pkl'
    scaler_path = f'{MODEL_STORAGE_PATH}/scaler_ip.pkl'
    selector_path = f'{MODEL_STORAGE_PATH}/selector_ip.pkl'
    feature_names_path = f'{MODEL_STORAGE_PATH}/ip_feature_names.pkl'
    
    joblib.dump(best_model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(selector, selector_path)
    joblib.dump(selected_features, feature_names_path)
    
    logger.info(f"\nModel saved to: {model_path}")
    logger.info(f"Scaler saved to: {scaler_path}")
    logger.info(f"Feature selector saved to: {selector_path}")
    logger.info(f"Selected feature names saved to: {feature_names_path}")
    
    # Generate comprehensive report
    end_time = time.time()
    start_time = timer.start_time
    graph_paths = [
        'training_artifacts/graphs/individual/train_ip_confusion_matrix.png',
        'training_artifacts/graphs/individual/train_ip_training_time.png'
    ]
    
    generate_report(
        'train_ip', 
        best_name, 
        selected_features, 
        time.ctime(start_time), 
        time.ctime(end_time), 
        timer.elapsed(), 
        metrics, 
        model_path, 
        graph_paths
    )
    
    logger.info("\n" + "=" * 60)
    logger.info("TRAINING COMPLETED WITH ROBUST VALIDATION")
    logger.info(f"Total training time: {timer.elapsed():.2f} seconds")
    logger.info("=" * 60)
    
    # Final recommendations
    logger.info("\n" + "=" * 60)
    logger.info("RECOMMENDATIONS FOR PRODUCTION USE")
    logger.info("=" * 60)
    logger.info("1. Monitor false positive rate in production")
    logger.info("2. Regularly update training data with new threat intelligence")
    logger.info("3. Consider ensemble methods for better generalization")
    logger.info("4. Implement a confidence threshold for predictions (e.g., >0.7 for malicious)")
    logger.info("5. Track model drift over time and retrain monthly")
    logger.info("6. Combine with reputation feeds for better coverage")
    
    return best_model, scaler, metrics

if __name__ == "__main__":
    train_ip_model()