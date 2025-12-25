"""
PRODUCTION NETWORK ANOMALY DETECTION MODEL
==========================================
Minimal features, maximum performance
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
warnings.filterwarnings('ignore')

# Import from your utils
from utils import setup_logging, TrainingTimer, calculate_classification_metrics, save_metrics, plot_confusion_matrix, plot_training_time, generate_report

# Paths
MODEL_STORAGE_PATH = os.getenv('MODEL_STORAGE_PATH', 'models')
DATASET_BASE_PATH = os.getenv('DATASET_BASE_PATH', 'datasets')

def load_network_dataset(logger):
    """Load and validate Network dataset"""
    try:
        df = pd.read_csv(f'{DATASET_BASE_PATH}/network/network_anomalies.csv')
        
        # Validate required columns
        required_columns = ['packet_count', 'bytes_transferred', 'duration_seconds', 'connection_count', 'is_anomalous']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Dataset missing required column: {col}")
        
        # Rename target column for consistency
        df['is_malicious'] = df['is_anomalous']
        df = df.drop('is_anomalous', axis=1, errors='ignore')
        
        logger.info(f"Network dataset loaded successfully. Shape: {df.shape}")
        
        # Detailed class analysis
        class_dist = df['is_malicious'].value_counts()
        logger.info(f"Class distribution:\n{class_dist}")
        logger.info(f"Normal traffic: {class_dist.get(0, 0)} ({class_dist.get(0, 0)/len(df)*100:.1f}%)")
        logger.info(f"Anomalous traffic: {class_dist.get(1, 0)} ({class_dist.get(1, 0)/len(df)*100:.1f}%)")
        
        return df
    except Exception as e:
        logger.error(f"Error loading Network dataset: {e}")
        raise

def engineer_features(df, logger):
    """Essential feature engineering - minimal but powerful features"""
    logger.info("Starting essential feature engineering...")
    
    # 1. BASIC DERIVED FEATURES (MOST IMPORTANT)
    df['packets_per_second'] = df['packet_count'] / (df['duration_seconds'] + 0.001)
    df['bytes_per_second'] = df['bytes_transferred'] / (df['duration_seconds'] + 0.001)
    df['avg_packet_size'] = df['bytes_transferred'] / (df['packet_count'] + 0.001)
    
    # 2. CONNECTION INTENSITY FEATURES
    df['connections_per_second'] = df['connection_count'] / (df['duration_seconds'] + 0.001)
    
    # 3. FAILURE RATE (critical for detecting attacks)
    df['failed_connections'] = df.get('failed_connections', 0)
    df['failure_rate'] = df['failed_connections'] / (df['connection_count'] + 0.001)
    
    # 4. TRAFFIC DENSITY (packets per connection)
    df['packets_per_connection'] = df['packet_count'] / (df['connection_count'] + 0.001)
    
    # 5. BYTE EFFICIENCY (bytes per packet)
    df['bytes_per_packet'] = df['bytes_transferred'] / (df['packet_count'] + 0.001)
    
    # 6. TRAFFIC BURSTINESS (variance indicator)
    df['traffic_burstiness'] = df['packets_per_second'] * df['bytes_per_second'] / 1000
    
    # 7. SESSION DURATION CATEGORY (normalized)
    df['session_duration_norm'] = np.log1p(df['duration_seconds'])
    
    # 8. PACKET SIZE VARIABILITY (important for attack detection)
    df['packet_size_variability'] = df['avg_packet_size'] / (df['bytes_per_packet'] + 0.001)
    
    # 9. CONNECTION SUCCESS RATE
    df['success_rate'] = 1 - df['failure_rate']
    
    # 10. TRAFFIC INTENSITY SCORE (combined metric)
    df['traffic_intensity_score'] = (
        df['packets_per_second'] * df['bytes_per_second'] * df['connections_per_second']
    ) / 1000000
    
    logger.info(f"Feature engineering completed. Total features: {df.shape[1]}")
    logger.info(f"Feature columns: {list(df.columns)}")
    
    # Check for any NaN values
    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        logger.warning(f"Found {nan_count} NaN values in features. Filling with median.")
        for col in df.columns:
            if df[col].dtype in ['float64', 'int64']:
                df[col] = df[col].fillna(df[col].median())
    
    return df

def validate_model_performance(y_true, y_pred, y_prob, logger):
    """Comprehensive model performance validation"""
    logger.info("\n" + "=" * 60)
    logger.info("MODEL PERFORMANCE VALIDATION")
    logger.info("=" * 60)
    
    # Basic metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    logger.info(f"Accuracy:  {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall:    {recall:.4f}")
    logger.info(f"F1-Score:  {f1:.4f}")
    
    # ROC-AUC if probabilities are available
    if y_prob is not None and len(y_prob.shape) > 1:
        try:
            roc_auc = roc_auc_score(y_true, y_prob[:, 1])
            logger.info(f"ROC-AUC:   {roc_auc:.4f}")
        except:
            logger.info("ROC-AUC:   Not available")
    
    # Confusion matrix analysis
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    logger.info(f"\nConfusion Matrix:")
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
    
    # Realistic performance checks
    if fpr < 0.01:
        logger.warning("⚠️  Very low false positives - may indicate overfitting")
    if fnr < 0.01:
        logger.warning("⚠️  Very low false negatives - check data quality")
    
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

def train_network_model():
    """Train Network model with production-grade validation"""
    logger = setup_logging('train_network')
    timer = TrainingTimer(logger)
    
    timer.start()
    logger.info("=" * 60)
    logger.info("NETWORK ANOMALY DETECTION MODEL TRAINING")
    logger.info("=" * 60)
    
    # Load dataset
    df = load_network_dataset(logger)
    
    # Engineer essential features
    df = engineer_features(df, logger)
    
    # Final NaN check
    if df.isnull().any().any():
        logger.warning(f"Found {df.isnull().sum().sum()} NaN values. Filling with median.")
        for col in df.columns:
            if df[col].dtype in ['float64', 'int64']:
                df[col] = df[col].fillna(df[col].median())
    
    # Prepare features and target
    X = df.drop('is_malicious', axis=1)
    y = df['is_malicious']
    
    logger.info(f"\nDataset shape: X: {X.shape}, y: {y.shape}")
    logger.info(f"Class distribution: Normal={y.value_counts().get(0, 0)}, Anomalous={y.value_counts().get(1, 0)}")
    logger.info(f"Features: {list(X.columns)}")
    
    # Ensure column names are strings
    X.columns = X.columns.astype(str)
    
    # Select top 10 features (minimal but effective)
    logger.info("Selecting top features...")
    selector = SelectKBest(f_classif, k=min(10, X.shape[1]))
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
    
    logger.info(f"\nData Split:")
    logger.info(f"Training:   {X_train_final.shape[0]} samples")
    logger.info(f"Validation: {X_val.shape[0]} samples")
    logger.info(f"Testing:    {X_test.shape[0]} samples")
    
    # Calculate class weights
    class_weights = compute_class_weight('balanced', classes=np.unique(y_train_final), y=y_train_final)
    class_weight_dict = {0: class_weights[0], 1: class_weights[1]}
    logger.info(f"Class weights: {class_weight_dict}")
    
    # Define production models with optimal settings
    models = {
        'random_forest': {
            'model': RandomForestClassifier(random_state=42, n_estimators=200, class_weight='balanced'),
            'params': {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 15, 20],
                'min_samples_split': [2, 5],
                'min_samples_leaf': [1, 2],
                'max_features': ['sqrt', 'log2']
            }
        },
        'gradient_boosting': {
            'model': GradientBoostingClassifier(random_state=42, n_estimators=200),
            'params': {
                'n_estimators': [100, 200],
                'learning_rate': [0.01, 0.05, 0.1],
                'max_depth': [3, 4, 5],
                'min_samples_split': [2, 5],
                'subsample': [0.8, 0.9]
            }
        },
        'logistic_regression': {
            'model': LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced'),
            'params': {
                'C': [0.01, 0.1, 1, 10],
                'penalty': ['l2'],
                'solver': ['lbfgs', 'saga']
            }
        }
    }
    
    best_model = None
    best_score = 0
    best_name = ''
    best_params = None
    model_results = {}
    
    logger.info("\n" + "=" * 60)
    logger.info("MODEL TRAINING")
    logger.info("=" * 60)
    
    # Use Stratified K-Fold for robust validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    for name, config in models.items():
        logger.info(f"\nTraining {name}...")
        
        try:
            # Perform cross-validation
            cv_scores = cross_val_score(
                config['model'], X_train_final, y_train_final, 
                cv=cv, scoring='f1', n_jobs=-1
            )
            logger.info(f"  CV F1: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")
            
            # Grid search
            grid = GridSearchCV(
                config['model'], 
                config['params'], 
                cv=3, 
                scoring='f1',
                n_jobs=-1,
                verbose=0
            )
            
            grid.fit(X_train_final, y_train_final)
            
            # Validation set evaluation
            y_pred_val = grid.predict(X_val)
            val_f1 = f1_score(y_val, y_pred_val, zero_division=0)
            
            # Test set evaluation
            y_pred_test = grid.predict(X_test)
            test_acc = accuracy_score(y_test, y_pred_test)
            
            # Calculate all metrics
            precision = precision_score(y_test, y_pred_test, zero_division=0)
            recall = recall_score(y_test, y_pred_test, zero_division=0)
            f1 = f1_score(y_test, y_pred_test, zero_division=0)
            
            model_results[name] = {
                'train_accuracy': grid.score(X_train_final, y_train_final),
                'validation_f1': val_f1,
                'test_accuracy': test_acc,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'best_params': grid.best_params_,
                'cv_mean_f1': cv_scores.mean()
            }
            
            logger.info(f"  Validation F1: {val_f1:.4f}")
            logger.info(f"  Test Accuracy: {test_acc:.4f}")
            logger.info(f"  Test F1: {f1:.4f}")
            
            # Select best model based on validation F1
            if val_f1 > best_score:
                best_score = val_f1
                best_model = grid.best_estimator_
                best_name = name
                best_params = grid.best_params_
                logger.info(f"  ✓ New best model!")
                
        except Exception as e:
            logger.error(f"Error training {name}: {e}")
            continue
    
    # Model comparison
    logger.info("\n" + "=" * 60)
    logger.info("MODEL COMPARISON")
    logger.info("=" * 60)
    
    for name, results in model_results.items():
        logger.info(f"{name.upper():20} | F1: {results['f1']:.4f} | Acc: {results['test_accuracy']:.4f} | Prec: {results['precision']:.4f} | Rec: {results['recall']:.4f}")
    
    logger.info(f"\nBest model: {best_name}")
    logger.info(f"Best F1: {best_score:.4f}")
    logger.info(f"Parameters: {best_params}")
    
    # Final comprehensive evaluation
    logger.info("\n" + "=" * 60)
    logger.info("FINAL EVALUATION")
    logger.info("=" * 60)
    
    # Predict on test set
    y_pred = best_model.predict(X_test)
    y_prob = None
    if hasattr(best_model, 'predict_proba'):
        y_prob = best_model.predict_proba(X_test)
    
    # Detailed report
    report = classification_report(y_test, y_pred, target_names=['Normal', 'Anomalous'])
    logger.info(f"\nClassification Report:\n{report}")
    
    # Comprehensive validation
    metrics = validate_model_performance(y_test, y_pred, y_prob, logger)
    
    # Add metadata
    metrics['training_duration'] = timer.elapsed()
    metrics['best_model'] = best_name
    metrics['best_parameters'] = str(best_params)
    metrics['selected_features'] = selected_features
    
    # Feature importance if available
    if hasattr(best_model, 'feature_importances_'):
        importances = best_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        logger.info("\nTop Features:")
        for i in range(min(5, len(importances))):
            feature_name = selected_features[indices[i]] if i < len(selected_features) else f"Feature_{indices[i]}"
            importance_value = importances[indices[i]]
            logger.info(f"  {i+1}. {feature_name}: {importance_value:.4f}")
    
    # Save metrics
    save_metrics(metrics, 'train_network')
    
    # Plot results
    plot_confusion_matrix(metrics['confusion_matrix'], 'train_network')
    plot_training_time(timer.elapsed(), 'train_network')
    
    # Save model and artifacts
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    model_path = f'{MODEL_STORAGE_PATH}/network_model.pkl'
    scaler_path = f'{MODEL_STORAGE_PATH}/scaler_network.pkl'
    selector_path = f'{MODEL_STORAGE_PATH}/selector_network.pkl'
    feature_names_path = f'{MODEL_STORAGE_PATH}/network_feature_names.pkl'
    
    joblib.dump(best_model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(selector, selector_path)
    joblib.dump(selected_features, feature_names_path)
    
    logger.info(f"\nModel saved to: {model_path}")
    logger.info(f"Scaler saved to: {scaler_path}")
    
    # Generate report
    end_time = time.time()
    start_time = timer.start_time
    graph_paths = [
        'training_artifacts/graphs/individual/train_network_confusion_matrix.png',
        'training_artifacts/graphs/individual/train_network_training_time.png'
    ]
    
    generate_report(
        'train_network', 
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
    logger.info("TRAINING COMPLETE")
    logger.info(f"Total time: {timer.elapsed():.2f} seconds")
    logger.info("=" * 60)
    
    # Production recommendations
    logger.info("\nPRODUCTION RECOMMENDATIONS:")
    logger.info("1. Monitor F1 score and false positive rate")
    logger.info("2. Retrain weekly with new data")
    logger.info("3. Set alert threshold at 0.7 confidence")
    logger.info("4. Combine with rule-based detection")
    
    return best_model, scaler, metrics

if __name__ == "__main__":
    train_network_model()
