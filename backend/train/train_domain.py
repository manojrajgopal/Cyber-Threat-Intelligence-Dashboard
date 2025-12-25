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

def load_domain_dataset(logger):
    """Load and validate Domain dataset"""
    try:
        df = pd.read_csv(f'{DATASET_BASE_PATH}/domain/malicious_domains.csv')
        
        # Validate required columns
        required_columns = ['domain', 'is_malicious']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Dataset missing required column: {col}")
        
        # Remove duplicates
        initial_count = len(df)
        df = df.drop_duplicates(subset=['domain'])
        final_count = len(df)
        logger.info(f"Removed {initial_count - final_count} duplicate domains.")
        
        logger.info(f"Domain dataset loaded successfully. Shape: {df.shape}")
        
        # Detailed class analysis
        class_dist = df['is_malicious'].value_counts()
        logger.info(f"Class distribution:\n{class_dist}")
        logger.info(f"Benign domains: {class_dist.get(0, 0)} ({class_dist.get(0, 0)/len(df)*100:.1f}%)")
        logger.info(f"Malicious domains: {class_dist.get(1, 0)} ({class_dist.get(1, 0)/len(df)*100:.1f}%)")
        
        return df
    except Exception as e:
        logger.error(f"Error loading Domain dataset: {e}")
        raise

def engineer_features(df, logger):
    """Feature engineering for Domain - REALISTIC features"""
    logger.info("Starting feature engineering...")
    
    original_count = len(df)
    
    # Remove any domains that are too short or invalid
    df = df[df['domain'].apply(lambda x: isinstance(x, str) and len(x) > 3)]
    logger.info(f"Removed {original_count - len(df)} invalid/short domains")
    
    # Remove risk_score and source columns to prevent data leakage
    if 'risk_score' in df.columns:
        df = df.drop('risk_score', axis=1)
        logger.info("Removed 'risk_score' column to prevent data leakage")
    if 'source' in df.columns:
        df = df.drop('source', axis=1)
        logger.info("Removed 'source' column to prevent data leakage")
    
    # 1. BASIC STRUCTURAL FEATURES
    df['domain_length'] = df['domain'].apply(len)
    df['num_dots'] = df['domain'].apply(lambda x: x.count('.'))
    df['num_hyphens'] = df['domain'].apply(lambda x: x.count('-'))
    df['num_underscores'] = df['domain'].apply(lambda x: x.count('_'))
    
    # 2. CHARACTER COMPOSITION
    df['has_digits'] = df['domain'].apply(lambda x: 1 if any(c.isdigit() for c in x) else 0)
    df['digit_count'] = df['domain'].apply(lambda x: sum(c.isdigit() for c in x))
    df['letter_count'] = df['domain'].apply(lambda x: sum(c.isalpha() for c in x))
    df['vowel_count'] = df['domain'].apply(lambda x: sum(c.lower() in 'aeiou' for c in x))
    df['consonant_count'] = df['domain'].apply(lambda x: sum(c.lower() in 'bcdfghjklmnpqrstvwxyz' for c in x))
    
    # 3. TLD ANALYSIS - More realistic approach
    def extract_tld(domain):
        parts = domain.split('.')
        return parts[-1] if len(parts) > 1 else ''
    
    df['tld'] = df['domain'].apply(extract_tld)
    
    # Broader categories instead of strict lists
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'uk', 'de', 
                   'fr', 'jp', 'cn', 'ca', 'au', 'in', 'br', 'ru', 'it', 'es', 'nl']
    
    new_tlds = ['xyz', 'top', 'site', 'online', 'tech', 'shop', 'club', 'app', 'dev', 'ai']
    
    df['has_common_tld'] = df['tld'].apply(lambda x: 1 if x in common_tlds else 0)
    df['has_new_tld'] = df['tld'].apply(lambda x: 1 if x in new_tlds else 0)
    df['tld_length'] = df['tld'].apply(len)
    df['tld_is_numeric'] = df['tld'].apply(lambda x: 1 if x.isdigit() else 0)
    
    # 4. DOMAIN NAME ANALYSIS
    def get_name_without_tld(domain):
        parts = domain.split('.')
        return '.'.join(parts[:-1]) if len(parts) > 1 else domain
    
    df['name_without_tld'] = df['domain'].apply(get_name_without_tld)
    df['name_length'] = df['name_without_tld'].apply(len)
    
    # 5. PATTERN ANALYSIS
    # Check for numbers at beginning (often suspicious)
    def starts_with_digit(s):
        return 1 if s and s[0].isdigit() else 0
    
    df['starts_with_digit'] = df['name_without_tld'].apply(starts_with_digit)
    
    # Check for consecutive consonants
    def has_consecutive_consonants(s, n=4):
        s = s.lower()
        consonant_count = 0
        for char in s:
            if char in 'bcdfghjklmnpqrstvwxyz':
                consonant_count += 1
                if consonant_count >= n:
                    return 1
            else:
                consonant_count = 0
        return 0
    
    df['has_4plus_consonants'] = df['name_without_tld'].apply(lambda x: has_consecutive_consonants(x, 4))
    
    # Check for suspicious patterns (less strict)
    suspicious_patterns = ['login', 'secure', 'verify', 'account', 'banking', 'payment',
                          'free', 'gift', 'bonus', 'win', 'prize', 'click', 'download']
    
    df['has_suspicious_pattern'] = df['name_without_tld'].apply(
        lambda x: 1 if any(pattern in x.lower() for pattern in suspicious_patterns) else 0
    )
    
    # 6. ENTROPY (realistic calculation)
    def calculate_entropy(s):
        if len(s) <= 1:
            return 0
        s = s.lower()
        char_counts = {}
        for char in s:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        total_chars = len(s)
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * np.log2(probability)
        return entropy
    
    df['entropy'] = df['name_without_tld'].apply(calculate_entropy)
    
    # 7. RATIOS AND PROPORTIONS
    df['vowel_ratio'] = df.apply(
        lambda row: row['vowel_count'] / row['letter_count'] if row['letter_count'] > 0 else 0, axis=1
    )
    df['digit_ratio'] = df.apply(
        lambda row: row['digit_count'] / row['domain_length'] if row['domain_length'] > 0 else 0, axis=1
    )
    df['letter_ratio'] = df.apply(
        lambda row: row['letter_count'] / row['domain_length'] if row['domain_length'] > 0 else 0, axis=1
    )
    
    # 8. SUBDOMAIN ANALYSIS
    df['subdomain_count'] = df['domain'].apply(lambda x: max(0, x.count('.') - 1))
    df['has_subdomain'] = df['subdomain_count'].apply(lambda x: 1 if x > 0 else 0)
    
    # 9. CHARACTER DIVERSITY
    df['unique_char_ratio'] = df['name_without_tld'].apply(
        lambda x: len(set(x.lower())) / len(x) if len(x) > 0 else 0
    )
    
    # 10. CHECK FOR REPETITIVE PATTERNS
    def has_repetitive_pattern(s):
        if len(s) < 4:
            return 0
        s = s.lower()
        for i in range(len(s) - 3):
            if s[i] == s[i+1] == s[i+2]:
                return 1
        return 0
    
    df['has_repetitive_chars'] = df['name_without_tld'].apply(has_repetitive_pattern)
    
    # 11. CHECK FOR MIXED CASE (unusual in domains)
    df['has_mixed_case'] = df['domain'].apply(
        lambda x: 1 if any(c.isupper() for c in x) and any(c.islower() for c in x) else 0
    )
    
    # 12. CHECK FOR CONSECUTIVE SPECIAL CHARS
    def has_consecutive_special(s):
        for i in range(len(s) - 1):
            if s[i] in '-_' and s[i+1] in '-_':
                return 1
        return 0
    
    df['has_consecutive_special'] = df['domain'].apply(has_consecutive_special)
    
    # 13. CHECK FOR SUSPICIOUS TLD-LENGTH DOMAIN NAMES
    df['is_short_with_new_tld'] = df.apply(
        lambda row: 1 if row['name_length'] <= 5 and row['has_new_tld'] == 1 else 0, axis=1
    )
    
    # DROP TEMPORARY COLUMNS
    columns_to_drop = ['domain', 'tld', 'name_without_tld']
    df = df.drop([col for col in columns_to_drop if col in df.columns], axis=1, errors='ignore')
    
    logger.info(f"Feature engineering completed. Total features: {df.shape[1]}")
    logger.info(f"Feature columns: {list(df.columns)}")
    
    # Check for any NaN values
    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        logger.warning(f"Found {nan_count} NaN values in features. Filling with 0.")
        df = df.fillna(0)
    
    return df

def add_realistic_domains(df, logger):
    """Add realistic domains to balance the dataset"""
    logger.info("Adding realistic domains to balance dataset...")
    
    # More realistic domains - mix of legitimate and suspicious
    additional_domains = [
        # Realistic benign domains with various TLDs
        {'domain': 'myblog.xyz', 'is_malicious': 0},
        {'domain': 'techstartup.top', 'is_malicious': 0},
        {'domain': 'portfolio.site', 'is_malicious': 0},
        {'domain': 'hobbyproject.online', 'is_malicious': 0},
        {'domain': 'familyphotos.info', 'is_malicious': 0},
        {'domain': 'localbusiness.cc', 'is_malicious': 0},
        {'domain': 'freelancer.work', 'is_malicious': 0},
        {'domain': 'artgallery.biz', 'is_malicious': 0},
        {'domain': 'musician.club', 'is_malicious': 0},
        {'domain': 'photography.win', 'is_malicious': 0},
        
        # Realistic malicious domains that look legitimate
        {'domain': 'secure-login-paypal.com', 'is_malicious': 1},
        {'domain': 'appleid-verification.net', 'is_malicious': 1},
        {'domain': 'microsoft-security-update.org', 'is_malicious': 1},
        {'domain': 'google-drive-backup.co', 'is_malicious': 1},
        {'domain': 'facebook-account-recovery.io', 'is_malicious': 1},
        {'domain': 'netflix-payment-update.com', 'is_malicious': 1},
        {'domain': 'amazon-gift-card-claim.net', 'is_malicious': 1},
        {'domain': 'bankofamerica-alert.org', 'is_malicious': 1},
        {'domain': 'chase-online-verify.com', 'is_malicious': 1},
        {'domain': 'wellsfargo-secure-login.co', 'is_malicious': 1},
        
        # Typosquatting domains (common attack)
        {'domain': 'g00gle.com', 'is_malicious': 1},
        {'domain': 'faceb00k.com', 'is_malicious': 1},
        {'domain': 'amaz0n.com', 'is_malicious': 1},
        {'domain': 'micr0soft.com', 'is_malicious': 1},
        {'domain': 'y0utube.com', 'is_malicious': 1},
        {'domain': 'paypai.com', 'is_malicious': 1},
        {'domain': 'whatsapp-login.com', 'is_malicious': 1},
        {'domain': 'instagrarn.com', 'is_malicious': 1},
        {'domain': 'twltter.com', 'is_malicious': 1},
        {'domain': 'netfl1x.com', 'is_malicious': 1},
        
        # More legitimate domains with numbers (common in tech)
        {'domain': 'web3-project.xyz', 'is_malicious': 0},
        {'domain': 'project-2024.com', 'is_malicious': 0},
        {'domain': 'team5-collab.net', 'is_malicious': 0},
        {'domain': 'api-v2-service.io', 'is_malicious': 0},
        {'domain': 'beta-test-01.app', 'is_malicious': 0},
        {'domain': 'version-3-release.tech', 'is_malicious': 0},
        {'domain': 'alpha-2024-test.site', 'is_malicious': 0},
        {'domain': 'server-01-backup.online', 'is_malicious': 0},
        {'domain': 'node-js-api-2.dev', 'is_malicious': 0},
        {'domain': 'react-app-18.demo', 'is_malicious': 0},
        
        # More sophisticated malicious domains
        {'domain': 'customer-support-update.com', 'is_malicious': 1},
        {'domain': 'billing-invoice-alert.net', 'is_malicious': 1},
        {'domain': 'security-verification-required.org', 'is_malicious': 1},
        {'domain': 'account-suspension-notice.co', 'is_malicious': 1},
        {'domain': 'payment-confirmation-required.io', 'is_malicious': 1},
        {'domain': 'fraud-detection-alert.com', 'is_malicious': 1},
        {'domain': 'login-activity-unusual.net', 'is_malicious': 1},
        {'domain': 'password-reset-immediate.org', 'is_malicious': 1},
        {'domain': 'suspicious-login-detected.co', 'is_malicious': 1},
        {'domain': 'verify-identity-now.io', 'is_malicious': 1},
    ]
    
    # Create DataFrame for additional domains
    new_df = pd.DataFrame(additional_domains)
    
    # Combine with original
    combined_df = pd.concat([df, new_df], ignore_index=True)
    
    logger.info(f"Added {len(new_df)} new domains (mix of benign and malicious)")
    logger.info(f"New dataset shape: {combined_df.shape}")
    
    # Show new class distribution
    class_dist = combined_df['is_malicious'].value_counts()
    logger.info(f"Updated class distribution: Benign={class_dist.get(0, 0)}, Malicious={class_dist.get(1, 0)}")
    
    return combined_df

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
        logger.warning("⚠️  ZERO FALSE POSITIVES: All benign domains correctly classified")
        logger.warning("   Real-world models typically have some false positives.")
    
    if fnr == 0:
        logger.warning("⚠️  ZERO FALSE NEGATIVES: All malicious domains detected")
        logger.warning("   This is unrealistic for domain classification.")
    
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

def train_domain_model():
    """Train Domain model with multiple algorithms and robust validation"""
    logger = setup_logging('train_domain')
    timer = TrainingTimer(logger)
    
    timer.start()
    logger.info("=" * 60)
    logger.info("STARTING DOMAIN MODEL TRAINING WITH ROBUST VALIDATION")
    logger.info("=" * 60)
    
    # Load dataset
    df = load_domain_dataset(logger)
    
    # Add realistic domains for better generalization
    df = add_realistic_domains(df, logger)
    
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
    logger.info(f"Features: {list(X.columns)}")
    
    # Ensure column names are strings
    X.columns = X.columns.astype(str)
    
    # Feature selection to reduce dimensionality
    logger.info("Performing feature selection...")
    selector = SelectKBest(f_classif, k=min(15, X.shape[1]))
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
                'C': [0.01, 0.1, 1, 10],  # More regularization options
                'penalty': ['l2'],
                'solver': ['lbfgs', 'saga'],
                'max_iter': [2000]
            }
        },
        'random_forest': {
            'model': RandomForestClassifier(random_state=42, n_estimators=100, class_weight='balanced_subsample'),
            'params': {
                'n_estimators': [50, 100, 150],
                'max_depth': [5, 10, 15, None],
                'min_samples_split': [2, 5, 10],  # Increased to reduce overfitting
                'min_samples_leaf': [1, 2, 4],
                'max_features': ['sqrt', 'log2', 0.5],
                'bootstrap': [True, False]
            }
        },
        'gradient_boosting': {
            'model': GradientBoostingClassifier(random_state=42, n_estimators=100),
            'params': {
                'n_estimators': [50, 100, 150],
                'learning_rate': [0.001, 0.01, 0.05, 0.1],
                'max_depth': [3, 4, 5],
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
                'kernel': ['linear', 'rbf'],  # Removed 'poly' to avoid convergence issues
                'gamma': ['scale', 'auto', 0.01, 0.1],
                'max_iter': [100000],  # Increased for convergence
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
            logger.info(f"  Cross-validation F1 scores (10-fold): {cv_scores}")
            logger.info(f"  Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
            
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
    save_metrics(metrics, 'train_domain')
    
    # Plot results
    plot_confusion_matrix(metrics['confusion_matrix'], 'train_domain')
    plot_training_time(timer.elapsed(), 'train_domain')
    
    # Save model, scaler, selector, and feature names
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    model_path = f'{MODEL_STORAGE_PATH}/domain_model.pkl'
    scaler_path = f'{MODEL_STORAGE_PATH}/scaler_domain.pkl'
    selector_path = f'{MODEL_STORAGE_PATH}/selector_domain.pkl'
    feature_names_path = f'{MODEL_STORAGE_PATH}/domain_feature_names.pkl'
    
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
        'training_artifacts/graphs/individual/train_domain_confusion_matrix.png',
        'training_artifacts/graphs/individual/train_domain_training_time.png'
    ]
    
    generate_report(
        'train_domain', 
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
    logger.info("TRAINING COMPLETED WITH REALISTIC VALIDATION")
    logger.info(f"Total training time: {timer.elapsed():.2f} seconds")
    logger.info("=" * 60)
    
    # Final recommendations
    logger.info("\n" + "=" * 60)
    logger.info("RECOMMENDATIONS FOR PRODUCTION USE")
    logger.info("=" * 60)
    logger.info("1. Monitor false positive rate in production")
    logger.info("2. Regularly update training data with new domain patterns")
    logger.info("3. Consider ensemble methods for better generalization")
    logger.info("4. Implement a confidence threshold for predictions")
    logger.info("5. Track model drift over time")
    
    return best_model, scaler, metrics

if __name__ == "__main__":
    train_domain_model()