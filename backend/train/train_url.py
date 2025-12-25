"""
ENHANCED URL MODEL TRAINING
===========================
Production-grade URL threat detection with comprehensive feature engineering
and robust validation similar to domain and IP models.
"""

import pandas as pd
import numpy as np
import re
import hashlib
import urllib.parse
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
import math
from collections import Counter
warnings.filterwarnings('ignore')

# Import from utils
from utils import setup_logging, TrainingTimer, calculate_classification_metrics, save_metrics, plot_confusion_matrix, plot_training_time, generate_report

# Paths
MODEL_STORAGE_PATH = os.getenv('MODEL_STORAGE_PATH', 'models')
DATASET_BASE_PATH = os.getenv('DATASET_BASE_PATH', 'datasets')

def load_url_dataset(logger):
    """Load and validate URL dataset with extension for better generalization"""
    try:
        df = pd.read_csv(f'{DATASET_BASE_PATH}/url/malicious_url.csv')
        
        # Validate required columns
        required_columns = ['url', 'status']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Dataset missing required column: {col}")
        
        # Rename status to is_malicious for consistency
        df['is_malicious'] = df['status']
        df = df.drop('status', axis=1)
        
        # Remove duplicates
        initial_count = len(df)
        df = df.drop_duplicates(subset=['url'])
        final_count = len(df)
        logger.info(f"Removed {initial_count - final_count} duplicate URLs.")
        
        logger.info(f"URL dataset loaded successfully. Shape: {df.shape}")
        
        # Detailed class analysis
        class_dist = df['is_malicious'].value_counts()
        logger.info(f"Class distribution:\n{class_dist}")
        logger.info(f"Benign URLs: {class_dist.get(0, 0)} ({class_dist.get(0, 0)/len(df)*100:.1f}%)")
        logger.info(f"Malicious URLs: {class_dist.get(1, 0)} ({class_dist.get(1, 0)/len(df)*100:.1f}%)")
        
        # If dataset is too small, extend it
        if len(df) < 1000:
            logger.info("Dataset is small. Extending with realistic URL patterns...")
            df = extend_url_dataset(df, logger, target_size=3000)
        
        return df
    except Exception as e:
        logger.error(f"Error loading URL dataset: {e}")
        raise

def extend_url_dataset(df, logger, target_size=3000):
    """Extend URL dataset with realistic synthetic patterns"""
    logger.info("Generating synthetic URL data for better model generalization...")
    
    synthetic_urls = []
    
    # Realistic benign URLs with various patterns
    benign_patterns = [
        # E-commerce
        {'url': 'https://www.amazon.com/product/electronics/headphones-2024', 'is_malicious': 0},
        {'url': 'https://shop.example.com/category/shoes/running', 'is_malicious': 0},
        {'url': 'https://store.company.com/checkout/cart?item=123', 'is_malicious': 0},
        
        # Social Media
        {'url': 'https://twitter.com/user/profile/posts', 'is_malicious': 0},
        {'url': 'https://www.facebook.com/groups/techdiscussion', 'is_malicious': 0},
        {'url': 'https://linkedin.com/in/johndoe/skills', 'is_malicious': 0},
        
        # News & Blogs
        {'url': 'https://news.website.com/2024/03/technology-updates', 'is_malicious': 0},
        {'url': 'https://blog.platform.io/article-machine-learning', 'is_malicious': 0},
        
        # Government & Education
        {'url': 'https://www.irs.gov/tax-payers/forms', 'is_malicious': 0},
        {'url': 'https://harvard.edu/courses/computer-science', 'is_malicious': 0},
        
        # Banking (legitimate)
        {'url': 'https://secure.chase.com/online/banking/login', 'is_malicious': 0},
        {'url': 'https://www.bankofamerica.com/accounts/overview', 'is_malicious': 0},
        
        # Tech Companies
        {'url': 'https://docs.microsoft.com/en-us/azure/architecture', 'is_malicious': 0},
        {'url': 'https://cloud.google.com/compute/docs/tutorials', 'is_malicious': 0},
        {'url': 'https://developer.apple.com/documentation/arkit', 'is_malicious': 0},
        
        # APIs
        {'url': 'https://api.weather.com/v1/forecast?location=NYC', 'is_malicious': 0},
        {'url': 'https://rest.example.com/v2/users/12345/profile', 'is_malicious': 0},
        
        # File paths (common in local networks)
        {'url': 'http://192.168.1.100:8080/files/document.pdf', 'is_malicious': 0},
        {'url': 'https://internal.corp.com/hr/policies/2024', 'is_malicious': 0},
    ]
    
    # Realistic malicious URLs with various attack patterns
    malicious_patterns = [
        # Phishing - Banking
        {'url': 'https://chase-secure-login-verify.com/account/update', 'is_malicious': 1},
        {'url': 'http://bankofamerica-security-alert.net/login/confirm', 'is_malicious': 1},
        {'url': 'https://wellsfargo-account-recovery.org/secure/form', 'is_malicious': 1},
        
        # Phishing - Payment
        {'url': 'https://paypal-confirm-identity.com/cgi-bin/webscr?cmd=login', 'is_malicious': 1},
        {'url': 'http://venmo-verification-required.xyz/account/secure', 'is_malicious': 1},
        
        # Phishing - Social Media
        {'url': 'https://facebook-security-check.xyz/login/verify.php', 'is_malicious': 1},
        {'url': 'http://instagram-account-recovery.com/password/reset', 'is_malicious': 1},
        {'url': 'https://twitter-verification-now.net/oauth/callback', 'is_malicious': 1},
        
        # Malware distribution
        {'url': 'http://download-update-2024.com/setup.exe', 'is_malicious': 1},
        {'url': 'https://free-software-crack.org/installer.zip', 'is_malicious': 1},
        {'url': 'http://driver-update-utility.net/download/setup.msi', 'is_malicious': 1},
        
        # Tech support scams
        {'url': 'https://microsoft-support-alert.com/scan/results', 'is_malicious': 1},
        {'url': 'http://apple-security-warning.xyz/check/virus', 'is_malicious': 1},
        
        # Typosquatting
        {'url': 'https://g00gle.com/search?q=login', 'is_malicious': 1},
        {'url': 'http://faceb00k.com/profile/security', 'is_malicious': 1},
        {'url': 'https://amaz0n.com/account/payment', 'is_malicious': 1},
        {'url': 'http://micr0soft.com/update/download', 'is_malicious': 1},
        {'url': 'https://y0utube.com/watch?v=malicious', 'is_malicious': 1},
        
        # Suspicious parameters and paths
        {'url': 'http://example.com/wp-admin/js/cgi-bin/webscr?cmd=login', 'is_malicious': 1},
        {'url': 'https://domain.com/images/icons/icon/mastercard/login.php', 'is_malicious': 1},
        {'url': 'http://site.net/administrator/components/com_admin/tmpl/portal/login.htm', 'is_malicious': 1},
        
        # Obfuscated URLs
        {'url': 'https://112.73.45.189:8443/cgi-bin/login.cgi', 'is_malicious': 1},
        {'url': 'http://453dcba9.hackersite.cn/admin/panel', 'is_malicious': 1},
        
        # Long suspicious URLs
        {'url': 'https://secure-verify-update.com/cgi-bin/webscr?cmd=_login-run&dispatch=5885d80a13c0db1f1ff80d546411d7f8a8350c132bc41e0934cfc023d4e8f9e5f5af1dac519b2ce98f0800646dcd7eddf5af1dac519b2ce98f0800646dcd7edd', 'is_malicious': 1},
        
        # Fake login pages
        {'url': 'https://login-apple-id.xyz/authenticate', 'is_malicious': 1},
        {'url': 'http://netflix-update-payment.com/billing', 'is_malicious': 1},
        {'url': 'https://spotify-premium-verification.net/account', 'is_malicious': 1},
        
        # Cryptocurrency scams
        {'url': 'https://free-bitcoin-generator.com/claim', 'is_malicious': 1},
        {'url': 'http://etherium-wallet-recovery.org/access', 'is_malicious': 1},
        
        # SEO spam
        {'url': 'https://buy-cheap-pills-online.ru/viagra', 'is_malicious': 1},
        {'url': 'http://online-casino-bonus-2024.club/play', 'is_malicious': 1},
        
        # Redirect chains
        {'url': 'http://link.redirectservice.tk/go/facebook.com', 'is_malicious': 1},
        {'url': 'https://url-shortener.xyz/l/amazon-gift-card', 'is_malicious': 1},
    ]
    
    # Add patterns
    for pattern in benign_patterns + malicious_patterns:
        synthetic_urls.append(pattern)
    
    # Generate variations
    base_urls = [
        "https://secure-login-{}.com",
        "http://update-{}.net",
        "https://verify-account-{}.org",
        "http://download-{}.xyz",
        "https://{}-payment.com"
    ]
    
    keywords = ['bank', 'paypal', 'amazon', 'microsoft', 'google', 'facebook', 'apple', 'netflix', 'twitter', 'instagram']
    
    for base in base_urls:
        for keyword in keywords:
            # Malicious variations
            url = base.format(keyword)
            synthetic_urls.append({
                'url': url + "/login/secure/form.php",
                'is_malicious': 1
            })
            
            # Benign variations with different patterns
            if np.random.random() > 0.7:  # 30% chance for benign
                synthetic_urls.append({
                    'url': base.format(keyword + "-official") + "/support",
                    'is_malicious': 0
                })
    
    # Generate more with random parameters
    domains = ['example', 'test', 'service', 'api', 'web', 'app', 'cloud', 'data', 'tech', 'online']
    tlds = ['com', 'net', 'org', 'io', 'co', 'xyz', 'site', 'online', 'tech', 'shop']
    
    for _ in range(200):
        domain = np.random.choice(domains)
        tld = np.random.choice(tlds)
        
        # Random path depth
        path_depth = np.random.randint(1, 5)
        path = "/".join([f"folder{i}" for i in range(path_depth)])
        
        # Add parameters sometimes
        params = ""
        if np.random.random() > 0.5:
            params = "?" + "&".join([f"param{i}={np.random.randint(1000,9999)}" for i in range(np.random.randint(1,4))])
        
        # Determine if malicious
        is_malicious = 1 if np.random.random() > 0.6 else 0
        
        # Add suspicious elements for malicious URLs
        if is_malicious and np.random.random() > 0.5:
            suspicious = ['login', 'secure', 'verify', 'account', 'bank', 'payment', 'update', 'download']
            path = f"/{np.random.choice(suspicious)}" + path
        
        protocol = "https://" if np.random.random() > 0.3 else "http://"
        
        synthetic_urls.append({
            'url': f"{protocol}{domain}{np.random.randint(1,100)}.{tld}/{path}{params}",
            'is_malicious': is_malicious
        })
    
    # Create DataFrame
    synthetic_df = pd.DataFrame(synthetic_urls)
    
    # Remove duplicates
    synthetic_df = synthetic_df.drop_duplicates(subset=['url'])
    
    # Combine with original
    extended_df = pd.concat([df, synthetic_df], ignore_index=True)
    
    # Shuffle
    extended_df = extended_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Limit to target size
    if len(extended_df) > target_size:
        extended_df = extended_df.head(target_size)
    
    logger.info(f"Extended dataset from {len(df)} to {len(extended_df)} rows")
    logger.info(f"Final class distribution: {extended_df['is_malicious'].value_counts().to_dict()}")
    logger.info(f"Benign: {extended_df['is_malicious'].value_counts().get(0, 0)}, Malicious: {extended_df['is_malicious'].value_counts().get(1, 0)}")
    
    return extended_df

def engineer_features(df, logger):
    """Comprehensive feature engineering for URLs"""
    logger.info("Starting comprehensive URL feature engineering...")
    
    original_count = len(df)
    
    # 1. BASIC STRUCTURAL FEATURES
    df['url_length'] = df['url'].apply(len)
    df['num_dots'] = df['url'].apply(lambda x: x.count('.'))
    df['num_hyphens'] = df['url'].apply(lambda x: x.count('-'))
    df['num_underscores'] = df['url'].apply(lambda x: x.count('_'))
    df['num_slashes'] = df['url'].apply(lambda x: x.count('/'))
    df['num_questionmarks'] = df['url'].apply(lambda x: x.count('?'))
    df['num_ampersands'] = df['url'].apply(lambda x: x.count('&'))
    df['num_equals'] = df['url'].apply(lambda x: x.count('='))
    df['num_at'] = df['url'].apply(lambda x: x.count('@'))
    df['num_percent'] = df['url'].apply(lambda x: x.count('%'))
    
    # 2. PROTOCOL AND SCHEME FEATURES
    df['has_https'] = df['url'].str.startswith('https').astype(int)
    df['has_http'] = df['url'].str.startswith('http').astype(int)
    df['has_ftp'] = df['url'].str.contains('ftp://').astype(int)
    
    # 3. DOMAIN EXTRACTION AND ANALYSIS
    def extract_domain(url):
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
            return domain.lower()
        except:
            return ""
    
    df['domain'] = df['url'].apply(extract_domain)
    df['domain_length'] = df['domain'].apply(len)
    
    # 4. PATH ANALYSIS
    def extract_path(url):
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.path if parsed.path else ""
        except:
            return ""
    
    df['path'] = df['url'].apply(extract_path)
    df['path_length'] = df['path'].apply(len)
    df['path_depth'] = df['path'].apply(lambda x: x.count('/') if x else 0)
    
    # 5. QUERY PARAMETER ANALYSIS
    def extract_query(url):
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.query if parsed.query else ""
        except:
            return ""
    
    df['query'] = df['url'].apply(extract_query)
    df['query_length'] = df['query'].apply(len)
    df['num_params'] = df['query'].apply(lambda x: x.count('&') + 1 if '&' in x else (1 if x else 0))
    
    # 6. TLD ANALYSIS
    def extract_tld(domain):
        parts = domain.split('.')
        return parts[-1] if len(parts) > 1 else ''
    
    df['tld'] = df['domain'].apply(extract_tld)
    df['tld_length'] = df['tld'].apply(len)
    
    # TLD categories
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'uk', 'de', 'fr', 'jp']
    new_tlds = ['xyz', 'top', 'site', 'online', 'tech', 'shop', 'club', 'app', 'dev', 'ai']
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'review', 'bid', 'win']
    
    df['has_common_tld'] = df['tld'].apply(lambda x: 1 if x in common_tlds else 0)
    df['has_new_tld'] = df['tld'].apply(lambda x: 1 if x in new_tlds else 0)
    df['has_suspicious_tld'] = df['tld'].apply(lambda x: 1 if x in suspicious_tlds else 0)
    df['tld_is_numeric'] = df['tld'].apply(lambda x: 1 if x.isdigit() else 0)
    
    # 7. SUBDOMAIN ANALYSIS
    def count_subdomains(domain):
        parts = domain.split('.')
        return max(0, len(parts) - 2)  # Subtract domain and TLD
    
    df['subdomain_count'] = df['domain'].apply(count_subdomains)
    df['has_subdomain'] = df['subdomain_count'].apply(lambda x: 1 if x > 0 else 0)
    
    # 8. CHARACTER COMPOSITION
    df['digit_count'] = df['url'].apply(lambda x: sum(c.isdigit() for c in x))
    df['letter_count'] = df['url'].apply(lambda x: sum(c.isalpha() for c in x))
    df['special_char_count'] = df['url'].apply(lambda x: sum(not c.isalnum() for c in x))
    
    # 9. ENTROPY CALCULATION (measure of randomness)
    def calculate_entropy(s):
        if len(s) <= 1:
            return 0
        s = s.lower()
        char_counts = Counter(s)
        entropy = 0
        total_chars = len(s)
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
        return entropy
    
    df['url_entropy'] = df['url'].apply(calculate_entropy)
    df['domain_entropy'] = df['domain'].apply(calculate_entropy)
    
    # 10. PATTERN DETECTION
    suspicious_keywords = [
        'login', 'secure', 'verify', 'account', 'bank', 'payment', 'update', 'download',
        'confirm', 'validate', 'signin', 'signon', 'password', 'credit', 'card', 'social',
        'security', 'alert', 'warning', 'urgent', 'immediate', 'action', 'required',
        'phish', 'hack', 'malware', 'virus', 'trojan', 'spyware', 'ransomware',
        'cgi-bin', 'wp-admin', 'administrator', 'admin', 'cmd', 'exec', 'shell'
    ]
    
    df['suspicious_keyword_count'] = df['url'].apply(
        lambda x: sum(1 for keyword in suspicious_keywords if keyword in x.lower())
    )
    
    # 11. IP ADDRESS IN URL
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    df['has_ip_address'] = df['url'].apply(lambda x: 1 if re.search(ip_pattern, x) else 0)
    
    # 12. HEX ENCODED CHARACTERS
    hex_pattern = r'%[0-9a-fA-F]{2}'
    df['hex_char_count'] = df['url'].apply(lambda x: len(re.findall(hex_pattern, x)))
    
    # 13. REPETITIVE PATTERNS
    def has_repetitive_chars(s, threshold=3):
        for i in range(len(s) - threshold + 1):
            if len(set(s[i:i+threshold])) == 1:
                return 1
        return 0
    
    df['has_repetitive_chars'] = df['url'].apply(lambda x: has_repetitive_chars(x, 3))
    
    # 14. SHORTENED URL DETECTION
    shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly']
    df['is_shortened'] = df['domain'].apply(lambda x: 1 if any(service in x for service in shortening_services) else 0)
    
    # 15. PORT NUMBER DETECTION
    port_pattern = r':(\d{2,5})/'
    df['has_port'] = df['url'].apply(lambda x: 1 if re.search(port_pattern, x) else 0)
    
    # 16. FILE EXTENSION ANALYSIS
    file_extensions = ['.exe', '.dll', '.bat', '.cmd', '.js', '.vbs', '.scr', '.pif', '.com']
    df['has_executable_extension'] = df['url'].apply(lambda x: 1 if any(ext in x.lower() for ext in file_extensions) else 0)
    
    # 17. URL ENCODING INDICATORS
    df['encoded_char_ratio'] = df.apply(
        lambda row: row['hex_char_count'] / row['url_length'] if row['url_length'] > 0 else 0, axis=1
    )
    
    # 18. RATIOS AND PROPORTIONS
    df['digit_ratio'] = df.apply(
        lambda row: row['digit_count'] / row['url_length'] if row['url_length'] > 0 else 0, axis=1
    )
    df['letter_ratio'] = df.apply(
        lambda row: row['letter_count'] / row['url_length'] if row['url_length'] > 0 else 0, axis=1
    )
    df['special_char_ratio'] = df.apply(
        lambda row: row['special_char_count'] / row['url_length'] if row['url_length'] > 0 else 0, axis=1
    )
    df['path_to_url_ratio'] = df.apply(
        lambda row: row['path_length'] / row['url_length'] if row['url_length'] > 0 else 0, axis=1
    )
    
    # 19. DOMAIN NAME FEATURES
    def get_domain_without_tld(domain):
        parts = domain.split('.')
        return '.'.join(parts[:-1]) if len(parts) > 1 else domain
    
    df['domain_name'] = df['domain'].apply(get_domain_without_tld)
    df['domain_name_length'] = df['domain_name'].apply(len)
    
    # Check for digits in domain name (often suspicious)
    df['domain_has_digits'] = df['domain_name'].apply(lambda x: 1 if any(c.isdigit() for c in x) else 0)
    
    # Check for consecutive consonants
    def has_consecutive_consonants(s, n=4):
        s = s.lower()
        consonant_count = 0
        consonants = 'bcdfghjklmnpqrstvwxyz'
        for char in s:
            if char in consonants:
                consonant_count += 1
                if consonant_count >= n:
                    return 1
            else:
                consonant_count = 0
        return 0
    
    df['has_consecutive_consonants'] = df['domain_name'].apply(lambda x: has_consecutive_consonants(x, 4))
    
    # 20. UNIQUE CHARACTER RATIO
    df['unique_char_ratio'] = df['url'].apply(
        lambda x: len(set(x.lower())) / len(x) if len(x) > 0 else 0
    )
    
    # 21. SUSPICIOUS PARAMETER NAMES
    suspicious_params = ['cmd', 'exec', 'shell', 'php', 'asp', 'jsp', 'upload', 'download', 'config']
    df['suspicious_param_count'] = df['query'].apply(
        lambda x: sum(1 for param in suspicious_params if param in x.lower())
    )
    
    # 22. LENGTH VARIABILITY
    df['length_variability'] = df['url'].apply(
        lambda x: np.std([len(part) for part in x.split('/')]) if '/' in x else 0
    )
    
    # 23. WORD BOUNDARY ANALYSIS
    def count_word_boundaries(s):
        return len(re.findall(r'[a-z][A-Z]|[A-Z][a-z]|[a-zA-Z][0-9]|[0-9][a-zA-Z]', s))
    
    df['word_boundary_count'] = df['url'].apply(count_word_boundaries)
    
    # 24. SUSPICIOUS SYMBOL COMBINATIONS
    suspicious_combos = ['//', '..', './', '/.', '\\']
    df['suspicious_combo_count'] = df['url'].apply(
        lambda x: sum(x.count(combo) for combo in suspicious_combos)
    )
    
    # 25. SSL/TLS INDICATORS
    df['has_ssl_indicator'] = df['url'].apply(
        lambda x: 1 if 'https://' in x.lower() or ':443' in x else 0
    )
    
    # 26. MIXED CASE DETECTION
    df['has_mixed_case'] = df['url'].apply(
        lambda x: 1 if any(c.isupper() for c in x) and any(c.islower() for c in x) else 0
    )
    
    # 27. SUSPICIOUS HASH PATTERNS (common in malware URLs)
    def has_suspicious_hash(url):
        # Look for long hexadecimal strings
        hex_pattern = r'[0-9a-fA-F]{16,}'
        return 1 if re.search(hex_pattern, url) else 0
    
    df['has_suspicious_hash'] = df['url'].apply(has_suspicious_hash)
    
    # 28. DIRECTORY TRAVERSAL INDICATORS
    traversal_patterns = ['../', '..\\', './../']
    df['has_traversal_pattern'] = df['url'].apply(
        lambda x: 1 if any(pattern in x for pattern in traversal_patterns) else 0
    )
    
    # 29. COMMON MALICIOUS PATHS
    malicious_paths = ['/cgi-bin/', '/wp-admin/', '/administrator/', '/phpmyadmin/', '/backup/']
    df['has_malicious_path'] = df['path'].apply(
        lambda x: 1 if any(mpath in x.lower() for mpath in malicious_paths) else 0
    )
    
    # 30. URL FRAGMENT ANALYSIS
    def extract_fragment(url):
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.fragment if parsed.fragment else ""
        except:
            return ""
    
    df['fragment'] = df['url'].apply(extract_fragment)
    df['fragment_length'] = df['fragment'].apply(len)
    df['has_fragment'] = df['fragment_length'].apply(lambda x: 1 if x > 0 else 0)
    
    # DROP TEMPORARY COLUMNS
    columns_to_drop = ['url', 'domain', 'path', 'query', 'tld', 'domain_name', 'fragment']
    df = df.drop([col for col in columns_to_drop if col in df.columns], axis=1, errors='ignore')
    
    logger.info(f"Feature engineering completed. Total features: {df.shape[1]}")
    logger.info(f"Sample features: {list(df.columns)[:20]}...")
    
    # Check for any NaN values
    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        logger.warning(f"Found {nan_count} NaN values in features. Filling with 0.")
        df = df.fillna(0)
    
    # Check for infinite values
    inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
    if inf_count > 0:
        logger.warning(f"Found {inf_count} infinite values. Replacing with large finite numbers.")
        df = df.replace([np.inf, -np.inf], np.finfo(np.float64).max)
    
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
            
            if roc_auc > 0.99:
                logger.warning("⚠️  VERY HIGH ROC-AUC: > 0.99 - potential overfitting!")
        except Exception as e:
            logger.info(f"ROC-AUC Score: Not available ({e})")
    
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
        logger.warning("⚠️  ZERO FALSE POSITIVES: All benign URLs correctly classified")
        logger.warning("   Real-world models typically have some false positives.")
    
    if fnr == 0:
        logger.warning("⚠️  ZERO FALSE NEGATIVES: All malicious URLs detected")
        logger.warning("   This is unrealistic for URL classification.")
    
    # Additional metrics
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    logger.info(f"Specificity: {specificity:.4f}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist(),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        'true_positives': int(tp),
        'specificity': specificity
    }

def train_url_model():
    """Train URL model with multiple algorithms and robust validation"""
    logger = setup_logging('train_url')
    timer = TrainingTimer(logger)
    
    timer.start()
    logger.info("=" * 60)
    logger.info("STARTING URL MODEL TRAINING WITH ROBUST VALIDATION")
    logger.info("=" * 60)
    
    # Load and extend dataset
    df = load_url_dataset(logger)
    
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
    logger.info(f"Total features generated: {len(X.columns)}")
    
    # Ensure column names are strings
    X.columns = X.columns.astype(str)
    
    # Feature selection to reduce dimensionality and prevent overfitting
    logger.info("Performing feature selection...")
    selector = SelectKBest(f_classif, k=min(30, X.shape[1]))
    X_selected = selector.fit_transform(X, y)
    selected_features = X.columns[selector.get_support()].tolist()
    logger.info(f"Selected {len(selected_features)} best features")
    
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
                'C': [0.001, 0.01, 0.1, 1, 10, 100],
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
                'learning_rate': [0.001, 0.01, 0.05, 0.1, 0.2],
                'max_depth': [3, 4, 5, 6],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'subsample': [0.7, 0.8, 0.9, 1.0],
                'max_features': ['sqrt', 'log2', None]
            }
        },
        'svc': {
            'model': SVC(random_state=42, probability=True, class_weight='balanced', max_iter=1000000),
            'params': {
                'C': [0.1, 1, 10, 100],
                'kernel': ['linear', 'rbf', 'poly'],
                'gamma': ['scale', 'auto', 0.001, 0.01, 0.1],
                'degree': [2, 3],
                'max_iter': [1000000],
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
        logger.info("\nFeature Importance (Top 15):")
        for i in range(min(15, len(importances))):
            feature_name = selected_features[indices[i]] if i < len(selected_features) else f"Feature_{indices[i]}"
            importance_value = importances[indices[i]]
            logger.info(f"  {i+1:2}. {feature_name:30}: {importance_value:.4f}")
            metrics['feature_importance'][feature_name] = float(importance_value)
    elif hasattr(best_model, 'coef_'):
        # For linear models
        importances = np.abs(best_model.coef_[0])
        indices = np.argsort(importances)[::-1]
        logger.info("\nFeature Importance (Top 15 - based on coefficients):")
        for i in range(min(15, len(importances))):
            feature_name = selected_features[indices[i]] if i < len(selected_features) else f"Feature_{indices[i]}"
            importance_value = importances[indices[i]]
            logger.info(f"  {i+1:2}. {feature_name:30}: {importance_value:.4f}")
            metrics['feature_importance'][feature_name] = float(importance_value)
    
    # Save metrics
    save_metrics(metrics, 'train_url')
    
    # Plot results
    plot_confusion_matrix(np.array(metrics['confusion_matrix']), 'train_url')
    plot_training_time(timer.elapsed(), 'train_url')
    
    # Save model, scaler, selector, and feature names
    os.makedirs(MODEL_STORAGE_PATH, exist_ok=True)
    model_path = f'{MODEL_STORAGE_PATH}/url_model.pkl'
    scaler_path = f'{MODEL_STORAGE_PATH}/scaler_url.pkl'
    selector_path = f'{MODEL_STORAGE_PATH}/selector_url.pkl'
    feature_names_path = f'{MODEL_STORAGE_PATH}/url_feature_names.pkl'
    
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
        'training_artifacts/graphs/individual/train_url_confusion_matrix.png',
        'training_artifacts/graphs/individual/train_url_training_time.png'
    ]
    
    generate_report(
        'train_url', 
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
    logger.info("TRAINING COMPLETED SUCCESSFULLY")
    logger.info(f"Total training time: {timer.elapsed():.2f} seconds")
    logger.info("=" * 60)
    
    # Final recommendations for production
    logger.info("\n" + "=" * 60)
    logger.info("PRODUCTION RECOMMENDATIONS")
    logger.info("=" * 60)
    logger.info("1. Monitor false positive rate in production (aim for < 5%)")
    logger.info("2. Regularly retrain model with new phishing/malicious URL patterns")
    logger.info("3. Implement confidence thresholds for predictions")
    logger.info("4. Combine with real-time threat intelligence feeds")
    logger.info("5. Use ensemble methods for critical decisions")
    logger.info("6. Track model drift and retrain monthly")
    logger.info("7. Implement rate limiting for URL checking API")
    logger.info("8. Log all predictions for audit and improvement")
    logger.info("9. Consider browser extension integration for real-time protection")
    logger.info("10. Implement feedback loop from user reports")
    
    # Performance summary
    logger.info("\n" + "=" * 60)
    logger.info("PERFORMANCE SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Best Model: {best_name}")
    logger.info(f"Test Accuracy: {metrics['accuracy']:.4f}")
    logger.info(f"Precision: {metrics['precision']:.4f}")
    logger.info(f"Recall: {metrics['recall']:.4f}")
    logger.info(f"F1-Score: {metrics['f1']:.4f}")
    logger.info(f"False Positive Rate: {metrics['false_positives']/(metrics['true_negatives'] + metrics['false_positives']) if (metrics['true_negatives'] + metrics['false_positives']) > 0 else 0:.4f}")
    
    return best_model, scaler, metrics

if __name__ == "__main__":
    train_url_model()