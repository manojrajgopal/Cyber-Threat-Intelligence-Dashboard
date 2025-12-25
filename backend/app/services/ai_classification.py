import numpy as np
import pandas as pd
from typing import Dict, Any, List
from ..models.models import AIPrediction, ThreatIOC, ThreatInput
from ..db.session import SessionLocal
import pickle
import os
from datetime import datetime
import joblib
import warnings
import re
import urllib.parse
import ipaddress
import math
from collections import Counter

class AIClassificationService:
    """AI-based threat classification service using trained domain-specific models."""

    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.selectors = {}
        self.feature_names = {}
        self.model_dir = os.getenv('MODEL_STORAGE_PATH', './models')
        os.makedirs(self.model_dir, exist_ok=True)
        self._load_trained_models()

    def _load_trained_models(self):
        """Load trained domain-specific models."""
        warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

        # IOC types and their model files
        ioc_types = ['domain', 'url', 'ip', 'hash', 'network']

        for ioc_type in ioc_types:
            try:
                # Load model
                model_path = os.path.join(self.model_dir, f'{ioc_type}_model.pkl')
                if os.path.exists(model_path):
                    self.models[ioc_type] = joblib.load(model_path)
                    print(f"Loaded {ioc_type} model from {model_path}")
                else:
                    print(f"Warning: {ioc_type} model not found at {model_path}")
                    continue

                # Load scaler - handle hash special case
                if ioc_type == 'hash':
                    scaler_path = os.path.join(self.model_dir, f'{ioc_type}_scaler.pkl')
                else:
                    scaler_path = os.path.join(self.model_dir, f'scaler_{ioc_type}.pkl')
                if os.path.exists(scaler_path):
                    self.scalers[ioc_type] = joblib.load(scaler_path)
                    print(f"Loaded {ioc_type} scaler from {scaler_path}")
                else:
                    print(f"Warning: {ioc_type} scaler not found at {scaler_path}")

                # Load selector
                selector_path = os.path.join(self.model_dir, f'selector_{ioc_type}.pkl')
                if os.path.exists(selector_path):
                    self.selectors[ioc_type] = joblib.load(selector_path)
                    print(f"Loaded {ioc_type} selector from {selector_path}")
                else:
                    # Hash models don't use feature selection, so no selector is expected
                    if ioc_type != 'hash':
                        print(f"Warning: {ioc_type} selector not found at {selector_path}")

                # Load feature names - handle hash special case
                if ioc_type == 'hash':
                    feature_names_path = os.path.join(self.model_dir, f'{ioc_type}_features.pkl')
                else:
                    feature_names_path = os.path.join(self.model_dir, f'{ioc_type}_feature_names.pkl')
                if os.path.exists(feature_names_path):
                    self.feature_names[ioc_type] = joblib.load(feature_names_path)
                    print(f"Loaded {ioc_type} feature names from {feature_names_path}")
                else:
                    print(f"Warning: {ioc_type} feature names not found at {feature_names_path}")

            except Exception as e:
                print(f"Error loading {ioc_type} models: {e}")
                continue

        print(f"Loaded models for IOC types: {list(self.models.keys())}")

    def _extract_features_for_ioc_type(self, ioc: ThreatIOC, ioc_type: str) -> pd.DataFrame:
        """Extract features for specific IOC type matching training code."""
        if ioc_type == 'domain':
            return self._extract_domain_features(ioc)
        elif ioc_type == 'url':
            return self._extract_url_features(ioc)
        elif ioc_type == 'ip':
            return self._extract_ip_features(ioc)
        elif ioc_type == 'hash':
            return self._extract_hash_features(ioc)
        elif ioc_type == 'network':
            return self._extract_network_features(ioc)
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")

    def _calculate_dynamic_risk_score(self, ioc: ThreatIOC) -> float:
        """Calculate dynamic risk score based on available data."""
        score = 0.0

        # Base score from database
        if ioc.risk_score:
            score += float(ioc.risk_score)

        # Enrichment-based scoring
        if ioc.enrichments:
            for enrichment in ioc.enrichments:
                if enrichment.enrichment_type == "virustotal":
                    vt_data = enrichment.data
                    if isinstance(vt_data, dict):
                        malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
                        total = sum(vt_data.get("last_analysis_stats", {}).values())
                        if total > 0:
                            score += (malicious / total) * 0.8

                        reputation = vt_data.get("reputation", 0)
                        if reputation < 0:
                            score += min(abs(reputation) / 100, 0.5)

        # Fallback scoring based on IOC characteristics
        if not ioc.enrichments or score == 0.0:
            score += self._calculate_fallback_risk_score(ioc)

        return min(score, 1.0)

    def _calculate_fallback_risk_score(self, ioc: ThreatIOC) -> float:
        """Calculate risk score based on IOC value characteristics."""
        score = 0.0
        value = ioc.value.lower()

        # Length-based scoring
        if len(value) > 100:
            score += 0.3  # Suspiciously long
        elif len(value) < 5:
            score += 0.1  # Very short

        # Character-based scoring
        if ioc.type == 'url':
            # Check for suspicious URL patterns
            suspicious_patterns = ['admin', 'login', 'password', 'bank', 'paypal', 'secure']
            for pattern in suspicious_patterns:
                if pattern in value:
                    score += 0.1

            # Check for IP in URL
            import re
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            if re.search(ip_pattern, value):
                score += 0.2  # IP addresses in URLs are suspicious

        elif ioc.type == 'domain':
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz']
            for tld in suspicious_tlds:
                if value.endswith(tld):
                    score += 0.3

            # Check for long subdomains
            parts = value.split('.')
            if len(parts) > 3:
                score += 0.2

        elif ioc.type == 'hash':
            # Hashes themselves are neutral, but length can indicate type
            if len(value) == 32:  # MD5
                score += 0.1
            elif len(value) == 64:  # SHA256
                score += 0.2

        return min(score, 0.8)  # Cap fallback score

    def _extract_domain_features(self, ioc: ThreatIOC) -> pd.DataFrame:
        """Extract domain features matching train_domain.py"""
        domain = ioc.value.lower().strip()

        # Remove invalid domains
        if len(domain) < 3 or not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
            # Return empty DataFrame with expected columns
            return pd.DataFrame()

        df = pd.DataFrame([{'domain': domain, 'is_malicious': 0}])  # Dummy target

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

        # 3. TLD ANALYSIS
        def extract_tld(domain):
            parts = domain.split('.')
            return parts[-1] if len(parts) > 1 else ''

        df['tld'] = df['domain'].apply(extract_tld)

        common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'uk', 'de',
                      'fr', 'jp', 'cn', 'ca', 'au', 'in', 'br', 'ru', 'it', 'es', 'nl']
        new_tlds = ['xyz', 'top', 'site', 'online', 'tech', 'shop', 'club', 'app', 'dev', 'ai']
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'review', 'bid', 'win']

        df['has_common_tld'] = df['tld'].apply(lambda x: 1 if x in common_tlds else 0)
        df['has_new_tld'] = df['tld'].apply(lambda x: 1 if x in new_tlds else 0)
        df['has_suspicious_tld'] = df['tld'].apply(lambda x: 1 if x in suspicious_tlds else 0)
        df['tld_length'] = df['tld'].apply(len)
        df['tld_is_numeric'] = df['tld'].apply(lambda x: 1 if x.isdigit() else 0)

        # 4. DOMAIN NAME ANALYSIS
        def get_name_without_tld(domain):
            parts = domain.split('.')
            return '.'.join(parts[:-1]) if len(parts) > 1 else domain

        df['name_without_tld'] = df['domain'].apply(get_name_without_tld)
        df['name_length'] = df['name_without_tld'].apply(len)

        # 5. PATTERN ANALYSIS
        def starts_with_digit(s):
            return 1 if s and s[0].isdigit() else 0

        df['starts_with_digit'] = df['name_without_tld'].apply(starts_with_digit)

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

        suspicious_patterns = ['login', 'secure', 'verify', 'account', 'banking', 'payment',
                             'free', 'gift', 'bonus', 'win', 'prize', 'click', 'download']

        df['has_suspicious_pattern'] = df['name_without_tld'].apply(
            lambda x: 1 if any(pattern in x.lower() for pattern in suspicious_patterns) else 0
        )

        # 6. ENTROPY
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

        # 10. REPETITIVE PATTERNS
        def has_repetitive_pattern(s):
            if len(s) < 4:
                return 0
            s = s.lower()
            for i in range(len(s) - 3):
                if s[i] == s[i+1] == s[i+2]:
                    return 1
            return 0

        df['has_repetitive_chars'] = df['name_without_tld'].apply(has_repetitive_pattern)

        # 11. MIXED CASE
        df['has_mixed_case'] = df['domain'].apply(
            lambda x: 1 if any(c.isupper() for c in x) and any(c.islower() for c in x) else 0
        )

        # 12. CONSECUTIVE SPECIAL CHARS
        def has_consecutive_special(s):
            for i in range(len(s) - 1):
                if s[i] in '-_' and s[i+1] in '-_':
                    return 1
            return 0

        df['has_consecutive_special'] = df['domain'].apply(has_consecutive_special)

        # 13. SUSPICIOUS TLD-LENGTH DOMAIN NAMES
        df['is_short_with_new_tld'] = df.apply(
            lambda row: 1 if row['name_length'] <= 5 and row['has_new_tld'] == 1 else 0, axis=1
        )

        # DROP TEMPORARY COLUMNS
        columns_to_drop = ['domain', 'tld', 'name_without_tld', 'is_malicious']
        df = df.drop([col for col in columns_to_drop if col in df.columns], axis=1, errors='ignore')

        # Fill NaN values
        df = df.fillna(0)

        return df

    def _extract_url_features(self, ioc: ThreatIOC) -> pd.DataFrame:
        """Extract URL features matching train_url.py"""
        url = ioc.value.strip()

        # Basic URL validation
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return pd.DataFrame()
        except:
            return pd.DataFrame()

        df = pd.DataFrame([{'url': url, 'is_malicious': 0}])  # Dummy target

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

        # 9. ENTROPY CALCULATION
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

        # Check for digits in domain name
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

        # 27. SUSPICIOUS HASH PATTERNS
        def has_suspicious_hash(url):
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
        columns_to_drop = ['url', 'domain', 'path', 'query', 'tld', 'domain_name', 'fragment', 'is_malicious']
        df = df.drop([col for col in columns_to_drop if col in df.columns], axis=1, errors='ignore')

        # Fill NaN values
        df = df.fillna(0)

        return df

    def _extract_ip_features(self, ioc: ThreatIOC) -> pd.DataFrame:
        """Extract IP features matching train_ip.py"""
        ip_str = ioc.value.strip()

        # Validate IP
        try:
            ipaddress.IPv4Address(ip_str)
        except:
            return pd.DataFrame()

        df = pd.DataFrame([{'ip': ip_str, 'is_malicious': 0}])  # Dummy target

        # Remove risk_score and source columns to prevent data leakage (not applicable here)

        # 1. BASIC OCTET FEATURES
        octets = df['ip'].str.split('.', expand=True).astype(float)
        df = pd.concat([df, octets], axis=1)
        df = df.rename(columns={0: 'octet1', 1: 'octet2', 2: 'octet3', 3: 'octet4'})

        # 2. IP AS INTEGER
        df['ip_int'] = df['ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))

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
        common_malicious_ends = [1, 254, 100, 200, 66, 88, 99]
        df['has_suspicious_end'] = df['octet4'].isin(common_malicious_ends).astype(int)

        # 12. OCTET ENTROPY
        def calculate_octet_entropy(row):
            octets = [row['octet1'], row['octet2'], row['octet3'], row['octet4']]
            values, counts = np.unique(octets, return_counts=True)
            probs = counts / len(octets)
            return -np.sum(probs * np.log2(probs))

        df['octet_entropy'] = df.apply(calculate_octet_entropy, axis=1)

        # 13. GEOGRAPHICAL HINTS
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

        # DROP ORIGINAL IP COLUMN AND TEMP COLUMNS
        df = df.drop(['ip', 'ip_class', 'is_malicious'], axis=1, errors='ignore')

        # Fill NaN values
        df = df.fillna(0)

        return df

    def _extract_hash_features(self, ioc: ThreatIOC) -> pd.DataFrame:
        """Extract hash features matching train_hash.py"""
        h = ioc.value.lower().strip()

        # Basic validation
        if not re.match(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', h, re.IGNORECASE):
            return pd.DataFrame()

        df = pd.DataFrame([{'hash': h, 'is_malicious': 0}])  # Dummy target

        df["length"] = df['hash'].apply(len)
        df["is_hex"] = df['hash'].apply(lambda x: int(all(c in "0123456789abcdef" for c in x)))

        # Character counts
        counts_df = df['hash'].apply(lambda x: Counter(x))
        df['entropy'] = counts_df.apply(self._calculate_hash_entropy)
        df['unique_ratio'] = counts_df.apply(lambda c: len(c) / len(df['hash'].iloc[0]) if len(df['hash']) > 0 else 0)
        df['digit_ratio'] = df['hash'].apply(lambda x: sum(c.isdigit() for c in x) / len(x) if len(x) > 0 else 0)
        df['letter_ratio'] = df['hash'].apply(lambda x: sum(c.isalpha() for c in x) / len(x) if len(x) > 0 else 0)

        # Runs
        df['max_run'] = df['hash'].apply(self._calculate_max_run)

        # Transitions
        df['transition_ratio'] = df['hash'].apply(self._calculate_transition_ratio)

        # Drop temporary columns
        df = df.drop(['hash', 'is_malicious'], axis=1, errors='ignore')

        # Fill NaN values
        df = df.fillna(0)

        return df

    def _calculate_hash_entropy(self, counter):
        """Calculate entropy for hash"""
        total = sum(counter.values())
        if total <= 1:
            return 0
        entropy = -sum((v/total) * np.log2(v/total) for v in counter.values())
        return entropy

    def _calculate_max_run(self, h):
        """Calculate maximum run length"""
        max_run = 1
        cur = 1
        for i in range(1, len(h)):
            if h[i] == h[i-1]:
                cur += 1
                max_run = max(max_run, cur)
            else:
                cur = 1
        return max_run

    def _calculate_transition_ratio(self, h):
        """Calculate transition ratio"""
        if len(h) <= 1:
            return 0
        transitions = sum(h[i].isdigit() != h[i-1].isdigit() for i in range(1, len(h)))
        return transitions / (len(h) - 1)

    def _extract_network_features(self, ioc: ThreatIOC) -> pd.DataFrame:
        """Extract network features matching train_network.py"""
        # For network IOCs, we need packet data. Since we don't have real network data,
        # we'll create a basic structure. In production, this would come from network monitoring.

        # For now, create dummy features based on typical network anomaly detection
        # This is a placeholder - real implementation would need actual network packet data

        df = pd.DataFrame([{
            'packet_count': 100,  # Dummy values
            'bytes_transferred': 50000,
            'duration_seconds': 30,
            'connection_count': 5,
            'failed_connections': 0,
            'is_malicious': 0  # Dummy target
        }])

        # 1. BASIC DERIVED FEATURES
        df['packets_per_second'] = df['packet_count'] / (df['duration_seconds'] + 0.001)
        df['bytes_per_second'] = df['bytes_transferred'] / (df['duration_seconds'] + 0.001)
        df['avg_packet_size'] = df['bytes_transferred'] / (df['packet_count'] + 0.001)

        # 2. CONNECTION INTENSITY FEATURES
        df['connections_per_second'] = df['connection_count'] / (df['duration_seconds'] + 0.001)

        # 3. FAILURE RATE
        df['failure_rate'] = df['failed_connections'] / (df['connection_count'] + 0.001)

        # 4. TRAFFIC DENSITY
        df['packets_per_connection'] = df['packet_count'] / (df['connection_count'] + 0.001)

        # 5. BYTE EFFICIENCY
        df['bytes_per_packet'] = df['bytes_transferred'] / (df['packet_count'] + 0.001)

        # 6. TRAFFIC BURSTINESS
        df['traffic_burstiness'] = df['packets_per_second'] * df['bytes_per_second'] / 1000

        # 7. SESSION DURATION CATEGORY
        df['session_duration_norm'] = np.log1p(df['duration_seconds'])

        # 8. PACKET SIZE VARIABILITY
        df['packet_size_variability'] = df['avg_packet_size'] / (df['bytes_per_packet'] + 0.001)

        # 9. CONNECTION SUCCESS RATE
        df['success_rate'] = 1 - df['failure_rate']

        # 10. TRAFFIC INTENSITY SCORE
        df['traffic_intensity_score'] = (
            df['packets_per_second'] * df['bytes_per_second'] * df['connections_per_second']
        ) / 1000000

        # Drop temporary columns
        df = df.drop(['is_malicious'], axis=1, errors='ignore')

        # Fill NaN values
        df = df.fillna(0)

        return df

    def classify_threat(self, ioc_id: int, db_session) -> AIPrediction:
        """Classify a threat IOC using trained domain-specific models."""
        ioc = db_session.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
        if not ioc:
            return None

        ioc_type = ioc.type

        # Check if we have a trained model for this IOC type
        if ioc_type not in self.models:
            print(f"No trained model available for IOC type: {ioc_type}")
            return self._create_fallback_prediction(ioc_id, ioc)

        # Extract features
        try:
            features_df = self._extract_features_for_ioc_type(ioc, ioc_type)
            if features_df.empty:
                print(f"Feature extraction failed for IOC type: {ioc_type}")
                return self._create_fallback_prediction(ioc_id, ioc)
        except Exception as e:
            print(f"Error extracting features for {ioc_type}: {e}")
            return self._create_fallback_prediction(ioc_id, ioc)

        # Select features using trained selector
        if ioc_type in self.selectors and ioc_type in self.feature_names:
            try:
                selected_features = self.feature_names[ioc_type]
                features_selected = features_df[selected_features]
            except Exception as e:
                print(f"Error selecting features for {ioc_type}: {e}")
                return self._create_fallback_prediction(ioc_id, ioc)
        else:
            print(f"No feature selector available for {ioc_type}")
            return self._create_fallback_prediction(ioc_id, ioc)

        # Scale features
        if ioc_type in self.scalers:
            try:
                features_scaled = self.scalers[ioc_type].transform(features_selected)
            except Exception as e:
                print(f"Error scaling features for {ioc_type}: {e}")
                return self._create_fallback_prediction(ioc_id, ioc)
        else:
            print(f"No scaler available for {ioc_type}")
            return self._create_fallback_prediction(ioc_id, ioc)

        # Make prediction
        try:
            model = self.models[ioc_type]

            if ioc_type == 'hash':
                # Hash is a risk scorer, not binary classifier
                risk_score = model.predict_proba(features_scaled)[0][1]
                prediction = 'malicious' if risk_score > 0.5 else 'benign'
                confidence = risk_score
            else:
                # Binary classification
                prediction_proba = model.predict_proba(features_scaled)[0]
                prediction = 'malicious' if model.predict(features_scaled)[0] == 1 else 'benign'
                confidence = max(prediction_proba)

        except Exception as e:
            print(f"Error making prediction for {ioc_type}: {e}")
            return self._create_fallback_prediction(ioc_id, ioc)

        # Create features dict for explanation
        features_dict = features_df.iloc[0].to_dict()
        features_dict.update({
            'ioc_type': ioc.type,
            'value': ioc.value,
            'model_used': f'{ioc_type}_model',
            'confidence': float(confidence)
        })

        # Generate explanation
        explanation = self._generate_detailed_explanation(ioc, prediction, confidence, features_dict, ioc_type)

        prediction_obj = AIPrediction(
            ioc_id=ioc_id,
            model_name=f'{ioc_type}_model',
            prediction=prediction,
            confidence=confidence,
            features_used=features_dict,
            explanation=explanation
        )

        return prediction_obj

    def _create_fallback_prediction(self, ioc_id: int, ioc: ThreatIOC) -> AIPrediction:
        """Create a fallback prediction when model is not available."""
        features_dict = {
            'ioc_type': ioc.type,
            'value': ioc.value,
            'model_used': 'fallback',
            'confidence': 0.5
        }

        explanation = f"Fallback prediction: No trained model available for {ioc.type} IOCs. " \
                     f"IOC value: {ioc.value}. Please train a model for this IOC type."

        return AIPrediction(
            ioc_id=ioc_id,
            model_name='fallback',
            prediction='unknown',
            confidence=0.5,
            features_used=features_dict,
            explanation=explanation
        )


    def _generate_detailed_explanation(self, ioc: ThreatIOC, prediction: str, confidence: float,
                                     features_dict: Dict[str, Any], ioc_type: str) -> str:
        """Generate detailed explanation for the prediction."""
        explanation = f"AI Analysis Result for {ioc_type.upper()} IOC\n"
        explanation += "=" * 50 + "\n\n"

        explanation += f"IOC Details:\n"
        explanation += f"- Type: {ioc.type}\n"
        explanation += f"- Value: {ioc.value}\n"
        explanation += f"- Source: {ioc.source or 'Unknown'}\n"
        explanation += f"- First Seen: {ioc.first_seen or 'Unknown'}\n"
        explanation += f"- Last Seen: {ioc.last_seen or 'Unknown'}\n\n"

        explanation += f"Prediction: {prediction.upper()}\n"
        explanation += f"Confidence: {confidence:.4f} ({confidence*100:.1f}%)\n\n"

        explanation += f"Model Used: {ioc_type}_model (trained on domain-specific features)\n\n"

        explanation += "Key Features Analyzed:\n"
        # Show top 10 most relevant features
        important_features = [
            'domain_length', 'url_length', 'ip_int', 'length', 'entropy',
            'has_suspicious_pattern', 'suspicious_keyword_count', 'is_private',
            'packets_per_second', 'bytes_per_second'
        ]

        for feature in important_features:
            if feature in features_dict:
                value = features_dict[feature]
                if isinstance(value, float):
                    explanation += f"- {feature}: {value:.4f}\n"
                else:
                    explanation += f"- {feature}: {value}\n"

        explanation += "\n"
        explanation += "Analysis Summary:\n"
        if prediction == 'malicious':
            explanation += f"- This {ioc_type} has been classified as MALICIOUS with {confidence*100:.1f}% confidence.\n"
            explanation += "- The AI model detected suspicious patterns consistent with known threats.\n"
        elif prediction == 'benign':
            explanation += f"- This {ioc_type} has been classified as BENIGN with {confidence*100:.1f}% confidence.\n"
            explanation += "- The AI model found no significant indicators of malicious activity.\n"
        else:
            explanation += "- Unable to make a confident classification. Further analysis recommended.\n"

        return explanation

    def _calculate_dynamic_risk_score(self, ioc: ThreatIOC) -> float:
        """Calculate dynamic risk score (kept for compatibility)."""
        score = 0.0

        if ioc.risk_score:
            score += float(ioc.risk_score)

        if ioc.enrichments:
            for enrichment in ioc.enrichments:
                if enrichment.enrichment_type == "virustotal":
                    try:
                        vt_data = enrichment.data
                        if isinstance(vt_data, dict):
                            malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
                            total = sum(vt_data.get("last_analysis_stats", {}).values())
                            if total > 0:
                                score += (malicious / total) * 0.8

                            reputation = vt_data.get("reputation", 0)
                            if reputation < 0:
                                score += min(abs(reputation) / 100, 0.5)
                    except:
                        pass

        return min(score, 1.0)

# Global instance
ai_service = AIClassificationService()

# Global instance
ai_service = AIClassificationService()