from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import numpy as np
from typing import Dict, Any, List
from ..models.models import AIPrediction, ThreatIOC, ThreatInput
from ..db.session import SessionLocal
import pickle
import os
from datetime import datetime
import joblib
import warnings

class AIClassificationService:
    """AI-based threat classification service."""

    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.model_dir = os.getenv('MODEL_STORAGE_PATH', './models')
        os.makedirs(self.model_dir, exist_ok=True)
        self._load_models()

    def _load_models(self):
        """Load or initialize ML models."""
        # Suppress sklearn version warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

        # Load scaler
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        if os.path.exists(scaler_path):
            try:
                self.scaler = joblib.load(scaler_path)
                print(f"Successfully loaded scaler from {scaler_path}")
            except Exception as e:
                print(f"Error loading scaler: {e}, using default")
                self.scaler = StandardScaler()
        else:
            print("Scaler not found, using default StandardScaler")
            self.scaler = StandardScaler()

        # Random Forest
        rf_path = os.path.join(self.model_dir, 'random_forest.pkl')
        if os.path.exists(rf_path):
            try:
                self.models['random_forest'] = joblib.load(rf_path)
                print(f"Successfully loaded random_forest model from {rf_path}")
            except Exception as e:
                print(f"Error loading random_forest model: {e}, using default")
                self.models['random_forest'] = RandomForestClassifier(n_estimators=100, random_state=42)
        else:
            self.models['random_forest'] = RandomForestClassifier(n_estimators=100, random_state=42)

        # Logistic Regression
        lr_path = os.path.join(self.model_dir, 'logistic_regression.pkl')
        if os.path.exists(lr_path):
            try:
                self.models['logistic_regression'] = joblib.load(lr_path)
                print(f"Successfully loaded logistic_regression model from {lr_path}")
            except Exception as e:
                print(f"Error loading logistic_regression model: {e}, using default")
                self.models['logistic_regression'] = LogisticRegression(random_state=42)
        else:
            self.models['logistic_regression'] = LogisticRegression(random_state=42)

        # Isolation Forest for anomaly detection
        if_path = os.path.join(self.model_dir, 'isolation_forest.pkl')
        if os.path.exists(if_path):
            try:
                self.models['isolation_forest'] = joblib.load(if_path)
                print(f"Successfully loaded isolation_forest model from {if_path}")
            except Exception as e:
                print(f"Error loading isolation_forest model: {e}, using default")
                self.models['isolation_forest'] = IsolationForest(random_state=42)
        else:
            self.models['isolation_forest'] = IsolationForest(random_state=42)

        # One-Class SVM
        svm_path = os.path.join(self.model_dir, 'one_class_svm.pkl')
        if os.path.exists(svm_path):
            try:
                self.models['one_class_svm'] = joblib.load(svm_path)
                print(f"Successfully loaded one_class_svm model from {svm_path}")
            except Exception as e:
                print(f"Error loading one_class_svm model: {e}, using default")
                self.models['one_class_svm'] = OneClassSVM(kernel='rbf', gamma='auto')
        else:
            self.models['one_class_svm'] = OneClassSVM(kernel='rbf', gamma='auto')

    def _extract_features(self, ioc: ThreatIOC, db_session) -> np.ndarray:
        """Extract features from IOC for classification."""
        features = []

        # Basic features
        type_encoded = {'ip': 0, 'domain': 1, 'url': 2, 'hash': 3}.get(ioc.type, 0)
        features.append(type_encoded)

        # Length features
        value_length = len(ioc.value)
        features.append(value_length)
        features.append(len(ioc.value.split('.')) if '.' in ioc.value else 0)

        # Dynamic risk score calculation
        risk_score = self._calculate_dynamic_risk_score(ioc)
        features.append(risk_score)

        # Enrichment count
        enrichment_count = len(ioc.enrichments) if ioc.enrichments else 0
        features.append(enrichment_count)

        # Alert count
        alert_count = len(ioc.alerts) if ioc.alerts else 0
        features.append(alert_count)

        # Time-based features
        if ioc.first_seen:
            days_since_first = (datetime.utcnow() - ioc.first_seen).days
            features.append(days_since_first)
        else:
            features.append(0)

        if ioc.last_seen:
            days_since_last = (datetime.utcnow() - ioc.last_seen).days
            features.append(days_since_last)
        else:
            features.append(0)

        # Source reputation (simplified)
        source_score = {'User Input': 0.5, 'AlienVault OTX': 0.8, 'AbuseIPDB': 0.7}.get(ioc.source, 0.5)
        features.append(source_score)

        # Additional IOC-specific features
        features.extend(self._extract_ioc_specific_features(ioc))

        return np.array(features).reshape(1, -1)

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

    def _extract_supervised_features(self, ioc: ThreatIOC, db_session) -> np.ndarray:
        """Extract features for supervised models (RF, LR) - expect 11 features."""
        features = []

        # Basic features (same as original)
        type_encoded = {'ip': 0, 'domain': 1, 'url': 2, 'hash': 3}.get(ioc.type, 0)
        features.append(type_encoded)

        # Length features
        value_length = len(ioc.value)
        features.append(value_length)
        features.append(len(ioc.value.split('.')) if '.' in ioc.value else 0)

        # Risk score
        risk_score = self._calculate_dynamic_risk_score(ioc)
        features.append(risk_score)

        # Enrichment count
        enrichment_count = len(ioc.enrichments) if ioc.enrichments else 0
        features.append(enrichment_count)

        # Alert count
        alert_count = len(ioc.alerts) if ioc.alerts else 0
        features.append(alert_count)

        # Time-based features
        if ioc.first_seen:
            days_since_first = (datetime.utcnow() - ioc.first_seen).days
            features.append(days_since_first)
        else:
            features.append(0)

        if ioc.last_seen:
            days_since_last = (datetime.utcnow() - ioc.last_seen).days
            features.append(days_since_last)
        else:
            features.append(0)

        # Source reputation
        source_score = {'User Input': 0.5, 'AlienVault OTX': 0.8, 'AbuseIPDB': 0.7}.get(ioc.source, 0.5)
        features.append(source_score)

        # Additional features to reach 11 total
        value = ioc.value.lower()
        alpha_ratio = sum(1 for c in value if c.isalpha()) / len(value) if len(value) > 0 else 0
        digit_ratio = sum(1 for c in value if c.isdigit()) / len(value) if len(value) > 0 else 0
        features.append(alpha_ratio)
        features.append(digit_ratio)

        # Ensure exactly 11 features
        while len(features) < 11:
            features.append(0.0)

        return np.array(features[:11]).reshape(1, -1)

    def _extract_unsupervised_features(self, ioc: ThreatIOC, db_session) -> np.ndarray:
        """Extract features for unsupervised models (IF, OCSVM) - expect 4 features."""
        features = []

        # Based on training code, unsupervised models get basic numeric features
        # From the training: X_scaled[y == 0] for benign samples
        # The features are likely: [ioc_type_encoded, value_length, risk_score, source_score]

        type_encoded = {'ip': 0, 'domain': 1, 'url': 2, 'hash': 3}.get(ioc.type, 0)
        features.append(float(type_encoded))

        value_length = len(ioc.value)
        features.append(float(value_length))

        risk_score = self._calculate_dynamic_risk_score(ioc)
        features.append(float(risk_score))

        source_score = {'User Input': 0.5, 'AlienVault OTX': 0.8, 'AbuseIPDB': 0.7}.get(ioc.source, 0.5)
        features.append(float(source_score))

        # Ensure exactly 4 features
        return np.array(features[:4]).reshape(1, -1)

    def _extract_ioc_specific_features(self, ioc: ThreatIOC) -> List[float]:
        """Extract additional IOC-specific features."""
        features = []
        value = ioc.value.lower()

        # Character distribution features
        alpha_count = sum(1 for c in value if c.isalpha())
        digit_count = sum(1 for c in value if c.isdigit())
        special_count = sum(1 for c in value if not c.isalnum())

        features.append(alpha_count / len(value) if len(value) > 0 else 0)  # Alpha ratio
        features.append(digit_count / len(value) if len(value) > 0 else 0)  # Digit ratio
        features.append(special_count / len(value) if len(value) > 0 else 0)  # Special char ratio

        # Entropy calculation (simple)
        entropy = 0
        for char in set(value):
            p = value.count(char) / len(value)
            if p > 0:
                entropy -= p * np.log2(p)
        features.append(entropy)

        # Type-specific features
        if ioc.type == 'url':
            features.extend(self._extract_url_features(value))
        elif ioc.type == 'domain':
            features.extend(self._extract_domain_features(value))
        elif ioc.type == 'ip':
            features.extend(self._extract_ip_features(value))
        else:
            # Default features for hash or unknown
            features.extend([0, 0, 0])

        return features

    def _extract_url_features(self, url: str) -> List[float]:
        """Extract URL-specific features."""
        features = []

        # Protocol
        has_https = 1 if url.startswith('https://') else 0
        features.append(has_https)

        # Domain length
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            features.append(len(domain))
            features.append(len(domain.split('.')))
        except:
            features.extend([0, 0])

        # Path length
        try:
            path = parsed.path
            features.append(len(path))
        except:
            features.append(0)

        return features

    def _extract_domain_features(self, domain: str) -> List[float]:
        """Extract domain-specific features."""
        features = []

        # Subdomain count
        parts = domain.split('.')
        features.append(len(parts) - 1)  # Number of dots

        # Length of each part
        if len(parts) >= 2:
            features.append(len(parts[-2]))  # Second level domain length
            features.append(len(parts[-1]))  # TLD length
        else:
            features.extend([0, 0])

        return features

    def _extract_ip_features(self, ip: str) -> List[float]:
        """Extract IP-specific features."""
        features = []

        try:
            parts = ip.split('.')
            if len(parts) == 4:
                # Convert to numerical features
                features.extend([int(p) for p in parts])
            else:
                features.extend([0, 0, 0, 0])
        except:
            features.extend([0, 0, 0, 0])

        return features

    def classify_threat(self, ioc_id: int, db_session) -> AIPrediction:
        """Classify a threat IOC using ensemble of models."""
        ioc = db_session.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
        if not ioc:
            return None

        predictions = []
        confidences = []
        model_details = {}

        # Extract features for supervised models (RF, LR) - expect 11 features
        supervised_features = self._extract_supervised_features(ioc, db_session)

        # Extract features for unsupervised models (IF, OCSVM) - expect 4 features
        unsupervised_features = self._extract_unsupervised_features(ioc, db_session)

        # Random Forest - uses supervised features (11 features)
        try:
            rf_pred = self.models['random_forest'].predict(supervised_features)[0]
            rf_proba = self.models['random_forest'].predict_proba(supervised_features)[0]
            pred_label = 'malicious' if rf_pred == 1 else 'benign'
            predictions.append(pred_label)
            confidences.append(max(rf_proba))
            model_details['random_forest'] = {'prediction': pred_label, 'confidence': max(rf_proba)}
        except Exception as e:
            print(f"Random Forest prediction failed: {e}")
            predictions.append('unknown')
            confidences.append(0.5)
            model_details['random_forest'] = {'prediction': 'unknown', 'confidence': 0.5}

        # Logistic Regression - uses supervised features (11 features)
        try:
            lr_pred = self.models['logistic_regression'].predict(supervised_features)[0]
            lr_proba = self.models['logistic_regression'].predict_proba(supervised_features)[0]
            pred_label = 'malicious' if lr_pred == 1 else 'benign'
            predictions.append(pred_label)
            confidences.append(max(lr_proba))
            model_details['logistic_regression'] = {'prediction': pred_label, 'confidence': max(lr_proba)}
        except Exception as e:
            print(f"Logistic Regression prediction failed: {e}")
            predictions.append('unknown')
            confidences.append(0.5)
            model_details['logistic_regression'] = {'prediction': 'unknown', 'confidence': 0.5}

        # Isolation Forest - uses unsupervised features (4 features)
        try:
            if_pred = self.models['isolation_forest'].predict(unsupervised_features)[0]
            # Isolation Forest: -1 = anomaly (malicious), 1 = normal (benign)
            pred_label = 'malicious' if if_pred == -1 else 'benign'
            # Calculate confidence based on anomaly score
            if_score = self.models['isolation_forest'].decision_function(unsupervised_features)[0]
            # Anomaly score: negative = more anomalous, positive = more normal
            confidence = 1 / (1 + np.exp(if_score))  # Sigmoid to convert to 0-1 scale
            predictions.append(pred_label)
            confidences.append(confidence)
            model_details['isolation_forest'] = {'prediction': pred_label, 'confidence': confidence}
        except Exception as e:
            print(f"Isolation Forest prediction failed: {e}")
            predictions.append('unknown')
            confidences.append(0.5)
            model_details['isolation_forest'] = {'prediction': 'unknown', 'confidence': 0.5}

        # One-Class SVM - uses unsupervised features (4 features)
        try:
            svm_pred = self.models['one_class_svm'].predict(unsupervised_features)[0]
            # One-Class SVM: -1 = outlier (malicious), 1 = inlier (benign)
            pred_label = 'malicious' if svm_pred == -1 else 'benign'
            # Calculate confidence based on decision function
            svm_score = self.models['one_class_svm'].decision_function(unsupervised_features)[0]
            confidence = 1 / (1 + np.exp(-svm_score))  # Sigmoid to convert to 0-1 scale
            predictions.append(pred_label)
            confidences.append(confidence)
            model_details['one_class_svm'] = {'prediction': pred_label, 'confidence': confidence}
        except Exception as e:
            print(f"One-Class SVM prediction failed: {e}")
            predictions.append('unknown')
            confidences.append(0.5)
            model_details['one_class_svm'] = {'prediction': 'unknown', 'confidence': 0.5}

        # Ensemble decision with weighted voting
        malicious_count = predictions.count('malicious')
        benign_count = predictions.count('benign')
        unknown_count = predictions.count('unknown')

        # Weighted decision based on confidence
        malicious_weight = sum(conf for pred, conf in zip(predictions, confidences) if pred == 'malicious')
        benign_weight = sum(conf for pred, conf in zip(predictions, confidences) if pred == 'benign')

        if malicious_weight > benign_weight and malicious_count >= 2:
            final_prediction = 'malicious'
            final_confidence = malicious_weight / sum(confidences)
        elif benign_weight > malicious_weight and benign_count >= 2:
            final_prediction = 'benign'
            final_confidence = benign_weight / sum(confidences)
        elif malicious_count > benign_count:
            final_prediction = 'malicious'
            final_confidence = np.mean([c for p, c in zip(predictions, confidences) if p == 'malicious'])
        elif benign_count > malicious_count:
            final_prediction = 'benign'
            final_confidence = np.mean([c for p, c in zip(predictions, confidences) if p == 'benign'])
        else:
            final_prediction = 'suspicious'  # Changed from 'unknown' to 'suspicious'
            final_confidence = 0.5


        # Enhanced features dict
        features_dict = self._get_features_dict(ioc)

        # Add vote counts to features for frontend display
        features_dict.update({
            'malicious_votes': malicious_count,
            'benign_votes': benign_count,
            'unknown_votes': unknown_count
        })

        # Detailed explanation
        explanation = self._generate_explanation(predictions, confidences, malicious_count, benign_count, unknown_count, features_dict, model_details)

        prediction = AIPrediction(
            ioc_id=ioc_id,
            model_name='ensemble_classifier',
            prediction=final_prediction,
            confidence=final_confidence,
            features_used=features_dict,
            explanation=explanation
        )

        return prediction

    def _get_features_dict(self, ioc: ThreatIOC) -> Dict[str, Any]:
        """Get comprehensive features dictionary."""
        features_dict = {
            'ioc_type': ioc.type,
            'value_length': len(ioc.value),
            'risk_score': self._calculate_dynamic_risk_score(ioc),
            'enrichment_count': len(ioc.enrichments) if ioc.enrichments else 0,
            'alert_count': len(ioc.alerts) if ioc.alerts else 0,
            'days_since_first_seen': (datetime.utcnow() - ioc.first_seen).days if ioc.first_seen else 0,
            'days_since_last_seen': (datetime.utcnow() - ioc.last_seen).days if ioc.last_seen else 0,
            'source_score': {'User Input': 0.5, 'AlienVault OTX': 0.8, 'AbuseIPDB': 0.7}.get(ioc.source, 0.5)
        }

        # Add IOC-specific features
        value = ioc.value.lower()
        features_dict.update({
            'alpha_ratio': sum(1 for c in value if c.isalpha()) / len(value) if len(value) > 0 else 0,
            'digit_ratio': sum(1 for c in value if c.isdigit()) / len(value) if len(value) > 0 else 0,
            'special_ratio': sum(1 for c in value if not c.isalnum()) / len(value) if len(value) > 0 else 0,
        })

        return features_dict

    def _generate_explanation(self, predictions: List[str], confidences: List[float],
                            malicious_count: int, benign_count: int, unknown_count: int,
                            features_dict: Dict[str, Any], model_details: Dict[str, Any]) -> str:
        """Generate detailed explanation for the prediction."""
        explanation = f"Ensemble Analysis Result: {malicious_count} malicious, {benign_count} benign, {unknown_count} unknown votes.\n\n"

        explanation += "Model Breakdown:\n"
        for model_name, details in model_details.items():
            explanation += f"- {model_name.replace('_', ' ').title()}: {details['prediction'].title()} "
            explanation += f"(Confidence: {details['confidence']:.2%})\n"

        explanation += f"\nFinal Decision: {predictions.count('malicious') > predictions.count('benign') and 'Malicious' or 'Benign'}\n"
        explanation += f"Overall Confidence: {np.mean(confidences):.2%}\n\n"

        explanation += "Key Features Analyzed:\n"
        for key, value in features_dict.items():
            if isinstance(value, float):
                explanation += f"- {key.replace('_', ' ').title()}: {value:.3f}\n"
            else:
                explanation += f"- {key.replace('_', ' ').title()}: {value}\n"

        return explanation

    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train models with labeled data."""
        if not training_data:
            return

        # Prepare supervised features (11 features for RF, LR)
        X_supervised = []
        # Prepare unsupervised features (4 features for IF, OCSVM)
        X_unsupervised = []
        y = []

        for item in training_data:
            # Supervised features (11 features)
            supervised_features = [
                item.get('ioc_type_encoded', 0),
                item.get('value_length', 0),
                item.get('risk_score', 0.0),
                item.get('enrichment_count', 0),
                item.get('alert_count', 0),
                item.get('days_since_first', 0),
                item.get('days_since_last', 0),
                item.get('source_score', 0.5),
                item.get('alpha_ratio', 0.0),
                item.get('digit_ratio', 0.0),
                0.0  # Padding to reach 11 features
            ]
            X_supervised.append(supervised_features)

            # Unsupervised features (4 features)
            unsupervised_features = [
                item.get('ioc_type_encoded', 0),
                item.get('value_length', 0),
                item.get('risk_score', 0.0),
                item.get('source_score', 0.5)
            ]
            X_unsupervised.append(unsupervised_features)

            y.append(1 if item.get('label') == 'malicious' else 0)

        X_supervised = np.array(X_supervised)
        X_unsupervised = np.array(X_unsupervised)
        y = np.array(y)

        if len(X_supervised) == 0:
            return

        # Scale supervised features
        X_supervised_scaled = self.scaler.fit_transform(X_supervised)

        # Train Random Forest
        self.models['random_forest'].fit(X_supervised_scaled, y)

        # Train Logistic Regression
        self.models['logistic_regression'].fit(X_supervised_scaled, y)

        # Train Isolation Forest (unsupervised) - uses unsupervised features
        self.models['isolation_forest'].fit(X_unsupervised)

        # Train One-Class SVM (unsupervised, using only benign samples)
        benign_X = X_unsupervised[y == 0]  # Use unsupervised features for benign samples
        if len(benign_X) > 0:
            self.models['one_class_svm'].fit(benign_X)

        # Save models
        self._save_models()

    def _save_models(self):
        """Save trained models and scaler."""
        # Save scaler
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        print(f"Saved scaler to {scaler_path}")

        # Save models
        for name, model in self.models.items():
            path = os.path.join(self.model_dir, f'{name}.pkl')
            joblib.dump(model, path)
            print(f"Saved {name} model to {path}")

# Global instance
ai_service = AIClassificationService()