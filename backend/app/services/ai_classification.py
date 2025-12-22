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
        # Random Forest
        rf_path = os.path.join(self.model_dir, 'random_forest.pkl')
        if os.path.exists(rf_path):
            with open(rf_path, 'rb') as f:
                self.models['random_forest'] = pickle.load(f)
        else:
            self.models['random_forest'] = RandomForestClassifier(n_estimators=100, random_state=42)

        # Logistic Regression
        lr_path = os.path.join(self.model_dir, 'logistic_regression.pkl')
        if os.path.exists(lr_path):
            with open(lr_path, 'rb') as f:
                self.models['logistic_regression'] = pickle.load(f)
        else:
            self.models['logistic_regression'] = LogisticRegression(random_state=42)

        # Isolation Forest for anomaly detection
        if_path = os.path.join(self.model_dir, 'isolation_forest.pkl')
        if os.path.exists(if_path):
            with open(if_path, 'rb') as f:
                self.models['isolation_forest'] = pickle.load(f)
        else:
            self.models['isolation_forest'] = IsolationForest(random_state=42)

        # One-Class SVM
        svm_path = os.path.join(self.model_dir, 'one_class_svm.pkl')
        if os.path.exists(svm_path):
            with open(svm_path, 'rb') as f:
                self.models['one_class_svm'] = pickle.load(f)
        else:
            self.models['one_class_svm'] = OneClassSVM(kernel='rbf', gamma='auto')

    def _extract_features(self, ioc: ThreatIOC, db_session) -> np.ndarray:
        """Extract features from IOC for classification."""
        features = []

        # Basic features
        type_encoded = {'ip': 0, 'domain': 1, 'url': 2, 'hash': 3}.get(ioc.type, 0)
        features.append(type_encoded)

        # Length features
        features.append(len(ioc.value))
        features.append(len(ioc.value.split('.')) if '.' in ioc.value else 0)

        # Risk score
        features.append(float(ioc.risk_score) if ioc.risk_score else 0.0)

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

        return np.array(features).reshape(1, -1)

    def classify_threat(self, ioc_id: int, db_session) -> AIPrediction:
        """Classify a threat IOC using ensemble of models."""
        ioc = db_session.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
        if not ioc:
            return None

        features = self._extract_features(ioc, db_session)

        predictions = []
        confidences = []

        # Random Forest
        try:
            rf_pred = self.models['random_forest'].predict(features)[0]
            rf_proba = self.models['random_forest'].predict_proba(features)[0]
            predictions.append('malicious' if rf_pred == 1 else 'benign')
            confidences.append(max(rf_proba))
        except:
            predictions.append('unknown')
            confidences.append(0.5)

        # Logistic Regression
        try:
            lr_pred = self.models['logistic_regression'].predict(features)[0]
            lr_proba = self.models['logistic_regression'].predict_proba(features)[0]
            predictions.append('malicious' if lr_pred == 1 else 'benign')
            confidences.append(max(lr_proba))
        except:
            predictions.append('unknown')
            confidences.append(0.5)

        # Isolation Forest (anomaly detection)
        try:
            if_pred = self.models['isolation_forest'].predict(features)[0]
            predictions.append('malicious' if if_pred == -1 else 'benign')
            confidences.append(0.8 if if_pred == -1 else 0.6)
        except:
            predictions.append('unknown')
            confidences.append(0.5)

        # One-Class SVM
        try:
            svm_pred = self.models['one_class_svm'].predict(features)[0]
            predictions.append('malicious' if svm_pred == -1 else 'benign')
            confidences.append(0.7 if svm_pred == -1 else 0.5)
        except:
            predictions.append('unknown')
            confidences.append(0.5)

        # Ensemble decision
        malicious_count = predictions.count('malicious')
        benign_count = predictions.count('benign')

        if malicious_count > benign_count:
            final_prediction = 'malicious'
        elif benign_count > malicious_count:
            final_prediction = 'benign'
        else:
            final_prediction = 'unknown'

        # Average confidence
        final_confidence = np.mean(confidences)

        # Features used
        features_dict = {
            'ioc_type': ioc.type,
            'value_length': len(ioc.value),
            'risk_score': float(ioc.risk_score) if ioc.risk_score else 0.0,
            'enrichment_count': len(ioc.enrichments) if ioc.enrichments else 0,
            'alert_count': len(ioc.alerts) if ioc.alerts else 0,
            'days_since_first_seen': (datetime.utcnow() - ioc.first_seen).days if ioc.first_seen else 0,
            'days_since_last_seen': (datetime.utcnow() - ioc.last_seen).days if ioc.last_seen else 0,
            'source_score': {'User Input': 0.5, 'AlienVault OTX': 0.8, 'AbuseIPDB': 0.7}.get(ioc.source, 0.5)
        }

        # Explanation
        explanation = f"Ensemble classification: {malicious_count} malicious, {benign_count} benign votes. "
        explanation += f"Features: {', '.join([f'{k}={v}' for k, v in features_dict.items()])}"

        prediction = AIPrediction(
            ioc_id=ioc_id,
            model_name='ensemble_classifier',
            prediction=final_prediction,
            confidence=final_confidence,
            features_used=features_dict,
            explanation=explanation
        )

        return prediction

    def train_models(self, training_data: List[Dict[str, Any]]):
        """Train models with labeled data."""
        if not training_data:
            return

        X = []
        y = []

        for item in training_data:
            features = [
                item.get('ioc_type_encoded', 0),
                item.get('value_length', 0),
                item.get('risk_score', 0.0),
                item.get('enrichment_count', 0),
                item.get('alert_count', 0),
                item.get('days_since_first', 0),
                item.get('days_since_last', 0),
                item.get('source_score', 0.5)
            ]
            X.append(features)
            y.append(1 if item.get('label') == 'malicious' else 0)

        X = np.array(X)
        y = np.array(y)

        if len(X) == 0:
            return

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train Random Forest
        self.models['random_forest'].fit(X_scaled, y)

        # Train Logistic Regression
        self.models['logistic_regression'].fit(X_scaled, y)

        # Train Isolation Forest (unsupervised)
        self.models['isolation_forest'].fit(X_scaled)

        # Train One-Class SVM (unsupervised, using only benign samples)
        benign_X = X_scaled[y == 0]
        if len(benign_X) > 0:
            self.models['one_class_svm'].fit(benign_X)

        # Save models
        self._save_models()

    def _save_models(self):
        """Save trained models."""
        for name, model in self.models.items():
            path = os.path.join(self.model_dir, f'{name}.pkl')
            with open(path, 'wb') as f:
                pickle.dump(model, f)

# Global instance
ai_service = AIClassificationService()