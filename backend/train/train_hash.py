"""
PRODUCTION-GRADE HASH MODEL
===========================

IMPORTANT:
- This model does NOT try to "detect malware by hash"
- It learns weak statistical heuristics
- It outputs a RISK SCORE, not truth
"""

import os
import time
import json
import hashlib
import numpy as np
import pandas as pd
from collections import Counter

from sklearn.model_selection import StratifiedKFold, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

import joblib


# =========================
# FEATURE EXTRACTION
# =========================

class HashFeatureExtractor:
    """
    ONLY structure-based features.
    No metadata.
    No cheating.
    """

    def extract(self, h: str) -> dict:
        h = h.lower().strip()
        features = {}

        features["length"] = len(h)
        features["is_hex"] = int(all(c in "0123456789abcdef" for c in h))

        counts = Counter(h)
        total = max(len(h), 1)

        # entropy
        entropy = -sum((v/total) * np.log2(v/total) for v in counts.values())
        features["entropy"] = entropy

        features["unique_ratio"] = len(counts) / total
        features["digit_ratio"] = sum(c.isdigit() for c in h) / total
        features["letter_ratio"] = sum(c.isalpha() for c in h) / total

        # runs
        max_run = 1
        cur = 1
        for i in range(1, len(h)):
            if h[i] == h[i-1]:
                cur += 1
                max_run = max(max_run, cur)
            else:
                cur = 1

        features["max_run"] = max_run

        # transitions
        transitions = sum(
            h[i].isdigit() != h[i-1].isdigit()
            for i in range(1, len(h))
        )
        features["transition_ratio"] = transitions / max(len(h)-1, 1)

        return features


# =========================
# LOAD DATA
# =========================

def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df.drop_duplicates(subset=["hash"])
    df = df[["hash", "is_malicious"]]
    return df


# =========================
# TRAINING
# =========================

def train_hash_model():
    start = time.time()

    df = load_dataset("datasets/hash/malware_hashes.csv")
    extractor = HashFeatureExtractor()

    X = pd.DataFrame([extractor.extract(h) for h in df["hash"]])
    y = df["is_malicious"].astype(int)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    rf = RandomForestClassifier(
        class_weight="balanced",
        random_state=42
    )

    param_grid = {
        "n_estimators": [200, 400],
        "max_depth": [8, 12, None],
        "min_samples_leaf": [2, 5],
    }

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    grid = GridSearchCV(
        rf,
        param_grid,
        scoring="roc_auc",
        cv=cv,
        n_jobs=-1
    )

    grid.fit(X_scaled, y)

    model = grid.best_estimator_

    preds = model.predict(X_scaled)
    probs = model.predict_proba(X_scaled)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y, preds),
        "precision": precision_score(y, preds, zero_division=0),
        "recall": recall_score(y, preds, zero_division=0),
        "f1": f1_score(y, preds, zero_division=0),
        "roc_auc": roc_auc_score(y, probs),
    }

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/hash_model.pkl")
    joblib.dump(scaler, "models/hash_scaler.pkl")
    joblib.dump(list(X.columns), "models/hash_features.pkl")

    with open("models/hash_metadata.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print("\nTRAINING COMPLETE")
    print(json.dumps(metrics, indent=2))
    print(f"Time: {time.time() - start:.2f}s")


# =========================
# PREDICTOR (PRODUCTION)
# =========================

class HashRiskScorer:
    """
    Returns RISK, not truth.
    """

    def __init__(self):
        self.model = joblib.load("models/hash_model.pkl")
        self.scaler = joblib.load("models/hash_scaler.pkl")
        self.features = joblib.load("models/hash_features.pkl")
        self.extractor = HashFeatureExtractor()

    def score(self, h: str) -> dict:
        f = self.extractor.extract(h)
        X = pd.DataFrame([f])[self.features]
        X = self.scaler.transform(X)

        prob = self.model.predict_proba(X)[0][1]

        return {
            "hash": h,
            "risk_score": round(float(prob), 4),
            "risk_level": (
                "LOW" if prob < 0.3 else
                "MEDIUM" if prob < 0.6 else
                "HIGH"
            )
        }


if __name__ == "__main__":
    train_hash_model()
