import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional
import os
import kaggle
from ..models.models import Dataset, AIPrediction
from ..db.session import SessionLocal
from .ai_classification import ai_service
from datetime import datetime

class DatasetIntelligenceService:
    """Service for managing and utilizing datasets for AI training."""

    def __init__(self):
        self.dataset_path = os.getenv('KAGGLE_DATASET_PATH', './datasets')
        os.makedirs(self.dataset_path, exist_ok=True)

    def download_kaggle_dataset(self, dataset_name: str, kaggle_username: str = None, kaggle_key: str = None) -> str:
        """Download dataset from Kaggle."""
        try:
            if kaggle_username and kaggle_key:
                os.environ['KAGGLE_USERNAME'] = kaggle_username
                os.environ['KAGGLE_KEY'] = kaggle_key

            # Download dataset
            kaggle.api.dataset_download_files(dataset_name, path=self.dataset_path, unzip=True)

            # Return path to downloaded dataset
            dataset_dir = os.path.join(self.dataset_path, dataset_name.split('/')[-1])
            return dataset_dir
        except Exception as e:
            print(f"Error downloading Kaggle dataset {dataset_name}: {e}")
            return None

    def register_dataset(self, name: str, source: str, path: str, features: List[str], target: str):
        """Register a dataset in the system."""
        db = SessionLocal()
        try:
            # Check if exists
            existing = db.query(Dataset).filter(Dataset.name == name).first()
            if existing:
                existing.path = path
                existing.features = features
                existing.target = target
                existing.is_trained = False
            else:
                dataset = Dataset(
                    name=name,
                    source=source,
                    path=path,
                    features=features,
                    target=target,
                    is_trained=False
                )
                db.add(dataset)
            db.commit()
        finally:
            db.close()

    def load_dataset(self, dataset_name: str) -> Optional[pd.DataFrame]:
        """Load dataset into pandas DataFrame."""
        db = SessionLocal()
        try:
            dataset = db.query(Dataset).filter(Dataset.name == dataset_name).first()
            if not dataset:
                return None

            # Try different file formats
            possible_files = ['data.csv', 'train.csv', 'dataset.csv', f'{dataset_name}.csv']
            for filename in possible_files:
                filepath = os.path.join(dataset.path, filename)
                if os.path.exists(filepath):
                    df = pd.read_csv(filepath)
                    return df

            # Try JSON
            json_file = os.path.join(dataset.path, 'data.json')
            if os.path.exists(json_file):
                df = pd.read_json(json_file)
                return df

            return None
        finally:
            db.close()

    def preprocess_dataset(self, df: pd.DataFrame, features: List[str], target: str) -> Dict[str, Any]:
        """Preprocess dataset for training."""
        # Handle missing values
        df = df.dropna()

        # Encode categorical features
        encoded_features = []
        for feature in features:
            if df[feature].dtype == 'object':
                # Simple label encoding for now
                df[f'{feature}_encoded'] = df[feature].astype('category').cat.codes
                encoded_features.append(f'{feature}_encoded')
            else:
                encoded_features.append(feature)

        # Prepare training data
        X = df[encoded_features].values
        y = df[target].values if target in df.columns else None

        return {
            'X': X,
            'y': y,
            'feature_names': encoded_features,
            'original_df': df
        }

    def train_from_dataset(self, dataset_name: str):
        """Train AI models using dataset."""
        df = self.load_dataset(dataset_name)
        if df is None:
            print(f"Could not load dataset {dataset_name}")
            return

        db = SessionLocal()
        try:
            dataset = db.query(Dataset).filter(Dataset.name == dataset_name).first()
            if not dataset:
                return

            # Preprocess
            processed = self.preprocess_dataset(df, dataset.features, dataset.target)
            if processed['y'] is None:
                print("No target column found for supervised training")
                return

            # Convert to training format
            training_data = []
            for i in range(len(processed['X'])):
                row = processed['X'][i]
                label = 'malicious' if processed['y'][i] == 1 else 'benign'

                # Map features to our feature names
                feature_dict = {}
                for j, feature_name in enumerate(processed['feature_names']):
                    if 'ioc_type' in feature_name.lower():
                        feature_dict['ioc_type_encoded'] = int(row[j])
                    elif 'length' in feature_name.lower():
                        feature_dict['value_length'] = int(row[j])
                    elif 'risk' in feature_name.lower():
                        feature_dict['risk_score'] = float(row[j])
                    elif 'enrichment' in feature_name.lower():
                        feature_dict['enrichment_count'] = int(row[j])
                    elif 'alert' in feature_name.lower():
                        feature_dict['alert_count'] = int(row[j])
                    elif 'first' in feature_name.lower():
                        feature_dict['days_since_first'] = int(row[j])
                    elif 'last' in feature_name.lower():
                        feature_dict['days_since_last'] = int(row[j])
                    elif 'source' in feature_name.lower():
                        feature_dict['source_score'] = float(row[j])

                feature_dict['label'] = label
                training_data.append(feature_dict)

            # Train models
            ai_service.train_models(training_data)

            # Mark as trained
            dataset.is_trained = True
            dataset.updated_at = datetime.utcnow()
            db.commit()

            print(f"Successfully trained models on dataset {dataset_name}")

        finally:
            db.close()

    def get_dataset_insights(self, dataset_name: str) -> Dict[str, Any]:
        """Get insights about a dataset."""
        df = self.load_dataset(dataset_name)
        if df is None:
            return {'error': 'Dataset not found'}

        insights = {
            'shape': df.shape,
            'columns': list(df.columns),
            'dtypes': df.dtypes.to_dict(),
            'missing_values': df.isnull().sum().to_dict(),
            'summary_stats': df.describe().to_dict()
        }

        # Class distribution if target exists
        db = SessionLocal()
        try:
            dataset = db.query(Dataset).filter(Dataset.name == dataset_name).first()
            if dataset and dataset.target in df.columns:
                insights['class_distribution'] = df[dataset.target].value_counts().to_dict()
        finally:
            db.close()

        return insights

    def list_available_datasets(self) -> List[str]:
        """List registered datasets."""
        db = SessionLocal()
        try:
            datasets = db.query(Dataset).all()
            return [d.name for d in datasets]
        finally:
            db.close()

# Global instance
dataset_service = DatasetIntelligenceService()