from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
from typing import Dict, Any, List, Optional
import os
from ..models.models import ModelRegistry, AIPrediction
from ..db.session import SessionLocal

class HuggingFaceIntegrationService:
    """Service for integrating Hugging Face models for threat intelligence."""

    def __init__(self):
        self.api_key = os.getenv('HUGGINGFACE_API_KEY')
        self.models = {}
        self._load_registered_models()

    def _load_registered_models(self):
        """Load registered models from database."""
        db = SessionLocal()
        try:
            models = db.query(ModelRegistry).filter(ModelRegistry.is_active == True).all()
            for model in models:
                self.models[model.name] = {
                    'model_id': model.model_id,
                    'version': model.version,
                    'local_path': model.local_path,
                    'pipeline': None  # Lazy load
                }
        finally:
            db.close()

    def _get_pipeline(self, model_name: str):
        """Get or create pipeline for model."""
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not registered")

        if self.models[model_name]['pipeline'] is None:
            model_id = self.models[model_name]['model_id']
            try:
                # Try to load from local path first
                local_path = self.models[model_name]['local_path']
                if local_path and os.path.exists(local_path):
                    self.models[model_name]['pipeline'] = pipeline(
                        'text-classification',
                        model=local_path,
                        tokenizer=local_path,
                        return_all_scores=True
                    )
                else:
                    # Load from Hugging Face Hub
                    self.models[model_name]['pipeline'] = pipeline(
                        'text-classification',
                        model=model_id,
                        use_auth_token=self.api_key,
                        return_all_scores=True
                    )
            except Exception as e:
                print(f"Error loading model {model_name}: {e}")
                return None

        return self.models[model_name]['pipeline']

    def register_model(self, name: str, model_id: str, version: str = None, local_path: str = None):
        """Register a new Hugging Face model."""
        db = SessionLocal()
        try:
            # Check if exists
            existing = db.query(ModelRegistry).filter(ModelRegistry.name == name).first()
            if existing:
                existing.model_id = model_id
                existing.version = version
                existing.local_path = local_path
                existing.is_active = True
            else:
                model_reg = ModelRegistry(
                    name=name,
                    source='huggingface',
                    model_id=model_id,
                    version=version,
                    local_path=local_path,
                    is_active=True
                )
                db.add(model_reg)
            db.commit()

            # Update in-memory
            self.models[name] = {
                'model_id': model_id,
                'version': version,
                'local_path': local_path,
                'pipeline': None
            }
        finally:
            db.close()

    def classify_threat_description(self, description: str, model_name: str = 'threat_classifier') -> Dict[str, Any]:
        """Classify threat based on description text."""
        pipeline = self._get_pipeline(model_name)
        if not pipeline:
            return {'error': f'Model {model_name} not available'}

        try:
            results = pipeline(description)
            # Assuming results is list of dicts with label and score
            if isinstance(results, list) and len(results) > 0:
                if isinstance(results[0], list):  # return_all_scores=True
                    results = results[0]

                # Find highest score
                best_result = max(results, key=lambda x: x['score'])
                return {
                    'label': best_result['label'],
                    'confidence': best_result['score'],
                    'all_scores': results
                }
            else:
                return {'error': 'Unexpected pipeline output'}
        except Exception as e:
            return {'error': str(e)}

    def detect_malware_family(self, hash_value: str, model_name: str = 'malware_classifier') -> Dict[str, Any]:
        """Detect malware family from hash (placeholder - would need specific model)."""
        # This is a placeholder. In reality, you'd need a model trained for malware classification
        # For now, return mock result
        return {
            'family': 'unknown',
            'confidence': 0.5,
            'note': 'Malware family detection requires specialized model'
        }

    def attribute_threat_actor(self, indicators: List[str], model_name: str = 'actor_attribution') -> Dict[str, Any]:
        """Attribute threat to actor based on indicators."""
        # Placeholder for actor attribution
        combined_text = ' '.join(indicators)
        result = self.classify_threat_description(combined_text, model_name)
        if 'error' not in result:
            return {
                'actor': result['label'],
                'confidence': result['confidence']
            }
        return result

    def analyze_threat_report(self, report_text: str) -> Dict[str, Any]:
        """Analyze a full threat report using multiple models."""
        results = {}

        # Threat classification
        threat_class = self.classify_threat_description(report_text, 'threat_classifier')
        results['threat_classification'] = threat_class

        # Severity assessment (if model available)
        severity = self.classify_threat_description(report_text, 'severity_classifier')
        results['severity'] = severity

        # Actor attribution
        actor = self.attribute_threat_actor([report_text], 'actor_attribution')
        results['actor'] = actor

        return results

    def get_available_models(self) -> List[str]:
        """Get list of available model names."""
        return list(self.models.keys())

    def unload_model(self, model_name: str):
        """Unload a model from memory."""
        if model_name in self.models:
            self.models[model_name]['pipeline'] = None

# Global instance
hf_service = HuggingFaceIntegrationService()