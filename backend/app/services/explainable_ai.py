from typing import Dict, Any, List
from ..models.models import AIPrediction, ThreatIOC
from ..db.session import SessionLocal
from .ai_classification import ai_service

class ExplainableAIService:
    """Service for providing explainable AI responses."""

    def explain_prediction(self, prediction_id: int) -> Dict[str, Any]:
        """Provide detailed explanation for an AI prediction."""
        db = SessionLocal()
        try:
            prediction = db.query(AIPrediction).filter(AIPrediction.id == prediction_id).first()
            if not prediction:
                return {'error': 'Prediction not found'}

            explanation = {
                'prediction_id': prediction.id,
                'model_name': prediction.model_name,
                'prediction': prediction.prediction,
                'confidence': prediction.confidence,
                'timestamp': prediction.created_at,
                'features_used': prediction.features_used,
                'explanation': prediction.explanation,
                'detailed_analysis': self._generate_detailed_explanation(prediction, db)
            }

            return explanation
        finally:
            db.close()

    def _generate_detailed_explanation(self, prediction: AIPrediction, db) -> Dict[str, Any]:
        """Generate detailed explanation for the prediction."""
        features = prediction.features_used or {}

        # Get IOC details
        ioc = None
        if prediction.ioc_id:
            ioc = db.query(ThreatIOC).filter(ThreatIOC.id == prediction.ioc_id).first()
        elif prediction.threat_input_id:
            # Could get from threat input, but for now focus on IOC
            pass

        detailed = {
            'feature_importance': self._calculate_feature_importance(features),
            'contributing_factors': self._identify_contributing_factors(features, prediction.prediction),
            'confidence_breakdown': self._breakdown_confidence(prediction),
            'comparative_analysis': self._comparative_analysis(prediction, db),
            'recommendations': self._generate_recommendations(prediction, ioc)
        }

        return detailed

    def _calculate_feature_importance(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Calculate and rank feature importance."""
        importance_scores = []

        # Define feature weights (simplified)
        feature_weights = {
            'risk_score': 0.3,
            'enrichment_count': 0.2,
            'alert_count': 0.15,
            'days_since_first_seen': 0.1,
            'days_since_last_seen': 0.1,
            'source_score': 0.1,
            'ioc_type_encoded': 0.05
        }

        for feature, value in features.items():
            weight = feature_weights.get(feature, 0.0)
            importance = weight * abs(value) if isinstance(value, (int, float)) else weight
            importance_scores.append({
                'feature': feature,
                'value': value,
                'importance': importance,
                'description': self._get_feature_description(feature)
            })

        # Sort by importance
        importance_scores.sort(key=lambda x: x['importance'], reverse=True)
        return importance_scores

    def _get_feature_description(self, feature: str) -> str:
        """Get human-readable description for a feature."""
        descriptions = {
            'risk_score': 'Historical risk assessment score',
            'enrichment_count': 'Number of enrichment data points',
            'alert_count': 'Number of alerts generated',
            'days_since_first_seen': 'Days since first observed',
            'days_since_last_seen': 'Days since last observed',
            'source_score': 'Reliability score of the source',
            'ioc_type_encoded': 'Type of indicator (IP, domain, etc.)',
            'value_length': 'Length of the indicator value'
        }
        return descriptions.get(feature, f'Feature: {feature}')

    def _identify_contributing_factors(self, features: Dict[str, Any], prediction: str) -> List[str]:
        """Identify key factors contributing to the prediction."""
        factors = []

        if prediction == 'malicious':
            if features.get('risk_score', 0) > 0.7:
                factors.append("High historical risk score indicates malicious behavior")
            if features.get('enrichment_count', 0) > 5:
                factors.append("Multiple enrichment data points suggest thorough analysis")
            if features.get('alert_count', 0) > 2:
                factors.append("Frequent alerts indicate ongoing malicious activity")
            if features.get('source_score', 0) > 0.7:
                factors.append("High-confidence source reporting this indicator")
        else:
            if features.get('risk_score', 0) < 0.3:
                factors.append("Low risk score suggests benign nature")
            if features.get('enrichment_count', 0) < 2:
                factors.append("Limited enrichment data available")
            if features.get('days_since_first_seen', 0) > 30:
                factors.append("Indicator has been known for an extended period without issues")

        return factors

    def _breakdown_confidence(self, prediction: AIPrediction) -> Dict[str, Any]:
        """Break down the confidence score."""
        confidence = prediction.confidence

        level = 'low'
        if confidence > 0.8:
            level = 'high'
        elif confidence > 0.6:
            level = 'medium'

        breakdown = {
            'overall_confidence': confidence,
            'confidence_level': level,
            'interpretation': self._interpret_confidence(confidence),
            'uncertainty_range': f"{max(0, confidence - 0.1):.2f} - {min(1.0, confidence + 0.1):.2f}"
        }

        return breakdown

    def _interpret_confidence(self, confidence: float) -> str:
        """Provide interpretation of confidence score."""
        if confidence > 0.9:
            return "Very high confidence - strong evidence supports this classification"
        elif confidence > 0.8:
            return "High confidence - reliable classification with good supporting evidence"
        elif confidence > 0.7:
            return "Moderate to high confidence - reasonable evidence supports classification"
        elif confidence > 0.6:
            return "Moderate confidence - some evidence but additional verification recommended"
        elif confidence > 0.5:
            return "Low to moderate confidence - limited evidence, further analysis needed"
        else:
            return "Low confidence - insufficient evidence for reliable classification"

    def _comparative_analysis(self, prediction: AIPrediction, db) -> Dict[str, Any]:
        """Provide comparative analysis with similar predictions."""
        # Get similar predictions
        similar_predictions = db.query(AIPrediction).filter(
            AIPrediction.model_name == prediction.model_name,
            AIPrediction.prediction == prediction.prediction,
            AIPrediction.id != prediction.id
        ).limit(10).all()

        if not similar_predictions:
            return {'note': 'No similar predictions found for comparison'}

        avg_confidence = sum(p.confidence for p in similar_predictions) / len(similar_predictions)
        confidence_comparison = 'higher' if prediction.confidence > avg_confidence else 'lower'

        return {
            'similar_predictions_count': len(similar_predictions),
            'average_confidence_similar': avg_confidence,
            'confidence_comparison': confidence_comparison,
            'insight': f"This prediction has {confidence_comparison} confidence than similar cases"
        }

    def _generate_recommendations(self, prediction: AIPrediction, ioc: ThreatIOC = None) -> List[str]:
        """Generate recommendations based on the prediction."""
        recommendations = []

        if prediction.prediction == 'malicious':
            recommendations.append("Consider blocking this indicator in security controls")
            if prediction.confidence > 0.8:
                recommendations.append("High confidence - immediate action recommended")
            else:
                recommendations.append("Monitor this indicator closely for additional evidence")

            if ioc and ioc.type == 'ip':
                recommendations.append("Check firewall logs for connections to this IP")
            elif ioc and ioc.type == 'domain':
                recommendations.append("Review DNS queries for this domain")
        else:
            recommendations.append("This indicator appears benign but continue monitoring")
            if prediction.confidence < 0.6:
                recommendations.append("Low confidence - gather more intelligence before final decision")

        recommendations.append("Review the feature importance breakdown for detailed reasoning")
        return recommendations

    def get_prediction_summary(self, ioc_id: int) -> Dict[str, Any]:
        """Get a summary of all predictions for an IOC."""
        db = SessionLocal()
        try:
            predictions = db.query(AIPrediction).filter(AIPrediction.ioc_id == ioc_id).all()

            if not predictions:
                return {'message': 'No AI predictions available for this IOC'}

            summary = {
                'total_predictions': len(predictions),
                'latest_prediction': self.explain_prediction(predictions[-1].id),
                'prediction_history': [
                    {
                        'id': p.id,
                        'model': p.model_name,
                        'prediction': p.prediction,
                        'confidence': p.confidence,
                        'timestamp': p.created_at
                    } for p in predictions
                ],
                'consensus': self._calculate_consensus(predictions)
            }

            return summary
        finally:
            db.close()

    def _calculate_consensus(self, predictions: List[AIPrediction]) -> Dict[str, Any]:
        """Calculate consensus from multiple predictions."""
        if not predictions:
            return {}

        malicious_count = sum(1 for p in predictions if p.prediction == 'malicious')
        benign_count = sum(1 for p in predictions if p.prediction == 'benign')

        total = len(predictions)
        consensus_prediction = 'malicious' if malicious_count > benign_count else 'benign'
        consensus_confidence = max(malicious_count, benign_count) / total

        return {
            'consensus_prediction': consensus_prediction,
            'consensus_confidence': consensus_confidence,
            'agreement_level': 'strong' if consensus_confidence > 0.7 else 'weak',
            'malicious_votes': malicious_count,
            'benign_votes': benign_count
        }

# Global instance
explainable_ai_service = ExplainableAIService()