from typing import List, Dict, Any
from datetime import datetime, timedelta
from ..models.models import ThreatIOC, Alert
from ..db.session import SessionLocal

class CorrelationService:
    """Service for correlating IOCs and generating alerts."""
    
    def __init__(self):
        self.correlation_rules = [
            {
                "name": "High Risk IP Alert",
                "condition": lambda ioc: ioc.type == "ip" and ioc.risk_score >= 0.7,
                "severity": "high",
                "message": "High-risk IP address detected"
            },
            {
                "name": "Malicious Domain Alert",
                "condition": lambda ioc: ioc.type == "domain" and ioc.risk_score >= 0.8,
                "severity": "critical",
                "message": "Malicious domain detected"
            },
            {
                "name": "Suspicious Hash Alert",
                "condition": lambda ioc: ioc.type == "hash" and ioc.risk_score >= 0.6,
                "severity": "medium",
                "message": "Suspicious file hash detected"
            }
        ]
    
    def correlate_and_alert(self, ioc: ThreatIOC, db_session = None) -> List[Alert]:
        """Check IOC against correlation rules and generate alerts."""
        db = db_session or SessionLocal()
        alerts_created = []
        
        try:
            for rule in self.correlation_rules:
                if rule["condition"](ioc):
                    # Check if alert already exists for this IOC and rule
                    existing_alert = db.query(Alert).filter(
                        Alert.ioc_id == ioc.id,
                        Alert.message == rule["message"]
                    ).first()
                    
                    if not existing_alert:
                        # Create new alert
                        alert = Alert(
                            ioc_id=ioc.id,
                            severity=rule["severity"],
                            message=rule["message"]
                        )
                        db.add(alert)
                        alerts_created.append(alert)
            
            if alerts_created:
                db.commit()
                
        except Exception as e:
            if db_session is None:
                db.rollback()
            print(f"Error in correlation: {e}")
        finally:
            if db_session is None:
                db.close()
        
        return alerts_created
    
    def find_related_iocs(self, ioc: ThreatIOC) -> List[ThreatIOC]:
        """Find related IOCs based on enrichment data."""
        related = []
        db = SessionLocal()
        
        try:
            # Find IOCs with same resolved IP
            for enrichment in ioc.enrichments:
                if enrichment.enrichment_type == "resolved_ip" and enrichment.data:
                    resolved_ip = enrichment.data
                    related_iocs = db.query(ThreatIOC).join(IOCEnrichment).filter(
                        IOCEnrichment.enrichment_type == "resolved_ip",
                        IOCEnrichment.data == resolved_ip,
                        ThreatIOC.id != ioc.id
                    ).all()
                    related.extend(related_iocs)
            
            # Find IOCs from same source
            if ioc.source:
                source_iocs = db.query(ThreatIOC).filter(
                    ThreatIOC.source == ioc.source,
                    ThreatIOC.id != ioc.id
                ).limit(5).all()
                related.extend(source_iocs)
            
            # Remove duplicates
            seen_ids = set()
            unique_related = []
            for rel_ioc in related:
                if rel_ioc.id not in seen_ids:
                    seen_ids.add(rel_ioc.id)
                    unique_related.append(rel_ioc)
            
            return unique_related[:10]  # Limit to 10
            
        except Exception as e:
            print(f"Error finding related IOCs: {e}")
            return []
        finally:
            db.close()
    
    def update_risk_scores(self):
        """Batch update risk scores for all IOCs."""
        from .enrichment import enrichment_service
        
        db = SessionLocal()
        try:
            iocs = db.query(ThreatIOC).filter(ThreatIOC.enriched == True).all()
            for ioc in iocs:
                new_score = enrichment_service.calculate_risk_score(ioc)
                if abs(ioc.risk_score - new_score) > 0.01:  # Only update if significant change
                    ioc.risk_score = new_score
                    # Re-correlate if score changed significantly
                    if new_score > ioc.risk_score:
                        self.correlate_and_alert(ioc, db)
            
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error updating risk scores: {e}")
        finally:
            db.close()

# Global service instance
correlation_service = CorrelationService()