from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
import networkx as nx
from ..models.models import ThreatIOC, Alert, IOCRelationship, AIPrediction
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

    def build_ioc_relationship_graph(self, days: int = 30) -> nx.Graph:
        """Build a graph of IOC relationships."""
        db = SessionLocal()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            # Get recent IOCs
            iocs = db.query(ThreatIOC).filter(ThreatIOC.created_at >= cutoff_date).all()

            # Create graph
            G = nx.Graph()

            # Add nodes
            for ioc in iocs:
                G.add_node(ioc.id, type=ioc.type, value=ioc.value, risk_score=ioc.risk_score)

            # Add edges based on relationships
            relationships = db.query(IOCRelationship).filter(
                IOCRelationship.created_at >= cutoff_date
            ).all()

            for rel in relationships:
                G.add_edge(rel.ioc1_id, rel.ioc2_id,
                          relationship=rel.relationship_type,
                          confidence=rel.confidence)

            # Add implicit relationships
            self._add_implicit_relationships(G, iocs, db)

            return G
        finally:
            db.close()

    def _add_implicit_relationships(self, G: nx.Graph, iocs: List[ThreatIOC], db):
        """Add implicit relationships based on shared attributes."""
        # Group by source
        source_groups = defaultdict(list)
        for ioc in iocs:
            if ioc.source:
                source_groups[ioc.source].append(ioc)

        # Add edges for same source
        for source, source_iocs in source_groups.items():
            if len(source_iocs) > 1:
                for i in range(len(source_iocs)):
                    for j in range(i+1, len(source_iocs)):
                        ioc1, ioc2 = source_iocs[i], source_iocs[j]
                        if not G.has_edge(ioc1.id, ioc2.id):
                            G.add_edge(ioc1.id, ioc2.id,
                                     relationship='same_source',
                                     confidence=0.6)

        # Group by enrichment data (e.g., same resolved IP)
        from ..models.models import IOCEnrichment
        enrichments = db.query(IOCEnrichment).filter(
            IOCEnrichment.ioc_id.in_([ioc.id for ioc in iocs])
        ).all()

        enrichment_groups = defaultdict(list)
        for enrich in enrichments:
            if enrich.enrichment_type in ['resolved_ip', 'asn', 'country']:
                key = f"{enrich.enrichment_type}:{enrich.data}"
                enrichment_groups[key].append(enrich.ioc_id)

        for key, ioc_ids in enrichment_groups.items():
            if len(ioc_ids) > 1:
                for i in range(len(ioc_ids)):
                    for j in range(i+1, len(ioc_ids)):
                        ioc1_id, ioc2_id = ioc_ids[i], ioc_ids[j]
                        if not G.has_edge(ioc1_id, ioc2_id):
                            G.add_edge(ioc1_id, ioc2_id,
                                     relationship='shared_enrichment',
                                     confidence=0.7)

    def find_connected_components(self, min_size: int = 3) -> List[Dict[str, Any]]:
        """Find connected components in IOC graph representing potential campaigns."""
        G = self.build_ioc_relationship_graph()

        components = []
        for component in nx.connected_components(G):
            if len(component) >= min_size:
                subgraph = G.subgraph(component)

                # Analyze component
                ioc_types = set()
                total_risk = 0
                nodes_data = []

                for node in subgraph.nodes():
                    node_data = subgraph.nodes[node]
                    ioc_types.add(node_data['type'])
                    total_risk += node_data.get('risk_score', 0) or 0
                    nodes_data.append({
                        'id': node,
                        'type': node_data['type'],
                        'value': node_data['value'],
                        'risk_score': node_data.get('risk_score', 0)
                    })

                components.append({
                    'component_id': f"component_{len(components)}",
                    'size': len(component),
                    'ioc_types': list(ioc_types),
                    'avg_risk_score': total_risk / len(component),
                    'nodes': nodes_data,
                    'is_campaign': len(ioc_types) > 1 and total_risk / len(component) > 0.6
                })

        return components

    def temporal_correlation_analysis(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Analyze temporal patterns in IOC appearances."""
        db = SessionLocal()
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)

            # Get IOC timeline
            iocs = db.query(ThreatIOC).filter(ThreatIOC.created_at >= cutoff_time).order_by(ThreatIOC.created_at).all()

            if len(iocs) < 5:
                return []

            # Create time series
            time_series = []
            for ioc in iocs:
                time_series.append({
                    'timestamp': ioc.created_at,
                    'ioc_id': ioc.id,
                    'type': ioc.type,
                    'risk_score': ioc.risk_score
                })

            # Detect bursts (rapid succession of high-risk IOCs)
            bursts = []
            current_burst = []
            burst_threshold = timedelta(minutes=30)

            for i, item in enumerate(time_series):
                if item['risk_score'] and item['risk_score'] > 0.7:
                    current_burst.append(item)

                    # Check if burst continues
                    if i < len(time_series) - 1:
                        next_item = time_series[i + 1]
                        if next_item['timestamp'] - item['timestamp'] > burst_threshold:
                            # End burst
                            if len(current_burst) >= 3:
                                bursts.append({
                                    'start_time': current_burst[0]['timestamp'],
                                    'end_time': current_burst[-1]['timestamp'],
                                    'duration_minutes': (current_burst[-1]['timestamp'] - current_burst[0]['timestamp']).total_seconds() / 60,
                                    'ioc_count': len(current_burst),
                                    'avg_risk': sum(b['risk_score'] for b in current_burst) / len(current_burst),
                                    'ioc_types': list(set(b['type'] for b in current_burst)),
                                    'severity': 'high' if len(current_burst) >= 5 else 'medium'
                                })
                            current_burst = []
                    else:
                        # Last item
                        if len(current_burst) >= 3:
                            bursts.append({
                                'start_time': current_burst[0]['timestamp'],
                                'end_time': current_burst[-1]['timestamp'],
                                'duration_minutes': (current_burst[-1]['timestamp'] - current_burst[0]['timestamp']).total_seconds() / 60,
                                'ioc_count': len(current_burst),
                                'avg_risk': sum(b['risk_score'] for b in current_burst) / len(current_burst),
                                'ioc_types': list(set(b['type'] for b in current_burst)),
                                'severity': 'high' if len(current_burst) >= 5 else 'medium'
                            })

            return bursts
        finally:
            db.close()

    def cross_source_confidence_boosting(self, ioc: ThreatIOC) -> float:
        """Boost confidence based on cross-source validation."""
        db = SessionLocal()
        try:
            # Find same IOC from different sources
            similar_iocs = db.query(ThreatIOC).filter(
                ThreatIOC.type == ioc.type,
                ThreatIOC.value == ioc.value,
                ThreatIOC.id != ioc.id
            ).all()

            if not similar_iocs:
                return ioc.risk_score or 0.0

            # Calculate boosted score
            sources = set([ioc.source for ioc in similar_iocs if ioc.source])
            source_count = len(sources)

            # Base score
            base_score = ioc.risk_score or 0.0

            # Boost factor based on source diversity
            boost_factor = min(0.3, source_count * 0.1)  # Max 30% boost

            boosted_score = min(1.0, base_score + boost_factor)

            return boosted_score
        finally:
            db.close()

    def update_relationships_from_ai(self):
        """Create relationships based on AI predictions."""
        db = SessionLocal()
        try:
            # Get recent AI predictions
            predictions = db.query(AIPrediction).filter(
                AIPrediction.created_at >= datetime.utcnow() - timedelta(days=1)
            ).all()

            for pred in predictions:
                if pred.prediction == 'malicious' and pred.confidence > 0.8:
                    # Find similar high-confidence predictions
                    similar_preds = db.query(AIPrediction).filter(
                        AIPrediction.prediction == 'malicious',
                        AIPrediction.confidence > 0.8,
                        AIPrediction.id != pred.id
                    ).all()

                    for sim_pred in similar_preds:
                        # Create relationship if not exists
                        existing_rel = db.query(IOCRelationship).filter(
                            ((IOCRelationship.ioc1_id == pred.ioc_id) & (IOCRelationship.ioc2_id == sim_pred.ioc_id)) |
                            ((IOCRelationship.ioc1_id == sim_pred.ioc_id) & (IOCRelationship.ioc2_id == pred.ioc_id))
                        ).first()

                        if not existing_rel:
                            relationship = IOCRelationship(
                                ioc1_id=pred.ioc_id,
                                ioc2_id=sim_pred.ioc_id,
                                relationship_type='ai_correlated',
                                confidence=min(pred.confidence, sim_pred.confidence),
                                source='AI Analysis'
                            )
                            db.add(relationship)

            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error updating AI relationships: {e}")
        finally:
            db.close()

# Global service instance
correlation_service = CorrelationService()