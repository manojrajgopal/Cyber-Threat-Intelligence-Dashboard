from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
import numpy as np
from typing import Dict, Any, List
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from ..models.models import ThreatIOC, Alert, ThreatInput
from ..db.session import SessionLocal

class BehavioralAnalysisService:
    """Service for detecting suspicious patterns and behaviors."""

    def __init__(self):
        self.scaler = StandardScaler()

    def detect_repeated_ioc_behavior(self, account_id: int = None, days: int = 30) -> List[Dict[str, Any]]:
        """Detect IOCs that appear repeatedly in short time frames."""
        db = SessionLocal()
        try:
            # Get IOCs from last N days
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            query = db.query(ThreatIOC).filter(ThreatIOC.created_at >= cutoff_date)
            if account_id:
                # Join with account mappings
                from ..models.models import AccountThreatMapping
                query = query.join(AccountThreatMapping).filter(AccountThreatMapping.account_id == account_id)

            iocs = query.all()

            # Group by value and count occurrences
            value_counts = Counter([ioc.value for ioc in iocs])
            repeated_iocs = [value for value, count in value_counts.items() if count > 3]

            # Analyze patterns
            patterns = []
            for value in repeated_iocs:
                ioc_instances = [ioc for ioc in iocs if ioc.value == value]
                timestamps = [ioc.created_at for ioc in ioc_instances]

                # Calculate time intervals
                intervals = []
                sorted_times = sorted(timestamps)
                for i in range(1, len(sorted_times)):
                    interval = (sorted_times[i] - sorted_times[i-1]).total_seconds() / 3600  # hours
                    intervals.append(interval)

                avg_interval = np.mean(intervals) if intervals else 0
                std_interval = np.std(intervals) if intervals else 0

                patterns.append({
                    'ioc_value': value,
                    'occurrences': len(ioc_instances),
                    'avg_interval_hours': avg_interval,
                    'std_interval_hours': std_interval,
                    'is_suspicious': avg_interval < 24 and std_interval < 12,  # Frequent and regular
                    'timestamps': timestamps
                })

            return patterns
        finally:
            db.close()

    def detect_lateral_movement(self, account_id: int = None, hours: int = 24) -> List[Dict[str, Any]]:
        """Detect potential lateral movement patterns."""
        db = SessionLocal()
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)

            # Get recent alerts
            query = db.query(Alert).filter(Alert.created_at >= cutoff_time)
            if account_id:
                # Filter by account
                from ..models.models import AccountThreatMapping
                ioc_ids = db.query(AccountThreatMapping.ioc_id).filter(AccountThreatMapping.account_id == account_id).subquery()
                query = query.filter(Alert.ioc_id.in_(ioc_ids))

            alerts = query.all()

            # Group alerts by time windows
            time_windows = defaultdict(list)
            for alert in alerts:
                window_key = alert.created_at.replace(minute=0, second=0, microsecond=0)
                time_windows[window_key].append(alert)

            # Analyze for lateral movement indicators
            lateral_indicators = []
            for window, window_alerts in time_windows.items():
                if len(window_alerts) < 3:
                    continue

                # Check for different IOC types in short time
                ioc_types = set()
                sources = set()
                for alert in window_alerts:
                    ioc = db.query(ThreatIOC).filter(ThreatIOC.id == alert.ioc_id).first()
                    if ioc:
                        ioc_types.add(ioc.type)
                        sources.add(ioc.source)

                if len(ioc_types) >= 2:  # Multiple types indicate potential lateral movement
                    lateral_indicators.append({
                        'time_window': window,
                        'alert_count': len(window_alerts),
                        'ioc_types': list(ioc_types),
                        'sources': list(sources),
                        'severity': 'high' if len(ioc_types) >= 3 else 'medium'
                    })

            return lateral_indicators
        finally:
            db.close()

    def cluster_similar_threats(self, features: List[str] = None) -> List[Dict[str, Any]]:
        """Cluster similar threats using K-Means."""
        db = SessionLocal()
        try:
            # Get recent IOCs
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            iocs = db.query(ThreatIOC).filter(ThreatIOC.created_at >= cutoff_date).all()

            if len(iocs) < 10:
                return []

            # Extract features
            feature_matrix = []
            for ioc in iocs:
                features_vec = [
                    {'ip': 0, 'domain': 1, 'url': 2, 'hash': 3, 'network': 4}.get(ioc.type, 0),
                    len(ioc.value),
                    float(ioc.risk_score) if ioc.risk_score else 0.0,
                    len(ioc.enrichments) if ioc.enrichments else 0,
                    (datetime.utcnow() - ioc.created_at).days if ioc.created_at else 0
                ]
                feature_matrix.append(features_vec)

            X = np.array(feature_matrix)
            X_scaled = self.scaler.fit_transform(X)

            # K-Means clustering
            n_clusters = min(5, len(iocs) // 2)
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            clusters = kmeans.fit_predict(X_scaled)

            # Analyze clusters
            cluster_analysis = []
            for cluster_id in range(n_clusters):
                cluster_iocs = [iocs[i] for i in range(len(iocs)) if clusters[i] == cluster_id]
                if len(cluster_iocs) < 2:
                    continue

                # Cluster characteristics
                types = Counter([ioc.type for ioc in cluster_iocs])
                avg_risk = np.mean([float(ioc.risk_score) if ioc.risk_score else 0.0 for ioc in cluster_iocs])

                cluster_analysis.append({
                    'cluster_id': cluster_id,
                    'size': len(cluster_iocs),
                    'dominant_type': types.most_common(1)[0][0],
                    'avg_risk_score': avg_risk,
                    'ioc_samples': [ioc.value for ioc in cluster_iocs[:5]],
                    'is_campaign': len(cluster_iocs) > 10 and avg_risk > 0.7
                })

            return cluster_analysis
        finally:
            db.close()

    def detect_anomalous_patterns(self, account_id: int = None, days: int = 7) -> List[Dict[str, Any]]:
        """Detect anomalous patterns in threat data."""
        db = SessionLocal()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            # Get time series data
            query = db.query(ThreatIOC.created_at).filter(ThreatIOC.created_at >= cutoff_date)
            if account_id:
                from ..models.models import AccountThreatMapping
                ioc_ids = db.query(AccountThreatMapping.ioc_id).filter(AccountThreatMapping.account_id == account_id).subquery()
                query = query.filter(ThreatIOC.id.in_(ioc_ids))

            timestamps = [row[0] for row in query.all()]

            if len(timestamps) < 10:
                return []

            # Create hourly bins
            hourly_counts = defaultdict(int)
            for ts in timestamps:
                hour_key = ts.replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour_key] += 1

            # Convert to time series
            hours = sorted(hourly_counts.keys())
            counts = [hourly_counts[h] for h in hours]

            if len(counts) < 24:
                return []

            # Simple anomaly detection: spikes above mean + 2*std
            mean_count = np.mean(counts)
            std_count = np.std(counts)

            anomalies = []
            for i, (hour, count) in enumerate(zip(hours, counts)):
                if count > mean_count + 2 * std_count:
                    anomalies.append({
                        'timestamp': hour,
                        'count': count,
                        'expected': mean_count,
                        'deviation': (count - mean_count) / std_count,
                        'severity': 'high' if count > mean_count + 3 * std_count else 'medium'
                    })

            return anomalies
        finally:
            db.close()

    def analyze_campaign_patterns(self) -> List[Dict[str, Any]]:
        """Analyze potential threat campaigns."""
        clusters = self.cluster_similar_threats()

        campaigns = []
        for cluster in clusters:
            if cluster['is_campaign']:
                # Additional analysis for campaigns
                campaign_info = {
                    'campaign_id': f"campaign_{cluster['cluster_id']}",
                    'size': cluster['size'],
                    'threat_type': cluster['dominant_type'],
                    'risk_level': 'high' if cluster['avg_risk_score'] > 0.8 else 'medium',
                    'indicators': cluster['ioc_samples'],
                    'estimated_start': None,  # Would need more complex analysis
                    'status': 'active'
                }
                campaigns.append(campaign_info)

        return campaigns

# Global instance
behavioral_service = BehavioralAnalysisService()