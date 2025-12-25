from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy import func
from ..models.models import ThreatLifecycle, ThreatInput, ThreatIOC, User
from ..db.session import SessionLocal

class ThreatLifecycleService:
    """Service for managing threat lifecycle states."""

    LIFECYCLE_STATES = [
        'new',
        'under_analysis',
        'confirmed_malicious',
        'false_positive',
        'mitigated'
    ]

    def add_lifecycle_entry(self, threat_input_id: Optional[int] = None,
                          ioc_id: Optional[int] = None,
                          state: str = 'new',
                          user_id: Optional[int] = None,
                          notes: Optional[str] = None,
                          db_session = None) -> ThreatLifecycle:
        """Add a new lifecycle entry."""
        if state not in self.LIFECYCLE_STATES:
            raise ValueError(f"Invalid state: {state}")

        db = db_session or SessionLocal()
        try:
            entry = ThreatLifecycle(
                threat_input_id=threat_input_id,
                ioc_id=ioc_id,
                state=state,
                user_id=user_id,
                notes=notes
            )
            db.add(entry)
            if db_session is None:
                db.commit()
                db.refresh(entry)
            return entry
        except Exception as e:
            if db_session is None:
                db.rollback()
            raise e
        finally:
            if db_session is None:
                db.close()

    def get_lifecycle_history(self, threat_input_id: Optional[int] = None,
                            ioc_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get the complete lifecycle history for a threat."""
        db = SessionLocal()
        try:
            query = db.query(ThreatLifecycle)
            if threat_input_id:
                query = query.filter(ThreatLifecycle.threat_input_id == threat_input_id)
            if ioc_id:
                query = query.filter(ThreatLifecycle.ioc_id == ioc_id)

            entries = query.order_by(ThreatLifecycle.timestamp).all()

            history = []
            for entry in entries:
                history.append({
                    'id': entry.id,
                    'state': entry.state,
                    'timestamp': entry.timestamp,
                    'user_id': entry.user_id,
                    'notes': entry.notes,
                    'threat_input_id': entry.threat_input_id,
                    'ioc_id': entry.ioc_id
                })

            return history
        finally:
            db.close()

    def get_current_state(self, threat_input_id: Optional[int] = None,
                        ioc_id: Optional[int] = None) -> Optional[str]:
        """Get the current state of a threat."""
        history = self.get_lifecycle_history(threat_input_id, ioc_id)
        if history:
            return history[-1]['state']
        return None

    def transition_state(self, threat_input_id: Optional[int] = None,
                         ioc_id: Optional[int] = None,
                         new_state: str = 'new',
                         user_id: Optional[int] = None,
                         notes: Optional[str] = None) -> bool:
        """Transition a threat to a new state."""
        current_state = self.get_current_state(threat_input_id, ioc_id)

        # If already in the target state, do nothing
        if current_state == new_state:
            return True

        # Validate transition
        if not self._is_valid_transition(current_state, new_state):
            raise ValueError(f"Invalid transition from {current_state} to {new_state}")

        # Add new entry
        self.add_lifecycle_entry(
            threat_input_id=threat_input_id,
            ioc_id=ioc_id,
            state=new_state,
            user_id=user_id,
            notes=notes
        )

        # Update related entities
        self._update_entity_state(threat_input_id, ioc_id, new_state)

        return True

    def _is_valid_transition(self, from_state: Optional[str], to_state: str) -> bool:
        """Validate state transition."""
        if from_state is None:
            return to_state == 'new'

        # Define valid transitions
        valid_transitions = {
            'new': ['under_analysis', 'confirmed_malicious', 'false_positive'],
            'under_analysis': ['confirmed_malicious', 'false_positive', 'new'],
            'confirmed_malicious': ['mitigated'],
            'false_positive': ['new'],  # Can be re-evaluated
            'mitigated': []  # Terminal state
        }

        return to_state in valid_transitions.get(from_state, [])

    def _update_entity_state(self, threat_input_id: Optional[int],
                            ioc_id: Optional[int], state: str):
        """Update the state of related entities."""
        db = SessionLocal()
        try:
            # Update ThreatInput status if applicable
            if threat_input_id:
                threat_input = db.query(ThreatInput).filter(ThreatInput.id == threat_input_id).first()
                if threat_input:
                    # Map lifecycle state to input status
                    status_mapping = {
                        'new': 'pending',
                        'under_analysis': 'processed',  # Changed from 'processing' to avoid DB issues
                        'confirmed_malicious': 'processed',
                        'false_positive': 'processed',
                        'mitigated': 'processed'
                    }
                    threat_input.status = status_mapping.get(state, 'pending')
                    threat_input.updated_at = datetime.utcnow()

            # Could also update IOC if needed, but IOCs don't have status field
            # Instead, we can use lifecycle for tracking

            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error updating entity state: {e}")
        finally:
            db.close()

    def get_threats_by_state(self, state: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all threats in a specific state."""
        db = SessionLocal()
        try:
            # Get latest entries for each threat
            subquery = db.query(
                ThreatLifecycle.threat_input_id,
                ThreatLifecycle.ioc_id,
                func.max(ThreatLifecycle.timestamp).label('max_timestamp')
            ).group_by(ThreatLifecycle.threat_input_id, ThreatLifecycle.ioc_id).subquery()

            entries = db.query(ThreatLifecycle).join(
                subquery,
                (ThreatLifecycle.threat_input_id == subquery.c.threat_input_id) &
                (ThreatLifecycle.ioc_id == subquery.c.ioc_id) &
                (ThreatLifecycle.timestamp == subquery.c.max_timestamp)
            ).filter(ThreatLifecycle.state == state).limit(limit).all()

            threats = []
            for entry in entries:
                threat_data = {
                    'lifecycle_id': entry.id,
                    'state': entry.state,
                    'timestamp': entry.timestamp,
                    'user_id': entry.user_id,
                    'notes': entry.notes
                }

                if entry.threat_input_id:
                    threat_input = db.query(ThreatInput).filter(ThreatInput.id == entry.threat_input_id).first()
                    if threat_input:
                        threat_data['threat_input'] = {
                            'id': threat_input.id,
                            'type': threat_input.type,
                            'value': threat_input.value,
                            'status': threat_input.status
                        }

                if entry.ioc_id:
                    ioc = db.query(ThreatIOC).filter(ThreatIOC.id == entry.ioc_id).first()
                    if ioc:
                        threat_data['ioc'] = {
                            'id': ioc.id,
                            'type': ioc.type,
                            'value': ioc.value,
                            'risk_score': ioc.risk_score
                        }

                threats.append(threat_data)

            return threats
        finally:
            db.close()

    def get_lifecycle_stats(self) -> Dict[str, Any]:
        """Get statistics about threat lifecycle states."""
        db = SessionLocal()
        try:
            # Count current states
            subquery = db.query(
                ThreatLifecycle.threat_input_id,
                ThreatLifecycle.ioc_id,
                func.max(ThreatLifecycle.timestamp).label('max_timestamp')
            ).group_by(ThreatLifecycle.threat_input_id, ThreatLifecycle.ioc_id).subquery()

            state_counts = db.query(
                ThreatLifecycle.state,
                func.count().label('count')
            ).join(
                subquery,
                (ThreatLifecycle.threat_input_id == subquery.c.threat_input_id) &
                (ThreatLifecycle.ioc_id == subquery.c.ioc_id) &
                (ThreatLifecycle.timestamp == subquery.c.max_timestamp)
            ).group_by(ThreatLifecycle.state).all()

            stats = {state: count for state, count in state_counts}

            # Ensure all states are present
            for state in self.LIFECYCLE_STATES:
                if state not in stats:
                    stats[state] = 0

            # Additional metrics
            total_transitions = db.query(ThreatLifecycle).count()
            avg_time_in_analysis = self._calculate_avg_time_in_state('under_analysis')

            return {
                'state_counts': stats,
                'total_lifecycle_entries': total_transitions,
                'avg_time_under_analysis_hours': avg_time_in_analysis
            }
        finally:
            db.close()

    def _calculate_avg_time_in_state(self, state: str) -> float:
        """Calculate average time spent in a state."""
        db = SessionLocal()
        try:
            # This is a simplified calculation
            # In practice, you'd need to track entry and exit times for each state
            entries = db.query(ThreatLifecycle).filter(ThreatLifecycle.state == state).all()

            if len(entries) < 2:
                return 0.0

            # Simple average based on time between state changes
            # This is approximate
            timestamps = sorted([e.timestamp for e in entries])
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600
                intervals.append(interval)

            return sum(intervals) / len(intervals) if intervals else 0.0
        finally:
            db.close()

# Global instance
lifecycle_service = ThreatLifecycleService()