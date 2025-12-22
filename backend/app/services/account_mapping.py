from typing import List, Dict, Any, Optional
from ..models.models import Account, AccountThreatMapping, ThreatIOC, ThreatInput, User
from ..db.session import SessionLocal

class AccountMappingService:
    """Service for managing account-scoped threat mappings."""

    def get_or_create_default_account(self, db_session) -> Account:
        """Get or create default account."""
        default_account = db_session.query(Account).filter(Account.name == "Default").first()
        if not default_account:
            default_account = Account(name="Default", description="Default account for threat inputs")
            db_session.add(default_account)
            db_session.flush()
        return default_account

    def assign_threat_to_account(self, threat_input_id: int, account_id: int, db_session):
        """Assign a threat input to an account."""
        # Check if already assigned
        existing = db_session.query(AccountThreatMapping).filter(
            AccountThreatMapping.threat_input_id == threat_input_id,
            AccountThreatMapping.account_id == account_id
        ).first()

        if not existing:
            mapping = AccountThreatMapping(
                threat_input_id=threat_input_id,
                account_id=account_id
            )
            db_session.add(mapping)

    def assign_ioc_to_account(self, ioc_id: int, account_id: int, db_session):
        """Assign an IOC to an account."""
        # Check if already assigned
        existing = db_session.query(AccountThreatMapping).filter(
            AccountThreatMapping.ioc_id == ioc_id,
            AccountThreatMapping.account_id == account_id
        ).first()

        if not existing:
            mapping = AccountThreatMapping(
                ioc_id=ioc_id,
                account_id=account_id
            )
            db_session.add(mapping)

    def get_account_threats(self, account_id: int, limit: int = 100) -> Dict[str, Any]:
        """Get all threats assigned to an account."""
        db = SessionLocal()
        try:
            # Get mappings
            mappings = db.query(AccountThreatMapping).filter(AccountThreatMapping.account_id == account_id).limit(limit).all()

            iocs = []
            threat_inputs = []

            for mapping in mappings:
                if mapping.ioc_id:
                    ioc = db.query(ThreatIOC).filter(ThreatIOC.id == mapping.ioc_id).first()
                    if ioc:
                        iocs.append({
                            'id': ioc.id,
                            'type': ioc.type,
                            'value': ioc.value,
                            'risk_score': ioc.risk_score,
                            'created_at': ioc.created_at
                        })

                if mapping.threat_input_id:
                    threat_input = db.query(ThreatInput).filter(ThreatInput.id == mapping.threat_input_id).first()
                    if threat_input:
                        threat_inputs.append({
                            'id': threat_input.id,
                            'type': threat_input.type,
                            'value': threat_input.value,
                            'status': threat_input.status,
                            'created_at': threat_input.created_at
                        })

            return {
                'account_id': account_id,
                'iocs': iocs,
                'threat_inputs': threat_inputs,
                'total_threats': len(iocs) + len(threat_inputs)
            }
        finally:
            db.close()

    def get_user_default_account(self, user_id: int) -> Optional[int]:
        """Get the default account for a user."""
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if user and hasattr(user, 'account_id') and user.account_id:
                return user.account_id

            # Return default account
            default_account = self.get_or_create_default_account(db)
            return default_account.id
        finally:
            db.close()

    def bulk_assign_threats_to_account(self, threat_ids: List[int], account_id: int, threat_type: str = 'ioc'):
        """Bulk assign multiple threats to an account."""
        db = SessionLocal()
        try:
            for threat_id in threat_ids:
                if threat_type == 'ioc':
                    self.assign_ioc_to_account(threat_id, account_id, db)
                elif threat_type == 'threat_input':
                    self.assign_threat_to_account(threat_id, account_id, db)
            db.commit()
        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close()

    def remove_threat_from_account(self, threat_id: int, account_id: int, threat_type: str = 'ioc'):
        """Remove a threat assignment from an account."""
        db = SessionLocal()
        try:
            if threat_type == 'ioc':
                mapping = db.query(AccountThreatMapping).filter(
                    AccountThreatMapping.ioc_id == threat_id,
                    AccountThreatMapping.account_id == account_id
                ).first()
            else:
                mapping = db.query(AccountThreatMapping).filter(
                    AccountThreatMapping.threat_input_id == threat_id,
                    AccountThreatMapping.account_id == account_id
                ).first()

            if mapping:
                db.delete(mapping)
                db.commit()
                return True
            return False
        finally:
            db.close()

    def get_account_statistics(self, account_id: int) -> Dict[str, Any]:
        """Get threat statistics for an account."""
        db = SessionLocal()
        try:
            # Count mappings
            total_mappings = db.query(AccountThreatMapping).filter(AccountThreatMapping.account_id == account_id).count()

            # Count by threat type
            ioc_mappings = db.query(AccountThreatMapping).filter(
                AccountThreatMapping.account_id == account_id,
                AccountThreatMapping.ioc_id.isnot(None)
            ).count()

            threat_input_mappings = db.query(AccountThreatMapping).filter(
                AccountThreatMapping.account_id == account_id,
                AccountThreatMapping.threat_input_id.isnot(None)
            ).count()

            # Risk score distribution
            ioc_ids = db.query(AccountThreatMapping.ioc_id).filter(
                AccountThreatMapping.account_id == account_id,
                AccountThreatMapping.ioc_id.isnot(None)
            ).subquery()

            risk_scores = db.query(ThreatIOC.risk_score).filter(ThreatIOC.id.in_(ioc_ids)).all()
            risk_scores = [r[0] for r in risk_scores if r[0] is not None]

            return {
                'account_id': account_id,
                'total_threats': total_mappings,
                'ioc_count': ioc_mappings,
                'threat_input_count': threat_input_mappings,
                'avg_risk_score': sum(risk_scores) / len(risk_scores) if risk_scores else 0,
                'high_risk_count': len([r for r in risk_scores if r and r > 0.7])
            }
        finally:
            db.close()

# Global instance
account_service = AccountMappingService()