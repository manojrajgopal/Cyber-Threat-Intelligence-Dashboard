from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from ...db.session import get_db
from ...models.models import ThreatIOC, Alert
from ...schemas.schemas import DashboardMetrics
from ...security.auth import get_current_active_user

router = APIRouter()

@router.get("/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get dashboard metrics."""
    # Total IOCs
    total_iocs = db.query(func.count(ThreatIOC.id)).scalar()
    
    # Risk level breakdown
    critical_risk_iocs = db.query(func.count(ThreatIOC.id)).filter(ThreatIOC.risk_score >= 0.9).scalar()
    high_risk_iocs = db.query(func.count(ThreatIOC.id)).filter(
        (ThreatIOC.risk_score >= 0.7) & (ThreatIOC.risk_score < 0.9)
    ).scalar()
    medium_risk_iocs = db.query(func.count(ThreatIOC.id)).filter(
        (ThreatIOC.risk_score >= 0.4) & (ThreatIOC.risk_score < 0.7)
    ).scalar()
    low_risk_iocs = db.query(func.count(ThreatIOC.id)).filter(ThreatIOC.risk_score < 0.4).scalar()
    
    # Active alerts (not acknowledged)
    active_alerts = db.query(func.count(Alert.id)).filter(Alert.acknowledged == False).scalar()
    
    # Acknowledged alerts
    acknowledged_alerts = db.query(func.count(Alert.id)).filter(Alert.acknowledged == True).scalar()
    
    # Recent alerts (last 10)
    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(10).all()
    
    return DashboardMetrics(
        total_iocs=total_iocs,
        high_risk_iocs=high_risk_iocs,
        active_alerts=active_alerts,
        acknowledged_alerts=acknowledged_alerts,
        recent_alerts=recent_alerts,
        critical_risk_iocs=critical_risk_iocs,
        medium_risk_iocs=medium_risk_iocs,
        low_risk_iocs=low_risk_iocs
    )