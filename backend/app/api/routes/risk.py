from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from typing import List, Optional
from ...db.session import get_db
from ...models.models import ThreatIOC
from ...schemas.schemas import IOC, RiskSummary, RiskFilterResponse
from ...security.auth import get_current_active_user

router = APIRouter()

@router.get("/", response_model=RiskFilterResponse)
async def get_risk_data(
    filter: str = Query("all", description="Filter by risk level: all, critical, high, medium, low"),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get risk data with optional filtering."""
    
    # Get summary counts for all risk levels
    total_iocs = db.query(func.count(ThreatIOC.id)).scalar()
    critical_count = db.query(func.count(ThreatIOC.id)).filter(ThreatIOC.risk_score >= 0.9).scalar()
    high_count = db.query(func.count(ThreatIOC.id)).filter(
        and_(ThreatIOC.risk_score >= 0.7, ThreatIOC.risk_score < 0.9)
    ).scalar()
    medium_count = db.query(func.count(ThreatIOC.id)).filter(
        and_(ThreatIOC.risk_score >= 0.4, ThreatIOC.risk_score < 0.7)
    ).scalar()
    low_count = db.query(func.count(ThreatIOC.id)).filter(ThreatIOC.risk_score < 0.4).scalar()
    
    # Create summary object
    summary = RiskSummary(
        total=total_iocs,
        critical=critical_count,
        high=high_count,
        medium=medium_count,
        low=low_count
    )
    
    # Filter risks based on the requested filter
    query = db.query(ThreatIOC)
    
    if filter == "critical":
        query = query.filter(ThreatIOC.risk_score >= 0.9)
    elif filter == "high":
        query = query.filter(and_(ThreatIOC.risk_score >= 0.7, ThreatIOC.risk_score < 0.9))
    elif filter == "medium":
        query = query.filter(and_(ThreatIOC.risk_score >= 0.4, ThreatIOC.risk_score < 0.7))
    elif filter == "low":
        query = query.filter(ThreatIOC.risk_score < 0.4)
    # For "all" filter, no additional filtering needed
    
    # Get filtered results
    risks = query.order_by(ThreatIOC.risk_score.desc()).all()
    
    return RiskFilterResponse(
        summary=summary,
        risks=risks,
        filter_applied=filter
    )