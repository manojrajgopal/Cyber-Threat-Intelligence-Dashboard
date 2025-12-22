from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from ...db.session import get_db
from ...models.models import IOCRelationship
from ...security.auth import get_current_active_user
from ...services.correlation import correlation_service

router = APIRouter()

@router.get("/relationships/{ioc_id}")
async def get_ioc_relationships(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get relationships for a specific IOC."""
    relationships = db.query(IOCRelationship).filter(
        (IOCRelationship.ioc1_id == ioc_id) | (IOCRelationship.ioc2_id == ioc_id)
    ).all()

    result = []
    for rel in relationships:
        related_ioc_id = rel.ioc2_id if rel.ioc1_id == ioc_id else rel.ioc1_id
        # Get the related IOC details
        from ...models.models import ThreatIOC
        related_ioc = db.query(ThreatIOC).filter(ThreatIOC.id == related_ioc_id).first()
        if related_ioc:
            result.append({
                'related_ioc_id': related_ioc.id,
                'related_value': related_ioc.value,
                'related_type': related_ioc.type,
                'relationship_type': rel.relationship_type,
                'confidence': rel.confidence,
                'source': rel.source
            })

    return result

@router.get("/campaigns")
async def get_threat_campaigns(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get detected threat campaigns."""
    campaigns = correlation_service.find_connected_components()
    return campaigns

@router.get("/temporal-analysis")
async def get_temporal_analysis(
    hours: int = 24,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get temporal correlation analysis."""
    analysis = correlation_service.temporal_correlation_analysis(hours)
    return analysis

@router.get("/anomalies")
async def get_anomaly_detection(
    days: int = 7,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get anomaly detection results."""
    from ...services.behavioral_analysis import behavioral_service
    anomalies = behavioral_service.detect_anomalous_patterns(days=days)
    return anomalies

@router.get("/behavioral-insights")
async def get_behavioral_insights(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get behavioral analysis insights."""
    from ...services.behavioral_analysis import behavioral_service

    insights = {
        'repeated_behaviors': behavioral_service.detect_repeated_ioc_behavior(),
        'lateral_movement': behavioral_service.detect_lateral_movement(),
        'campaigns': behavioral_service.analyze_campaign_patterns()
    }
    return insights