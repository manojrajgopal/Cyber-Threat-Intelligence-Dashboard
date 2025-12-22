from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ...db.session import get_db
from ...models.models import Alert, AlertLog
from ...schemas.schemas import Alert as AlertSchema, AlertCreate, AlertAcknowledge
from ...security.auth import get_current_active_user, ANALYST_OR_ADMIN

router = APIRouter()

@router.get("/", response_model=List[AlertSchema])
async def get_alerts(
    skip: int = 0,
    limit: int = 100,
    acknowledged: bool = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get all alerts."""
    query = db.query(Alert)
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    alerts = query.offset(skip).limit(limit).all()
    return alerts

@router.post("/", response_model=AlertSchema)
async def create_alert(
    alert: AlertCreate,
    db: Session = Depends(get_db),
    current_user = Depends(ANALYST_OR_ADMIN)
):
    """Create a new alert."""
    # Check if IOC exists
    from ...models.models import ThreatIOC
    db_ioc = db.query(ThreatIOC).filter(ThreatIOC.id == alert.ioc_id).first()
    if not db_ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    db_alert = Alert(
        ioc_id=alert.ioc_id,
        severity=alert.severity or "medium",
        message=alert.message
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    
    # Log alert creation
    alert_log = AlertLog(
        alert_id=db_alert.id,
        action="created",
        user_id=current_user.id,
        details={"severity": db_alert.severity}
    )
    db.add(alert_log)
    db.commit()
    
    return db_alert

@router.get("/{alert_id}", response_model=AlertSchema)
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get alert by ID."""
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return db_alert

@router.put("/{alert_id}/acknowledge", response_model=AlertSchema)
async def acknowledge_alert(
    alert_id: int,
    acknowledge_data: AlertAcknowledge,
    db: Session = Depends(get_db),
    current_user = Depends(ANALYST_OR_ADMIN)
):
    """Acknowledge or unacknowledge an alert."""
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    from datetime import datetime
    db_alert.acknowledged = acknowledge_data.acknowledged
    if acknowledge_data.acknowledged:
        db_alert.acknowledged_by = current_user.id
        db_alert.acknowledged_at = datetime.utcnow()
    else:
        db_alert.acknowledged_by = None
        db_alert.acknowledged_at = None
    
    db.commit()
    db.refresh(db_alert)
    
    # Log acknowledgment
    alert_log = AlertLog(
        alert_id=alert_id,
        action="acknowledged" if acknowledge_data.acknowledged else "unacknowledged",
        user_id=current_user.id
    )
    db.add(alert_log)
    db.commit()
    
    return db_alert

@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(ANALYST_OR_ADMIN)
):
    """Delete an alert."""
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    db.delete(db_alert)
    db.commit()
    
    return {"message": "Alert deleted"}