from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from ...db.session import get_db
from ...models.models import ThreatLifecycle
from ...schemas.schemas import ThreatLifecycle as ThreatLifecycleSchema, ThreatLifecycleCreate, ThreatLifecycleTransition
from ...security.auth import get_current_active_user
from ...services.threat_lifecycle import lifecycle_service

router = APIRouter()

@router.get("/history/{threat_input_id}")
async def get_lifecycle_history(
    threat_input_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get lifecycle history for a threat input."""
    history = lifecycle_service.get_lifecycle_history(threat_input_id=threat_input_id)
    return history

@router.get("/ioc-history/{ioc_id}")
async def get_ioc_lifecycle_history(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get lifecycle history for an IOC."""
    history = lifecycle_service.get_lifecycle_history(ioc_id=ioc_id)
    return history

@router.post("/transition")
async def transition_lifecycle(
    transition: ThreatLifecycleTransition,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Transition a threat to a new lifecycle state."""
    try:
        success = lifecycle_service.transition_state(
            threat_input_id=transition.threat_input_id,
            ioc_id=transition.ioc_id,
            new_state=transition.new_state,
            user_id=current_user.id,
            notes=transition.notes
        )
        if success:
            return {"message": f"Successfully transitioned to {transition.new_state}"}
        else:
            raise HTTPException(status_code=400, detail="Transition failed")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/states/{state}")
async def get_threats_by_state(
    state: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get all threats in a specific state."""
    threats = lifecycle_service.get_threats_by_state(state, limit)
    return threats

@router.get("/stats")
async def get_lifecycle_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get lifecycle statistics."""
    stats = lifecycle_service.get_lifecycle_stats()
    return stats