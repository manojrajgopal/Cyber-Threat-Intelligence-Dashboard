from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...models.models import User
from ...security.auth import get_current_active_user
from ...services.account_mapping import account_service

router = APIRouter()

@router.get("/threats")
async def get_account_threats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all threats assigned to the current user's account."""
    account_id = account_service.get_user_default_account(current_user.id)
    if not account_id:
        return {"threats": [], "message": "No account assigned"}

    threats = account_service.get_account_threats(account_id)
    return threats

@router.get("/stats")
async def get_account_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get threat statistics for the current user's account."""
    account_id = account_service.get_user_default_account(current_user.id)
    if not account_id:
        return {"message": "No account assigned"}

    stats = account_service.get_account_statistics(account_id)
    return stats

@router.delete("/threats/ioc/{ioc_id}")
async def remove_ioc_from_account(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Remove an IOC assignment from the current user's account."""
    account_id = account_service.get_user_default_account(current_user.id)
    if not account_id:
        raise HTTPException(status_code=400, detail="No account assigned")

    success = account_service.remove_threat_from_account(ioc_id, account_id, 'ioc')
    if success:
        return {"message": "IOC removed from account"}
    else:
        raise HTTPException(status_code=404, detail="IOC assignment not found")

@router.delete("/threats/input/{threat_input_id}")
async def remove_threat_input_from_account(
    threat_input_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Remove a threat input assignment from the current user's account."""
    account_id = account_service.get_user_default_account(current_user.id)
    if not account_id:
        raise HTTPException(status_code=400, detail="No account assigned")

    success = account_service.remove_threat_from_account(threat_input_id, account_id, 'threat_input')
    if success:
        return {"message": "Threat input removed from account"}
    else:
        raise HTTPException(status_code=404, detail="Threat input assignment not found")