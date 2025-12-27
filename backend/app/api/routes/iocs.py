from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from ...db.session import get_db
from ...models.models import ThreatIOC, IOCEnrichment, Alert, IOCRelationship, AccountThreatMapping, AlertLog, AIPrediction, ThreatLifecycle
from ...schemas.schemas import IOC as IOCSchema, IOCCreate, IOCEnrichment as IOCEnrichmentSchema
from ...security.auth import get_current_active_user, ANALYST_OR_ADMIN
from ...services.enrichment import enrich_ioc

router = APIRouter()

@router.get("/", response_model=List[IOCSchema])
async def get_iocs(
    skip: int = 0,
    limit: int = 100,
    type_filter: str = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get all IOCs sorted by latest first."""
    query = db.query(ThreatIOC)
    if type_filter:
        query = query.filter(ThreatIOC.type == type_filter)
    # Sort by created_at in descending order to show latest IOCs first
    iocs = query.order_by(ThreatIOC.created_at.desc()).offset(skip).limit(limit).all()
    return iocs

@router.post("/", response_model=IOCSchema)
async def create_ioc(
    ioc: IOCCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(ANALYST_OR_ADMIN)
):
    """Create a new IOC."""
    # Check if IOC already exists
    db_ioc = db.query(ThreatIOC).filter(
        ThreatIOC.type == ioc.type,
        ThreatIOC.value == ioc.value
    ).first()
    if db_ioc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IOC already exists"
        )
    
    db_ioc = ThreatIOC(
        type=ioc.type,
        value=ioc.value,
        source=ioc.source
    )
    db.add(db_ioc)
    db.commit()
    db.refresh(db_ioc)
    
    # Trigger enrichment in background
    background_tasks.add_task(enrich_ioc, db_ioc.id, db)
    
    return db_ioc

@router.get("/{ioc_id}", response_model=IOCSchema)
async def get_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get IOC by ID."""
    db_ioc = db.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
    if db_ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return db_ioc

@router.post("/{ioc_id}/enrich")
async def enrich_ioc_endpoint(
    ioc_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(ANALYST_OR_ADMIN)
):
    """Manually trigger IOC enrichment."""
    db_ioc = db.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
    if db_ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    # Trigger enrichment
    background_tasks.add_task(enrich_ioc, ioc_id, db)
    
    return {"message": "Enrichment started"}

@router.delete("/{ioc_id}")
async def delete_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(ANALYST_OR_ADMIN)
):
    """Delete an IOC."""
    db_ioc = db.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
    if db_ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Delete related records first to avoid foreign key constraint issues
    # Delete alert logs first
    db.query(AlertLog).filter(AlertLog.alert_id.in_(db.query(Alert.id).filter(Alert.ioc_id == ioc_id))).delete(synchronize_session=False)
    # Then delete alerts
    db.query(Alert).filter(Alert.ioc_id == ioc_id).delete(synchronize_session=False)
    db.query(IOCEnrichment).filter(IOCEnrichment.ioc_id == ioc_id).delete(synchronize_session=False)
    db.query(AIPrediction).filter(AIPrediction.ioc_id == ioc_id).delete(synchronize_session=False)
    db.query(ThreatLifecycle).filter(ThreatLifecycle.ioc_id == ioc_id).delete(synchronize_session=False)
    db.query(IOCRelationship).filter((IOCRelationship.ioc1_id == ioc_id) | (IOCRelationship.ioc2_id == ioc_id)).delete(synchronize_session=False)
    db.query(AccountThreatMapping).filter(AccountThreatMapping.ioc_id == ioc_id).delete(synchronize_session=False)

    db.delete(db_ioc)
    db.commit()

    return {"message": "IOC deleted"}

@router.get("/map", response_model=List[Dict[str, Any]])
async def get_map_iocs(db: Session = Depends(get_db), current_user = Depends(get_current_active_user)):
    enrichments = db.query(IOCEnrichment).filter(IOCEnrichment.enrichment_type == "geolocation").all()
    map_data = []
    for enrichment in enrichments:
        ioc = enrichment.ioc
        geo_data = enrichment.data
        if isinstance(geo_data, dict):
            lat = geo_data.get("lat")
            lon = geo_data.get("lon")
            if lat is not None and lon is not None:
                map_data.append({
                    "id": ioc.id,
                    "type": ioc.type,
                    "value": ioc.value,
                    "risk_score": float(ioc.risk_score),
                    "lat": lat,
                    "lon": lon,
                    "country": geo_data.get("country"),
                    "city": geo_data.get("city")
                })
    return map_data