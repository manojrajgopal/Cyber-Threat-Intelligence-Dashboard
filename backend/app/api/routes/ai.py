from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ...db.session import get_db
from ...models.models import AIPrediction, ThreatIOC
from ...schemas.schemas import AIPrediction as AIPredictionSchema
from ...security.auth import get_current_active_user
from ...services.ai_classification import ai_service
from ...services.explainable_ai import explainable_ai_service

router = APIRouter()

@router.get("/predictions/{ioc_id}", response_model=List[AIPredictionSchema])
async def get_ai_predictions_for_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get all AI predictions for a specific IOC."""
    predictions = db.query(AIPrediction).filter(AIPrediction.ioc_id == ioc_id).all()
    return predictions

@router.get("/explain/{prediction_id}")
async def explain_prediction(
    prediction_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get detailed explanation for an AI prediction."""
    explanation = explainable_ai_service.explain_prediction(prediction_id)
    if 'error' in explanation:
        raise HTTPException(status_code=404, detail=explanation['error'])
    return explanation

@router.get("/summary/{ioc_id}")
async def get_prediction_summary(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Get AI prediction summary for an IOC."""
    summary = explainable_ai_service.get_prediction_summary(ioc_id)
    return summary

@router.post("/classify/{ioc_id}")
async def trigger_ai_classification(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Manually trigger AI classification for an IOC."""
    ioc = db.query(ThreatIOC).filter(ThreatIOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    prediction = ai_service.classify_threat(ioc_id, db)
    if prediction:
        db.add(prediction)
        db.commit()
        return {"message": "AI classification completed", "prediction_id": prediction.id}
    else:
        raise HTTPException(status_code=500, detail="AI classification failed")

@router.delete("/predictions/{prediction_id}")
async def delete_ai_prediction(
    prediction_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Delete a specific AI prediction."""
    prediction = db.query(AIPrediction).filter(AIPrediction.id == prediction_id).first()
    if not prediction:
        raise HTTPException(status_code=404, detail="Prediction not found")

    db.delete(prediction)
    db.commit()
    return {"message": "Prediction deleted"}

@router.delete("/predictions/ioc/{ioc_id}")
async def delete_all_ai_predictions_for_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Delete all AI predictions for a specific IOC."""
    predictions = db.query(AIPrediction).filter(AIPrediction.ioc_id == ioc_id).all()
    for prediction in predictions:
        db.delete(prediction)
    db.commit()
    return {"message": f"Deleted {len(predictions)} predictions"}