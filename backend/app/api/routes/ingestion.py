from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, UploadFile, File
from sqlalchemy.orm import Session
from typing import List
import csv
import json
import io
from ...db.session import get_db
from ...models.models import ThreatInput, BulkIngestionJob, Account, User
from ...schemas.schemas import ThreatInput as ThreatInputSchema, BulkIngestionJob as BulkIngestionJobSchema, SingleIngestionRequest, BulkIngestionRequest, IngestionResponse
from ...security.auth import get_current_active_user, ANALYST_OR_ADMIN
from ...services.ingestion import process_single_input, process_bulk_file

router = APIRouter()

@router.post("/single", response_model=IngestionResponse)
async def ingest_single(
    request: SingleIngestionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Ingest a single threat input and return AI prediction."""
    try:
        # Validate input type
        if request.type not in ['ip', 'domain', 'url', 'hash']:
            raise HTTPException(status_code=400, detail="Invalid input type")

        # Get default account (assuming user has account, or create default)
        account_id = None
        if hasattr(current_user, 'account_id') and current_user.account_id:
            account_id = current_user.account_id
        else:
            # Find or create default account
            default_account = db.query(Account).filter(Account.name == "Default").first()
            if not default_account:
                default_account = Account(name="Default", description="Default account for threat inputs")
                db.add(default_account)
                db.commit()
                db.refresh(default_account)
            account_id = default_account.id

        # Create threat input
        threat_input = ThreatInput(
            type=request.type,
            value=request.value,
            user_id=current_user.id,
            account_id=account_id,
            continuous_monitoring=request.continuous_monitoring,
            status='pending'
        )
        db.add(threat_input)
        db.commit()
        db.refresh(threat_input)

        # Process synchronously and get prediction result
        prediction_result = process_single_input(threat_input.id, db)

        response_data = {
            "threat_input_id": threat_input.id,
            "ioc_processed": True
        }

        if prediction_result:
            response_data["ai_prediction"] = prediction_result
            message = f"Threat input processed successfully. AI Prediction: {prediction_result['prediction'].upper()}"
        else:
            message = "Threat input processed successfully, but AI prediction failed."

        return IngestionResponse(
            success=True,
            message=message,
            data=response_data
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/bulk", response_model=IngestionResponse)
async def ingest_bulk(
    request: BulkIngestionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(ANALYST_OR_ADMIN)
):
    """Ingest bulk threat inputs from uploaded file."""
    try:
        # Save file temporarily (in production, use proper file storage)
        file_path = f"/tmp/bulk_{current_user.id}_{request.file_type}.tmp"
        with open(file_path, "wb") as f:
            f.write(request.file)

        # Create job
        job = BulkIngestionJob(
            user_id=current_user.id,
            file_path=file_path,
            file_type=request.file_type,
            status='pending'
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        # Process in background
        background_tasks.add_task(process_bulk_file, job.id, db)

        return IngestionResponse(
            success=True,
            message="Bulk ingestion job created",
            data={"job_id": job.id}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/upload", response_model=IngestionResponse)
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(ANALYST_OR_ADMIN)
):
    """Upload and ingest threat inputs from file."""
    try:
        # Validate file type
        if file.filename.endswith('.csv'):
            file_type = 'csv'
        elif file.filename.endswith('.json'):
            file_type = 'json'
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")

        # Read file content
        content = await file.read()

        # Save file
        file_path = f"/tmp/upload_{current_user.id}_{file.filename}"
        with open(file_path, "wb") as f:
            f.write(content)

        # Create job
        job = BulkIngestionJob(
            user_id=current_user.id,
            file_path=file_path,
            file_type=file_type,
            status='pending'
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        # Process in background
        background_tasks.add_task(process_bulk_file, job.id, db)

        return IngestionResponse(
            success=True,
            message="File uploaded and ingestion job created",
            data={"job_id": job.id}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/jobs", response_model=List[BulkIngestionJobSchema])
async def get_ingestion_jobs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = 0,
    limit: int = 100
):
    """Get ingestion jobs for current user."""
    jobs = db.query(BulkIngestionJob).filter(BulkIngestionJob.user_id == current_user.id).offset(skip).limit(limit).all()
    return jobs

@router.get("/jobs/{job_id}", response_model=BulkIngestionJobSchema)
async def get_ingestion_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get specific ingestion job."""
    job = db.query(BulkIngestionJob).filter(
        BulkIngestionJob.id == job_id,
        BulkIngestionJob.user_id == current_user.id
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job