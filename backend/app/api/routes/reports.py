from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List
import json
import csv
import io
from datetime import datetime
from ...db.session import get_db
from ...models.models import ThreatIOC, Alert, AuditLog
from ...schemas.schemas import ReportExport
from ...security.auth import get_current_active_user

router = APIRouter()

@router.post("/export")
async def export_report(
    report_config: ReportExport,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user)
):
    """Export reports in various formats."""
    data = []
    
    if report_config.report_type == "iocs":
        query = db.query(ThreatIOC)
        if report_config.date_from:
            query = query.filter(ThreatIOC.created_at >= report_config.date_from)
        if report_config.date_to:
            query = query.filter(ThreatIOC.created_at <= report_config.date_to)
        items = query.all()
        
        for item in items:
            data.append({
                "id": item.id,
                "type": item.type,
                "value": item.value,
                "source": item.source,
                "risk_score": float(item.risk_score),
                "enriched": item.enriched,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "updated_at": item.updated_at.isoformat() if item.updated_at else None
            })
    
    elif report_config.report_type == "alerts":
        query = db.query(Alert)
        if report_config.date_from:
            query = query.filter(Alert.created_at >= report_config.date_from)
        if report_config.date_to:
            query = query.filter(Alert.created_at <= report_config.date_to)
        items = query.all()
        
        for item in items:
            data.append({
                "id": item.id,
                "ioc_id": item.ioc_id,
                "ioc_value": item.ioc.value if item.ioc else None,
                "severity": item.severity,
                "message": item.message,
                "acknowledged": item.acknowledged,
                "acknowledged_by": item.acknowledged_user.username if item.acknowledged_user else None,
                "created_at": item.created_at.isoformat()
            })
    
    elif report_config.report_type == "audit":
        query = db.query(AuditLog)
        if report_config.date_from:
            query = query.filter(AuditLog.timestamp >= report_config.date_from)
        if report_config.date_to:
            query = query.filter(AuditLog.timestamp <= report_config.date_to)
        items = query.all()
        
        for item in items:
            data.append({
                "id": item.id,
                "user": item.user.username if item.user else None,
                "action": item.action,
                "resource": item.resource,
                "resource_id": item.resource_id,
                "timestamp": item.timestamp.isoformat(),
                "ip_address": item.ip_address
            })
    
    else:
        raise HTTPException(status_code=400, detail="Invalid report type")
    
    # Generate response based on format
    if report_config.format == "json":
        json_data = json.dumps(data, indent=2)
        return StreamingResponse(
            io.StringIO(json_data),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={report_config.report_type}_report.json"}
        )
    
    elif report_config.format == "csv":
        output = io.StringIO()
        if data:
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={report_config.report_type}_report.csv"}
        )
    
    else:
        raise HTTPException(status_code=400, detail="Invalid format")