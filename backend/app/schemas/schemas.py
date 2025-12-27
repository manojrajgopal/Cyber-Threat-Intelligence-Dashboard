from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
from decimal import Decimal

# Auth schemas
class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None

# User schemas
class RoleBase(BaseModel):
    name: str
    permissions: Optional[Dict[str, Any]] = None

class Role(RoleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str
    role_id: Optional[int] = None

class User(UserBase):
    id: int
    role: Optional[Role] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# IOC schemas
class IOCBase(BaseModel):
    type: str  # ip, domain, url, hash, network
    value: str
    source: Optional[str] = None

class IOCCreate(IOCBase):
    pass

class IOCEnrichment(BaseModel):
    enrichment_type: str
    data: Dict[str, Any]

class IOC(IOCBase):
    id: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    risk_score: Decimal
    enriched: bool
    enrichments: List[IOCEnrichment] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Alert schemas
class AlertBase(BaseModel):
    ioc_id: int
    severity: Optional[str] = "medium"  # low, medium, high, critical
    message: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class AlertAcknowledge(BaseModel):
    acknowledged: bool

class Alert(BaseModel):
    id: int
    ioc: IOC
    severity: str
    message: Optional[str] = None
    acknowledged: bool
    acknowledged_by: Optional[int] = None
    acknowledged_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Dashboard schemas
class DashboardMetrics(BaseModel):
    total_iocs: int
    high_risk_iocs: int
    active_alerts: int
    acknowledged_alerts: int
    recent_alerts: List[Alert]
    # Risk level breakdown
    critical_risk_iocs: int = 0
    medium_risk_iocs: int = 0
    low_risk_iocs: int = 0

# Report schemas
class ReportExport(BaseModel):
    report_type: str  # iocs, alerts, audit
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    format: str = "json"  # json, csv, pdf

# Audit schemas
class AuditLog(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    resource: Optional[str] = None
    resource_id: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True

# Generic response schemas
class APIResponse(BaseModel):
    success: bool
    message: Optional[str] = None
    data: Optional[Any] = None

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int

# Account schemas
class AccountBase(BaseModel):
    name: str
    description: Optional[str] = None

class AccountCreate(AccountBase):
    pass

class Account(AccountBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Threat Input schemas
class ThreatInputBase(BaseModel):
    type: str  # ip, domain, url, hash, network
    value: str
    continuous_monitoring: Optional[bool] = False

class ThreatInputCreate(ThreatInputBase):
    pass

class ThreatInput(ThreatInputBase):
    id: int
    user_id: Optional[int] = None
    account_id: Optional[int] = None
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Bulk Ingestion schemas
class BulkIngestionJobBase(BaseModel):
    file_type: str  # csv, json

class BulkIngestionJobCreate(BulkIngestionJobBase):
    pass

class BulkIngestionJob(BulkIngestionJobBase):
    id: int
    user_id: Optional[int] = None
    file_path: Optional[str] = None
    status: str
    total_items: int
    processed_items: int
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# AI Prediction schemas
class AIPredictionBase(BaseModel):
    model_name: str
    prediction: str
    confidence: float
    features_used: Optional[Dict[str, Any]] = None
    explanation: Optional[str] = None

class AIPredictionCreate(AIPredictionBase):
    threat_input_id: Optional[int] = None
    ioc_id: Optional[int] = None

class AIPrediction(AIPredictionBase):
    id: int
    threat_input_id: Optional[int] = None
    ioc_id: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Model Registry schemas
class ModelRegistryBase(BaseModel):
    name: str
    source: str  # huggingface, custom
    model_id: Optional[str] = None
    version: Optional[str] = None
    local_path: Optional[str] = None

class ModelRegistryCreate(ModelRegistryBase):
    pass

class ModelRegistry(ModelRegistryBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Dataset schemas
class DatasetBase(BaseModel):
    name: str
    source: str  # kaggle, custom
    path: Optional[str] = None
    features: Optional[List[str]] = None
    target: Optional[str] = None

class DatasetCreate(DatasetBase):
    pass

class Dataset(DatasetBase):
    id: int
    is_trained: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Threat Lifecycle schemas
class ThreatLifecycleBase(BaseModel):
    state: str  # new, under_analysis, confirmed_malicious, false_positive, mitigated
    notes: Optional[str] = None

class ThreatLifecycleCreate(ThreatLifecycleBase):
    threat_input_id: Optional[int] = None
    ioc_id: Optional[int] = None

class ThreatLifecycleTransition(BaseModel):
    threat_input_id: Optional[int] = None
    ioc_id: Optional[int] = None
    new_state: str
    notes: Optional[str] = None

class ThreatLifecycle(ThreatLifecycleBase):
    id: int
    threat_input_id: Optional[int] = None
    ioc_id: Optional[int] = None
    user_id: Optional[int] = None
    timestamp: datetime

    class Config:
        from_attributes = True

# IOC Relationship schemas
class IOCRelationshipBase(BaseModel):
    ioc1_id: int
    ioc2_id: int
    relationship_type: str
    confidence: Optional[float] = 0.0
    source: Optional[str] = None

class IOCRelationshipCreate(IOCRelationshipBase):
    pass

class IOCRelationship(IOCRelationshipBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Account Threat Mapping schemas
class AccountThreatMappingBase(BaseModel):
    account_id: int

class AccountThreatMappingCreate(AccountThreatMappingBase):
    ioc_id: Optional[int] = None
    threat_input_id: Optional[int] = None

class AccountThreatMapping(AccountThreatMappingBase):
    id: int
    ioc_id: Optional[int] = None
    threat_input_id: Optional[int] = None
    assigned_at: datetime

    class Config:
        from_attributes = True

# Ingestion schemas
class SingleIngestionRequest(BaseModel):
    type: str
    value: str
    continuous_monitoring: Optional[bool] = False

class BulkIngestionRequest(BaseModel):
    file: bytes  # For file upload
    file_type: str

class IngestionResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

# Risk Management schemas
class RiskSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int

class RiskFilterResponse(BaseModel):
    summary: RiskSummary
    risks: List[IOC]
    filter_applied: str