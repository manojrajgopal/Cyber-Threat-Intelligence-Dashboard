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
    type: str  # ip, domain, url, hash
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
        orm_mode = True
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