from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, DECIMAL, Enum, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from ..db.session import Base

class Role(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    permissions = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    role = relationship("Role", back_populates="users")
    alerts_acknowledged = relationship("Alert", back_populates="acknowledged_user")
    audit_logs = relationship("AuditLog", back_populates="user")

class ThreatIOC(Base):
    __tablename__ = "threat_iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum('ip', 'domain', 'url', 'hash'), nullable=False)
    value = Column(String(500), nullable=False)
    source = Column(String(255))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    risk_score = Column(DECIMAL(3,2), default=0.00)
    enriched = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    enrichments = relationship("IOCEnrichment", back_populates="ioc", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="ioc")
    
    __table_args__ = (
        Index('idx_threat_iocs_type_value', 'type', 'value', unique=True),
        Index('idx_threat_iocs_risk_score', 'risk_score'),
    )

class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichment"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id"), nullable=False)
    enrichment_type = Column(String(50), nullable=False)
    data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    ioc = relationship("ThreatIOC", back_populates="enrichments")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id"), nullable=False)
    severity = Column(Enum('low', 'medium', 'high', 'critical'), default='medium')
    message = Column(Text)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(Integer, ForeignKey("users.id"))
    acknowledged_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    ioc = relationship("ThreatIOC", back_populates="alerts")
    acknowledged_user = relationship("User", back_populates="alerts_acknowledged")
    logs = relationship("AlertLog", back_populates="alert", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_alerts_acknowledged', 'acknowledged'),
        Index('idx_alerts_created_at', 'created_at'),
    )

class AlertLog(Base):
    __tablename__ = "alert_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    action = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    alert = relationship("Alert", back_populates="logs")
    user = relationship("User")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100), nullable=False)
    resource = Column(String(100))
    resource_id = Column(Integer)
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    __table_args__ = (
        Index('idx_audit_logs_timestamp', 'timestamp'),
        Index('idx_audit_logs_user', 'user_id'),
    )