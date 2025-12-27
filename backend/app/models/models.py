from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, DECIMAL, Enum, JSON, ForeignKey, Index, Float
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
    type = Column(Enum('ip', 'domain', 'url', 'hash', 'network'), nullable=False)
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

class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    threat_mappings = relationship("AccountThreatMapping", back_populates="account")

class ThreatInput(Base):
    __tablename__ = "threat_inputs"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum('ip', 'domain', 'url', 'hash', 'network'), nullable=False)
    value = Column(String(500), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    account_id = Column(Integer, ForeignKey("accounts.id"))
    continuous_monitoring = Column(Boolean, default=False)
    status = Column(Enum('pending', 'processing', 'processed', 'failed'), default='pending')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
    account = relationship("Account")
    lifecycle_entries = relationship("ThreatLifecycle", back_populates="threat_input", cascade="all, delete-orphan")
    ai_predictions = relationship("AIPrediction", back_populates="threat_input", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_threat_inputs_type_value', 'type', 'value'),
        Index('idx_threat_inputs_user', 'user_id'),
        Index('idx_threat_inputs_account', 'account_id'),
    )

class BulkIngestionJob(Base):
    __tablename__ = "bulk_ingestion_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    file_path = Column(String(500))
    file_type = Column(Enum('csv', 'json'), nullable=False)
    status = Column(Enum('pending', 'processing', 'completed', 'failed'), default='pending')
    total_items = Column(Integer, default=0)
    processed_items = Column(Integer, default=0)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")

    __table_args__ = (
        Index('idx_bulk_jobs_user', 'user_id'),
        Index('idx_bulk_jobs_status', 'status'),
    )

class AIPrediction(Base):
    __tablename__ = "ai_predictions"

    id = Column(Integer, primary_key=True, index=True)
    threat_input_id = Column(Integer, ForeignKey("threat_inputs.id"))
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id"))
    model_name = Column(String(255), nullable=False)
    prediction = Column(String(100), nullable=False)  # e.g., 'malicious', 'benign'
    confidence = Column(Float, nullable=False)
    features_used = Column(JSON)
    explanation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    threat_input = relationship("ThreatInput", back_populates="ai_predictions")
    ioc = relationship("ThreatIOC")

    __table_args__ = (
        Index('idx_ai_predictions_threat_input', 'threat_input_id'),
        Index('idx_ai_predictions_ioc', 'ioc_id'),
    )

class ModelRegistry(Base):
    __tablename__ = "model_registry"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    source = Column(Enum('huggingface', 'custom'), default='huggingface')
    model_id = Column(String(500))  # Hugging Face model ID
    version = Column(String(50))
    local_path = Column(String(500))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    source = Column(Enum('kaggle', 'custom'), default='kaggle')
    path = Column(String(500))
    features = Column(JSON)  # List of features
    target = Column(String(100))
    is_trained = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ThreatLifecycle(Base):
    __tablename__ = "threat_lifecycle"

    id = Column(Integer, primary_key=True, index=True)
    threat_input_id = Column(Integer, ForeignKey("threat_inputs.id"))
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id"))
    state = Column(Enum('new', 'under_analysis', 'confirmed_malicious', 'false_positive', 'mitigated'), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    notes = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    threat_input = relationship("ThreatInput", back_populates="lifecycle_entries")
    ioc = relationship("ThreatIOC")
    user = relationship("User")

    __table_args__ = (
        Index('idx_lifecycle_threat_input', 'threat_input_id'),
        Index('idx_lifecycle_ioc', 'ioc_id'),
        Index('idx_lifecycle_state', 'state'),
    )

class IOCRelationship(Base):
    __tablename__ = "ioc_relationships"

    id = Column(Integer, primary_key=True, index=True)
    ioc1_id = Column(Integer, ForeignKey("threat_iocs.id"), nullable=False)
    ioc2_id = Column(Integer, ForeignKey("threat_iocs.id"), nullable=False)
    relationship_type = Column(String(100), nullable=False)  # e.g., 'related', 'campaign'
    confidence = Column(Float, default=0.0)
    source = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    ioc1 = relationship("ThreatIOC", foreign_keys=[ioc1_id])
    ioc2 = relationship("ThreatIOC", foreign_keys=[ioc2_id])

    __table_args__ = (
        Index('idx_ioc_rel_ioc1', 'ioc1_id'),
        Index('idx_ioc_rel_ioc2', 'ioc2_id'),
    )

class AccountThreatMapping(Base):
    __tablename__ = "account_threat_mapping"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("accounts.id"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("threat_iocs.id"))
    threat_input_id = Column(Integer, ForeignKey("threat_inputs.id"))
    assigned_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    account = relationship("Account", back_populates="threat_mappings")
    ioc = relationship("ThreatIOC")
    threat_input = relationship("ThreatInput")

    __table_args__ = (
        Index('idx_mapping_account', 'account_id'),
        Index('idx_mapping_ioc', 'ioc_id'),
        Index('idx_mapping_threat_input', 'threat_input_id'),
    )