"""SQLAlchemy database models for phishing detection system."""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    Text, JSON, ForeignKey, Index, create_engine
)
from sqlalchemy.orm import relationship, DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class URLCheck(Base):
    """Records of all URL checks performed."""
    __tablename__ = "url_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(Text, nullable=False, index=True)
    url_hash = Column(String(64), nullable=False, index=True)

    # ML Model Results
    ml_score = Column(Float, nullable=True)
    ml_prediction = Column(Boolean, nullable=True)
    ml_model_version = Column(String(50), nullable=True)

    # PhishTank Results
    phishtank_match = Column(Boolean, nullable=True)
    phishtank_id = Column(Integer, nullable=True)
    phishtank_target = Column(String(255), nullable=True)

    # Combined Result
    is_phishing = Column(Boolean, nullable=False)
    confidence = Column(Float, nullable=False)
    detection_source = Column(String(50), nullable=False)  # 'ml', 'database', 'both'

    # Extracted Features (stored as JSON for analysis)
    features = Column(JSON, nullable=True)

    # Metadata
    checked_at = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(45), nullable=True)

    # Relationships
    alerts = relationship("Alert", back_populates="url_check")

    __table_args__ = (
        Index('ix_url_checks_date_phishing', 'checked_at', 'is_phishing'),
    )


class Alert(Base):
    """Alerts generated for detected phishing URLs."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url_check_id = Column(Integer, ForeignKey("url_checks.id"), nullable=False)

    severity = Column(String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    status = Column(String(20), default="new")  # 'new', 'acknowledged', 'resolved', 'false_positive'

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(255), nullable=True)

    # Relationships
    url_check = relationship("URLCheck", back_populates="alerts")

    __table_args__ = (
        Index('ix_alerts_status_severity', 'status', 'severity'),
    )


class PhishTankEntry(Base):
    """Cached PhishTank database entries."""
    __tablename__ = "phishtank_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    phish_id = Column(Integer, unique=True, nullable=False, index=True)
    url = Column(Text, nullable=False)
    url_hash = Column(String(64), nullable=False, index=True)

    submission_time = Column(DateTime, nullable=True)
    verification_time = Column(DateTime, nullable=True)
    online = Column(Boolean, default=True)
    target = Column(String(255), nullable=True, index=True)

    # Sync metadata
    synced_at = Column(DateTime, default=datetime.utcnow)


class MLModel(Base):
    """ML model versioning and metadata."""
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String(50), unique=True, nullable=False)

    model_type = Column(String(100), nullable=False)
    model_path = Column(String(500), nullable=False)

    # Training metrics
    accuracy = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    auc_roc = Column(Float, nullable=True)

    # Training data info
    training_samples = Column(Integer, nullable=True)
    phishing_samples = Column(Integer, nullable=True)
    legitimate_samples = Column(Integer, nullable=True)

    # Status
    is_active = Column(Boolean, default=False)
    trained_at = Column(DateTime, default=datetime.utcnow)
    activated_at = Column(DateTime, nullable=True)

    # Hyperparameters
    hyperparameters = Column(JSON, nullable=True)
    feature_names = Column(JSON, nullable=True)


class DailyStatistics(Base):
    """Aggregated daily statistics for dashboard."""
    __tablename__ = "daily_statistics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime, unique=True, nullable=False, index=True)

    total_checks = Column(Integer, default=0)
    phishing_detected = Column(Integer, default=0)
    legitimate_detected = Column(Integer, default=0)

    ml_detections = Column(Integer, default=0)
    database_detections = Column(Integer, default=0)
    both_detections = Column(Integer, default=0)

    # Top targets
    top_targets = Column(JSON, nullable=True)

    # Average scores
    avg_ml_score = Column(Float, nullable=True)
    avg_confidence = Column(Float, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def init_db(database_url: str):
    """Initialize database and create all tables."""
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(engine)
    return engine


def get_session(engine):
    """Get a database session."""
    Session = sessionmaker(bind=engine)
    return Session()
