from sqlalchemy import JSON, Column, Integer, String, DateTime, ForeignKey, Enum as SQLEnum, Text
from sqlalchemy.orm import relationship
from app.db.base import Base
import enum
from datetime import datetime, timezone

class ScanStatus(enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    failed = "failed"

class ScanType(enum.Enum):
    quick = "quick"
    full = "full"
    custom = "custom"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_url = Column(String(500), nullable=False)
    scan_type = Column(SQLEnum(ScanType), default=ScanType.full)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.pending)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    scan_duration = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    custom_options = Column(JSON, nullable=True)

    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
