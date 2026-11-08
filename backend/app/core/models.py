from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime, timezone


class FileEvent(Base):
    __tablename__ = "file_events"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_size = Column(Integer, default=0)
    file_hash = Column(String, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    scan_results = relationship("ScanResult", back_populates="file_event")
    alerts = relationship("Alert", back_populates="file_event")


class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    file_event_id = Column(Integer, ForeignKey("file_events.id"), nullable=True)
    file_hash = Column(String, nullable=True)
    verdict = Column(String, default="clean")
    threat_score = Column(Integer, default=0)
    findings = Column(Text, default="[]")
    scan_duration_ms = Column(Float, default=0.0)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    file_event = relationship("FileEvent", back_populates="scan_results")


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    file_event_id = Column(Integer, ForeignKey("file_events.id"), nullable=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=True)
    severity = Column(String, default="info")
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    file_event = relationship("FileEvent", back_populates="alerts")