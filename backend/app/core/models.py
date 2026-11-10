from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.core.database import Base


class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    event_type = Column(
        String, nullable=False
    )  # copy, move, delete, create, modify, upload, download
    source_path = Column(String, nullable=True)
    dest_path = Column(String, nullable=True)
    file_size = Column(Integer, default=0)
    file_hash = Column(String, nullable=True)  # BLAKE3 hash after event
    pre_hash = Column(String, nullable=True)  # hash before transfer
    post_hash = Column(String, nullable=True)  # hash after transfer
    integrity_status = Column(
        String, default="unknown"
    )  # verified, tampered, unknown
    process_name = Column(String, nullable=True)  # which app did this
    username = Column(String, nullable=True)  # which user
    is_sensitive = Column(Boolean, default=False)  # is in restricted dir
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan_results = relationship("ScanResult", back_populates="file_event")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    file_event_id = Column(Integer, ForeignKey("file_events.id"), nullable=True)
    file_hash = Column(String, nullable=True)
    verdict = Column(String)  # clean, suspicious, dangerous
    threat_score = Column(Integer, default=0)
    findings = Column(Text, default="")
    scan_duration_ms = Column(Float, default=0)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    file_event = relationship("FileEvent", back_populates="scan_results")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String)  # low, medium, high, critical
    alert_type = Column(
        String, default="threat"
    )  # threat, unauthorized_move, integrity_mismatch, policy_violation, exfiltration
    title = Column(String)
    description = Column(Text)
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    policy_type = Column(
        String
    )  # extension_block, size_limit, double_extension, archive_scan, whitelist, restricted_dir, transfer_limit
    action = Column(String)  # block, alert, allow, quarantine
    enabled = Column(Boolean, default=True)
    parameters = Column(Text, default="")  # comma-separated values or JSON


class SensitiveDirectory(Base):
    __tablename__ = "sensitive_directories"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, nullable=False, unique=True)
    label = Column(String, default="")  # e.g. "HR Documents", "Finance"
    alert_on_access = Column(Boolean, default=True)
    alert_on_copy = Column(Boolean, default=True)
    alert_on_move = Column(Boolean, default=True)
    alert_on_delete = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class QuarantinedFile(Base):
    __tablename__ = "quarantined_files"
    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String, nullable=False)
    original_path = Column(String, nullable=False)
    quarantine_path = Column(String, nullable=False)
    file_hash = Column(String, nullable=True)
    file_size = Column(Integer, default=0)
    reason = Column(Text, default="")
    quarantined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_restored = Column(Boolean, default=False)