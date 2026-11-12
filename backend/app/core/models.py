from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from datetime import datetime
from app.core.database import Base

class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String)
    source_path = Column(String)
    dest_path = Column(String, nullable=True)
    file_size = Column(Integer, default=0)
    process_name = Column(String, default="unknown")
    username = Column(String, default="unknown")
    file_hash = Column(String, default="UNKNOWN_HASH")
    integrity_state = Column(String, default="BASELINE")
    timestamp = Column(DateTime, default=datetime.utcnow)

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    threat_score = Column(Integer, default=0)
    verdict = Column(String, default="BENIGN")
    threats_detected = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String, default="HIGH")
    title = Column(String)
    description = Column(Text)
    file_path = Column(String)
    status = Column(String, default="UNRESOLVED")
    timestamp = Column(DateTime, default=datetime.utcnow)

class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    rule_type = Column(String)
    target_value = Column(String)
    is_active = Column(Boolean, default=True)

class SensitiveDirectory(Base):
    __tablename__ = "sensitive_directories"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String, unique=True)
    description = Column(String, default="")

class QuarantinedFile(Base):
    __tablename__ = "quarantined_files"

    id = Column(Integer, primary_key=True, index=True)
    original_name = Column(String)
    original_path = Column(String)
    quarantine_path = Column(String)
    file_hash = Column(String)
    reason = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)