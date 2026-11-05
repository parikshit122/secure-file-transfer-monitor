from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from .database import Base

class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now())
    event_type = Column(String(50))
    src_path = Column(Text)
    dest_path = Column(Text, nullable=True)
    file_name = Column(String(500))
    file_size = Column(Integer, default=0)
    file_type = Column(String(100), nullable=True)
    user = Column(String(200), nullable=True)
    process = Column(String(200), nullable=True)
    hash_blake3 = Column(String(128), nullable=True)
    hash_sha256 = Column(String(128), nullable=True)
    is_sensitive = Column(Integer, default=0)
    threat_level = Column(String(20), default="clean")
    details = Column(Text, nullable=True)

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now())
    file_name = Column(String(500))
    file_path = Column(Text)
    file_type = Column(String(100))
    scan_type = Column(String(50))
    result = Column(String(20))
    threat_name = Column(String(200), nullable=True)
    details = Column(Text, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now())
    severity = Column(String(20))
    title = Column(String(500))
    description = Column(Text)
    file_name = Column(String(500), nullable=True)
    action_taken = Column(String(100), nullable=True)
    is_resolved = Column(Integer, default=0)
