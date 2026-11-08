from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.models import FileEvent, ScanResult, Alert
from app.scanning.scanner import scan_file, scan_bytes

router = APIRouter()


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(FileEvent).count()
    scans = db.query(ScanResult).count()
    threats = (
        db.query(ScanResult)
        .filter(ScanResult.verdict.in_(["suspicious", "dangerous"]))
        .count()
    )
    alerts = db.query(Alert).filter(Alert.is_resolved == False).count()
    return {
        "total_files": total,
        "total_scans": scans,
        "threats_blocked": threats,
        "active_alerts": alerts,
    }


@router.get("/events")
def get_events(limit: int = 50, db: Session = Depends(get_db)):
    events = db.query(FileEvent).order_by(FileEvent.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "filename": e.filename,
            "event_type": e.event_type,
            "file_path": e.file_path,
            "file_size": e.file_size,
            "file_hash": e.file_hash,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]


@router.get("/scans")
def get_scans(limit: int = 50, db: Session = Depends(get_db)):
    scans = (
        db.query(ScanResult).order_by(ScanResult.scanned_at.desc()).limit(limit).all()
    )
    results = []
    for s in scans:
        fe = db.query(FileEvent).filter(FileEvent.id == s.file_event_id).first()
        results.append(
            {
                "id": s.id,
                "filename": fe.filename if fe else "unknown",
                "file_hash": s.file_hash,
                "verdict": s.verdict,
                "threat_score": s.threat_score,
                "findings": s.findings,
                "scan_duration_ms": s.scan_duration_ms,
                "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
            }
        )
    return results


@router.get("/alerts")
def get_alerts(active_only: bool = True, db: Session = Depends(get_db)):
    q = db.query(Alert).order_by(Alert.created_at.desc())
    if active_only:
        q = q.filter(Alert.is_resolved == False)
    return [
        {
            "id": a.id,
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "is_resolved": a.is_resolved,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in q.limit(50).all()
    ]


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.is_resolved = True
        db.commit()
        return {"status": "resolved"}
    return {"status": "not found"}


@router.post("/scan")
def scan_upload(file: UploadFile = File(...)):
    data = file.file.read()
    result = scan_bytes(file.filename, data)
    return {
        "filename": file.filename,
        "file_size": result.file_size,
        "file_hash": result.file_hash,
        "file_type": result.file_type,
        "verdict": result.verdict,
        "threat_score": result.threat_score,
        "findings": result.findings,
        "scan_duration_ms": result.scanned_in_ms,
    }
