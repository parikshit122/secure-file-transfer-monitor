import os
import shutil
import tempfile
import csv
import io
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.core.models import FileEvent, ScanResult, Alert, Policy, SensitiveDirectory, QuarantinedFile
from app.scanning.scanner import scan_file, scan_bytes
from app.defense.quarantine import quarantine_file, restore_quarantined_file, delete_quarantined_file
from app.core.notifications import send_alert_notification

router = APIRouter()

# --- STATS ENDPOINT ---
@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_transfers = db.query(FileEvent).count()
    total_threats = db.query(ScanResult).filter(ScanResult.threat_score >= 35).count()
    unresolved_alerts = db.query(Alert).filter(Alert.status == "UNRESOLVED").count()
    quarantined_count = db.query(QuarantinedFile).count()

    recent_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(5).all()

    return {
        "total_transfers": total_transfers,
        "total_threats": total_threats,
        "unresolved_alerts": unresolved_alerts,
        "quarantined_count": quarantined_count,
        "recent_alerts": [
            {
                "id": a.id,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "file_path": a.file_path,
                "status": a.status,
                "timestamp": a.timestamp.isoformat() if a.timestamp else ""
            } for a in recent_alerts
        ]
    }

# --- EVENTS ENDPOINT ---
@router.get("/events")
def get_events(
    event_type: Optional[str] = None,
    integrity_state: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(FileEvent)
    if event_type:
        query = query.filter(FileEvent.event_type == event_type)
    if integrity_state:
        query = query.filter(FileEvent.integrity_state == integrity_state)
    if search:
        query = query.filter(
            (FileEvent.source_path.like(f"%{search}%")) |
            (FileEvent.process_name.like(f"%{search}%")) |
            (FileEvent.username.like(f"%{search}%"))
        )
    events = query.order_by(FileEvent.timestamp.desc()).limit(limit).all()
    return events

# --- SCANS ENDPOINT ---
@router.get("/scans")
def get_scans(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(ScanResult).order_by(ScanResult.timestamp.desc()).limit(limit).all()

# --- SCAN UPLOAD ENDPOINT ---
@router.post("/scan")
async def handle_scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    temp_path = None
    try:
        temp_dir = os.path.join(tempfile.gettempdir(), "sftms_scans")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, file.filename)

        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = scan_file(temp_path, db)

        # Dynamic Kwargs for ScanResult based on model columns
        valid_cols = [c.name for c in ScanResult.__table__.columns]
        scan_kwargs = {
            "threat_score": result["threat_score"],
            "verdict": result["verdict"],
            "threats_detected": "; ".join(result["threats_detected"]),
            "timestamp": datetime.utcnow()
        }
        if "file_name" in valid_cols:
            scan_kwargs["file_name"] = file.filename
        if "file_path" in valid_cols:
            scan_kwargs["file_path"] = file.filename

        scan_record = ScanResult(**scan_kwargs)
        db.add(scan_record)

        # Alert & Notification for Threats (Score >= 35)
        if result["threat_score"] >= 35:
            severity = "CRITICAL" if result["verdict"] == "MALICIOUS" else "HIGH"
            alert = Alert(
                severity=severity,
                title=f"Scanner Threat Detected: {file.filename}",
                description=f"Manual scanner upload scored {result['threat_score']}/100 ({result['verdict']}). Threats: {', '.join(result['threats_detected'])}",
                file_path=file.filename,
                status="UNRESOLVED",
                timestamp=datetime.utcnow()
            )
            db.add(alert)

            send_alert_notification(
                title=f"⚠️ SFTMS Threat Detected ({result['verdict']})",
                message=f"File: {file.filename}\nScore: {result['threat_score']}/100\nThreats: {', '.join(result['threats_detected'][:2])}"
            )

            # Auto Quarantine for High Risk (Score >= 70)
            if result["threat_score"] >= 70:
                quarantined = quarantine_file(temp_path, db, f"Manual Scan Neutralization ({result['verdict']})")
                if quarantined:
                    temp_path = None
                    send_alert_notification(
                        title="🛡️ Threat Auto-Quarantined",
                        message=f"{file.filename} was isolated to Quarantine Vault."
                    )

        db.commit()
        return result
    except Exception as e:
        db.rollback()
        return {
            "file_name": file.filename,
            "threat_score": 0,
            "verdict": "ERROR",
            "threats_detected": [f"Scan processing error: {str(e)}"],
            "details": "Failed to inspect uploaded file."
        }
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

# --- ALERTS ENDPOINTS ---
@router.get("/alerts")
def get_alerts(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    return query.order_by(Alert.timestamp.desc()).all()

@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "RESOLVED"
    db.commit()
    return {"message": "Alert resolved"}

# --- POLICIES ENDPOINTS ---
@router.get("/policies")
def get_policies(db: Session = Depends(get_db)):
    return db.query(Policy).all()

@router.post("/policies")
def create_policy(name: str, rule_type: str, target_value: str, is_active: bool = True, db: Session = Depends(get_db)):
    p = Policy(name=name, rule_type=rule_type, target_value=target_value, is_active=is_active)
    db.add(p)
    db.commit()
    db.refresh(p)
    return p

@router.put("/policies/{policy_id}")
def toggle_policy(policy_id: int, is_active: bool, db: Session = Depends(get_db)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    p.is_active = is_active
    db.commit()
    return p

@router.delete("/policies/{policy_id}")
def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(p)
    db.commit()
    return {"message": "Policy deleted"}

# --- SENSITIVE DIRECTORIES ENDPOINTS ---
@router.get("/sensitive-dirs")
def get_sensitive_dirs(db: Session = Depends(get_db)):
    return db.query(SensitiveDirectory).all()

@router.post("/sensitive-dirs")
def create_sensitive_dir(path: str, description: str = "", db: Session = Depends(get_db)):
    s_dir = SensitiveDirectory(path=path, description=description)
    db.add(s_dir)
    db.commit()
    db.refresh(s_dir)
    return s_dir

@router.delete("/sensitive-dirs/{dir_id}")
def delete_sensitive_dir(dir_id: int, db: Session = Depends(get_db)):
    s_dir = db.query(SensitiveDirectory).filter(SensitiveDirectory.id == dir_id).first()
    if not s_dir:
        raise HTTPException(status_code=404, detail="Sensitive directory not found")
    db.delete(s_dir)
    db.commit()
    return {"message": "Sensitive directory removed"}

# --- QUARANTINE VAULT ENDPOINTS ---
@router.get("/quarantine")
def list_quarantined_files(db: Session = Depends(get_db)):
    return db.query(QuarantinedFile).order_by(QuarantinedFile.timestamp.desc()).all()

@router.post("/quarantine/{quarantine_id}/restore")
def handle_restore(quarantine_id: int, db: Session = Depends(get_db)):
    success = restore_quarantined_file(quarantine_id, db)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to restore file from quarantine")
    return {"message": "File restored successfully"}

@router.delete("/quarantine/{quarantine_id}")
def handle_delete_quarantine(quarantine_id: int, db: Session = Depends(get_db)):
    success = delete_quarantined_file(quarantine_id, db)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete file from quarantine")
    return {"message": "Quarantined file permanently deleted"}

# --- REPORTS EXPORT ENDPOINT ---
@router.get("/reports/export")
def export_csv_report(db: Session = Depends(get_db)):
    events = db.query(FileEvent).order_by(FileEvent.timestamp.desc()).limit(1000).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Event Type", "Source Path", "Dest Path", "Size (Bytes)", "Process", "User", "Hash", "Integrity State"])

    for e in events:
        writer.writerow([
            e.id,
            e.timestamp.isoformat() if e.timestamp else "",
            e.event_type,
            e.source_path,
            e.dest_path or "",
            e.file_size,
            e.process_name,
            e.username,
            e.file_hash,
            e.integrity_state
        ])

    response = Response(content=output.getvalue(), media_type="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=sftms_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return response