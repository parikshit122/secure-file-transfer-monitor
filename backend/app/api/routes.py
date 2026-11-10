from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.models import QuarantinedFile
from app.defense.quarantine import restore_quarantined_file, delete_quarantined_file
from app.core.models import (
    FileEvent,
    ScanResult,
    Alert,
    Policy,
    SensitiveDirectory,
)
from app.scanning.scanner import scan_bytes

router = APIRouter()


# ── Stats ────────────────────────────────────────────────────


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
    transfers = (
        db.query(FileEvent)
        .filter(FileEvent.event_type.in_(["move", "transfer"]))
        .count()
    )
    tampered = (
        db.query(FileEvent)
        .filter(FileEvent.integrity_status == "tampered")
        .count()
    )
    return {
        "total_files": total,
        "total_scans": scans,
        "threats_blocked": threats,
        "active_alerts": alerts,
        "total_transfers": transfers,
        "tampered_files": tampered,
    }


# ── File Events (Transfer Log) ──────────────────────────────


@router.get("/events")
def get_events(limit: int = 50, db: Session = Depends(get_db)):
    events = (
        db.query(FileEvent).order_by(FileEvent.timestamp.desc()).limit(limit).all()
    )
    return [
        {
            "id": e.id,
            "filename": e.filename,
            "event_type": e.event_type,
            "source_path": e.source_path,
            "dest_path": e.dest_path,
            "file_size": e.file_size,
            "file_hash": e.file_hash,
            "pre_hash": e.pre_hash,
            "post_hash": e.post_hash,
            "integrity_status": e.integrity_status,
            "process_name": e.process_name,
            "username": e.username,
            "is_sensitive": e.is_sensitive,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]


# ── Scans ────────────────────────────────────────────────────


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


# ── Alerts ───────────────────────────────────────────────────


@router.get("/alerts")
def get_alerts(active_only: bool = True, db: Session = Depends(get_db)):
    q = db.query(Alert).order_by(Alert.created_at.desc())
    if active_only:
        q = q.filter(Alert.is_resolved == False)
    return [
        {
            "id": a.id,
            "severity": a.severity,
            "alert_type": a.alert_type,
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


# ── Manual Scan ──────────────────────────────────────────────


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


# ── Policies ─────────────────────────────────────────────────


@router.get("/policies")
def get_policies(db: Session = Depends(get_db)):
    policies = db.query(Policy).order_by(Policy.id).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "policy_type": p.policy_type,
            "action": p.action,
            "enabled": p.enabled,
            "parameters": p.parameters,
        }
        for p in policies
    ]


@router.post("/policies")
def create_policy(data: dict, db: Session = Depends(get_db)):
    p = Policy(
        name=data.get("name", ""),
        description=data.get("description", ""),
        policy_type=data.get("policy_type", "extension_block"),
        action=data.get("action", "block"),
        enabled=data.get("enabled", True),
        parameters=data.get("parameters", ""),
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return {"id": p.id, "status": "created"}


@router.put("/policies/{policy_id}")
def update_policy(policy_id: int, data: dict, db: Session = Depends(get_db)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        return {"status": "not found"}
    for key in ["name", "description", "policy_type", "action", "enabled", "parameters"]:
        if key in data:
            setattr(p, key, data[key])
    db.commit()
    return {"status": "updated"}


@router.delete("/policies/{policy_id}")
def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if p:
        db.delete(p)
        db.commit()
        return {"status": "deleted"}
    return {"status": "not found"}


@router.post("/policies/seed")
def seed_policies(db: Session = Depends(get_db)):
    count = db.query(Policy).count()
    if count > 0:
        return {"status": "already seeded", "count": count}
    defaults = [
        Policy(
            name="Block Executables",
            description="Block .exe, .bat, .cmd, .ps1, .msi files",
            policy_type="extension_block",
            action="block",
            enabled=True,
            parameters=".exe,.bat,.cmd,.ps1,.msi",
        ),
        Policy(
            name="Block Scripts",
            description="Block .js, .vbs, .wsf, .sh script files",
            policy_type="extension_block",
            action="block",
            enabled=True,
            parameters=".js,.vbs,.wsf,.sh",
        ),
        Policy(
            name="Large File Warning",
            description="Flag files larger than 100 MB",
            policy_type="size_limit",
            action="alert",
            enabled=True,
            parameters="104857600",
        ),
        Policy(
            name="Double Extension Block",
            description="Block files with double extensions like .pdf.exe",
            policy_type="double_extension",
            action="block",
            enabled=True,
            parameters="",
        ),
        Policy(
            name="Archive Scan",
            description="Scan inside .zip and .rar archives",
            policy_type="archive_scan",
            action="scan",
            enabled=True,
            parameters=".zip,.rar,.7z",
        ),
        Policy(
            name="Whitelist Documents",
            description="Allow .pdf, .docx, .xlsx, .pptx without deep scan",
            policy_type="whitelist",
            action="allow",
            enabled=True,
            parameters=".pdf,.docx,.xlsx,.pptx",
        ),
    ]
    db.add_all(defaults)
    db.commit()
    return {"status": "seeded", "count": len(defaults)}


# ── Sensitive Directories ────────────────────────────────────


@router.get("/sensitive-dirs")
def get_sensitive_dirs(db: Session = Depends(get_db)):
    dirs = db.query(SensitiveDirectory).order_by(SensitiveDirectory.id).all()
    return [
        {
            "id": d.id,
            "path": d.path,
            "label": d.label,
            "alert_on_access": d.alert_on_access,
            "alert_on_copy": d.alert_on_copy,
            "alert_on_move": d.alert_on_move,
            "alert_on_delete": d.alert_on_delete,
        }
        for d in dirs
    ]


@router.post("/sensitive-dirs")
def add_sensitive_dir(data: dict, db: Session = Depends(get_db)):
    d = SensitiveDirectory(
        path=data.get("path", ""),
        label=data.get("label", ""),
        alert_on_access=data.get("alert_on_access", True),
        alert_on_copy=data.get("alert_on_copy", True),
        alert_on_move=data.get("alert_on_move", True),
        alert_on_delete=data.get("alert_on_delete", True),
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"id": d.id, "status": "created"}


@router.delete("/sensitive-dirs/{dir_id}")
def remove_sensitive_dir(dir_id: int, db: Session = Depends(get_db)):
    d = db.query(SensitiveDirectory).filter(SensitiveDirectory.id == dir_id).first()
    if d:
        db.delete(d)
        db.commit()
        return {"status": "deleted"}
    return {"status": "not found"}

# ── Quarantine Vault API ──────────────────────────────────────

@router.get("/quarantine")
def get_quarantined_files(db: Session = Depends(get_db)):
    files = (
        db.query(QuarantinedFile)
        .filter(QuarantinedFile.is_restored == False)
        .order_by(QuarantinedFile.quarantined_at.desc())
        .all()
    )
    return [
        {
            "id": f.id,
            "filename": f.original_filename,
            "original_path": f.original_path,
            "file_size": f.file_size,
            "file_hash": f.file_hash,
            "reason": f.reason,
            "quarantined_at": f.quarantined_at.isoformat() if f.quarantined_at else None,
        }
        for f in files
    ]

@router.post("/quarantine/{file_id}/restore")
def restore_file_route(file_id: int, db: Session = Depends(get_db)):
    success = restore_quarantined_file(file_id, db)
    return {"status": "restored" if success else "failed"}

@router.delete("/quarantine/{file_id}")
def delete_quarantined_route(file_id: int, db: Session = Depends(get_db)):
    success = delete_quarantined_file(file_id, db)
    return {"status": "deleted" if success else "failed"}