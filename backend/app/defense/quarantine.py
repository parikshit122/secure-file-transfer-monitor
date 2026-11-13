import os
import shutil
import hashlib
from datetime import datetime
from sqlalchemy.orm import Session
from app.core.models import QuarantinedFile, Alert
from app.defense.shredder import shred_file

def quarantine_file(file_path: str, db: Session, reason: str = "Automated Active Defense Neutralization") -> bool:
    if not os.path.exists(file_path):
        return False

    try:
        vault_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "quarantine_vault"))
        os.makedirs(vault_dir, exist_ok=True)

        file_name = os.path.basename(file_path)
        
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        quarantine_path = os.path.join(vault_dir, f"{file_hash}.quarantine")

        if os.path.exists(quarantine_path):
            try:
                shred_file(quarantine_path)
            except Exception:
                pass

        shutil.move(file_path, quarantine_path)
        
        try:
            os.chmod(quarantine_path, 0o444)
        except Exception:
            pass

        q_record = QuarantinedFile(
            original_name=file_name,
            original_path=file_path,
            quarantine_path=quarantine_path,
            file_hash=file_hash,
            reason=reason,
            timestamp=datetime.utcnow()
        )
        db.add(q_record)

        alert = Alert(
            severity="CRITICAL",
            title=f"Quarantined Threat: {file_name}",
            description=f"File isolated to quarantine vault. Reason: {reason}",
            file_path=file_path,
            status="RESOLVED",
            timestamp=datetime.utcnow()
        )
        db.add(alert)
        db.commit()

        return True
    except Exception:
        db.rollback()
        return False

def restore_quarantined_file(quarantine_id: int, db: Session) -> bool:
    record = db.query(QuarantinedFile).filter(QuarantinedFile.id == quarantine_id).first()
    if not record:
        return False

    try:
        if os.path.exists(record.quarantine_path):
            try:
                os.chmod(record.quarantine_path, 0o777)
            except Exception:
                pass

            dest_dir = os.path.dirname(record.original_path)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            shutil.move(record.quarantine_path, record.original_path)

        db.delete(record)
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False

def delete_quarantined_file(quarantine_id: int, db: Session) -> bool:
    """Permanently shreds file from disk using DoD 3-Pass Overwrite standard."""
    record = db.query(QuarantinedFile).filter(QuarantinedFile.id == quarantine_id).first()
    if not record:
        return False

    try:
        if os.path.exists(record.quarantine_path):
            shred_file(record.quarantine_path)

        db.delete(record)
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False