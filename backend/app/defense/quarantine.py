import os
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.core.models import QuarantinedFile, Alert

# Vault directory where neutralized files live safely
VAULT_DIR = Path(__file__).resolve().parent.parent.parent / "quarantine_vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)


def quarantine_file(filepath: str, reason: str, db: Session) -> QuarantinedFile | None:
    """Safely moves a dangerous file out of watch folder into quarantine vault."""
    if not os.path.exists(filepath):
        return None

    try:
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)

        # Compute hash for unique vault filename
        h = hashlib.blake2b(digest_size=16)
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        file_hash = h.hexdigest()

        # Vault path: quarantine_vault/<hash>.quarantine
        vault_filename = f"{file_hash}.quarantine"
        vault_path = str(VAULT_DIR / vault_filename)

        # Move file out of user space into vault
        shutil.move(filepath, vault_path)

        # Store in DB
        record = QuarantinedFile(
            original_filename=filename,
            original_path=filepath,
            quarantine_path=vault_path,
            file_hash=file_hash,
            file_size=file_size,
            reason=reason,
        )
        db.add(record)

        # Raise critical alert
        alert = Alert(
            severity="critical",
            alert_type="threat",
            title=f"🛡️ Threat Neutralized & Quarantined: {filename}",
            description=f"File was isolated from '{filepath}' to quarantine vault. Reason: {reason}",
        )
        db.add(alert)
        db.commit()
        db.refresh(record)

        print(f"[QUARANTINE] Neutralized dangerous file: {filename} -> {vault_path}")
        return record

    except Exception as e:
        print(f"[QUARANTINE ERROR] Failed to quarantine {filepath}: {e}")
        return None


def restore_quarantined_file(quarantine_id: int, db: Session) -> bool:
    """Restores a quarantined file back to its original location."""
    record = db.query(QuarantinedFile).filter(QuarantinedFile.id == quarantine_id).first()
    if not record or record.is_restored or not os.path.exists(record.quarantine_path):
        return False

    try:
        # Move back to original location
        os.makedirs(os.path.dirname(record.original_path), exist_ok=True)
        shutil.move(record.quarantine_path, record.original_path)

        record.is_restored = True
        db.commit()
        return True
    except Exception as e:
        print(f"[RESTORE ERROR] Could not restore {record.original_filename}: {e}")
        return False


def delete_quarantined_file(quarantine_id: int, db: Session) -> bool:
    """Permanently deletes a file from the quarantine vault."""
    record = db.query(QuarantinedFile).filter(QuarantinedFile.id == quarantine_id).first()
    if not record:
        return False

    try:
        if os.path.exists(record.quarantine_path):
            os.remove(record.quarantine_path)
        db.delete(record)
        db.commit()
        return True
    except Exception as e:
        print(f"[DELETE ERROR] Could not delete quarantined file: {e}")
        return False