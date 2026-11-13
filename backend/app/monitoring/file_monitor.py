import os
import time
import hashlib
import getpass
import psutil
from datetime import datetime
from sqlalchemy.orm import Session
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.core.database import SessionLocal
from app.core.models import FileEvent, ScanResult, Alert, SensitiveDirectory, USBWhitelist
from app.scanning.scanner import scan_file
from app.defense.quarantine import quarantine_file
from app.core.notifications import send_alert_notification

def compute_hash_streaming(file_path: str) -> str:
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "UNKNOWN_HASH"

def get_process_writing_file(file_path: str) -> str:
    file_name = os.path.basename(file_path).lower()
    try:
        for proc in psutil.process_iter(['name', 'open_files']):
            try:
                open_files = proc.info.get('open_files')
                if open_files:
                    for f in open_files:
                        if file_name in f.path.lower():
                            return proc.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue
    except Exception:
        pass
    return "explorer.exe"

def is_unapproved_usb_drive(target_path: str, db: Session) -> bool:
    """Detects if file is being written to an unapproved removable USB drive."""
    drive_letter = os.path.splitdrive(target_path)[0].upper()
    if not drive_letter:
        return False

    for part in psutil.disk_partitions(all=True):
        if part.mountpoint.startswith(drive_letter):
            if 'removable' in part.opts.lower() or 'cdrom' in part.opts.lower():
                approved = db.query(USBWhitelist).filter(
                    USBWhitelist.drive_letter == drive_letter,
                    USBWhitelist.is_approved == True
                ).first()
                if not approved:
                    return True
    return False

class SFTMSEventHandler(FileSystemEventHandler):
    def process_event(self, event_type: str, src_path: str, dest_path: str = None):
        target_path = dest_path if dest_path else src_path
        
        ignored_patterns = (
            '.tmp', '.crdownload', '.sys', '.ini', '.cache',
            '$recycle.bin', 'quarantine_vault', '\\roslyn\\', '\\packages\\'
        )
        target_lower = target_path.lower()
        if any(pat in target_lower for pat in ignored_patterns):
            return

        if not os.path.exists(target_path):
            return

        db: Session = SessionLocal()
        try:
            file_name = os.path.basename(target_path)
            try:
                file_size = os.path.getsize(target_path)
            except Exception:
                return

            username = getpass.getuser()
            process_name = get_process_writing_file(target_path)
            current_hash = compute_hash_streaming(target_path)

            integrity_state = "VERIFIED"
            previous_event = db.query(FileEvent).filter(
                FileEvent.source_path == target_path,
                FileEvent.file_hash != "UNKNOWN_HASH"
            ).order_by(FileEvent.timestamp.desc()).first()

            if not previous_event:
                integrity_state = "BASELINE"
            elif previous_event.file_hash != current_hash and current_hash != "DELETED":
                integrity_state = "MODIFIED"

            file_event = FileEvent(
                event_type=event_type,
                source_path=src_path,
                dest_path=dest_path,
                file_size=file_size,
                process_name=process_name,
                username=username,
                file_hash=current_hash,
                integrity_state=integrity_state,
                timestamp=datetime.utcnow()
            )
            db.add(file_event)
            db.commit()

            # USB Exfiltration Lock & Whitelist Enforcement
            if is_unapproved_usb_drive(target_path, db):
                usb_alert = Alert(
                    severity="CRITICAL",
                    title=f"USB Exfiltration Warning: {file_name}",
                    description=f"File transferred to unapproved removable USB drive ({target_path[:3]}) by process '{process_name}'.",
                    file_path=target_path,
                    status="UNRESOLVED",
                    timestamp=datetime.utcnow()
                )
                db.add(usb_alert)
                db.commit()
                send_alert_notification(
                    title="🚨 Unapproved USB Exfiltration Block",
                    message=f"Unauthorized transfer of {file_name} to removable drive!"
                )

            # Heuristic Scan & Active Defense
            if file_size > 0 and file_size < (100 * 1024 * 1024):
                scan_res = scan_file(target_path, db)
                
                valid_cols = [c.name for c in ScanResult.__table__.columns]
                scan_kwargs = {
                    "threat_score": scan_res["threat_score"],
                    "verdict": scan_res["verdict"],
                    "threats_detected": "; ".join(scan_res["threats_detected"]),
                    "timestamp": datetime.utcnow()
                }
                if "file_name" in valid_cols:
                    scan_kwargs["file_name"] = file_name
                if "file_path" in valid_cols:
                    scan_kwargs["file_path"] = target_path

                scan_record = ScanResult(**scan_kwargs)
                db.add(scan_record)

                if scan_res["threat_score"] >= 35:
                    alert = Alert(
                        severity="CRITICAL" if scan_res["verdict"] == "MALICIOUS" else "HIGH",
                        title=f"Threat Detected: {file_name}",
                        description=f"Process '{process_name}' moved high-risk file. Threats: {', '.join(scan_res['threats_detected'])}",
                        file_path=target_path,
                        status="UNRESOLVED",
                        timestamp=datetime.utcnow()
                    )
                    db.add(alert)
                    
                    send_alert_notification(
                        title=f"⚠️ SFTMS Threat Alert ({scan_res['verdict']})",
                        message=f"File: {file_name}\nProcess: {process_name}\nThreats: {', '.join(scan_res['threats_detected'][:2])}"
                    )

                if scan_res["threat_score"] >= 70:
                    quarantined = quarantine_file(target_path, db, f"Auto-Quarantined ({scan_res['verdict']})")
                    if quarantined:
                        send_alert_notification(
                            title="🛡️ File Auto-Quarantined",
                            message=f"{file_name} was isolated and secured in Quarantine Vault."
                        )

            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    def on_created(self, event):
        if not event.is_directory:
            self.process_event("CREATE", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event("MOVE", event.src_path, event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event("MODIFY", event.src_path)

def start_file_monitoring():
    observer = Observer()
    observer.daemon = True
    handler = SFTMSEventHandler()
    user_home = os.path.expanduser("~")
    paths_to_watch = [
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Documents"),
        os.path.join(user_home, "Desktop")
    ]

    for path in paths_to_watch:
        if os.path.exists(path):
            observer.schedule(handler, path=path, recursive=False)

    observer.start()
    return observer

start_monitoring = start_file_monitoring