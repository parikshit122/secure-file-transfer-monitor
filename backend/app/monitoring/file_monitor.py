import os
import time
import hashlib
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from app.core.database import SessionLocal
from app.core.models import (
    FileEvent,
    ScanResult,
    Alert,
    SensitiveDirectory,
)
from app.scanning.scanner import scan_bytes
from app.defense.quarantine import quarantine_file

WATCH_PATHS = [
    str(Path.home() / "Downloads"),
    str(Path.home() / "Documents"),
    str(Path.home() / "Desktop"),
]

MAX_AUTO_SCAN_SIZE = 100 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
HASH_CACHE: dict[str, str] = {}


def safe_open_file(filepath: str, mode: str = "rb", max_retries: int = 3):
    delay = 0.3
    last_err = None
    for _ in range(max_retries):
        try:
            return open(filepath, mode)
        except (PermissionError, OSError) as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise last_err if last_err else RuntimeError("Could not open file")


def compute_hash_streaming(filepath: str) -> tuple[str | None, int]:
    try:
        h = hashlib.blake2b(digest_size=32)
        total_size = 0
        with safe_open_file(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
                total_size += len(chunk)
        return h.hexdigest(), total_size
    except Exception as e:
        print(f"Hash error for {filepath}: {e}")
        return None, 0


def read_file_safely(filepath: str, max_size: int) -> bytes | None:
    try:
        if os.path.getsize(filepath) > max_size:
            return None
        with safe_open_file(filepath, "rb") as f:
            return f.read()
    except Exception as e:
        print(f"Read error for {filepath}: {e}")
        return None


def get_previous_hash(filepath: str, db) -> str | None:
    if filepath in HASH_CACHE:
        return HASH_CACHE[filepath]

    last = (
        db.query(FileEvent)
        .filter(
            (FileEvent.dest_path == filepath) | (FileEvent.source_path == filepath)
        )
        .order_by(FileEvent.id.desc())
        .first()
    )
    if last is None:
        return None
    if last.event_type == "delete":
        return None
    if last.event_type in ("move", "transfer") and last.source_path == filepath:
        return None
    return last.post_hash


def get_username() -> str:
    try:
        return os.getlogin()
    except Exception:
        return "unknown"


def is_sensitive_path(filepath: str, db) -> bool:
    dirs = db.query(SensitiveDirectory).all()
    fp = filepath.lower()
    for d in dirs:
        if fp.startswith(d.path.lower()):
            return True
    return False


def create_alert(db, severity: str, alert_type: str, title: str, desc: str):
    alert = Alert(
        severity=severity,
        alert_type=alert_type,
        title=title,
        description=desc,
    )
    db.add(alert)
    db.commit()


class TransferHandler(FileSystemEventHandler):
    def __init__(self):
        self._debounce: dict[str, float] = {}

    def _should_process(self, path: str) -> bool:
        now = time.time()
        if path in self._debounce and now - self._debounce[path] < 2:
            return False
        self._debounce[path] = now
        name = os.path.basename(path).lower()
        if name.startswith("~") or name.endswith(".tmp") or name.endswith(".crdownload"):
            return False
        return True

    def on_created(self, event):
        if event.is_directory or not self._should_process(event.src_path):
            return
        self._handle_event("create", event.src_path, None)

    def on_modified(self, event):
        if event.is_directory or not self._should_process(event.src_path):
            return
        self._handle_event("modify", event.src_path, None)

    def on_deleted(self, event):
        if event.is_directory or not self._should_process(event.src_path):
            return
        self._handle_event("delete", event.src_path, None)

    def on_moved(self, event):
        if event.is_directory or not self._should_process(event.dest_path):
            return
        self._handle_event("move", event.src_path, event.dest_path)

    def _handle_event(
        self,
        event_type: str,
        src_path: str | None,
        dest_path: str | None,
    ):
        db = SessionLocal()
        try:
            filepath = dest_path or src_path or ""
            filename = os.path.basename(filepath)
            user = get_username()

            sensitive = any(
                is_sensitive_path(p, db) for p in (src_path, dest_path) if p
            )

            pre_hash = get_previous_hash(src_path or filepath, db)
            post_hash = None
            file_size = 0

            if event_type != "delete" and os.path.exists(filepath):
                time.sleep(0.2)
                post_hash, file_size = compute_hash_streaming(filepath)

            if event_type == "delete" or post_hash is None:
                integrity = "unknown"
            elif pre_hash is None:
                integrity = "baseline"
            elif pre_hash == post_hash:
                integrity = "verified"
            elif event_type == "move":
                integrity = "tampered"
            else:
                integrity = "modified"

            if event_type == "delete":
                HASH_CACHE.pop(filepath, None)
            else:
                if event_type == "move" and src_path:
                    HASH_CACHE.pop(src_path, None)
                if post_hash:
                    HASH_CACHE[filepath] = post_hash

            actual_type = event_type
            if event_type == "move" and src_path and dest_path:
                src_drive = os.path.splitdrive(src_path)[0]
                dst_drive = os.path.splitdrive(dest_path)[0]
                if src_drive != dst_drive:
                    actual_type = "transfer"

            fe = FileEvent(
                filename=filename,
                event_type=actual_type,
                source_path=src_path,
                dest_path=dest_path,
                file_size=file_size,
                file_hash=post_hash,
                pre_hash=pre_hash,
                post_hash=post_hash,
                integrity_status=integrity,
                process_name=None,
                username=user,
                is_sensitive=sensitive,
            )
            db.add(fe)
            db.commit()
            db.refresh(fe)

            if actual_type in ("create", "modify", "transfer"):
                data = read_file_safely(filepath, MAX_AUTO_SCAN_SIZE)
                if data is not None:
                    try:
                        result = scan_bytes(filename, data, db=db)
                        sr = ScanResult(
                            file_event_id=fe.id,
                            file_hash=result.file_hash,
                            verdict=result.verdict,
                            threat_score=result.threat_score,
                            findings=result.findings,
                            scan_duration_ms=result.scanned_in_ms,
                        )
                        db.add(sr)
                        db.commit()

                        if result.verdict == "dangerous":
                            quarantine_file(
                                filepath=filepath,
                                reason=f"Threat Score {result.threat_score}/100: {result.findings}",
                                db=db,
                            )
                    except Exception as e:
                        print(f"Scan error for {filename}: {e}")
                else:
                    create_alert(
                        db,
                        "low",
                        "info",
                        f"Large file logged: {filename}",
                        f"File size {file_size/(1024*1024):.1f} MB exceeds auto-scan limit. Hash recorded only.",
                    )

            if integrity == "tampered":
                create_alert(
                    db,
                    "high",
                    "integrity_mismatch",
                    f"File changed during transfer: {filename}",
                    f"Hash before: {pre_hash[:12]}... after: {post_hash[:12]}...",
                )
            elif integrity == "modified" and sensitive:
                create_alert(
                    db,
                    "medium",
                    "integrity_mismatch",
                    f"Sensitive file modified: {filename}",
                    f"Content changed at {filepath} (user: {user})",
                )

            if sensitive and actual_type in ("move", "transfer", "delete"):
                verb = {
                    "move": "moved",
                    "transfer": "transferred",
                    "delete": "deleted",
                }[actual_type]
                create_alert(
                    db,
                    "critical",
                    "unauthorized_move",
                    f"Sensitive file {verb}: {filename}",
                    f"From {src_path} to {dest_path or 'n/a'} (user: {user})",
                )

            if actual_type == "transfer":
                create_alert(
                    db,
                    "high",
                    "exfiltration",
                    f"Cross-drive transfer: {filename}",
                    f"File transferred from {src_path} to {dest_path}. Possible USB or network exfiltration.",
                )

        except Exception as e:
            print(f"Monitor error: {e}")
        finally:
            db.close()


_observer: Observer | None = None


def start_monitoring():
    global _observer
    _observer = Observer()
    handler = TransferHandler()
    for p in WATCH_PATHS:
        if os.path.isdir(p):
            _observer.schedule(handler, p, recursive=True)
            print(f"Monitoring: {p}")
    _observer.daemon = True
    _observer.start()


def stop_monitoring():
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()