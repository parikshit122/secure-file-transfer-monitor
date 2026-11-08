import time
import logging
from pathlib import Path
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from app.core.database import SessionLocal
from app.core.models import FileEvent, ScanResult, Alert
from app.scanning.scanner import scan_file

logger = logging.getLogger(__name__)

class TransferHandler(FileSystemEventHandler):
    def _record(self, event_type: str, path: str):
        p = Path(path)
        if p.is_dir():
            return

        db = SessionLocal()
        try:
            fe = FileEvent(
                filename=p.name,
                event_type=event_type,
                file_path=str(p),
                file_size=p.stat().st_size if p.exists() else 0,
                timestamp=datetime.now(timezone.utc),
            )
            db.add(fe)
            db.commit()
            db.refresh(fe)

            if event_type in ('created', 'modified') and p.exists():
                try:
                    result = scan_file(str(p))
                    if result:
                        sr = ScanResult(
                            file_event_id=fe.id,
                            file_hash=result.file_hash,
                            verdict=result.verdict,
                            threat_score=result.threat_score,
                            findings=str(result.findings),
                            scan_duration_ms=result.scanned_in_ms,
                            scanned_at=datetime.now(timezone.utc),
                        )
                        db.add(sr)
                        fe.file_hash = result.file_hash
                        db.commit()
                        db.refresh(sr)

                        if result.verdict in ('suspicious', 'dangerous'):
                            alert = Alert(
                                file_event_id=fe.id,
                                scan_result_id=sr.id,
                                severity=result.verdict,
                                title=f"{'Threat' if result.verdict == 'dangerous' else 'Suspicious'}: {p.name}",
                                description=" | ".join(result.findings),
                                is_resolved=False,
                                created_at=datetime.now(timezone.utc),
                            )
                            db.add(alert)
                            db.commit()
                            logger.warning(f"ALERT [{result.verdict.upper()}] {p.name} score={result.threat_score}")
                        else:
                            logger.info(f"CLEAN {p.name} score={result.threat_score}")
                except Exception as e:
                    logger.error(f"Scan error: {e}")
        except Exception as e:
            logger.error(f"DB error: {e}")
            db.rollback()
        finally:
            db.close()

    def on_created(self, event):
        time.sleep(1)
        self._record('created', event.src_path)

    def on_modified(self, event):
        self._record('modified', event.src_path)

    def on_deleted(self, event):
        self._record('deleted', event.src_path)

    def on_moved(self, event):
        self._record('moved', event.dest_path)

_observer = None

def start_monitoring(watch_path: str = None):
    global _observer
    if _observer is not None:
        return
    if watch_path is None:
        watch_path = str(Path.home() / "Downloads")
    path = Path(watch_path)
    path.mkdir(parents=True, exist_ok=True)
    handler = TransferHandler()
    _observer = Observer()
    _observer.schedule(handler, str(path), recursive=False)
    _observer.start()
    logger.info(f"Monitoring started: {path}")

def stop_monitoring():
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()
        _observer = None