import os
import asyncio
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import magic
import blake3
from sqlalchemy import insert
from ..core.database import async_session
from ..core.models import FileEvent

SENSITIVE_EXTENSIONS = {".pem", ".key", ".pfx", ".p12", ".env", ".conf", ".sql", ".db"}
SENSITIVE_DIRS = {"secrets", "credentials", "private", "config"}

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, loop):
        self.loop = loop

    def _get_process_name(self):
        try:
            return psutil.Process(os.getpid()).name()
        except Exception:
            return "unknown"

    def _get_file_type(self, path):
        try:
            if os.path.isfile(path):
                return magic.from_file(path, mime=True)
        except Exception:
            pass
        return "unknown"

    def _compute_hashes(self, path):
        try:
            if not os.path.isfile(path):
                return None, None
            b3 = blake3.blake3()
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    b3.update(chunk)
                    sha.update(chunk)
            return b3.hexdigest(), sha.hexdigest()
        except Exception:
            return None, None

    def _is_sensitive(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in SENSITIVE_EXTENSIONS:
            return True
        parts = path.lower().replace("\\", "/").split("/")
        for d in SENSITIVE_DIRS:
            if d in parts:
                return True
        return False

    def _handle_event(self, event_type, src, dest=None):
        if os.path.isdir(src):
            return
        file_name = os.path.basename(src)
        file_size = 0
        try:
            if os.path.exists(src):
                file_size = os.path.getsize(src)
        except Exception:
            pass
        is_sensitive = 1 if self._is_sensitive(src) else 0
        file_type = self._get_file_type(src)
        hash_b3, hash_sha = self._compute_hashes(src)
        record = {
            "event_type": event_type,
            "src_path": src,
            "dest_path": dest,
            "file_name": file_name,
            "file_size": file_size,
            "file_type": file_type,
            "user": os.getlogin(),
            "process": self._get_process_name(),
            "hash_blake3": hash_b3,
            "hash_sha256": hash_sha,
            "is_sensitive": is_sensitive,
            "threat_level": "clean",
        }
        asyncio.run_coroutine_threadsafe(self._save_event(record), self.loop)

    async def _save_event(self, record):
        try:
            async with async_session() as session:
                await session.execute(insert(FileEvent).values(**record))
                await session.commit()
        except Exception as e:
            print(f"DB error: {e}")

    def on_created(self, event):
        self._handle_event("created", event.src_path)

    def on_modified(self, event):
        self._handle_event("modified", event.src_path)

    def on_deleted(self, event):
        self._handle_event("deleted", event.src_path)

    def on_moved(self, event):
        self._handle_event("moved", event.src_path, event.dest_path)

class FileMonitor:
    def __init__(self):
        self.observer = None
        self.is_running = False

    def start(self, path, loop):
        if self.is_running:
            return
        self.observer = Observer()
        handler = FileMonitorHandler(loop)
        self.observer.schedule(handler, path, recursive=True)
        self.observer.daemon = True
        self.observer.start()
        self.is_running = True
        print(f"Monitoring started: {path}")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            print("Monitoring stopped")

file_monitor = FileMonitor()
