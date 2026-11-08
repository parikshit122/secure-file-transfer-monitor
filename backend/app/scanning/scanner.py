import os
import time
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

try:
    import blake3

    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

DANGEROUS_EXT = {
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".scr",
    ".pif",
    ".com",
    ".hta",
    ".msi",
    ".msp",
    ".reg",
    ".dll",
}

SUSPICIOUS_EXT = {
    ".docm",
    ".xlsm",
    ".pptm",
    ".jar",
    ".sh",
    ".py",
    ".pyw",
    ".iso",
    ".img",
    ".lnk",
    ".url",
}

MAGIC_MAP = {
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip/office",
    b"\x89PNG": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF8": "gif",
    b"BM": "bmp",
    b"\x1f\x8b": "gzip",
    b"Rar!": "rar",
    b"7z\xbc\xaf": "7z",
}


@dataclass
class ScanResult:
    filepath: str
    filename: str
    file_size: int
    file_hash: str
    verdict: str
    threat_score: int
    findings: list = field(default_factory=list)
    file_type: str = "unknown"
    scanned_in_ms: float = 0.0


def compute_hash(filepath: str, max_bytes: int = 10_485_760) -> str:
    h = blake3.blake3() if HAS_BLAKE3 else hashlib.sha256()
    file_size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        if file_size <= max_bytes:
            while True:
                chunk = f.read(262144)
                if not chunk:
                    break
                h.update(chunk)
        else:
            head = f.read(max_bytes // 2)
            h.update(head)
            f.seek(-(max_bytes // 2), 2)
            tail = f.read(max_bytes // 2)
            h.update(tail)
            h.update(str(file_size).encode())
    return h.hexdigest()


def detect_type(filepath: str) -> str:
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        for magic, ftype in MAGIC_MAP.items():
            if header.startswith(magic):
                return ftype
        if header[:2] == b"MZ":
            return "executable"
    except Exception:
        pass
    return "unknown"


def scan_file(filepath: str) -> Optional[ScanResult]:
    start = time.time()
    p = Path(filepath)
    if not p.exists() or not p.is_file():
        return None

    filename = p.name
    file_size = p.stat().st_size
    ext = p.suffix.lower()
    findings = []
    score = 0

    try:
        file_hash = compute_hash(filepath)
    except Exception:
        file_hash = "error"

    detected = detect_type(filepath)

    if ext in DANGEROUS_EXT:
        score += 40
        findings.append(f"Dangerous file type: {ext}")
    if ext in SUSPICIOUS_EXT:
        score += 20
        findings.append(f"Suspicious file type: {ext}")

    parts = filename.split(".")
    if len(parts) >= 3:
        inner = "." + parts[-2].lower()
        if (
            inner in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt"}
            and ext in DANGEROUS_EXT
        ):
            score += 30
            findings.append(f"Double extension trick: {inner}{ext}")

    if detected == "executable" and ext not in {".exe", ".dll", ".sys", ".com", ".scr"}:
        score += 35
        findings.append(f"Hidden executable disguised as {ext}")
    if detected == "zip/office" and ext in DANGEROUS_EXT:
        score += 25
        findings.append("Archive/executable mismatch")
    if file_size == 0:
        score += 10
        findings.append("Empty file (0 bytes)")
    if file_size > 1_073_741_824:
        score += 15
        findings.append("Extremely large file (>1GB)")

    try:
        zone = Path(filepath + ":Zone.Identifier")
        if zone.exists():
            findings.append("Downloaded from internet")
            score += 5
    except Exception:
        pass

    score = min(score, 100)
    if score >= 50:
        verdict = "dangerous"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"
        if not findings:
            findings.append("No threats detected")

    return ScanResult(
        filepath=str(filepath),
        filename=filename,
        file_size=file_size,
        file_hash=file_hash,
        verdict=verdict,
        threat_score=score,
        findings=findings,
        file_type=detected,
        scanned_in_ms=round((time.time() - start) * 1000, 2),
    )


def scan_bytes(filename: str, data: bytes) -> ScanResult:
    """Scan file directly from memory — no disk writes. Used for uploads."""
    start = time.time()
    file_size = len(data)
    ext = Path(filename).suffix.lower()
    findings = []
    score = 0

    h = blake3.blake3() if HAS_BLAKE3 else hashlib.sha256()
    h.update(data)
    file_hash = h.hexdigest()

    detected = "unknown"
    header = data[:16]
    for magic, ftype in MAGIC_MAP.items():
        if header.startswith(magic):
            detected = ftype
            break
    if header[:2] == b"MZ":
        detected = "executable"

    if ext in DANGEROUS_EXT:
        score += 40
        findings.append(f"Dangerous file type: {ext}")
    if ext in SUSPICIOUS_EXT:
        score += 20
        findings.append(f"Suspicious file type: {ext}")

    parts = filename.split(".")
    if len(parts) >= 3:
        inner = "." + parts[-2].lower()
        if (
            inner in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt"}
            and ext in DANGEROUS_EXT
        ):
            score += 30
            findings.append(f"Double extension trick: {inner}{ext}")

    if detected == "executable" and ext not in {".exe", ".dll", ".sys", ".com", ".scr"}:
        score += 35
        findings.append(f"Hidden executable disguised as {ext}")
    if detected == "zip/office" and ext in DANGEROUS_EXT:
        score += 25
        findings.append("Archive/executable mismatch")
    if file_size == 0:
        score += 10
        findings.append("Empty file (0 bytes)")
    if file_size > 1_073_741_824:
        score += 15
        findings.append("Extremely large file (>1GB)")

    score = min(score, 100)
    if score >= 50:
        verdict = "dangerous"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"
        if not findings:
            findings.append("No threats detected")

    return ScanResult(
        filepath="upload",
        filename=filename,
        file_size=file_size,
        file_hash=file_hash,
        verdict=verdict,
        threat_score=score,
        findings=findings,
        file_type=detected,
        scanned_in_ms=round((time.time() - start) * 1000, 2),
    )
