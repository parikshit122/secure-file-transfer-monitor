import os
import hashlib
from typing import List
from dataclasses import dataclass
from sqlalchemy.orm import Session
from app.core.models import Policy


@dataclass
class ScanResultDTO:
    filename: str
    file_size: int
    file_hash: str
    file_type: str
    verdict: str  # clean, suspicious, dangerous
    threat_score: int  # 0 to 100
    findings: str
    scanned_in_ms: float


MAGIC_SIGNATURES = {
    b"MZ": "Windows Executable / DLL",
    b"\x7fELF": "Linux Executable",
    b"\xca\xfe\xba\xbe": "Java Bytecode / Mach-O",
    b"\xfe\xed\xfa\xce": "Mach-O Executable",
    b"PK\x03\x04": "Zip Archive",
    b"%PDF": "PDF Document",
}

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".vbs",
    ".scr",
    ".pif",
    ".application",
    ".gadget",
    ".hta",
    ".cpl",
    ".msc",
    ".jar",
}


def scan_bytes(
    filename: str,
    data: bytes,
    db: Session | None = None,
) -> ScanResultDTO:
    import time

    start = time.time()

    file_size = len(data)
    file_hash = hashlib.blake2b(data, digest_size=32).hexdigest()
    ext = os.path.splitext(filename)[1].lower()

    # Detect file type via magic bytes
    file_type = "unknown"
    for signature, description in MAGIC_SIGNATURES.items():
        if data.startswith(signature):
            file_type = description
            break
    if file_type == "unknown":
        file_type = ext if ext else "binary/text"

    score = 0
    findings_list: List[str] = []

    # ── HEURISTIC RULE 1: Dangerous Executable Extension ──────
    if ext in DANGEROUS_EXTENSIONS:
        score += 50
        findings_list.append(f"Dangerous executable extension ('{ext}')")

    # ── HEURISTIC RULE 2: Double Extension Trick (e.g. pdf.exe) ──
    parts = filename.split(".")
    if len(parts) > 2 and f".{parts[-1].lower()}" in DANGEROUS_EXTENSIONS:
        score += 40
        findings_list.append(
            f"Double extension trick detected ('{parts[-2]}.{parts[-1]}')"
        )

    # ── HEURISTIC RULE 3: Executable Header Mismatch ──────────
    if data.startswith(b"MZ") and ext in [
        ".pdf",
        ".docx",
        ".xlsx",
        ".png",
        ".jpg",
        ".txt",
    ]:
        score += 60
        findings_list.append(
            f"HEADER MISMATCH: Executable signature ('MZ') disguised as document '{ext}'"
        )

    # ── HEURISTIC RULE 4: Zero-byte file ─────────────────────
    if file_size == 0:
        score += 10
        findings_list.append("Zero-byte empty file")

    # ── DB POLICY OVERRIDES & CUSTOM RULES ───────────────────
    if db:
        try:
            active_policies = (
                db.query(Policy).filter(Policy.enabled == True).all()
            )
            for p in active_policies:
                if p.policy_type == "whitelist" and p.parameters:
                    allowed_exts = [
                        e.strip().lower() for e in p.parameters.split(",")
                    ]
                    if ext in allowed_exts:
                        score = 0
                        findings_list = [
                            f"Whitelisted extension ({ext}) by policy '{p.name}'"
                        ]
                        break
                elif p.policy_type == "size_limit" and p.parameters:
                    try:
                        max_bytes = int(p.parameters.strip())
                        if file_size > max_bytes:
                            score += 25
                            findings_list.append(
                                f"Exceeds policy '{p.name}' size limit"
                            )
                    except ValueError:
                        pass
        except Exception:
            pass

    # Verdict
    if score >= 50:
        verdict = "dangerous"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"

    findings = (
        "; ".join(findings_list) if findings_list else "No threat indicators found"
    )
    duration_ms = round((time.time() - start) * 1000, 2)

    return ScanResultDTO(
        filename=filename,
        file_size=file_size,
        file_hash=file_hash,
        file_type=file_type,
        verdict=verdict,
        threat_score=score,
        findings=findings,
        scanned_in_ms=duration_ms,
    )