import os
import zipfile
import re
import math
from collections import Counter
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.core.models import Policy

# Magic byte signatures
MAGIC_BYTES = {
    "exe": [b"MZ"],
    "pdf": [b"%PDF"],
    "zip": [b"PK\x03\x04"],
    "elf": [b"\x7fELF"],
    "office_legacy": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
}

# High-risk Android permissions found in modded / spyware APKs
DANGEROUS_APK_PERMISSIONS = {
    b"android.permission.BIND_ACCESSIBILITY_SERVICE": 35,
    b"android.permission.SYSTEM_ALERT_WINDOW": 25,
    b"android.permission.READ_SMS": 20,
    b"android.permission.RECEIVE_SMS": 20,
    b"android.permission.SEND_SMS": 20,
    b"android.permission.RECORD_AUDIO": 15,
    b"android.permission.CAMERA": 15,
    b"android.permission.READ_CALL_LOG": 15,
    b"android.permission.REQUEST_INSTALL_PACKAGES": 15,
    b"android.permission.READ_CONTACTS": 10,
    b"android.permission.ACCESS_FINE_LOCATION": 10,
}

# Suspicious bytecode execution indicators
APK_SUSPICIOUS_PATTERNS = [
    (b"DexClassLoader", 20, "Dynamic DEX execution (unauthorized code execution)"),
    (b"PathClassLoader", 15, "Dynamic class loading"),
    (b"System.loadLibrary", 10, "Native code execution (.so payload execution)"),
    (b"testkey", 25, "App signed with public test/debug key (likely modded)"),
    (b"androiddebugkey", 25, "App signed with debug key (likely cracked/modded)"),
    (b"Lcom/cheat", 25, "Injected cheat/mod framework"),
    (b"Lcom/mod", 15, "Modded application signature"),
]

# Regex patterns for YARA-style sensitive data leak detection
SECRETS_PATTERNS = [
    (re.compile(rb"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"), 40, "Exfiltration Risk: Private SSH/PGP Key Leak"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), 35, "Exfiltration Risk: Hardcoded AWS Access Key ID"),
    (re.compile(rb"ghp_[a-zA-Z0-9]{36}"), 35, "Exfiltration Risk: GitHub Personal Access Token"),
    (re.compile(rb"xox[baprs]-[0-9a-zA-Z]{10,48}"), 30, "Exfiltration Risk: Slack API Token"),
    (re.compile(rb"(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{4,}[\"']", re.IGNORECASE), 25, "Exfiltration Risk: Hardcoded Password String"),
]

def calculate_entropy(file_path: str, max_bytes: int = 1024 * 1024) -> float:
    """Calculates Shannon Entropy (0.0 to 8.0) to detect encrypted ransomware/packed malware."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception:
        return 0.0

def scan_file(file_path: str, db: Session) -> Dict[str, Any]:
    """Comprehensive scanner: Magic bytes, Modded APKs, Entropy, Office Macros, and Secret leaks."""
    if not os.path.exists(file_path):
        return {
            "file_name": os.path.basename(file_path),
            "threat_score": 0,
            "verdict": "BENIGN",
            "threats_detected": ["File not found"],
            "details": "File does not exist on disk."
        }

    threat_score = 0
    threats = []
    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_name)[1].lower()
    file_size = os.path.getsize(file_path)

    # 1. DB Policy Check
    active_policies = db.query(Policy).filter(Policy.is_active == True).all()
    blocked_exts = []
    for p in active_policies:
        if p.rule_type == "BLOCK_EXTENSION":
            blocked_exts.extend([e.strip().lower() for e in p.target_value.split(",")])

    if file_ext in blocked_exts:
        threat_score += 100
        threats.append(f"Blocked file extension policy ({file_ext})")

    # 2. Shannon Entropy Analysis (Ransomware / UPX Packed Payload Check)
    if file_size > 1024:  # Analyze files larger than 1KB
        entropy = calculate_entropy(file_path)
        if entropy > 7.6:
            threat_score += 35
            threats.append(f"High Shannon Entropy ({entropy}/8.0): Likely Encrypted Payload or Ransomware")
        elif entropy > 7.2 and file_ext in [".exe", ".dll", ".sys"]:
            threat_score += 25
            threats.append(f"Suspicious Packed Executable Entropy ({entropy}/8.0)")

    # 3. Magic Bytes Validation
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            
        if file_ext == ".exe" and not header.startswith(b"MZ"):
            threat_score += 40
            threats.append("Spoofed .exe file (magic bytes mismatch)")
        elif file_ext == ".pdf" and not header.startswith(b"%PDF"):
            threat_score += 40
            threats.append("Spoofed .pdf file (magic bytes mismatch)")
        elif file_ext in [".zip", ".apk", ".docx", ".xlsx", ".pptx"] and not header.startswith(b"PK\x03\x04"):
            threat_score += 40
            threats.append("Invalid header signature for archived format")
    except Exception as e:
        threats.append(f"Header reading error: {str(e)}")

    # 4. Modded APK Inspection
    if file_ext == ".apk":
        apk_res = inspect_apk(file_path)
        threat_score += apk_res["score_adder"]
        threats.extend(apk_res["threats"])

    # 5. Office Document Macro Check
    elif file_ext in [".docm", ".xlsm", ".pptm", ".docx", ".xlsx"]:
        macro_res = inspect_office_document(file_path)
        threat_score += macro_res["score_adder"]
        threats.extend(macro_res["threats"])

    # 6. Sensitive Data Leak / YARA Secrets Pattern Matching (For text/code/config files)
    if file_ext in [".txt", ".json", ".xml", ".py", ".js", ".env", ".pem", ".key", ".config"]:
        try:
            with open(file_path, "rb") as f:
                content_sample = f.read(512 * 1024)  # Scan first 512KB
                for pattern, score_add, threat_desc in SECRETS_PATTERNS:
                    if pattern.search(content_sample):
                        threat_score += score_add
                        threats.append(threat_desc)
        except Exception:
            pass

    # Double Extension Check
    if re.search(r'\.(exe|vbs|bat|ps1|apk)\.(exe|vbs|bat|ps1|apk|zip)$', file_name.lower()):
        threat_score += 50
        threats.append("Suspicious double file extension detected")

    threat_score = min(100, threat_score)

    if threat_score >= 70:
        verdict = "MALICIOUS"
    elif threat_score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    return {
        "file_name": file_name,
        "threat_score": threat_score,
        "verdict": verdict,
        "threats_detected": threats if threats else ["No immediate threats detected"],
        "details": f"Analyzed {file_size} bytes. High-entropy, Secrets, APK, & Macro checks completed."
    }

def inspect_apk(apk_path: str) -> Dict[str, Any]:
    score = 0
    threats = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zip_file:
            file_list = zip_file.namelist()

            cert_files = [f for f in file_list if f.startswith("META-INF/") and (f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".SF"))]
            if not cert_files:
                score += 30
                threats.append("Unsigned APK (Missing signature certificates)")
            else:
                for cert in cert_files:
                    try:
                        cert_data = zip_file.read(cert)
                        if b"testkey" in cert_data.lower() or b"androiddebugkey" in cert_data.lower():
                            score += 25
                            threats.append("Modded APK: Signed with public debug/test key")
                            break
                    except Exception:
                        pass

            hidden_payloads = [f for f in file_list if (f.startswith("assets/") or f.startswith("res/")) and (f.endswith(".dex") or f.endswith(".jar") or f.endswith(".apk"))]
            if hidden_payloads:
                score += 35
                threats.append(f"Payload Dropper: Hidden executables in assets ({', '.join(hidden_payloads[:2])})")

            manifest_data = b""
            if "AndroidManifest.xml" in file_list:
                manifest_data = zip_file.read("AndroidManifest.xml")

            for perm, weight in DANGEROUS_APK_PERMISSIONS.items():
                if perm in manifest_data:
                    score += weight
                    perm_name = perm.decode('utf-8').split('.')[-1]
                    threats.append(f"Dangerous Permission: {perm_name}")

            dex_files = [f for f in file_list if f.endswith(".dex")]
            for dex in dex_files[:3]:
                try:
                    dex_data = zip_file.read(dex)
                    for pattern, pattern_weight, pattern_desc in APK_SUSPICIOUS_PATTERNS:
                        if pattern in dex_data:
                            score += pattern_weight
                            threats.append(f"Bytecode Suspicion: {pattern_desc}")
                except Exception:
                    pass
    except zipfile.BadZipFile:
        score += 50
        threats.append("Corrupted APK archive structure")
    except Exception as e:
        threats.append(f"APK check error: {str(e)}")

    return {"score_adder": score, "threats": list(set(threats))}

def inspect_office_document(file_path: str) -> Dict[str, Any]:
    score = 0
    threats = []
    try:
        with zipfile.ZipFile(file_path, "r") as zip_file:
            file_list = zip_file.namelist()
            if any("vbaProject.bin" in f for f in file_list):
                score += 35
                threats.append("Contains Embedded VBA Macros")
                try:
                    vba_key = "word/vbaProject.bin" if "word/vbaProject.bin" in file_list else "xl/vbaProject.bin"
                    vba_data = zip_file.read(vba_key).lower()
                    if b"powershell" in vba_data or b"cmd.exe" in vba_data:
                        score += 40
                        threats.append("Macro contains system command execution")
                    if b"autoopen" in vba_data or b"workbook_open" in vba_data:
                        score += 20
                        threats.append("Macro auto-executes on document open")
                except Exception:
                    pass
    except Exception:
        pass
    return {"score_adder": score, "threats": threats}