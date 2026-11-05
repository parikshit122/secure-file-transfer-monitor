# 🛡️ Secure File Transfer Monitoring System (SFTMS)

Real-time file transfer monitoring and threat detection system with live security dashboard, file integrity hashing, and sensitive data movement tracking.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.162-009688?style=flat-square)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## 📌 Overview

File transfers pose significant risks including data leakage, unauthorized access, malware distribution, and insider misuse. SFTMS monitors file activity in a watched folder in real time, computes cryptographic hashes for integrity verification, flags sensitive files, and shows everything on a live security dashboard.

### Detection Goals

- Unauthorized movement of sensitive files (`.pem`, `.key`, `.env`, `.sql`)
- File tampering and integrity violations
- Suspicious transfers to USB, network shares, and cloud folders *(planned)*
- Potential data exfiltration attempts *(planned)*

---

## ✨ Features

| Feature | Status | Description |
|---------|--------|-------------|
| Real-time File Monitoring | ✅ | Detects create, modify, move, delete events |
| Multi-Algorithm Hashing | ✅ | BLAKE3 + SHA-256 computed in streamed 4 MB chunks |
| Sensitive File Detection | ✅ | Flags restricted extensions and folder names |
| Magic Byte Identification | ✅ | True MIME type detection regardless of extension |
| Async Database Writes | ✅ | Events saved through async SQLAlchemy + aiosqlite |
| Audit Logging | ✅ | Full event history stored in SQLite with timestamps |
| Live Security Dashboard | ✅ | Dark-themed React UI, auto-refreshing every few seconds |
| Deep Content Scanning | 🔜 | YARA rules, macro detection, archive inspection |
| Threat Neutralization | 🔜 | Quarantine, block, process termination |
| USB / Network / Cloud Detection | 🔜 | Outbound transfer channel detection |
| Behavioral Anomaly Detection | 🔜 | Baseline deviation alerts |
| Desktop App | 🔜 | Tauri 2.x shell for Windows, macOS, Linux |

---

## 🏗️ Architecture

```
┌─────────────────┐      REST API       ┌──────────────────┐
│   React UI      │ ◄─────────────────► │   FastAPI        │
│   (Port 5173)   │                     │   (Port 8000)    │
│   Tailwind CSS  │                     │                  │
└─────────────────┘                     └────────┬─────────┘
                                                 │
                                      ┌──────────┼──────────┐
                                      ▼          ▼          ▼
                                ┌──────────┐ ┌────────┐ ┌────────┐
                                │ Watchdog │ │ BLAKE3 │ │ SQLite │
                                │ Monitor  │ │ SHA256 │ │   DB   │
                                └──────────┘ └────────┘ └────────┘
```

### Data Flow

1. **Watchdog** captures file system events in the watched folder
2. File type is identified using **magic bytes**
3. **BLAKE3 + SHA-256** hashes are computed
4. Sensitive file rules are checked
5. The event is saved to **SQLite**
6. **FastAPI** serves data through REST endpoints
7. The **React dashboard** polls the API and displays live stats

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.12** ([Download](https://www.python.org/downloads/))
- **Node.js 20+** ([Download](https://nodejs.org/))
- **Git** ([Download](https://git-scm.com/))

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/parikshit122/secure-file-transfer-monitor.git
cd secure-file-transfer-monitor

# 2. Backend setup
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux / macOS

cd backend
pip install fastapi "uvicorn[standard]" pydantic pydantic-settings python-multipart
pip install watchdog psutil blake3 python-magic-bin structlog
pip install "sqlalchemy[asyncio]" aiosqlite alembic
pip install cryptography "passlib[bcrypt]" "python-jose[cryptography]" pyyaml
pip install oletools PyMuPDF py7zr rarfile Pillow httpx yara-python

# 3. Frontend setup
cd ../apps/web
npm install
```

> **Note:** `python-magic-bin` is for Windows. On Linux/macOS, install `python-magic` and the `libmagic` system library instead.

### Configure the Watched Folder

Open `backend/app/main.py` and change `WATCH_PATH` to the folder you want to monitor:

```python
WATCH_PATH = "E:\\SFTMS\\test_watch"
```

### Running

Open **two** terminal windows.

**Terminal 1: Backend**
```bash
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2: Frontend**
```bash
cd apps/web
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Testing

Create files in the watched folder and watch the dashboard update:

```powershell
echo "hello" > E:\SFTMS\test_watch\readme.txt
echo "secret" > E:\SFTMS\test_watch\server.pem
```

---

## 📁 Project Structure

```
secure-file-transfer-monitor/
├── apps/
│   ├── desktop/              # Tauri shell (planned)
│   └── web/                  # React dashboard
│       └── src/
│           ├── components/   # Layout
│           └── pages/        # Dashboard
├── backend/
│   ├── app/
│   │   ├── api/              # REST routes (/api/stats, /api/events)
│   │   ├── core/             # Database + models
│   │   ├── monitoring/       # Watchdog file observer
│   │   ├── scanning/         # Threat scanners (planned)
│   │   ├── policy/           # Rule engine (planned)
│   │   ├── actions/          # Quarantine / block (planned)
│   │   ├── intel/            # Threat intel (planned)
│   │   ├── workers/          # Background workers (planned)
│   │   └── main.py           # Application entry point
│   ├── rules/                # YARA rules (planned)
│   └── tests/
├── docs/
├── .gitignore
└── README.md
```

---

## 🗺️ Roadmap

### Phase 1: Core MVP ✅
- [x] File system event monitoring
- [x] BLAKE3 + SHA-256 integrity hashing
- [x] Sensitive file detection
- [x] SQLite audit logging
- [x] Live React dashboard

### Phase 2: Deep Scanning
- [ ] YARA rule-based detection
- [ ] Office macro analysis
- [ ] PDF inspection
- [ ] Archive scanning with bomb detection

### Phase 3: Active Defense
- [ ] Automated quarantine
- [ ] Alert system (Email, Slack)
- [ ] Process termination

### Phase 4: Intelligence
- [ ] Behavioral baselines and anomaly detection
- [ ] Threat intel integration (VirusTotal, MISP)

### Phase 5: Production
- [ ] Tauri desktop application
- [ ] Authentication and RBAC
- [ ] SIEM log export

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, Uvicorn |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Database | SQLite, SQLAlchemy 2.0 (async) |
| Monitoring | Watchdog, psutil |
| Hashing | BLAKE3, SHA-256 |
| File Typing | python-magic |
| Desktop | Tauri 2.x (planned) |

---

## 🔒 Security Notes

- Backend binds to `127.0.0.1` only (not exposed to the network)
- CORS is restricted to the local dashboard origin
- Files are hashed in streamed chunks (no full-file memory loading)
- Sensitive-file rules are currently defined in code and will move to a config-driven policy engine
- Authentication, WAL mode, and tamper-evident logs are planned

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m "Add my feature"`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

<p align="center">Built for security 🛡️</p>
