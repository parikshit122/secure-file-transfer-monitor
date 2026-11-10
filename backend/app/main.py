from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import engine, Base, SessionLocal
from app.core import models
from app.api.routes import router
from app.monitoring.file_monitor import start_monitoring
from app.core.models import Policy

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SFTMS", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


def seed_default_policies():
    db = SessionLocal()
    try:
        if db.query(Policy).count() == 0:
            defaults = [
                Policy(
                    name="Block Executables",
                    description="Block .exe, .bat, .cmd, .ps1, .msi files",
                    policy_type="extension_block",
                    action="block",
                    enabled=True,
                    parameters=".exe,.bat,.cmd,.ps1,.msi",
                ),
                Policy(
                    name="Double Extension Block",
                    description="Block files with double extensions like .pdf.exe",
                    policy_type="double_extension",
                    action="block",
                    enabled=True,
                    parameters="",
                ),
            ]
            db.add_all(defaults)
            db.commit()
            print("Seeded default security policies.")
    except Exception as e:
        print(f"Policy seeding error: {e}")
    finally:
        db.close()


@app.on_event("startup")
def startup():
    seed_default_policies()
    start_monitoring()


@app.get("/")
def root():
    return {"status": "SFTMS running", "monitoring": "Active"}