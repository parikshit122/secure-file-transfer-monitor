from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import engine, Base
from app.api.routes import router
from app.monitoring.file_monitor import start_monitoring

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SFTMS Security API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

observer_instance = None

@app.on_event("startup")
def startup_event():
    global observer_instance
    try:
        observer_instance = start_monitoring()
    except Exception:
        pass

@app.on_event("shutdown")
def shutdown_event():
    global observer_instance
    if observer_instance:
        try:
            observer_instance.stop()
        except Exception:
            pass

@app.get("/")
def read_root():
    return {"status": "SFTMS Core Active Defense Engine Online"}