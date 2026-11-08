from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import engine, Base
from app.core import models  # THIS LINE IS THE FIX
from app.api.routes import router
from app.monitoring.file_monitor import start_monitoring

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SFTMS", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

@app.on_event("startup")
def startup():
    start_monitoring()

@app.get("/")
def root():
    return {"status": "SFTMS running", "monitoring": "Downloads folder"}