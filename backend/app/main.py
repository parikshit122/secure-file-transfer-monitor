import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.database import init_db
from .monitoring.file_monitor import file_monitor
from .api.routes import router

WATCH_PATH = "E:\\SFTMS\\test_watch"

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    os.makedirs(WATCH_PATH, exist_ok=True)
    loop = asyncio.get_event_loop()
    file_monitor.start(WATCH_PATH, loop)
    yield
    file_monitor.stop()

app = FastAPI(title="SFTMS", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/")
async def root():
    return {"status": "running", "message": "SFTMS Backend is alive"}
