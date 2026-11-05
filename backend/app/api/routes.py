from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from ..core.database import get_db
from ..core.models import FileEvent, ScanResult, Alert

router = APIRouter(prefix="/api")

@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count(FileEvent.id)))).scalar() or 0
    threats = (await db.execute(
        select(func.count(FileEvent.id)).where(FileEvent.threat_level != "clean")
    )).scalar() or 0
    alerts_count = (await db.execute(
        select(func.count(Alert.id)).where(Alert.is_resolved == 0)
    )).scalar() or 0
    scans = (await db.execute(select(func.count(ScanResult.id)))).scalar() or 0
    return {
        "files_monitored": total,
        "threats_blocked": threats,
        "active_alerts": alerts_count,
        "integrity_checks": scans,
    }

@router.get("/events")
async def get_events(limit: int = 50, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(FileEvent).order_by(FileEvent.timestamp.desc()).limit(limit)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "timestamp": str(e.timestamp),
            "event_type": e.event_type,
            "file_name": e.file_name,
            "src_path": e.src_path,
            "dest_path": e.dest_path,
            "file_size": e.file_size,
            "file_type": e.file_type,
            "is_sensitive": e.is_sensitive,
            "threat_level": e.threat_level,
        }
        for e in events
    ]
