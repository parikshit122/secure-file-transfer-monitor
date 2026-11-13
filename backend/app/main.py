from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from app.core.database import engine, Base
from app.api.routes import router
from app.monitoring.file_monitor import start_monitoring

# Create missing DB tables
Base.metadata.create_all(bind=engine)

# Universal SQLite Schema Auto-Migrator
def auto_migrate_db():
    try:
        with engine.begin() as conn:
            inspector = inspect(engine)
            existing_tables = inspector.get_table_names()

            for table_name, table in Base.metadata.tables.items():
                if table_name in existing_tables:
                    existing_columns = {c["name"] for c in inspector.get_columns(table_name)}
                    for column in table.columns:
                        if column.name not in existing_columns:
                            col_type = "VARCHAR"
                            type_str = str(column.type).upper()
                            if "INTEGER" in type_str:
                                col_type = "INTEGER"
                            elif "BOOLEAN" in type_str:
                                col_type = "BOOLEAN"
                            elif "DATETIME" in type_str:
                                col_type = "DATETIME"
                            elif "TEXT" in type_str:
                                col_type = "TEXT"

                            conn.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}'))
    except Exception:
        pass

auto_migrate_db()

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