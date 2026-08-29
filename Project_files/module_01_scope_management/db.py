"""Database configuration; credentials are always environment-provided."""
from __future__ import annotations
from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:////home/thunder/Project_thunder/thunder.db"
    scope_export_dir: str = "./exports"

settings = Settings()
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
    pool_pre_ping=True
)
SessionLocal = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

def init_db():
    try:
        import module_01_scope_management.models
    except Exception: pass
    try:
        import module_02_asset_discovery.models
    except Exception: pass
    try:
        import module_03_identity_correlation.models
    except Exception: pass
    try:
        import module_04_attack_surface_inventory.models
    except Exception: pass
    try:
        import module_08_ai_validation_and_risk.models
    except Exception: pass
    try:
        import module_09_alerting.models
    except Exception: pass
    try:
        import module_10_continuous_monitoring.models
    except Exception: pass
    try:
        import module_11_reporting.models
    except Exception: pass
    try:
        import module_12_unified_reporting.models
    except Exception: pass
    Base.metadata.create_all(bind=engine)

init_db()

def get_session() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session

