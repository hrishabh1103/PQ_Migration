from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.api import api_router

# Import scanners module so all scanner plugins auto-register with ScannerRegistry
import app.scanners  # noqa: F401

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from alembic.config import Config
        from alembic import command
        import os

        alembic_cfg = Config("alembic.ini")
        db_url = os.getenv("DATABASE_URL", str(engine.url))
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)

        with engine.connect() as conn:
            from sqlalchemy import inspect
            inspector = inspect(conn)
            tables = inspector.get_table_names()
            if "authorized_targets" in tables and "alembic_version" not in tables:
                logger.info("Stamping unversioned legacy database with 001_initial_v1...")
                command.stamp(alembic_cfg, "001_initial_v1")

        logger.info("Running database schema migrations (alembic upgrade head)...")
        command.upgrade(alembic_cfg, "head")
    except Exception as e:
        logger.warning(f"Database auto-migration warning: {e}")
        Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "message": "Enterprise Cryptographic Discovery Platform API",
        "docs_url": "/docs",
        "health_check": f"{settings.API_V1_STR}/health"
    }
