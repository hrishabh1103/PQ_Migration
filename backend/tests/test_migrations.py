import os
import tempfile
import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, inspect

def test_alembic_fresh_database_migration():
    """Test Alembic upgrade head on a fresh empty database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        db_url = f"sqlite:///{db_path}"
        os.environ["DATABASE_URL"] = db_url
        
        alembic_cfg = Config("alembic.ini")

        # Run migration to head
        command.upgrade(alembic_cfg, "head")

        engine = create_engine(db_url)
        inspector = inspect(engine)
        tables = inspector.get_table_names()

        # Check all V2.1 tables exist
        expected_tables = {
            "authorized_targets", "scan_jobs", "assets", "services",
            "normalized_algorithms", "crypto_findings", "discovery_runs",
            "provenance", "crypto_objects", "relationships", "data_assets",
            "data_flows", "discovery_coverage"
        }
        for table in expected_tables:
            assert table in tables, f"Table '{table}' missing after fresh migration"

        # Check asset columns
        asset_cols = [c["name"] for c in inspector.get_columns("assets")]
        assert "asset_category" in asset_cols
        assert "identity_key" in asset_cols
        assert "status" in asset_cols

        # Check finding columns
        finding_cols = [c["name"] for c in inspector.get_columns("crypto_findings")]
        assert "crypto_object_id" in finding_cols
        assert "discovery_run_id" in finding_cols
        assert "provenance_id" in finding_cols

        engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_alembic_upgrade_from_v1_schema():
    """Test Alembic upgrade head from a pre-V2 (V1) database schema without data loss."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        db_url = f"sqlite:///{db_path}"
        os.environ["DATABASE_URL"] = db_url
        
        alembic_cfg = Config("alembic.ini")

        # 1. Upgrade to V1 schema
        command.upgrade(alembic_cfg, "001_initial_v1")

        engine = create_engine(db_url)
        # Insert V1 mock data
        with engine.begin() as conn:
            conn.execute(
                sa.text("INSERT INTO authorized_targets (id, name, target_type, target_value, created_at, updated_at) VALUES ('t1', 'Target 1', 'HOSTNAME', 'example.com', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
            )
            conn.execute(
                sa.text("INSERT INTO assets (id, target_id, hostname, asset_type, environment, metadata_json, first_seen_at, last_seen_at) VALUES ('a1', 't1', 'example.com', 'HOST', 'DEVELOPMENT', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
            )

        # 2. Upgrade to V2.1 head
        command.upgrade(alembic_cfg, "head")

        inspector = inspect(engine)
        asset_cols = [c["name"] for c in inspector.get_columns("assets")]
        assert "asset_category" in asset_cols
        assert "identity_key" in asset_cols

        # Verify existing data preserved
        with engine.connect() as conn:
            res = conn.execute(sa.text("SELECT id, hostname, asset_category FROM assets WHERE id = 'a1'")).fetchone()
            assert res is not None
            assert res[0] == 'a1'
            assert res[1] == 'example.com'
            assert res[2] == 'INFRASTRUCTURE' # Default server_default

        engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
