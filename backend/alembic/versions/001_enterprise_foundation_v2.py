"""enterprise foundation v2

Revision ID: 001_foundation_v2
Revises: 
Create Date: 2026-07-28 22:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001_foundation_v2'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. Create relationships table
    op.create_table(
        'relationships',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('source_entity_type', sa.String(length=64), nullable=False),
        sa.Column('source_entity_id', sa.String(length=64), nullable=False),
        sa.Column('target_entity_type', sa.String(length=64), nullable=False),
        sa.Column('target_entity_id', sa.String(length=64), nullable=False),
        sa.Column('relationship_type', sa.String(length=64), nullable=False),
        sa.Column('scanner_or_connector_id', sa.String(length=64), nullable=False),
        sa.Column('evidence_snippet', sa.Text(), nullable=True),
        sa.Column('evidence_hash', sa.String(length=64), nullable=True),
        sa.Column('confidence', sa.String(length=16), nullable=False, server_default='HIGH'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_relationships_source_id', 'relationships', ['source_entity_id'], unique=False)
    op.create_index('ix_relationships_target_id', 'relationships', ['target_entity_id'], unique=False)
    op.create_index('ix_relationships_type', 'relationships', ['relationship_type'], unique=False)

    # 2. Create crypto_objects table
    op.create_table(
        'crypto_objects',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('object_type', sa.String(length=64), nullable=False),
        sa.Column('canonical_name', sa.String(length=255), nullable=False),
        sa.Column('provider', sa.String(length=64), nullable=True),
        sa.Column('version', sa.String(length=64), nullable=True),
        sa.Column('identity_key', sa.String(length=255), nullable=False),
        sa.Column('fingerprint', sa.String(length=255), nullable=True),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('provider_resource_id', sa.String(length=255), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('identity_key')
    )
    op.create_index('ix_crypto_objects_object_type', 'crypto_objects', ['object_type'], unique=False)
    op.create_index('ix_crypto_objects_fingerprint', 'crypto_objects', ['fingerprint'], unique=False)

    # 3. Create data_assets table
    op.create_table(
        'data_assets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('classification', sa.String(length=64), nullable=False, server_default='CONFIDENTIAL'),
        sa.Column('required_confidentiality_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retention_period', sa.String(length=64), nullable=True),
        sa.Column('business_criticality', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # 4. Create data_flows table
    op.create_table(
        'data_flows',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('source_entity_type', sa.String(length=64), nullable=False),
        sa.Column('source_entity_id', sa.String(length=64), nullable=False),
        sa.Column('destination_entity_type', sa.String(length=64), nullable=False),
        sa.Column('destination_entity_id', sa.String(length=64), nullable=False),
        sa.Column('data_asset_id', sa.String(length=36), nullable=True),
        sa.Column('protocol', sa.String(length=64), nullable=True),
        sa.Column('crypto_object_id', sa.String(length=36), nullable=True),
        sa.Column('protection_purpose', sa.String(length=64), nullable=False, server_default='ENCRYPTION'),
        sa.Column('direction', sa.String(length=32), nullable=False, server_default='INBOUND'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['data_asset_id'], ['data_assets.id']),
        sa.ForeignKeyConstraint(['crypto_object_id'], ['crypto_objects.id']),
        sa.PrimaryKeyConstraint('id')
    )

    # 5. Create discovery_coverage table
    op.create_table(
        'discovery_coverage',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='NOT_SCANNED'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_discovery_coverage_asset', 'discovery_coverage', ['asset_id'], unique=False)
    op.create_index('ix_discovery_coverage_capability', 'discovery_coverage', ['capability'], unique=False)

    # 6. Create discovery_runs table
    op.create_table(
        'discovery_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('run_type', sa.String(length=32), nullable=False, server_default='SCAN'),
        sa.Column('plugin_id', sa.String(length=64), nullable=False),
        sa.Column('plugin_version', sa.String(length=32), nullable=False, server_default='1.0.0'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('stats_json', sa.JSON(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade() -> None:
    op.drop_table('discovery_runs')
    op.drop_table('discovery_coverage')
    op.drop_table('data_flows')
    op.drop_table('data_assets')
    op.drop_table('crypto_objects')
    op.drop_table('relationships')
