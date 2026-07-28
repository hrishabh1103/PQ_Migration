"""initial v1 schema

Revision ID: 001_initial_v1
Revises: 
Create Date: 2026-07-28 20:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '001_initial_v1'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. authorized_targets
    op.create_table(
        'authorized_targets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_type', sa.String(length=64), nullable=False),
        sa.Column('target_value', sa.String(length=512), nullable=False),
        sa.Column('is_authorized', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('environment', sa.String(length=64), nullable=False, server_default='DEVELOPMENT'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_authorized_targets_target_value', 'authorized_targets', ['target_value'], unique=False)

    # 2. scan_jobs
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('requested_scanners', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('stats_json', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['authorized_targets.id']),
        sa.PrimaryKeyConstraint('id')
    )

    # 3. assets (V1 schema)
    op.create_table(
        'assets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('asset_type', sa.String(length=64), nullable=False, server_default='HOST'),
        sa.Column('environment', sa.String(length=64), nullable=False, server_default='DEVELOPMENT'),
        sa.Column('operating_system', sa.String(length=128), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['authorized_targets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_assets_hostname', 'assets', ['hostname'], unique=False)
    op.create_index('ix_assets_ip_address', 'assets', ['ip_address'], unique=False)

    # 4. services (V1 schema)
    op.create_table(
        'services',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('transport_protocol', sa.String(length=32), nullable=False, server_default='TCP'),
        sa.Column('application_protocol', sa.String(length=32), nullable=False, server_default='HTTPS'),
        sa.Column('service_name', sa.String(length=64), nullable=False, server_default='https'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.PrimaryKeyConstraint('id')
    )

    # 5. normalized_algorithms
    op.create_table(
        'normalized_algorithms',
        sa.Column('canonical_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('observed_name', sa.String(length=128), nullable=False),
        sa.Column('canonical_family', sa.String(length=64), nullable=False),
        sa.Column('canonical_variant', sa.String(length=64), nullable=False),
        sa.Column('implementation_variant', sa.String(length=64), nullable=True),
        sa.Column('primitive_type', sa.String(length=64), nullable=False),
        sa.Column('quantum_safety_status', sa.String(length=64), nullable=False),
        sa.Column('estimated_security_bits', sa.Integer(), nullable=True),
        sa.Column('nist_standard_status', sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint('canonical_id')
    )

    # 6. crypto_findings
    op.create_table(
        'crypto_findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_job_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('service_id', sa.String(length=36), nullable=True),
        sa.Column('scanner_id', sa.String(length=64), nullable=False),
        sa.Column('scanner_version', sa.String(length=32), nullable=False, server_default='1.0.0'),
        sa.Column('finding_type', sa.String(length=64), nullable=False),
        sa.Column('raw_algorithm_name', sa.String(length=128), nullable=False),
        sa.Column('normalized_algorithm_id', sa.String(length=64), nullable=False),
        sa.Column('purpose', sa.String(length=64), nullable=False, server_default='UNKNOWN'),
        sa.Column('location_identifier', sa.String(length=512), nullable=False),
        sa.Column('evidence_snippet', sa.Text(), nullable=False),
        sa.Column('evidence_hash', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.String(length=16), nullable=False, server_default='HIGH'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['normalized_algorithm_id'], ['normalized_algorithms.canonical_id']),
        sa.ForeignKeyConstraint(['scan_job_id'], ['scan_jobs.id']),
        sa.ForeignKeyConstraint(['service_id'], ['services.id']),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade() -> None:
    op.drop_table('crypto_findings')
    op.drop_table('normalized_algorithms')
    op.drop_table('services')
    op.drop_table('assets')
    op.drop_table('scan_jobs')
    op.drop_table('authorized_targets')
