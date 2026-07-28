"""foundation v2 1 schema migration

Revision ID: 002_foundation_v2_1
Revises: 001_initial_v1
Create Date: 2026-07-28 21:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '002_foundation_v2_1'
down_revision = '001_initial_v1'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. discovery_runs
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

    # 2. provenance
    op.create_table(
        'provenance',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('discovery_run_id', sa.String(length=36), nullable=True),
        sa.Column('target_id', sa.String(length=36), nullable=True),
        sa.Column('plugin_id', sa.String(length=64), nullable=False),
        sa.Column('plugin_version', sa.String(length=32), nullable=False, server_default='1.0.0'),
        sa.Column('collection_method', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('evidence_type', sa.String(length=64), nullable=False, server_default='OBSERVATION'),
        sa.Column('evidence_hash', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.String(length=16), nullable=False, server_default='HIGH'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id']),
        sa.ForeignKeyConstraint(['target_id'], ['authorized_targets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_provenance_evidence_hash', 'provenance', ['evidence_hash'], unique=False)

    # 3. crypto_objects
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
        sa.Column('provenance_id', sa.String(length=36), nullable=True),
        sa.Column('discovery_run_id', sa.String(length=36), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id']),
        sa.ForeignKeyConstraint(['provenance_id'], ['provenance.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_crypto_objects_identity_key', 'crypto_objects', ['identity_key'], unique=True)
    op.create_index('ix_crypto_objects_fingerprint', 'crypto_objects', ['fingerprint'], unique=False)

    # 4. relationships
    op.create_table(
        'relationships',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('source_entity_type', sa.String(length=64), nullable=False),
        sa.Column('source_entity_id', sa.String(length=64), nullable=False),
        sa.Column('target_entity_type', sa.String(length=64), nullable=False),
        sa.Column('target_entity_id', sa.String(length=64), nullable=False),
        sa.Column('relationship_type', sa.String(length=64), nullable=False),
        sa.Column('scanner_or_connector_id', sa.String(length=64), nullable=False),
        sa.Column('provenance_id', sa.String(length=36), nullable=True),
        sa.Column('discovery_run_id', sa.String(length=36), nullable=True),
        sa.Column('evidence_snippet', sa.Text(), nullable=True),
        sa.Column('evidence_hash', sa.String(length=64), nullable=True),
        sa.Column('confidence', sa.String(length=16), nullable=False, server_default='HIGH'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id']),
        sa.ForeignKeyConstraint(['provenance_id'], ['provenance.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_relationships_source_pair', 'relationships', ['source_entity_type', 'source_entity_id'], unique=False)
    op.create_index('ix_relationships_target_pair', 'relationships', ['target_entity_type', 'target_entity_id'], unique=False)

    # 5. data_assets & data_flows
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
        sa.Column('provenance_id', sa.String(length=36), nullable=True),
        sa.Column('protection_purpose', sa.String(length=64), nullable=False, server_default='ENCRYPTION'),
        sa.Column('direction', sa.String(length=32), nullable=False, server_default='INBOUND'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['crypto_object_id'], ['crypto_objects.id']),
        sa.ForeignKeyConstraint(['data_asset_id'], ['data_assets.id']),
        sa.ForeignKeyConstraint(['provenance_id'], ['provenance.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_data_flows_source_pair', 'data_flows', ['source_entity_type', 'source_entity_id'], unique=False)
    op.create_index('ix_data_flows_dest_pair', 'data_flows', ['destination_entity_type', 'destination_entity_id'], unique=False)

    # 6. discovery_coverage
    op.create_table(
        'discovery_coverage',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('plugin_id', sa.String(length=64), nullable=True),
        sa.Column('discovery_run_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='NOT_SCANNED'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_discovery_coverage_asset_id', 'discovery_coverage', ['asset_id'], unique=False)

    # 7. Add columns to assets
    with op.batch_alter_table('assets') as batch_op:
        batch_op.add_column(sa.Column('asset_category', sa.String(length=64), nullable=False, server_default='INFRASTRUCTURE'))
        batch_op.add_column(sa.Column('asset_subtype', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('taxonomy_namespace', sa.String(length=64), nullable=True, server_default='enterprise_v2'))
        batch_op.add_column(sa.Column('identity_key', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('external_id', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('provider_resource_id', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('provider', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('region', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('account_or_tenant_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'))
        batch_op.create_index('ix_assets_asset_category', ['asset_category'], unique=False)
        batch_op.create_index('ix_assets_identity_key', ['identity_key'], unique=False)
        batch_op.create_index('ix_assets_status', ['status'], unique=False)

    # 8. Add columns to crypto_findings
    with op.batch_alter_table('crypto_findings') as batch_op:
        batch_op.add_column(sa.Column('crypto_object_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('discovery_run_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('provenance_id', sa.String(length=36), nullable=True))
        batch_op.create_foreign_key('fk_findings_crypto_object', 'crypto_objects', ['crypto_object_id'], ['id'])
        batch_op.create_foreign_key('fk_findings_discovery_run', 'discovery_runs', ['discovery_run_id'], ['id'])
        batch_op.create_foreign_key('fk_findings_provenance', 'provenance', ['provenance_id'], ['id'])

def downgrade() -> None:
    with op.batch_alter_table('crypto_findings') as batch_op:
        batch_op.drop_constraint('fk_findings_provenance', type_='foreignkey')
        batch_op.drop_constraint('fk_findings_discovery_run', type_='foreignkey')
        batch_op.drop_constraint('fk_findings_crypto_object', type_='foreignkey')
        batch_op.drop_column('provenance_id')
        batch_op.drop_column('discovery_run_id')
        batch_op.drop_column('crypto_object_id')

    with op.batch_alter_table('assets') as batch_op:
        batch_op.drop_index('ix_assets_status')
        batch_op.drop_index('ix_assets_identity_key')
        batch_op.drop_index('ix_assets_asset_category')
        batch_op.drop_column('status')
        batch_op.drop_column('account_or_tenant_id')
        batch_op.drop_column('region')
        batch_op.drop_column('provider')
        batch_op.drop_column('provider_resource_id')
        batch_op.drop_column('external_id')
        batch_op.drop_column('identity_key')
        batch_op.drop_column('taxonomy_namespace')
        batch_op.drop_column('asset_subtype')
        batch_op.drop_column('asset_category')

    op.drop_table('discovery_coverage')
    op.drop_table('data_flows')
    op.drop_table('data_assets')
    op.drop_table('relationships')
    op.drop_table('crypto_objects')
    op.drop_table('provenance')
    op.drop_table('discovery_runs')
