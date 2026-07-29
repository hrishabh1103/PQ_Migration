"""correlation records and readiness assessments migration

Revision ID: 003_correlation_and_readiness
Revises: 002_foundation_v2_1
Create Date: 2026-07-29 05:42:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '003_correlation_and_readiness'
down_revision = '002_foundation_v2_1'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. correlation_records
    op.create_table(
        'correlation_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('source_entity_type', sa.String(length=64), nullable=False),
        sa.Column('source_entity_id', sa.String(length=64), nullable=False),
        sa.Column('target_entity_type', sa.String(length=64), nullable=False),
        sa.Column('target_entity_id', sa.String(length=64), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('matching_evidence_json', sa.JSON(), nullable=False),
        sa.Column('conflicting_evidence_json', sa.JSON(), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False, server_default='rule-default'),
        sa.Column('rule_version', sa.String(length=32), nullable=False, server_default='v1.0'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_correlation_records_source_type', 'correlation_records', ['source_entity_type'])
    op.create_index('ix_correlation_records_source_id', 'correlation_records', ['source_entity_id'])
    op.create_index('ix_correlation_records_target_type', 'correlation_records', ['target_entity_type'])
    op.create_index('ix_correlation_records_target_id', 'correlation_records', ['target_entity_id'])

    # 2. readiness_assessments
    op.create_table(
        'readiness_assessments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=True),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('policy_id', sa.String(length=64), nullable=False, server_default='pqc-default'),
        sa.Column('policy_version', sa.String(length=32), nullable=False, server_default='v1.0'),
        sa.Column('readiness_result', sa.String(length=32), nullable=False),
        sa.Column('quantum_exposure', sa.String(length=32), nullable=False),
        sa.Column('migration_priority_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('migration_category', sa.String(length=32), nullable=False, server_default='LOW'),
        sa.Column('confidence', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('known_factors_json', sa.JSON(), nullable=False),
        sa.Column('unknown_factors_json', sa.JSON(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['authorized_targets.id'], ),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_readiness_assessments_target_id', 'readiness_assessments', ['target_id'])
    op.create_index('ix_readiness_assessments_asset_id', 'readiness_assessments', ['asset_id'])

def downgrade() -> None:
    op.drop_index('ix_readiness_assessments_asset_id', table_name='readiness_assessments')
    op.drop_index('ix_readiness_assessments_target_id', table_name='readiness_assessments')
    op.drop_table('readiness_assessments')

    op.drop_index('ix_correlation_records_target_id', table_name='correlation_records')
    op.drop_index('ix_correlation_records_target_type', table_name='correlation_records')
    op.drop_index('ix_correlation_records_source_id', table_name='correlation_records')
    op.drop_index('ix_correlation_records_source_type', table_name='correlation_records')
    op.drop_table('correlation_records')
