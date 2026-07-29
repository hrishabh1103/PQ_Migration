"""assessment runs and factor breakdown migration

Revision ID: 004_assessment_runs
Revises: 003_correlation_and_readiness
Create Date: 2026-07-29 07:34:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '004_assessment_runs'
down_revision = '003_correlation_and_readiness'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. create assessment_runs table
    op.create_table(
        'assessment_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('policy_id', sa.String(length=64), nullable=False, server_default='pqc-default'),
        sa.Column('policy_version', sa.String(length=32), nullable=False, server_default='v1.0'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='RUNNING'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('evaluated_entity_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_entity_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # 2. add assessment_run_id and factor_breakdown_json to readiness_assessments
    with op.batch_alter_table('readiness_assessments') as batch_op:
        batch_op.add_column(sa.Column('assessment_run_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('factor_breakdown_json', sa.JSON(), nullable=False, server_default='{}'))
        batch_op.create_index('ix_readiness_assessments_assessment_run_id', ['assessment_run_id'])
        batch_op.create_foreign_key('fk_readiness_assessments_assessment_run', 'assessment_runs', ['assessment_run_id'], ['id'])

def downgrade() -> None:
    with op.batch_alter_table('readiness_assessments') as batch_op:
        batch_op.drop_constraint('fk_readiness_assessments_assessment_run', type_='foreignkey')
        batch_op.drop_index('ix_readiness_assessments_assessment_run_id')
        batch_op.drop_column('factor_breakdown_json')
        batch_op.drop_column('assessment_run_id')

    op.drop_table('assessment_runs')
