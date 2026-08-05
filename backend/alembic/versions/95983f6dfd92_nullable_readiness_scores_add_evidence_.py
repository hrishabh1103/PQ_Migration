"""nullable_readiness_scores_add_evidence_counts

Revision ID: 95983f6dfd92
Revises: 004_assessment_runs
Create Date: 2026-07-31 10:16:10.237197

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '95983f6dfd92'
down_revision: Union[str, None] = '004_assessment_runs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite-compatible: use batch_alter_table to recreate the table
    # This allows making columns nullable and adding new columns atomically.
    with op.batch_alter_table('readiness_assessments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('evidence_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('vulnerable_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('resistant_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('hybrid_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('unknown_count', sa.Integer(), nullable=False, server_default='0'))
        # Make priority score and category nullable (no evidence = null, not 0/LOW)
        batch_op.alter_column('migration_priority_score',
                               existing_type=sa.INTEGER(),
                               nullable=True,
                               existing_server_default=None)
        batch_op.alter_column('migration_category',
                               existing_type=sa.VARCHAR(length=32),
                               nullable=True,
                               existing_server_default=None)

    # Make scan_job_id nullable on crypto_findings for DiscoveryRun connector syncs
    with op.batch_alter_table('crypto_findings', schema=None) as batch_op:
        batch_op.alter_column('scan_job_id',
                               existing_type=sa.VARCHAR(length=36),
                               nullable=True,
                               existing_server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('crypto_findings', schema=None) as batch_op:
        batch_op.alter_column('scan_job_id',
                               existing_type=sa.VARCHAR(length=36),
                               nullable=False,
                               existing_server_default=None)

    with op.batch_alter_table('readiness_assessments', schema=None) as batch_op:
        batch_op.alter_column('migration_category',
                               existing_type=sa.VARCHAR(length=32),
                               nullable=False,
                               existing_server_default=None)
        batch_op.alter_column('migration_priority_score',
                               existing_type=sa.INTEGER(),
                               nullable=False,
                               existing_server_default=None)
        batch_op.drop_column('unknown_count')
        batch_op.drop_column('hybrid_count')
        batch_op.drop_column('resistant_count')
        batch_op.drop_column('vulnerable_count')
        batch_op.drop_column('evidence_count')
