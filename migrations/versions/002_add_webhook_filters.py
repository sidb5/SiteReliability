"""Add webhook_filters column to api_keys

Revision ID: 002
Revises: 001
Create Date: 2026-06-27
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("webhook_filters", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("api_keys", "webhook_filters")
