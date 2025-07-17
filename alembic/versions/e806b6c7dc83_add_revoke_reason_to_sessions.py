"""add_revoke_reason_to_sessions

Revision ID: e806b6c7dc83
Revises: 55e74adcf14e
Create Date: 2025-07-10 18:37:59.939900

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e806b6c7dc83'
down_revision: Union[str, None] = '55e74adcf14e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add revoke_reason column to sessions table
    op.add_column('sessions', sa.Column('revoke_reason', sa.String(255), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    # Remove revoke_reason column from sessions table
    op.drop_column('sessions', 'revoke_reason')
