"""add_family_id_to_sessions

Revision ID: bf368e38abad
Revises: e806b6c7dc83
Create Date: 2025-07-18 13:38:58.634580

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bf368e38abad'
down_revision: Union[str, None] = 'e806b6c7dc83'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add family_id column to sessions table for token family correlation."""
    # Add family_id column to sessions table
    op.add_column('sessions', sa.Column('family_id', sa.String(255), nullable=True))
    
    # Create index for family_id column for performance
    op.create_index('ix_sessions_family_id', 'sessions', ['family_id'])


def downgrade() -> None:
    """Remove family_id column from sessions table."""
    # Drop index first
    op.drop_index('ix_sessions_family_id', table_name='sessions')
    
    # Drop family_id column
    op.drop_column('sessions', 'family_id')
