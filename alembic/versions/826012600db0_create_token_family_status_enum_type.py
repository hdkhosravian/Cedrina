"""Create token_family_status enum type

Revision ID: 826012600db0
Revises: c2c1eddc321e
Create Date: 2025-07-09 17:40:22.031882

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '826012600db0'
down_revision: Union[str, None] = 'c2c1eddc321e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the token_family_status enum type."""
    # Create enum type for token family status
    op.execute("CREATE TYPE token_family_status AS ENUM ('active', 'compromised', 'revoked', 'expired')")


def downgrade() -> None:
    """Drop the token_family_status enum type."""
    op.execute("DROP TYPE IF EXISTS token_family_status")
