"""update jti column to varchar for enhanced tokens

Revision ID: c2c1eddc321e
Revises: 13d2b725085f
Create Date: 2025-07-07 16:49:20.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c2c1eddc321e'
down_revision: Union[str, None] = '13d2b725085f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to support enhanced 43-character base64url JTI tokens.
    
    This migration changes the jti column from UUID to VARCHAR(43) to support
    the new TokenId.generate() format which produces 256-bit entropy tokens
    in base64url format (43 characters).
    """
    # Change jti column from UUID to VARCHAR(43)
    op.alter_column('sessions', 'jti',
                    existing_type=sa.UUID(as_uuid=False),
                    type_=sa.String(length=43),
                    existing_nullable=False)


def downgrade() -> None:
    """Downgrade schema back to UUID format.
    
    Note: This downgrade will fail if there are existing sessions with
    43-character JTIs, as they cannot be converted back to UUID format.
    """
    # Change jti column back to UUID
    op.alter_column('sessions', 'jti',
                    existing_type=sa.String(length=43),
                    type_=sa.UUID(as_uuid=False),
                    existing_nullable=False)
