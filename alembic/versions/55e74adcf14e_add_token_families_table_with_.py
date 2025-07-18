"""Add token_families table with encryption and user relationships

Revision ID: 55e74adcf14e
Revises: 826012600db0
Create Date: 2025-07-09 17:37:32.722984

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '55e74adcf14e'
down_revision: Union[str, None] = '826012600db0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add token_families table with encryption and user relationships."""
    # Create token_families table with encrypted storage for sensitive data
    op.create_table('token_families',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('family_id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('status', postgresql.ENUM('active', 'compromised', 'revoked', 'expired', name='token_family_status', create_type=False), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
    sa.Column('last_used_at', sa.DateTime(), nullable=True),
    sa.Column('compromised_at', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('active_tokens_encrypted', postgresql.BYTEA(), nullable=True),
    sa.Column('revoked_tokens_encrypted', postgresql.BYTEA(), nullable=True),
    sa.Column('usage_history_encrypted', postgresql.BYTEA(), nullable=True),
    sa.Column('compromise_reason', sa.Text(), nullable=True),
    sa.Column('security_score', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for optimal query performance
    op.create_index('ix_token_families_expires_at', 'token_families', ['expires_at'], unique=False)
    op.create_index(op.f('ix_token_families_family_id'), 'token_families', ['family_id'], unique=True)
    op.create_index('ix_token_families_status', 'token_families', ['status'], unique=False)
    op.create_index(op.f('ix_token_families_user_id'), 'token_families', ['user_id'], unique=False)
    op.create_index('ix_token_families_user_id_status', 'token_families', ['user_id', 'status'], unique=False)


def downgrade() -> None:
    """Remove token_families table and its indexes."""
    # Drop indexes
    op.drop_index('ix_token_families_user_id_status', table_name='token_families')
    op.drop_index(op.f('ix_token_families_user_id'), table_name='token_families')
    op.drop_index('ix_token_families_status', table_name='token_families')
    op.drop_index(op.f('ix_token_families_family_id'), table_name='token_families')
    op.drop_index('ix_token_families_expires_at', table_name='token_families')
    
    # Drop table
    op.drop_table('token_families')
