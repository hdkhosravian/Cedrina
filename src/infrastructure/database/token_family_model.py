from typing import Optional, List
from datetime import datetime
from sqlmodel import SQLModel, Field, Column, JSON, String
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy import LargeBinary

class TokenFamilyModel(SQLModel, table=True):
    __tablename__ = "token_families"

    id: Optional[int] = Field(default=None, primary_key=True)
    family_id: str = Field(sa_column=Column(String(36), unique=True, nullable=False))
    user_id: int = Field(nullable=False, index=True)
    status: str = Field(sa_column=Column(ENUM('active', 'compromised', 'revoked', 'expired', name='token_family_status', create_type=False), nullable=False, index=True))
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    last_used_at: Optional[datetime] = Field(default=None)
    compromised_at: Optional[datetime] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None)
    compromise_reason: Optional[str] = Field(default=None)
    security_score: float = Field(default=1.0, nullable=False)
    # Encrypted fields (store as binary data)
    active_tokens_encrypted: Optional[bytes] = Field(default=None, sa_column=Column("active_tokens_encrypted", LargeBinary, nullable=True))
    revoked_tokens_encrypted: Optional[bytes] = Field(default=None, sa_column=Column("revoked_tokens_encrypted", LargeBinary, nullable=True))
    usage_history_encrypted: Optional[bytes] = Field(default=None, sa_column=Column("usage_history_encrypted", LargeBinary, nullable=True)) 