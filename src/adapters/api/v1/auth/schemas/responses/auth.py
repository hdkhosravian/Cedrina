from __future__ import annotations

"""Composite response Pydantic models for authentication endpoints."""

from typing import Optional

from pydantic import BaseModel

from src.adapters.api.v1.auth.schemas.responses.token import TokenPair
from src.adapters.api.v1.auth.schemas.responses.user import UserOut


class AuthResponse(BaseModel):
    """Response returned by register & login endpoints."""

    user: UserOut
    tokens: Optional[TokenPair] = None


class OAuthAuthResponse(BaseModel):
    """Response returned by OAuth endpoint."""

    user: UserOut
    provider: str
    oauth_profile_id: Optional[int] = None
    tokens: TokenPair
