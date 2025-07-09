from __future__ import annotations

"""Utility functions for authentication API routes.

This module provides shared helper functions to ensure consistency and reduce
duplication across authentication endpoints like login, register, and OAuth.
"""

from src.adapters.api.v1.auth.schemas import TokenPair
from src.core.config.settings import settings
from src.domain.entities.user import User
from src.domain.value_objects.jwt_token import TokenId
from src.infrastructure.services.authentication.token import TokenService


async def create_token_pair(token_service: TokenService, user: User) -> TokenPair:
    """Create a pair of JWT access and refresh tokens for a user.

    This utility centralizes token creation logic to ensure consistency across
    authentication endpoints. It generates access and refresh tokens using the
    provided token service and applies configuration from settings.

    Args:
        token_service: Service for token generation.
        user: The user entity for whom tokens are created.

    Returns:
        TokenPair: Pydantic model with access token, refresh token, token type,
            and expiration time in seconds.

    Note:
        - Uses cryptographically secure TokenId generation (256-bit entropy)
        - Both access and refresh tokens use the same JTI for session validation
        - Expiration time is validated to prevent invalid values
        - Tokens are created asynchronously to align with FastAPI's async nature
    """
    # Generate cryptographically secure JTI (256-bit entropy)
    secure_jti = TokenId.generate().value
    
    # Create both tokens with the same secure JTI
    access_token = await token_service.create_access_token(user=user, jti=secure_jti)
    refresh_token = await token_service.create_refresh_token(user=user, jti=secure_jti)

    # Ensure minimum expiration time of 60 seconds
    expires_in = max(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 60)

    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=expires_in,
    )
