from __future__ import annotations

"""Utility functions for authentication API routes.

This module provides shared helper functions to ensure consistency and reduce
duplication across authentication endpoints like login, register, and OAuth.
"""

from src.adapters.api.v1.auth.schemas import TokenPair
from src.core.config.settings import settings
from src.domain.entities.user import User
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.services.authentication.token_lifecycle_management_service import TokenCreationRequest
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService


async def create_token_pair(token_service: DomainTokenService, user: User) -> TokenPair:
    """Create a pair of JWT access and refresh tokens for a user.

    This utility centralizes token creation logic to ensure consistency across
    authentication endpoints. It generates access and refresh tokens using the
    provided domain token service and applies configuration from settings.

    Args:
        token_service: Domain token service for token generation.
        user: The user entity for whom tokens are created.

    Returns:
        TokenPair: Pydantic model with access token, refresh token, token type,
            and expiration time in seconds.

    Note:
        - Uses the new domain token service with token family security
        - Both access and refresh tokens use the same JTI for session validation
        - Expiration time is validated to prevent invalid values
        - Tokens are created asynchronously to align with FastAPI's async nature
        - Implements advanced security patterns with token family management
    """
    # Create security context for the request
    security_context = SecurityContext.create_for_request(
        client_ip="127.0.0.1",  # Will be overridden by actual request context
        user_agent="API-Client",
        correlation_id=None
    )
    
    # Create token creation request using domain service
    request = TokenCreationRequest(
        user=user,
        security_context=security_context,
        correlation_id=None
    )
    
    # Create token pair using domain service with family security
    token_pair = await token_service.create_token_pair_with_family_security(request)

    # Ensure minimum expiration time of 60 seconds
    expires_in = max(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 60)

    return TokenPair(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        token_type="Bearer",
        expires_in=expires_in,
    )
