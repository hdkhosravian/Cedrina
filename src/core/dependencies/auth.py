"""Authentication and authorization dependencies for FastAPI.

This module provides dependency injection functions for authentication and
authorization services, following clean architecture principles.
"""

from __future__ import annotations

from typing import Annotated, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config.settings import settings
from src.common.exceptions import AuthenticationError, PermissionError
from src.domain.entities.role import Role
from src.domain.entities.user import User
# Removed ITokenService import to fix circular dependency - using local import instead
from src.infrastructure.database.async_db import get_async_db_dependency
from src.infrastructure.dependency_injection.auth_dependencies import get_token_service
from src.common.i18n import get_translated_message

__all__ = [
    "get_current_user",
    "get_current_admin_user",
]


# ---------------------------------------------------------------------------
# Type-annotated dependency shortcuts
# ---------------------------------------------------------------------------


# Configure HTTPBearer with auto_error=False to handle missing tokens manually
# This allows us to return 401 instead of 403 for missing Authorization headers
TokenCred = Annotated[Optional[HTTPAuthorizationCredentials], Depends(HTTPBearer(auto_error=False))]
DBSession = Annotated[AsyncSession, Depends(get_async_db_dependency)]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _auth_fail(request: Request, key: str) -> HTTPException:
    """Consistently shaped *401* UNAUTHORIZED response."""
    detail = get_translated_message(key, request.state.language)
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------------
# Public dependencies
# ---------------------------------------------------------------------------


async def get_current_user(
    request: Request,
    credentials: TokenCred = None,
    db_session: AsyncSession = Depends(get_async_db_dependency),
) -> User:
    """Get the current authenticated user from JWT token.

    This dependency validates the JWT token from the Authorization header and
    returns the corresponding user. It handles various error cases gracefully
    and provides consistent error responses.

    Args:
        request: FastAPI request object for language detection
        credentials: HTTP authorization credentials from dependency
        db_session: Database session for user lookup

    Returns:
        User: The authenticated user

    Raises:
        HTTPException: 401 Unauthorized if token is invalid, missing, or user not found

    Note:
        This dependency follows security best practices:
        - Validates JWT signature and claims
        - Checks token expiration
        - Verifies user exists and is active
        - Provides consistent error responses
        - Supports internationalization
    """
    if not credentials:
        raise _auth_fail(request, "missing_authorization_header")

    token = credentials.credentials
    if not token:
        raise _auth_fail(request, "missing_authorization_header")

    try:
        # Use the new domain token service for validation
        if db_session is None:
            raise _auth_fail(request, "database_session_unavailable")
            
        # Import here to avoid circular import
        from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
        
        token_service = DomainTokenService(db_session=db_session)
        payload = await token_service.validate_access_token(token, request.state.language)
        
        user_id = int(payload["sub"])
        user = await db_session.get(User, user_id)
        
        if not user or not user.is_active:
            raise _auth_fail(request, "user_is_invalid_or_inactive")
        
        return user
        
    except AuthenticationError as e:
        raise _auth_fail(request, str(e))
    except Exception as e:
        # Log unexpected errors but don't expose details
        raise _auth_fail(request, "invalid_token")


async def get_current_admin_user(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Get the current authenticated user, ensuring they have admin role.

    This dependency extends get_current_user to require admin privileges.
    It validates that the authenticated user has the admin role.

    Args:
        current_user: The authenticated user from get_current_user
        request: FastAPI request object for language detection

    Returns:
        User: The authenticated admin user

    Raises:
        HTTPException: 403 Forbidden if user is not an admin

    Note:
        This dependency enforces role-based access control:
        - Requires valid authentication first
        - Checks for admin role specifically
        - Provides clear error messages
        - Supports internationalization
    """
    if current_user.role != Role.ADMIN:
        detail = get_translated_message("admin_privileges_required", request.state.language if request else "en")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )
    
    return current_user
