from __future__ import annotations

# FastAPI & typing
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# Removed Redis import - unified architecture uses database-only approach
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import AuthenticationError, PermissionError

# Project imports
from src.domain.entities.user import Role, User
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.infrastructure.database.async_db import get_async_db_dependency
# Removed Redis dependency - unified architecture eliminates Redis usage
from src.utils.i18n import get_translated_message

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
# Removed Redis client dependency - unified architecture uses database-only approach


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
    request: Request, token: TokenCred, db_session: DBSession
) -> User:
    """Return the authenticated :class:`~src.domain.entities.user.User`.

    The function performs **no** role checks; it merely authenticates the JWT and
    looks up the corresponding user-record.  Call :pyfunc:`get_current_admin_user`
    for role-enforced logic.
    """
    try:
        # Get the language from request state, fallback to 'en' if not set
        language = getattr(request.state, "language", "en")
        
        # Check if Authorization header is missing
        if token is None:
            raise _auth_fail(request, "missing_authorization_header")
        
        # Extract the JWT token from HTTPAuthorizationCredentials
        jwt_token = token.credentials
        token_service = DomainTokenService(db_session=db_session)
        payload = await token_service.validate_token(jwt_token, language)
        user_id = payload.get("sub")
        if user_id is None:
            raise _auth_fail(request, "invalid_token_subject")

        user = await db_session.get(User, int(user_id))
        if user is None or not user.is_active:
            raise _auth_fail(request, "user_not_found_or_inactive")
        return user
    except AuthenticationError as exc:
        # Here we translate the exception message itself, assuming it's a valid key
        raise _auth_fail(request, str(exc)) from exc


def get_current_admin_user(
    request: Request, current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    """Ensure the authenticated user has *ADMIN* role."""
    if current_user.role != Role.ADMIN:
        message = get_translated_message("admin_privileges_required", request.state.language)
        raise PermissionError(message)
    return current_user
