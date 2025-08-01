from __future__ import annotations

"""
User logout endpoint for revoking authentication tokens.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status, Header

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_user_logout_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import MessageResponse
from src.adapters.api.v1.auth.utils import handle_authentication_error, setup_request_context
from src.common.exceptions import AuthenticationError
from src.domain.interfaces import IUserLogoutService, IErrorClassificationService
from src.domain.security.logging_service import secure_logging_service
from src.common.i18n import get_translated_message, extract_language_from_request
from src.core.dependencies.auth import get_current_user, TokenCred
from src.domain.entities.user import User
from src.core.config.settings import settings

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Logout user",
    description=(
        "Logs out the current user and revokes both access and refresh tokens.\\n\\n"
        "**REQUIRED HEADERS:**\\n"
        "- `Authorization: Bearer <access_token>` - Your current access token\\n\\n"
        "**SECURITY**: This endpoint automatically finds and revokes both the access token "
        "and its associated refresh token for complete logout. This ensures both tokens "
        "are revoked and cannot be reused, preventing security vulnerabilities.\\n\\n"
        "**Example Headers:**\\n"
        "```\\n"
        "Authorization: Bearer eyJhbGciOiJSUzI1NiIs...\\n"
        "```"
    ),
)
async def logout_user(
    request: Request,
    current_user: User = Depends(get_current_user),
    logout_service: IUserLogoutService = Depends(get_user_logout_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
) -> MessageResponse:
    """Logout current user and revoke both access and refresh tokens.
    
    Invalidates both access and refresh tokens for complete session termination.
    Implements comprehensive security logging and error handling.
    """
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "logout", "user_logout"
    )
    
    request_logger.info(
        "Logout attempt initiated",
        user_id=current_user.id,
        username_masked=secure_logging_service.mask_username(current_user.username),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = extract_language_from_request(request)
        
        # Extract access token from Authorization header
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthenticationError(get_translated_message("missing_authorization_header", language))
        
        access_token_string = authorization.split(" ", 1)[1]
        
        # Create access token value object from credentials
        from src.domain.value_objects.jwt_token import AccessToken
        
        access_token = AccessToken.from_encoded(
            token=access_token_string,
            public_key=settings.JWT_PUBLIC_KEY,
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE
        )
        
        # Delegate logout to domain service - it will find and revoke both tokens
        await logout_service.logout_user(
            access_token=access_token,
            user=current_user,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Logout completed successfully",
            user_id=current_user.id,
            username_masked=secure_logging_service.mask_username(current_user.username),
            security_enhanced=True
        )
        
        # Return localized success message
        success_message = get_translated_message("logout_successful", language)
        return MessageResponse(message=success_message)
        
    except Exception as e:
        # Handle authentication errors consistently
        context_info = {
            "user_id": current_user.id,
            "username_masked": secure_logging_service.mask_username(current_user.username)
        }
        raise await handle_authentication_error(
            error=e,
            request_logger=request_logger,
            error_classification_service=error_classification_service,
            request=request,
            correlation_id=correlation_id,
            context_info=context_info
        ) 