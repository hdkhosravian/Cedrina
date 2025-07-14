from __future__ import annotations

"""
User logout endpoint for revoking authentication tokens.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

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
    description="Logs out the current user and revokes their authentication tokens using clean architecture principles.",
)
async def logout_user(
    request: Request,
    token: TokenCred,
    current_user: User = Depends(get_current_user),
    logout_service: IUserLogoutService = Depends(get_user_logout_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
) -> MessageResponse:
    """Logout current user and revoke session tokens.
    
    Invalidates access token and terminates user session.
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
        
        # Create access token value object from credentials
        from src.domain.value_objects.jwt_token import AccessToken
        
        access_token = AccessToken.from_encoded(
            token=token.credentials,
            public_key=settings.JWT_PUBLIC_KEY,
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE
        )
        
        # Delegate logout to domain service
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