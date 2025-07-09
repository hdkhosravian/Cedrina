from __future__ import annotations

"""
User logout endpoint for revoking access and refresh tokens.
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
from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_user, TokenCred
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.interfaces import (
    IUserLogoutService,
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.delete(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Logout current user",
    description="Logout user by revoking access and refresh tokens using clean architecture principles.",
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
    # Generate correlation ID for request tracking
    correlation_id = str(uuid.uuid4())
    
    # Extract security context
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Create structured logger with correlation context and security information
    request_logger = logger.bind(
        correlation_id=correlation_id,
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="logout",
        operation="user_logout"
    )
    
    request_logger.info(
        "Logout attempt initiated",
        user_id=current_user.id,
        username_masked=secure_logging_service.mask_username(current_user.username),
        security_enhanced=True
    )
    
    try:
        # Token should never be None here since get_current_user dependency would have failed
        if token is None:
            raise AuthenticationError("Authorization header is missing")
            
        # Token is already validated by get_current_user dependency, use it directly
        # Validate and decode JWT access token
        access_token = AccessToken.from_encoded(
            token=token.credentials,
            public_key=settings.JWT_PUBLIC_KEY,
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
        
        # Extract language from request for I18N
        language = get_request_language(request)
        
        request_logger.debug(
            "Domain value objects created",
            user_id=current_user.id,
            access_token_id=access_token.get_token_id().mask_for_logging(),
            security_enhanced=True
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
            "User logged out successfully",
            user_id=current_user.id,
            username_masked=secure_logging_service.mask_username(current_user.username),
            security_enhanced=True
        )

        # Return localized success message
        return MessageResponse(message=get_translated_message("logout_successful", language))

    except (ValueError, AuthenticationError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)

        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)

        # Log the error with security context
        request_logger.warning(
            "Logout failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            user_id=current_user.id,
            username_masked=secure_logging_service.mask_username(current_user.username),
            security_enhanced=True
        )

        # Re-raise for FastAPI exception handlers
        raise classified_error
        
    except Exception as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Log unexpected errors for debugging
        request_logger.error(
            "Logout failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            user_id=current_user.id,
            username_masked=secure_logging_service.mask_username(current_user.username),
            security_enhanced=True
        )
        
        # Create standardized error response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        raise AuthenticationError(message=standardized_response["detail"])
