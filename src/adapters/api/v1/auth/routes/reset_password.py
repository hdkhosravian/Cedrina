"""
Password reset execution endpoint for completing password reset with token.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_password_reset_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import ResetPasswordRequest, MessageResponse
from src.adapters.api.v1.auth.utils import handle_authentication_error, setup_request_context
from src.common.exceptions import (
    AuthenticationError,
    PasswordResetError,
    RateLimitExceededError,
)
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.interfaces import (
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.password_reset.password_reset_service import (
    PasswordResetService,
)
from src.common.i18n import get_request_language, get_translated_message
from src.common.i18n import extract_language_from_request

logger = structlog.get_logger(__name__)
router = APIRouter()

# Use centralized rate limiter for consistency
limiter = get_limiter()


@router.post(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Reset password with token",
    description="Executes a password reset using a valid token received via email using clean architecture principles.",
)
@limiter.limit("5/hour")
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    password_reset_service: PasswordResetService = Depends(get_password_reset_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
) -> MessageResponse:
    """Reset password using a valid reset token.
    
    Validates token, updates password, and invalidates token.
    Rate limited to 5 requests per hour.
    """
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "reset_password", "password_reset_execution"
    )
    
    request_logger.info(
        "Password reset execution initiated",
        token_masked=secure_logging_service.mask_token(payload.token),
        has_new_password=bool(payload.new_password),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = extract_language_from_request(request)
        
        # Delegate to domain service for password reset execution
        await password_reset_service.reset_password(
            token=payload.token,
            new_password=payload.new_password,
            language=language,
            ip_address=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Password reset completed successfully",
            token_masked=secure_logging_service.mask_token(payload.token),
            security_enhanced=True
        )
        
        # Return localized success message
        success_message = get_translated_message("password_reset_successful", language)
        return MessageResponse(message=success_message)
        
    except Exception as e:
        # Handle authentication errors consistently
        context_info = {
            "token_masked": secure_logging_service.mask_token(payload.token),
            "has_new_password": bool(payload.new_password)
        }
        raise await handle_authentication_error(
            error=e,
            request_logger=request_logger,
            error_classification_service=error_classification_service,
            request=request,
            correlation_id=correlation_id,
            context_info=context_info
        ) 