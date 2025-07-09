"""
Password reset execution endpoint for resetting password using a valid token.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_password_reset_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import MessageResponse, ResetPasswordRequest
from src.core.exceptions import (
    AuthenticationError,
    ForgotPasswordError,
    PasswordResetError,
    UserNotFoundError,
)
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.interfaces import (
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.password_reset.password_reset_service import PasswordResetService
from src.utils.i18n import get_request_language, get_translated_message

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
        endpoint="reset_password",
        operation="password_reset_execution"
    )
    
    request_logger.info(
        "Password reset execution initiated",
        token_masked=secure_logging_service.mask_token(payload.token),
        has_new_password=bool(payload.new_password),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Delegate to domain service for token validation, password update, and token invalidation
        result = await password_reset_service.reset_password(
            token=payload.token,
            new_password=payload.new_password,
            language=language,
            user_agent=user_agent,
            ip_address=client_ip,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Password reset execution completed successfully",
            token_masked=secure_logging_service.mask_token(payload.token),
            security_enhanced=True
        )

        # Return localized success message
        success_message = result.get("message", get_translated_message("password_reset_success", language))
        return MessageResponse(message=success_message)

    except (ValueError, PasswordResetError, UserNotFoundError, ForgotPasswordError, AuthenticationError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)
        
        # Log the error with security context
        request_logger.warning(
            "Password reset execution failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            token_masked=secure_logging_service.mask_token(payload.token),
            security_enhanced=True
        )
        
        # Re-raise for FastAPI exception handlers
        raise classified_error
        
    except Exception as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Log unexpected errors for debugging
        request_logger.error(
            "Password reset execution failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            token_masked=secure_logging_service.mask_token(payload.token),
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