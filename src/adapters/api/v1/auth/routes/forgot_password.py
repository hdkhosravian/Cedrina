"""
Password reset request endpoint for initiating password reset via email.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_password_reset_request_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import ForgotPasswordRequest, MessageResponse
from src.core.exceptions import (
    AuthenticationError,
    EmailServiceError,
    ForgotPasswordError,
    RateLimitExceededError,
)
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.interfaces import (
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.password_reset.password_reset_request_service import (
    PasswordResetRequestService,
)
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
    summary="Request password reset",
    description="Initiates a password reset request by sending a secure reset link to the user's email using clean architecture principles.",
)
@limiter.limit("3/hour")
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    password_reset_service: PasswordResetRequestService = Depends(get_password_reset_request_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
) -> MessageResponse:
    """Request password reset via email.
    
    Sends reset link to user's email if account exists.
    Always returns success to prevent email enumeration.
    Rate limited to 3 requests per hour.
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
        endpoint="forgot_password",
        operation="password_reset_request"
    )
    
    request_logger.info(
        "Password reset request initiated",
        email_masked=secure_logging_service.mask_email(payload.email),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Delegate to domain service for user lookup, token generation, and email delivery
        await password_reset_service.request_password_reset(
            email=payload.email,
            language=language,
            user_agent=user_agent,
            ip_address=client_ip,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Password reset request completed successfully",
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )

        # Always return success to prevent email enumeration
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message)

    except (ValueError, RateLimitExceededError, EmailServiceError, ForgotPasswordError, AuthenticationError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)
        
        # Log the error with security context
        request_logger.warning(
            "Password reset request failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        # Return success for email errors to prevent information leakage
        if isinstance(e, EmailServiceError):
            success_message = get_translated_message("password_reset_email_sent", language)
            return MessageResponse(message=success_message)
        
        # Re-raise for FastAPI exception handlers
        raise classified_error
        
    except Exception as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Log unexpected errors for debugging
        request_logger.error(
            "Password reset request failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        # Create standardized error response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(e),
            correlation_id=correlation_id,
            language=language
        )
        
        # Return success to prevent information leakage
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message) 