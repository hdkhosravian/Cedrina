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
from src.adapters.api.v1.auth.utils import handle_authentication_error, setup_request_context
from src.common.exceptions import (
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
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "forgot_password", "password_reset_request"
    )
    
    request_logger.info(
        "Password reset request initiated",
        email_masked=secure_logging_service.mask_email(payload.email),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = extract_language_from_request(request)
        
        # Delegate to domain service for password reset request
        await password_reset_service.request_password_reset(
            email=payload.email,
            language=language,
            ip_address=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "Password reset request processed successfully",
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        # Return localized success message
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message)
        
    except EmailServiceError as e:
        # Log email service error for monitoring but return success to prevent enumeration
        request_logger.warning(
            "Email service error during password reset request",
            error_message=str(e),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        # Return success message to prevent email enumeration attacks
        language = extract_language_from_request(request)
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message)
        
    except (RateLimitExceededError, ForgotPasswordError) as e:
        # Known domain errors should be handled by the error handler
        context_info = {
            "email_masked": secure_logging_service.mask_email(payload.email)
        }
        raise await handle_authentication_error(
            error=e,
            request_logger=request_logger,
            error_classification_service=error_classification_service,
            request=request,
            correlation_id=correlation_id,
            context_info=context_info
        )
    except Exception as e:
        # Log unexpected errors and return generic success to prevent information leakage
        request_logger.error(
            "Unexpected error during password reset request",
            error_message=str(e),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        language = extract_language_from_request(request)
        success_message = get_translated_message("password_reset_email_sent", language)
        return MessageResponse(message=success_message) 