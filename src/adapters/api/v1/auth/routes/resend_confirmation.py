"""
Resend confirmation email endpoint for users requiring account activation.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_email_confirmation_request_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas.requests import ResendConfirmationRequest
from src.adapters.api.v1.auth.schemas import MessageResponse
from src.core.exceptions import AuthenticationError, UserNotFoundError
from src.domain.interfaces import (
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.email_confirmation.email_confirmation_request_service import (
    EmailConfirmationRequestService,
)
from src.domain.value_objects.email import Email
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Resend confirmation email",
    description="Resends a confirmation email to the provided address if the user account requires confirmation using clean architecture principles.",
)
async def resend_confirmation(
    request: Request,
    payload: ResendConfirmationRequest,
    confirmation_request_service: EmailConfirmationRequestService = Depends(get_email_confirmation_request_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
) -> MessageResponse:
    """Resend confirmation email to user's email address.
    
    Sends new confirmation email if user account requires activation.
    Only works for inactive accounts.
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
        endpoint="resend_confirmation",
        operation="email_confirmation_resend"
    )
    
    request_logger.info(
        "Email confirmation resend initiated",
        email_masked=secure_logging_service.mask_email(payload.email),
        security_enhanced=True
    )
    
    try:
        # Validate and create email value object
        email = Email(payload.email)  # Auto-normalizes to lowercase
        
        # Extract language from request for I18N
        language = get_request_language(request)
        
        request_logger.debug(
            "Domain value objects created",
            email_masked=secure_logging_service.mask_email(str(email)),
            security_enhanced=True
        )
        
        # Delegate to domain service for user lookup, token generation, and email delivery
        await confirmation_request_service.resend_confirmation_email(str(email), language)
        
        request_logger.info(
            "Email confirmation resend completed successfully",
            email_masked=secure_logging_service.mask_email(str(email)),
            security_enhanced=True
        )

        # Return localized success message
        success_message = get_translated_message("confirmation_email_sent", language)
        return MessageResponse(message=success_message)

    except (ValueError, UserNotFoundError, AuthenticationError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)
        
        # Log the error with security context
        request_logger.warning(
            "Email confirmation resend failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        # Re-raise for FastAPI exception handlers
        raise classified_error
        
    except Exception as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Log unexpected errors for debugging
        request_logger.error(
            "Email confirmation resend failed - unexpected error",
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
        raise AuthenticationError(message=standardized_response["detail"])
