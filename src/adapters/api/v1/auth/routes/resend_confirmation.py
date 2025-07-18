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
from src.adapters.api.v1.auth.utils import handle_authentication_error, setup_request_context
from src.common.exceptions import AuthenticationError, UserNotFoundError
from src.domain.interfaces import (
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.email_confirmation.email_confirmation_request_service import (
    EmailConfirmationRequestService,
)
from src.domain.value_objects.email import Email
from src.common.i18n import get_translated_message, extract_language_from_request

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
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "resend_confirmation", "email_confirmation_resend"
    )
    
    request_logger.info(
        "Email confirmation resend initiated",
        email_masked=secure_logging_service.mask_email(payload.email),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = extract_language_from_request(request)
        
        # Validate email using domain value object
        email = Email(payload.email)
        
        # Delegate to domain service for confirmation email resend
        await confirmation_request_service.resend_confirmation_email(
            email=email.value,
            language=language,
        )
        
        request_logger.info(
            "Email confirmation resend completed successfully",
            email_masked=secure_logging_service.mask_email(payload.email),
            security_enhanced=True
        )
        
        # Return localized success message
        success_message = get_translated_message("confirmation_email_resent", language)
        return MessageResponse(message=success_message)
        
    except Exception as e:
        # Handle authentication errors consistently
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
