"""
Email confirmation endpoint for activating user accounts via confirmation token.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Query, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_email_confirmation_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import MessageResponse
from src.adapters.api.v1.auth.utils import handle_authentication_error, setup_request_context
from src.common.exceptions import AuthenticationError, UserNotFoundError
from src.domain.interfaces import (
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.email_confirmation.email_confirmation_service import (
    EmailConfirmationService,
)
from src.common.i18n import get_translated_message, extract_language_from_request

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get(
    "",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Confirm email address",
    description="Validates the confirmation token and activates the user's account using clean architecture principles.",
)
async def confirm_email(
    request: Request,
    token: str = Query(...),
    confirmation_service: EmailConfirmationService = Depends(get_email_confirmation_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
) -> MessageResponse:
    """Confirm email address using confirmation token.
    
    Validates token, activates user account, and marks email as confirmed.
    Token can only be used once.
    """
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "confirm_email", "email_confirmation"
    )
    
    request_logger.info(
        "Email confirmation initiated",
        token_masked=secure_logging_service.mask_token(token),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = extract_language_from_request(request)
        
        # Delegate to domain service for token validation, account activation, and token invalidation
        user = await confirmation_service.confirm_email(token, language)
        
        request_logger.info(
            "Email confirmation completed successfully",
            user_id=user.id,
            username_masked=secure_logging_service.mask_username(user.username),
            email_masked=secure_logging_service.mask_email(user.email),
            security_enhanced=True
        )

        # Return localized success message
        success_message = get_translated_message("email_confirmed_success", language)
        return MessageResponse(message=success_message)

    except Exception as e:
        # Handle authentication errors consistently
        context_info = {
            "token_masked": secure_logging_service.mask_token(token)
        }
        raise await handle_authentication_error(
            error=e,
            request_logger=request_logger,
            error_classification_service=error_classification_service,
            request=request,
            correlation_id=correlation_id,
            context_info=context_info
        )
