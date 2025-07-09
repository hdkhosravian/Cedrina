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
from src.core.exceptions import AuthenticationError, UserNotFoundError
from src.domain.interfaces import (
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.services.email_confirmation.email_confirmation_service import (
    EmailConfirmationService,
)
from src.utils.i18n import get_request_language, get_translated_message

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
        endpoint="confirm_email",
        operation="email_confirmation"
    )
    
    request_logger.info(
        "Email confirmation initiated",
        token_masked=secure_logging_service.mask_token(token),
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = get_request_language(request)
        
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

    except (ValueError, UserNotFoundError, AuthenticationError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)
        
        # Log the error with security context
        request_logger.warning(
            "Email confirmation failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            token_masked=secure_logging_service.mask_token(token),
            security_enhanced=True
        )
        
        # Re-raise for FastAPI exception handlers
        raise classified_error
        
    except Exception as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Log unexpected errors for debugging
        request_logger.error(
            "Email confirmation failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            token_masked=secure_logging_service.mask_token(token),
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
