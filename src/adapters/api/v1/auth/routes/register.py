"""
User registration endpoint for creating new accounts with username, email, and password.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

from __future__ import annotations

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_user_registration_service,
    get_token_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import AuthResponse, RegisterRequest, UserOut
from src.adapters.api.v1.auth.utils import (
    create_token_pair, 
    handle_authentication_error, 
    setup_request_context
)
from src.domain.interfaces import (
    ITokenService, 
    IUserRegistrationService,
    IErrorClassificationService
)
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username
from src.common.i18n import get_translated_message, extract_language_from_request

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    summary="Register a new user",
    description="Creates a new user account with username, email, and password using clean architecture principles.",
)
async def register_user(
    request: Request,
    payload: RegisterRequest,
    registration_service: IUserRegistrationService = Depends(get_user_registration_service),
    token_service: ITokenService = Depends(get_token_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
):
    """Register a new user with username, email, and password.
    
    Creates user account, sends confirmation email, and returns JWT tokens.
    Implements comprehensive security logging and error handling.
    """
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "register", "user_registration"
    )
    
    request_logger.info(
        "Registration attempt initiated",
        username_masked=secure_logging_service.mask_username(payload.username),
        email_masked=secure_logging_service.mask_email(payload.email),
        has_password=bool(payload.password),
        security_enhanced=True
    )
    
    try:
        # Validate and create domain value objects
        username = Username.create_safe(payload.username)
        email = Email(payload.email)  # Auto-normalizes to lowercase
        password = Password(payload.password)
        
        # Extract language from request for I18N
        language = extract_language_from_request(request)
        
        request_logger.debug(
            "Domain value objects created",
            username_masked=secure_logging_service.mask_username(str(username)),
            email_masked=secure_logging_service.mask_email(str(email)),
            security_enhanced=True
        )
        
        # Delegate registration to domain service
        user = await registration_service.register_user(
            username=username,
            email=email,
            password=password,
            language=language,
            ip_address=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "User registered successfully",
            user_id=user.id,
            username_masked=secure_logging_service.mask_username(user.username),
            email_masked=secure_logging_service.mask_email(user.email),
            security_enhanced=True
        )
        
        # Generate JWT tokens for authenticated session using utility function
        tokens = await create_token_pair(token_service, user, correlation_id)
        
        request_logger.info(
            "Registration tokens created",
            user_id=user.id,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            security_enhanced=True
        )
        
        # Return user data and tokens
        return AuthResponse(
            tokens=tokens.dict(),
            user=UserOut.from_entity(user)
        )
        
    except Exception as e:
        # Handle authentication errors consistently
        context_info = {
            "username_masked": secure_logging_service.mask_username(payload.username),
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
