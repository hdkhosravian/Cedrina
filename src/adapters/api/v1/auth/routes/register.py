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
from src.core.exceptions import (
    AuthenticationError,
    DuplicateUserError,
    PasswordPolicyError,
)
from src.domain.interfaces import (
    ITokenService, 
    IUserRegistrationService,
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username
from src.utils.i18n import get_request_language, get_translated_message

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
        endpoint="register",
        operation="user_registration"
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
        language = get_request_language(request)
        
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
        
        # Generate JWT tokens for authenticated session
        if hasattr(token_service, 'create_token_pair'):
            tokens = await token_service.create_token_pair(user)
        else:
            # Fallback: create tokens individually
            access_token = await token_service.create_access_token(user)
            refresh_token = await token_service.create_refresh_token(user)
            tokens = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": 900,
            }
        
        request_logger.info(
            "Registration tokens created",
            user_id=user.id,
            token_type=tokens.get("token_type", "bearer"),
            expires_in=tokens.get("expires_in", 900),
            security_enhanced=True
        )
        
        # Return user data and tokens
        return AuthResponse(
            tokens=tokens,
            user=UserOut.from_entity(user)
        )
        
    except (ValueError, AuthenticationError, DuplicateUserError, PasswordPolicyError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)
        
        # Log the error with security context
        request_logger.warning(
            "Registration failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            username_masked=secure_logging_service.mask_username(payload.username),
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
            "Registration failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            username_masked=secure_logging_service.mask_username(payload.username),
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
