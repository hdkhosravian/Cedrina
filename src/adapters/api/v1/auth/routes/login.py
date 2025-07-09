"""
User authentication endpoint for logging in with username and password.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_user_authentication_service,
    get_token_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import AuthResponse, LoginRequest, UserOut
from src.core.exceptions import AuthenticationError
from src.domain.interfaces import (
    ITokenService, 
    IUserAuthenticationService,
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.password import LoginPassword
from src.domain.value_objects.username import Username
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate a user",
    description="Authenticates a user with username and password using clean architecture principles.",
)
async def login_user(
    request: Request,
    payload: LoginRequest,
    auth_service: IUserAuthenticationService = Depends(get_user_authentication_service),
    token_service: ITokenService = Depends(get_token_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
):
    """Authenticate user with username and password.
    
    Validates credentials, creates session, and returns JWT tokens.
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
        endpoint="login",
        operation="user_authentication"
    )
    
    request_logger.info(
        "Authentication attempt initiated",
        username_masked=secure_logging_service.mask_username(payload.username),
        has_password=bool(payload.password),
        security_enhanced=True
    )
    
    try:
        # Validate and create domain value objects
        username = Username(payload.username)
        password = LoginPassword(payload.password)
        
        # Extract language from request for I18N
        language = get_request_language(request)
        
        request_logger.debug(
            "Domain value objects created",
            username_masked=secure_logging_service.mask_username(str(username)),
            security_enhanced=True
        )
        
        # Delegate authentication to domain service
        user = await auth_service.authenticate_user(
            username=username,
            password=password,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "User authenticated successfully",
            user_id=user.id,
            username_masked=secure_logging_service.mask_username(user.username),
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
            "Authentication tokens created",
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
        
    except (ValueError, AuthenticationError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)
        
        # Log the error with security context
        request_logger.warning(
            "Authentication failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            username_masked=secure_logging_service.mask_username(payload.username),
            security_enhanced=True
        )
        
        # Re-raise for FastAPI exception handlers
        raise classified_error
        
    except Exception as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Log unexpected errors for debugging
        request_logger.error(
            "Authentication failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            username_masked=secure_logging_service.mask_username(payload.username),
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
