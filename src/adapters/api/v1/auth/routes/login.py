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
from src.adapters.api.v1.auth.utils import (
    create_token_pair, 
    handle_authentication_error, 
    setup_request_context,

)
from src.domain.interfaces import (
    ITokenService, 
    IUserAuthenticationService,
    IErrorClassificationService
)
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.password import LoginPassword
from src.domain.value_objects.username import Username
from src.common.i18n import get_request_language, extract_language_from_request

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
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "login", "user_authentication"
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
        language = extract_language_from_request(request)
        
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

        # Generate JWT tokens for authenticated session using utility function
        tokens = await create_token_pair(token_service, user)
        
        request_logger.info(
            "Authentication tokens created",
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
            "username_masked": secure_logging_service.mask_username(payload.username)
        }
        raise await handle_authentication_error(
            error=e,
            request_logger=request_logger,
            error_classification_service=error_classification_service,
            request=request,
            correlation_id=correlation_id,
            context_info=context_info
        )
