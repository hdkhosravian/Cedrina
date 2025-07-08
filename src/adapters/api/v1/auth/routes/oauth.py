"""
OAuth authentication endpoint for external provider authentication.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid
from typing import Any, Dict

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_oauth_service,
    get_token_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import OAuthAuthResponse, OAuthAuthenticateRequest, UserOut
from src.core.exceptions import AuthenticationError
from src.domain.interfaces import (
    IOAuthService, 
    ITokenService,
    IErrorClassificationService
)
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.utils.i18n import get_request_language, get_translated_message

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=OAuthAuthResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Authenticate with OAuth provider",
    description=(
        "Authenticates a user using an OAuth token from a provider (Google, Microsoft, Facebook) "
        "using Domain-Driven Design principles. This endpoint follows clean architecture with "
        "no business logic in the API layer. All OAuth logic is handled by domain services "
        "with proper value objects, domain events, and security context capture."
    ),
)
async def oauth_authenticate(
    request: Request,
    payload: OAuthAuthenticateRequest,
    oauth_service: IOAuthService = Depends(get_oauth_service),
    token_service: ITokenService = Depends(get_token_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
):
    """Authenticate user with OAuth provider token.
    
    Validates OAuth token, creates/links user account, and returns JWT tokens.
    Supports Google, Microsoft, and Facebook providers.
    """
    # Generate correlation ID for request tracking
    correlation_id = str(uuid.uuid4())
    
    # Extract security context
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Extract language from request for I18N
    language = get_request_language(request)
    
    # Create structured logger with correlation context and security information
    request_logger = logger.bind(
        correlation_id=correlation_id,
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint="oauth",
        operation="oauth_authentication"
    )
    
    request_logger.info(
        "OAuth authentication attempt initiated",
        provider=payload.provider,
        has_token=bool(payload.token),
        security_enhanced=True
    )
    
    try:
        # Validate and create domain value objects
        provider = OAuthProvider.create_safe(payload.provider)
        token = OAuthToken.create_safe(payload.token)
        
        request_logger.debug(
            "Domain value objects created",
            provider=provider.mask_for_logging(),
            token_info=token.mask_for_logging(),
            security_enhanced=True
        )
        
        # Delegate OAuth authentication to domain service
        user, oauth_profile = await oauth_service.authenticate_with_oauth(
            provider=provider,
            token=token,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
        )
        
        request_logger.info(
            "User authenticated successfully via OAuth",
            user_id=user.id,
            provider=provider.mask_for_logging(),
            security_enhanced=True
        )

        # Generate JWT tokens for authenticated session
        tokens = await token_service.create_token_pair(user)
        
        request_logger.info(
            "OAuth authentication tokens created",
            user_id=user.id,
            token_type=tokens.get("token_type", "bearer"),
            expires_in=tokens.get("expires_in", 900),
            security_enhanced=True
        )
        
        # Return user data and tokens
        return OAuthAuthResponse(
            user=UserOut.from_entity(user),
            provider=payload.provider,
            oauth_profile_id=oauth_profile.id if oauth_profile else None,
            tokens=tokens,
        )
        
    except (ValueError, AuthenticationError) as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Classify error for consistent response format
        classified_error = error_classification_service.classify_error(e)
        
        # Log the error with security context
        request_logger.warning(
            "OAuth authentication failed",
            error_type=type(classified_error).__name__,
            error_message=str(classified_error),
            provider=payload.provider,
            security_enhanced=True
        )
        
        # Re-raise for FastAPI exception handlers
        raise classified_error
        
    except Exception as e:
        # Extract language from request for I18N
        language = get_request_language(request)
        
        # Log unexpected errors for debugging
        request_logger.error(
            "OAuth authentication failed - unexpected error",
            error=str(e),
            error_type=type(e).__name__,
            provider=payload.provider,
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
