"""
OAuth authentication endpoint for external provider authentication.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid
from typing import Any, Dict

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_unified_authentication_service,
    get_token_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import OAuthAuthResponse, OAuthAuthenticateRequest, UserOut
from src.adapters.api.v1.auth.utils import (
    create_token_pair, 
    handle_authentication_error, 
    setup_request_context
)
from src.domain.interfaces import (
    ITokenService,
    IErrorClassificationService
)
from src.domain.security.logging_service import secure_logging_service
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.common.i18n import get_translated_message, extract_language_from_request

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
    unified_auth_service = Depends(get_unified_authentication_service),
    token_service: ITokenService = Depends(get_token_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
):
    """Authenticate user with OAuth provider token.
    
    Validates OAuth token, creates/links user account, and returns JWT tokens.
    Supports Google, Microsoft, and Facebook providers.
    """
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "oauth", "oauth_authentication"
    )
    
    # Extract language from request for I18N
    language = extract_language_from_request(request)
    
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
        
        # Delegate OAuth authentication to unified authentication service
        user, oauth_profile = await unified_auth_service.authenticate_with_oauth(
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

        # Generate JWT tokens for authenticated session using utility function
        tokens = await create_token_pair(token_service, user)
        
        request_logger.info(
            "OAuth authentication tokens created",
            user_id=user.id,
            token_type=tokens.token_type,
            expires_in=tokens.expires_in,
            security_enhanced=True
        )
        
        # Return user data and tokens
        return OAuthAuthResponse(
            user=UserOut.from_entity(user),
            provider=payload.provider,
            oauth_profile_id=oauth_profile.id if oauth_profile else None,
            tokens=tokens.dict(),
        )
        
    except Exception as e:
        # Handle authentication errors consistently
        context_info = {
            "provider": payload.provider
        }
        raise await handle_authentication_error(
            error=e,
            request_logger=request_logger,
            error_classification_service=error_classification_service,
            request=request,
            correlation_id=correlation_id,
            context_info=context_info
        )
