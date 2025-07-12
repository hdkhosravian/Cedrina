"""
Token refresh endpoint for securely refreshing JWT tokens.
Implements clean architecture, DDD, SOLID, and advanced error handling patterns.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_token_service,
    get_error_classification_service,
)
from src.adapters.api.v1.auth.schemas import RefreshTokenRequest, TokenPair
from src.adapters.api.v1.auth.utils import handle_authentication_error, setup_request_context
from src.domain.interfaces import ITokenService, IErrorClassificationService
from src.domain.security.logging_service import secure_logging_service
from src.common.exceptions import AuthenticationError, RateLimitExceededError
from src.core.rate_limiting.ratelimiter import get_limiter, get_remote_address
from src.domain.security.error_standardization import error_standardization_service
from src.common.i18n import get_translated_message, extract_language_from_request

logger = structlog.get_logger(__name__)
router = APIRouter()

# Configure rate limiting specifically for refresh endpoint
limiter = get_limiter()


@router.post(
    "",
    response_model=TokenPair,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Refresh JWT token pair",
    description=(
        "Securely refresh JWT tokens with advanced security validation. "
        "Both access and refresh tokens must be provided and belong to the same session. "
        "If tokens don't match, both are immediately revoked for security. "
        "Rate limited to prevent abuse and brute force attacks."
    ),
    responses={
        200: {
            "description": "Tokens refreshed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJSUzI1NiIs...",
                        "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
                        "token_type": "bearer",
                        "expires_in": 900
                    }
                }
            }
        },
        401: {
            "description": "Token validation failed or security violation detected",
            "content": {
                "application/json": {
                    "examples": {
                        "jti_mismatch": {
                            "summary": "JTI mismatch security violation",
                            "value": {"detail": "Token pair security violation detected"}
                        },
                        "expired_token": {
                            "summary": "Expired refresh token",
                            "value": {"detail": "Refresh token has expired"}
                        },
                        "cross_user_attack": {
                            "summary": "Cross-user token attack",
                            "value": {"detail": "Security violation: token ownership mismatch"}
                        }
                    }
                }
            }
        },
        422: {
            "description": "Invalid request format or malformed tokens",
            "content": {
                "application/json": {
                    "example": {
                        "detail": [
                            {
                                "loc": ["body", "access_token"],
                                "msg": "Invalid JWT format: must have exactly 3 parts separated by dots",
                                "type": "value_error"
                            }
                        ]
                    }
                }
            }
        },
        429: {
            "description": "Rate limit exceeded",
            "content": {
                "application/json": {
                    "example": {"detail": "Rate limit exceeded. Please try again later."}
                }
            }
        }
    }
)
@limiter.limit("10/minute", key_func=lambda request: get_remote_address(request))  # Rate limiting
async def refresh_tokens(
    request: Request,
    payload: RefreshTokenRequest,
    token_service: ITokenService = Depends(get_token_service),
    error_classification_service: IErrorClassificationService = Depends(get_error_classification_service),
) -> TokenPair:
    """
    Refresh JWT token pair with advanced security validation.
    
    This endpoint implements the core security requirement that both access and refresh
    tokens must belong to the same session (same JTI). If validation fails, both tokens
    are immediately revoked to prevent security exploitation.
    
    Security Process:
    1. Validate request format and basic token structure
    2. Enhanced token pairing validation (JTI matching)
    3. Cross-user attack prevention
    4. Session consistency validation
    5. Token rotation with new JTI
    6. Comprehensive security logging
    
    Rate Limiting:
    - 10 requests per minute per IP address
    - Protects against brute force and token stuffing attacks
    - Escalated monitoring for suspicious activity
    
    Args:
        request: FastAPI request object for security context
        payload: RefreshTokenRequest with access and refresh tokens
        token_service: Token creation and management service  
        error_classification_service: Error classification and response service
        
    Returns:
        TokenPair: New access and refresh tokens with metadata
        
    Raises:
        AuthenticationError: If validation fails or security violation detected
        RateLimitExceededError: If rate limit is exceeded
    """
    # Set up request context using centralized utility
    request_logger, correlation_id, client_ip, user_agent = setup_request_context(
        request, "refresh_tokens", "secure_token_refresh"
    )
    
    request_logger.info(
        "Secure token refresh initiated",
        has_access_token=bool(payload.access_token),
        has_refresh_token=bool(payload.refresh_token),
        access_token_length=len(payload.access_token) if payload.access_token else 0,
        refresh_token_length=len(payload.refresh_token) if payload.refresh_token else 0,
        security_enhanced=True
    )
    
    try:
        # Extract language from request for I18N
        language = extract_language_from_request(request)
        
        # Step 1: Enhanced token pairing validation
        # This is the critical security check that ensures both tokens belong to same session
        request_logger.debug(
            "Initiating enhanced token validation",
            security_enhanced=True
        )
        
        # Validate token pair using token service
        validation_result = await token_service.validate_token_pair(
            access_token=payload.access_token,
            refresh_token=payload.refresh_token,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
            language=language,
        )
        
        # Extract validated data
        user = validation_result["user"]
        access_payload = validation_result["access_payload"] 
        refresh_payload = validation_result["refresh_payload"]
        validation_metadata = validation_result.get("validation_metadata", {})
        
        request_logger.info(
            "Token validation successful",
            user_id=user.id,
            username_masked=secure_logging_service.mask_username(user.username),
            jti_validated=validation_metadata.get("jti_validated", False),
            validation_time_ms=validation_metadata.get("validation_time_ms", 0),
            security_enhanced=True
        )
        
        # Step 2: Create new token pair with rotation
        # Generate new JTI for enhanced security (token rotation)
        request_logger.debug(
            "Creating new token pair with rotation",
            old_jti_masked=access_payload.get("jti", "unknown")[:8] + "...",
            security_enhanced=True
        )
        
        # Create tokens individually with same JTI for session consistency
        from src.domain.value_objects.jwt_token import TokenId
        new_jti = TokenId.generate().value
        
        new_access_token = await token_service.create_access_token(user, new_jti)
        new_refresh_token = await token_service.create_refresh_token(user, new_jti)
        
        new_tokens = {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": 900,  # 15 minutes
        }
        
        # Step 3: Revoke old session to complete token rotation
        # This ensures the old token pair cannot be reused
        old_jti = access_payload.get("jti")
        if old_jti and hasattr(token_service, 'revoke_access_token'):
            try:
                await token_service.revoke_access_token(old_jti)
                request_logger.debug(
                    "Old session revoked successfully",
                    old_jti_masked=old_jti[:8] + "...",
                    security_enhanced=True
                )
            except Exception as e:
                # Log but don't fail the refresh - new tokens are already created
                request_logger.warning(
                    "Failed to revoke old session",
                    error=str(e),
                    old_jti_masked=old_jti[:8] + "...",
                    security_enhanced=True
                )
        
        # Step 4: Success logging and security metrics
        request_logger.info(
            "Token refresh completed successfully",
            user_id=user.id,
            username_masked=secure_logging_service.mask_username(user.username),
            new_jti_masked=new_tokens.get("access_token", "")[:20] + "..." if new_tokens.get("access_token") else "unknown",
            token_type=new_tokens.get("token_type", "bearer"),
            expires_in=new_tokens.get("expires_in", 900),
            security_enhanced=True
        )
        
        # Return new token pair
        return TokenPair(
            access_token=new_tokens["access_token"],
            refresh_token=new_tokens["refresh_token"],
            token_type=new_tokens.get("token_type", "bearer"),
            expires_in=new_tokens.get("expires_in", 900),
        )
        
    except Exception as e:
        # Handle authentication errors consistently
        context_info = {
            "access_token_preview": payload.access_token[:20] + "..." if payload.access_token else "none",
            "refresh_token_preview": payload.refresh_token[:20] + "..." if payload.refresh_token else "none"
        }
        raise await handle_authentication_error(
            error=e,
            request_logger=request_logger,
            error_classification_service=error_classification_service,
            request=request,
            correlation_id=correlation_id,
            context_info=context_info
        ) 