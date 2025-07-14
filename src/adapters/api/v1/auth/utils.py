from __future__ import annotations

"""Utility functions for authentication API routes.

This module provides shared helper functions to ensure consistency and reduce
duplication across authentication endpoints like login, register, and OAuth.
"""

import asyncio
import uuid
from typing import Dict, Any, Optional

from src.adapters.api.v1.auth.schemas import TokenPair
from src.core.config.settings import settings
from src.domain.entities.user import User
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_requests import TokenCreationRequest
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.common.exceptions import AuthenticationError
from src.domain.interfaces import IErrorClassificationService
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.common.i18n import get_translated_message, extract_language_from_request
import structlog

logger = structlog.get_logger(__name__)


def extract_security_context(request) -> Dict[str, str]:
    """Extract security context from FastAPI request.
    
    This utility centralizes the extraction of security-related information
    from requests to ensure consistency across all authentication endpoints.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dict containing correlation_id, client_ip, and user_agent
    """
    correlation_id = str(uuid.uuid4())
    client_ip = request.client.host or "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    return {
        "correlation_id": correlation_id,
        "client_ip": client_ip,
        "user_agent": user_agent
    }


def setup_request_context(
    request,
    endpoint: str,
    operation: str
) -> tuple[structlog.BoundLogger, str, str, str]:
    """Set up request context with security information and logging.
    
    This utility centralizes the common pattern of setting up request context
    including correlation ID generation, security context extraction, and
    structured logger creation.
    
    Args:
        request: FastAPI request object
        endpoint: Endpoint name for logging context
        operation: Operation name for logging context
        
    Returns:
        Tuple of (request_logger, correlation_id, client_ip, user_agent)
    """
    security_context = extract_security_context(request)
    
    request_logger = create_request_logger(
        correlation_id=security_context["correlation_id"],
        client_ip=security_context["client_ip"],
        user_agent=security_context["user_agent"],
        endpoint=endpoint,
        operation=operation
    )
    
    return (
        request_logger,
        security_context["correlation_id"],
        security_context["client_ip"],
        security_context["user_agent"]
    )


async def create_token_pair(token_service: DomainTokenService, user: User, correlation_id: str) -> TokenPair:
    """Create a pair of JWT access and refresh tokens for a user.

    This utility centralizes token creation logic to ensure consistency across
    authentication endpoints. It generates access and refresh tokens using the
    provided domain token service and applies configuration from settings.

    Args:
        token_service: Domain token service for token generation.
        user: The user entity for whom tokens are created.

    Returns:
        TokenPair: Pydantic model with access token, refresh token, token type,
            and expiration time in seconds.

    Note:
        - Uses the new domain token service with token family security
        - Both access and refresh tokens use the same JTI for session validation
        - Expiration time is validated to prevent invalid values
        - Tokens are created asynchronously to align with FastAPI's async nature
        - Implements advanced security patterns with token family management
    """
    # Create security context for the request
    security_context = SecurityContext.create_for_request(
        client_ip="127.0.0.1",  # Will be overridden by actual request context
        user_agent="API-Client",
        correlation_id=correlation_id
    )
    
    # Create token creation request using domain service
    request = TokenCreationRequest(
        user=user,
        security_context=security_context,
        correlation_id=correlation_id
    )
    
    # Create token pair using domain service with family security
    token_pair = await token_service.create_token_pair_with_family_security(request)

    # Ensure minimum expiration time of 60 seconds
    expires_in = max(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 60)

    return TokenPair(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        token_type="Bearer",
        expires_in=expires_in,
    )


async def handle_authentication_error(
    error: Exception,
    request_logger: structlog.BoundLogger,
    error_classification_service: IErrorClassificationService,
    request,
    correlation_id: str,
    context_info: dict = None
) -> Exception:
    """Handle authentication errors consistently across all endpoints.
    
    This utility centralizes error handling logic to ensure consistent
    error responses and logging across all authentication endpoints.
    
    Args:
        error: The exception that occurred
        request_logger: Structured logger for the request
        error_classification_service: Service for classifying errors
        request: FastAPI request object for language detection
        correlation_id: Request correlation ID for tracking
        context_info: Additional context information for logging
        
    Returns:
        Exception: Standardized domain exception
        
    Note:
        - Provides consistent error handling across all auth endpoints
        - Implements secure logging with data masking
        - Uses error classification for appropriate error types
        - Supports internationalization for error messages
        - Handles domain-specific exceptions properly
    """
    # Extract language from request for I18N
    language = extract_language_from_request(request)
    
    # Prepare context for logging
    log_context = {
        "error_type": type(error).__name__,
        "correlation_id": correlation_id,
        "security_enhanced": True
    }
    
    if context_info:
        log_context.update(context_info)
    
    # Handle domain-specific exceptions that should be re-raised as-is
    from src.common.exceptions import (
        DuplicateUserError, PasswordPolicyError, UserNotFoundError,
        PasswordResetError, ForgotPasswordError, RateLimitExceededError
    )
    
    if isinstance(error, (DuplicateUserError, PasswordPolicyError, UserNotFoundError, PasswordResetError, ForgotPasswordError, RateLimitExceededError)):
        # Log the domain-specific error with security context
        request_logger.warning(
            "Authentication failed - domain error",
            error_message=str(error),
            **log_context
        )
        # Re-raise domain exceptions as-is for proper HTTP status codes
        raise error
    
    if isinstance(error, (ValueError, AuthenticationError)):
        # Classify error for consistent response format
        try:
            if asyncio.iscoroutinefunction(error_classification_service.classify_error):
                classified_error = await error_classification_service.classify_error(error)
            else:
                classified_error = error_classification_service.classify_error(error)
        except Exception as classification_error:
            # Fallback to original error if classification fails
            classified_error = error
            
        # Log the error with security context
        request_logger.warning(
            "Authentication failed",
            error_message=str(classified_error),
            **log_context
        )
        raise classified_error
    else:
        # Log unexpected errors for debugging
        request_logger.error(
            "Authentication failed - unexpected error",
            error=str(error),
            **log_context
        )
        
        # Create standardized error response
        standardized_response = await error_standardization_service.create_standardized_response(
            error_type="internal_error",
            actual_error=str(error),
            correlation_id=correlation_id,
            language=language
        )
        raise AuthenticationError(standardized_response["detail"])


def create_request_logger(
    correlation_id: str,
    client_ip: str,
    user_agent: str,
    endpoint: str,
    operation: str
) -> structlog.BoundLogger:
    """Create a structured logger with security context for authentication requests.
    
    This utility centralizes logger creation to ensure consistent
    security context and correlation tracking across all endpoints.
    
    Args:
        correlation_id: Request correlation ID for tracking
        client_ip: Client IP address (will be masked)
        user_agent: User agent string (will be sanitized)
        endpoint: Endpoint name for logging context
        operation: Operation name for logging context
        
    Returns:
        structlog.BoundLogger: Structured logger with security context
        
    Note:
        - Applies consistent security masking across all endpoints
        - Provides correlation tracking for request tracing
        - Implements secure logging practices
    """
    return logger.bind(
        correlation_id=correlation_id,
        client_ip=secure_logging_service.mask_ip_address(client_ip),
        user_agent=secure_logging_service.sanitize_user_agent(user_agent),
        endpoint=endpoint,
        operation=operation
    )
