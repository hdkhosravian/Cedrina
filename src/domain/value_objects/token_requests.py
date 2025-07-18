"""
Token Request Value Objects.

This module contains value objects for token-related requests following
Domain-Driven Design principles with clear ubiquitous language and
immutable state.

Domain Concepts:
- Token Creation Request: Request to create new token pair with security context
- Token Refresh Request: Request to refresh existing tokens with validation
- Token Validation Request: Request to validate token with security checks
- Security Context: Security metadata for request tracking and threat assessment

Business Rules:
- All requests must include security context for threat assessment
- Correlation IDs are required for audit trail and request tracing
- Language specification is required for internationalized error messages
- Expiration times must be in the future
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from src.domain.entities.user import User
from src.domain.value_objects.security_context import SecurityContext


@dataclass(frozen=True)
class TokenCreationRequest:
    """
    Value object for token creation requests with security context.
    
    This value object encapsulates all necessary information for creating
    a new token pair with family security patterns, following DDD principles
    with clear business rules and validation.
    
    Business Rules:
    - User must be active and authorized
    - Security context is required for threat assessment
    - Expiration time must be in the future (if specified)
    - Correlation ID is required for audit trail
    - Language specification is required for error messages
    """
    user: User
    security_context: SecurityContext
    expires_at: Optional[datetime] = None
    correlation_id: Optional[str] = None
    language: str = "en"
    
    def __post_init__(self):
        """Validate request data after initialization."""
        if not self.user.is_active:
            raise ValueError("Cannot create tokens for inactive user")
        
        if self.expires_at and self.expires_at <= datetime.now(self.expires_at.tzinfo):
            raise ValueError("Expiration time must be in the future")
        
        if not self.correlation_id:
            raise ValueError("Correlation ID is required for audit trail")
        
        if not self.language:
            raise ValueError("Language specification is required")


@dataclass(frozen=True)
class TokenRefreshRequest:
    """
    Value object for token refresh requests with security context.
    
    This value object encapsulates all necessary information for refreshing
    existing tokens with comprehensive security validation, following DDD
    principles with clear business rules and validation.
    
    Business Rules:
    - Refresh token must be provided
    - Security context is required for threat assessment
    - Language specification is required for error messages
    - Correlation ID is required for audit trail
    """
    refresh_token: str
    security_context: SecurityContext
    correlation_id: Optional[str] = None
    language: str = "en"
    
    def __post_init__(self):
        """Validate request data after initialization."""
        if not self.refresh_token:
            raise ValueError("Refresh token is required")
        
        if not self.correlation_id:
            raise ValueError("Correlation ID is required for audit trail")
        
        if not self.language:
            raise ValueError("Language specification is required")


@dataclass(frozen=True)
class TokenValidationRequest:
    """
    Value object for token validation requests with security context.
    
    This value object encapsulates all necessary information for validating
    access tokens with comprehensive security checks, following DDD principles
    with clear business rules and validation.
    
    Business Rules:
    - Access token must be provided
    - Security context is required for threat assessment
    - Language specification is required for error messages
    - Correlation ID is required for audit trail
    """
    access_token: str
    security_context: SecurityContext
    correlation_id: Optional[str] = None
    language: str = "en"
    
    def __post_init__(self):
        """Validate request data after initialization."""
        if not self.access_token:
            raise ValueError("Access token is required")
        
        if not self.correlation_id:
            raise ValueError("Correlation ID is required for audit trail")
        
        if not self.language:
            raise ValueError("Language specification is required")


@dataclass(frozen=True)
class TokenRevocationRequest:
    """
    Value object for token revocation requests with security context.
    
    This value object encapsulates all necessary information for revoking
    tokens with comprehensive security tracking, following DDD principles
    with clear business rules and validation.
    
    Business Rules:
    - Token identifier must be provided
    - Security context is required for audit trail
    - Correlation ID is required for audit trail
    - Language specification is required for error messages
    """
    token_id: str
    security_context: SecurityContext
    correlation_id: Optional[str] = None
    language: str = "en"
    
    def __post_init__(self):
        """Validate request data after initialization."""
        if not self.token_id:
            raise ValueError("Token identifier is required")
        
        if not self.correlation_id:
            raise ValueError("Correlation ID is required for audit trail")
        
        if not self.language:
            raise ValueError("Language specification is required") 