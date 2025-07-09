"""
Token Lifecycle Management Service Interface.

This module defines the domain interface for token lifecycle management
following Domain-Driven Design principles and advanced security patterns.

The interface abstracts the complex business logic of token family security,
providing a clean contract for token creation, refresh, validation, and
security incident management.

Key DDD Principles Applied:
- Single Responsibility: Focused on token lifecycle management
- Ubiquitous Language: Method names reflect business security concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Interface Segregation: Clients depend only on methods they use
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from src.domain.value_objects.security_context import SecurityContext


class ITokenLifecycleManagementService(ABC):
    """
    Interface for token lifecycle management with family security patterns.
    
    This domain service interface defines the contract for comprehensive token
    management including creation, refresh, validation, and security incident
    handling using token family security patterns.
    
    **Domain Responsibilities:**
    - Token pair creation with family security associations
    - Secure token refresh with reuse detection and validation
    - Token validation with comprehensive security checks
    - Security incident detection and family-wide response
    - Audit trail generation for compliance and forensic analysis
    
    **Security Features:**
    - Token families group related tokens for security correlation
    - Real-time reuse detection prevents replay attacks
    - Family-wide revocation provides immediate threat containment
    - Advanced threat analysis with risk scoring
    - Zero-trust validation with fail-secure error handling
    
    **Business Rules Enforced:**
    - Users must be active and authorized for token operations
    - Security context must pass threat assessment
    - Token families must be successfully established before use
    - All operations must complete within transaction boundaries
    - Security incidents trigger immediate family-wide responses
    """
    
    @abstractmethod
    async def create_token_pair_with_family_security(
        self,
        request: "TokenCreationRequest"
    ) -> "TokenPair":
        """
        Create a new token pair with family security patterns.
        
        This method implements secure token pair creation following domain business rules
        for user validation, security assessment, and family establishment.
        
        Args:
            request: Token creation request with user and security context
            
        Returns:
            TokenPair: Complete token pair with family security metadata
            
        Raises:
            AuthenticationError: If user is invalid or token creation fails
            SecurityViolationError: If security context indicates threat
        """
        raise NotImplementedError
    
    @abstractmethod
    async def refresh_tokens_with_family_security(
        self,
        request: "TokenRefreshRequest"
    ) -> "TokenPair":
        """
        Refresh tokens with comprehensive family security validation.
        
        This method implements secure token refresh with advanced security patterns
        including reuse detection, family validation, and threat analysis.
        
        Args:
            request: Token refresh request with security context
            
        Returns:
            TokenPair: New token pair with updated security metadata
            
        Raises:
            AuthenticationError: If refresh token is invalid or expired
            SecurityViolationError: If token reuse or family compromise detected
        """
        raise NotImplementedError
    
    @abstractmethod
    async def validate_token_with_family_security(
        self,
        access_token: str,
        security_context: SecurityContext,
        correlation_id: Optional[str] = None,
        language: str = "en"
    ) -> Dict[str, Any]:
        """
        Validate access token with comprehensive family security checks.
        
        This method implements zero-trust token validation with advanced security
        including family security validation and threat assessment.
        
        Args:
            access_token: JWT access token to validate
            security_context: Current request security context
            correlation_id: Request correlation ID for tracking
            language: Language for error messages
            
        Returns:
            Dict[str, Any]: Validated token payload with security metadata
            
        Raises:
            AuthenticationError: If token is invalid, expired, or user inactive
            SecurityViolationError: If family is compromised or security threat detected
        """
        raise NotImplementedError 