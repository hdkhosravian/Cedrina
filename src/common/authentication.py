"""Common authentication interfaces for user authentication and OAuth services.

This module provides authentication service interfaces that can be used across
all layers without creating circular dependencies.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.domain.value_objects.password import LoginPassword, Password
    from src.domain.value_objects.username import Username
    from src.domain.value_objects.oauth_provider import OAuthProvider
    from src.domain.value_objects.oauth_token import OAuthToken
    from src.domain.entities.user import User
    from src.domain.entities.oauth_profile import OAuthProfile


class IUserAuthenticationService(ABC):
    """Interface for user authentication operations.
    
    This service provides the core authentication functionality following
    Domain-Driven Design principles. It handles user authentication with
    comprehensive security validation and standardized error handling.
    
    DDD Principles:
    - Single Responsibility: Handles only user authentication
    - Domain Value Objects: Uses validated username and password objects
    - Ubiquitous Language: Method names reflect authentication concepts
    - Fail-Safe Security: Implements secure authentication with proper error handling
    """

    @abstractmethod
    async def authenticate_user(
        self,
        username: "Username",
        password: "LoginPassword",
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> "User":
        """Authenticate user with comprehensive security validation.
        
        Args:
            username: Username value object (validated and normalized)
            password: Password value object (secure validation)
            language: Language code for I18N error messages
            client_ip: Client IP address for security context
            user_agent: User agent string for security context
            correlation_id: Request correlation ID for tracking
            
        Returns:
            User: Authenticated user entity
            
        Raises:
            AuthenticationError: If authentication fails (standardized message)
        """
        raise NotImplementedError

    @abstractmethod
    async def verify_password(self, user: "User", password: "Password") -> bool:
        """Verify a password against a user's stored password hash.
        
        Args:
            user: User entity to verify password against
            password: Password value object to verify
            
        Returns:
            bool: True if password is valid, False otherwise
        """
        raise NotImplementedError


class IOAuthService(ABC):
    """Interface for OAuth authentication operations.
    
    This service provides OAuth authentication functionality following
    Domain-Driven Design principles. It handles OAuth provider integration
    with comprehensive security validation and standardized error handling.
    
    DDD Principles:
    - Single Responsibility: Handles only OAuth authentication
    - Domain Value Objects: Uses validated OAuth provider and token objects
    - Ubiquitous Language: Method names reflect OAuth concepts
    - Fail-Safe Security: Implements secure OAuth with proper error handling
    """

    @abstractmethod
    async def authenticate_with_oauth(
        self,
        provider: "OAuthProvider",
        token: "OAuthToken",
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> Tuple["User", "OAuthProfile"]:
        """Authenticate user with OAuth provider.
        
        Args:
            provider: OAuth provider value object
            token: OAuth token value object
            language: Language code for I18N error messages
            client_ip: Client IP address for security context
            user_agent: User agent string for security context
            correlation_id: Request correlation ID for tracking
            
        Returns:
            Tuple[User, OAuthProfile]: Authenticated user and OAuth profile
            
        Raises:
            AuthenticationError: If OAuth authentication fails
        """
        raise NotImplementedError

    @abstractmethod
    async def validate_oauth_state(self, state: str, stored_state: str, language: str = "en") -> bool:
        """Validate OAuth state parameter for CSRF protection.
        
        Args:
            state: State parameter from OAuth callback
            stored_state: Stored state from session
            language: Language code for I18N error messages
            
        Returns:
            bool: True if state is valid, False otherwise
        """
        raise NotImplementedError 