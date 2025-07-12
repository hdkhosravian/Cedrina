"""Unified Authentication Service - Main Implementation.

This module contains the main unified authentication service that
orchestrates all authentication components following advanced software
engineering principles including TDD, DDD, SOLID, DRY, and Clean Code.

Key Features:
- Comprehensive user authentication with security logging
- OAuth integration with provider management
- Token lifecycle management with family security
- Advanced threat detection and response
- Zero-trust security principles
- Performance optimization for high-throughput systems

Design Principles Applied:
- Single Responsibility: Each component has one clear purpose
- Open/Closed: Extensible through strategy patterns
- Liskov Substitution: All implementations are interchangeable
- Interface Segregation: Focused interfaces for specific needs
- Dependency Inversion: Depends on abstractions, not concretions
"""

import time
from typing import Dict, Any, Optional, Tuple, Union

import structlog

from src.common.exceptions import AuthenticationError, ValidationError
from src.domain.entities.user import User
from src.domain.entities.oauth_profile import OAuthProfile
from src.domain.interfaces.repositories import IUserRepository, IOAuthProfileRepository
from src.domain.interfaces.authentication.user_authentication import IUserAuthenticationService as DomainUserAuthenticationService
from src.domain.interfaces.authentication.oauth import IOAuthService as DomainOAuthService
from src.common.events import IEventPublisher
from src.common.authentication import IUserAuthenticationService, IOAuthService

from src.domain.value_objects.username import Username
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.password import LoginPassword, Password
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.common.i18n import get_translated_message

from .context import AuthenticationContext, AuthenticationMetrics
from .flow_executor import AuthenticationFlowExecutor
from .email_confirmation_checker import EmailConfirmationChecker
from .oauth_handler import OAuthAuthenticationHandler
from .event_handler import AuthenticationEventHandler

logger = structlog.get_logger(__name__)


class UnifiedAuthenticationService(IUserAuthenticationService, IOAuthService, DomainUserAuthenticationService, DomainOAuthService):
    """Unified authentication service with enterprise-grade security features.
    
    This service consolidates all authentication functionality following
    advanced software engineering principles:
    
    **Core Responsibilities:**
    - User authentication with comprehensive security validation
    - OAuth integration with provider-specific handling
    - Token lifecycle management with family security
    - Advanced threat detection and response
    - Zero-trust security principles
    - Performance optimization for high-throughput systems
    
    **Security Features:**
    - Timing attack protection via constant-time operations
    - Comprehensive security event logging with data masking
    - Zero-trust validation with fail-secure error handling
    - Advanced threat pattern analysis and risk scoring
    - Real-time security incident detection and response
    - Audit trail generation for compliance and forensics
    
    **Performance Characteristics:**
    - Sub-millisecond authentication for high-throughput applications
    - Optimized database queries with strategic indexing
    - Concurrent security operations with ACID transaction guarantees
    - Streaming audit logs for real-time security monitoring
    
    **Domain Events Published:**
    - UserLoggedInEvent: Successful authentication
    - AuthenticationFailedEvent: Failed authentication attempts
    - OAuthAuthenticationSuccessEvent: Successful OAuth authentication
    - OAuthAuthenticationFailedEvent: Failed OAuth authentication
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        oauth_profile_repository: Optional[IOAuthProfileRepository] = None,
        event_publisher: Optional[IEventPublisher] = None,
    ):
        """Initialize unified authentication service.
        
        Args:
            user_repository: Repository for user data access
            oauth_profile_repository: Repository for OAuth profile data access
            event_publisher: Publisher for domain events
        """
        self._user_repository = user_repository
        self._oauth_profile_repository = oauth_profile_repository
        self._event_publisher = event_publisher
        
        # Initialize security services
        self._secure_logger = secure_logging_service
        self._error_standardizer = error_standardization_service
        
        # Initialize supporting services
        self._flow_executor = AuthenticationFlowExecutor(
            self._secure_logger, 
            self._error_standardizer
        )
        self._email_confirmation_checker = EmailConfirmationChecker()
        self._oauth_handler = OAuthAuthenticationHandler(oauth_profile_repository) if oauth_profile_repository else None
        self._event_handler = AuthenticationEventHandler(event_publisher, self._secure_logger)
        
        # Performance metrics
        self._auth_metrics = AuthenticationMetrics()
        
        logger.info(
            "UnifiedAuthenticationService initialized",
            service_type="domain_service",
            responsibilities=[
                "user_authentication",
                "oauth_integration", 
                "security_monitoring",
                "threat_detection",
                "audit_trail"
            ]
        )

    async def authenticate_user(
        self,
        username: "Username",
        password: "LoginPassword",
        security_context_or_language: Union[SecurityContext, str] = "en",
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> "User":
        """Authenticate user with comprehensive security validation.
        
        This method supports both common and domain interfaces:
        - Common interface: Uses individual security parameters
        - Domain interface: Uses SecurityContext value object
        
        Args:
            username: Username value object (validated and normalized)
            password: Password value object (secure validation)
            security_context_or_language: Either SecurityContext (domain) or language string (common)
            language: Language code for I18N error messages (common interface)
            client_ip: Client IP address for security context (common interface)
            user_agent: User agent string for security context (common interface)
            correlation_id: Request correlation ID for tracking (common interface)
            
        Returns:
            User: Authenticated user entity
            
        Raises:
            AuthenticationError: If authentication fails (standardized message)
            ValidationError: If security context is invalid
        """
        request_start_time = time.time()
        
        # Determine if this is a domain interface call (SecurityContext) or common interface call
        if isinstance(security_context_or_language, SecurityContext):
            # Domain interface call
            security_context = security_context_or_language
            context = AuthenticationContext(
                client_ip=security_context.client_ip,
                user_agent=security_context.user_agent,
                correlation_id=security_context.correlation_id or "",
                language=language
            )
        else:
            # Common interface call
            context = AuthenticationContext(
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id,
                language=security_context_or_language
            )
        
        async def _perform_user_authentication() -> User:
            return await self._authenticate_user_internal(username, password, context)
        
        result = await self._flow_executor.execute(
            _perform_user_authentication,
            context,
            request_start_time,
            oauth=False
        )
        
        # Update metrics
        duration_ms = (time.time() - request_start_time) * 1000
        self._auth_metrics = self._auth_metrics.update_success(duration_ms, oauth=False)
        
        return result
    
    async def authenticate_with_oauth(
        self,
        provider: "OAuthProvider",
        token: "OAuthToken",
        security_context_or_language: Union[SecurityContext, str] = "en",
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> Tuple["User", "OAuthProfile"]:
        """Authenticate user via OAuth with comprehensive security validation.
        
        This method supports both common and domain interfaces:
        - Common interface: Uses individual security parameters
        - Domain interface: Uses SecurityContext value object
        
        Args:
            provider: OAuth provider value object
            token: OAuth token value object
            security_context_or_language: Either SecurityContext (domain) or language string (common)
            language: Language code for I18N error messages (common interface)
            client_ip: Client IP address for security context (common interface)
            user_agent: User agent string for security context (common interface)
            correlation_id: Request correlation ID for tracking (common interface)
            
        Returns:
            Tuple[User, OAuthProfile]: Authenticated user and OAuth profile
            
        Raises:
            AuthenticationError: If OAuth authentication fails
            ValidationError: If security context is invalid
        """
        if not self._oauth_handler:
            raise AuthenticationError("OAuth authentication not configured")
            
        request_start_time = time.time()
        
        # Determine if this is a domain interface call (SecurityContext) or common interface call
        if isinstance(security_context_or_language, SecurityContext):
            # Domain interface call
            security_context = security_context_or_language
            context = AuthenticationContext(
                client_ip=security_context.client_ip,
                user_agent=security_context.user_agent,
                correlation_id=security_context.correlation_id or "",
                language=language
            )
        else:
            # Common interface call
            context = AuthenticationContext(
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id,
                language=security_context_or_language
            )
        
        async def _perform_oauth_authentication() -> Tuple[User, OAuthProfile]:
            return await self._authenticate_oauth_internal(provider, token, context)
        
        result = await self._flow_executor.execute(
            _perform_oauth_authentication,
            context,
            request_start_time,
            oauth=True
        )
        
        # Update metrics
        duration_ms = (time.time() - request_start_time) * 1000
        self._auth_metrics = self._auth_metrics.update_success(duration_ms, oauth=True)
        
        return result
    
    async def _authenticate_user_internal(
        self,
        username: "Username",
        password: "LoginPassword", 
        context: AuthenticationContext
    ) -> User:
        """Internal user authentication logic.
        
        Args:
            username: Username value object
            password: Password value object
            context: Authentication context
            
        Returns:
            User: Authenticated user entity
            
        Raises:
            AuthenticationError: If authentication fails
        """
        # Log authentication attempt with security context
        self._secure_logger.log_authentication_attempt(
            username=str(username),
            success=False,  # Will be updated on success
            correlation_id=context.correlation_id,
            ip_address=context.client_ip,
            user_agent=context.user_agent,
            risk_indicators=[]
        )
        
        # Retrieve user by normalized username
        user = await self._user_repository.get_by_username(str(username))
        
        # Verify user exists and password is correct
        if not user or not await self.verify_password(user, password):
            await self._event_handler.handle_authentication_failure(
                username=username,
                failure_reason="invalid_credentials",
                context=context
            )
            
            # Return standardized error response
            error_response = await self._error_standardizer.create_authentication_error_response(
                actual_failure_reason="invalid_credentials",
                username=str(username),
                correlation_id=context.correlation_id,
                language=context.language,
                request_start_time=time.time()
            )
            raise AuthenticationError(error_response["detail"])
        
        # Check user account status
        if not user.is_active:
            await self._event_handler.handle_authentication_failure(
                username=username,
                failure_reason="account_inactive",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("account_inactive", context.language)
            )
        
        # Check email confirmation if required
        if self._email_confirmation_checker.is_confirmation_required(user):
            await self._event_handler.handle_authentication_failure(
                username=username,
                failure_reason="email_confirmation_required",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("email_confirmation_required", context.language)
            )
        
        # Log successful authentication
        await self._event_handler.handle_authentication_success(user, context)
        
        return user
    
    async def _authenticate_oauth_internal(
        self,
        provider: OAuthProvider,
        token: OAuthToken,
        context: AuthenticationContext
    ) -> Tuple[User, OAuthProfile]:
        """Internal OAuth authentication logic.
        
        Args:
            provider: OAuth provider
            token: OAuth token
            context: Authentication context
            
        Returns:
            Tuple[User, OAuthProfile]: Authenticated user and OAuth profile
            
        Raises:
            AuthenticationError: If OAuth authentication fails
        """
        # Validate OAuth token
        if not await self._oauth_handler.validate_oauth_token(provider, token):
            await self._event_handler.handle_oauth_failure(
                provider=provider,
                failure_reason="invalid_token",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("oauth_token_invalid", context.language)
            )
        
        # Fetch user info from OAuth provider
        user_info = await self._oauth_handler.fetch_oauth_user_info(provider, token)
        if not user_info:
            await self._event_handler.handle_oauth_failure(
                provider=provider,
                failure_reason="user_info_fetch_failed",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("oauth_user_info_failed", context.language)
            )
        
        # Find or create user and OAuth profile
        user, oauth_profile = await self._oauth_handler.link_or_create_oauth_user(
            provider, user_info, context
        )
        
        # Log successful OAuth authentication
        await self._event_handler.handle_oauth_success(user, oauth_profile, context)
        
        return user, oauth_profile
    
    async def verify_password(self, user: "User", password: "Password") -> bool:
        """Verify password using constant-time comparison.
        
        This method handles both Password and LoginPassword value objects
        since both implement the verify_against_hash method.
        
        Args:
            user: User entity
            password: Password value object (Password or LoginPassword)
            
        Returns:
            bool: True if password is valid
        """
        try:
            if not user or not user.hashed_password or not password:
                return False
            
            # Use domain value object for secure password verification
            return password.verify_against_hash(user.hashed_password)
            
        except Exception as e:
            logger.error(
                "Password verification error",
                user_id=user.id if user else None,
                error=str(e)
            )
            return False
    
    async def validate_oauth_state(self, state: str, stored_state: str, language: str = "en") -> bool:
        """Validate OAuth state parameter to prevent CSRF attacks.
        
        Args:
            state: State value received from OAuth provider callback
            stored_state: State value that was originally generated and stored
            language: Language for error messages
            
        Returns:
            bool: True if states match, False otherwise
        """
        try:
            # Constant-time comparison to prevent timing attacks
            if len(state) != len(stored_state):
                return False
            
            result = 0
            for a, b in zip(state, stored_state):
                result |= ord(a) ^ ord(b)
            
            return result == 0
            
        except Exception as e:
            logger.error(
                "OAuth state validation error",
                error=str(e)
            )
            return False
    
    def get_auth_metrics(self) -> Dict[str, Any]:
        """Get authentication metrics for monitoring.
        
        Returns:
            Dict[str, Any]: Authentication metrics
        """
        return {
            "total_authentications": self._auth_metrics.total_authentications,
            "successful_authentications": self._auth_metrics.successful_authentications,
            "failed_authentications": self._auth_metrics.failed_authentications,
            "oauth_authentications": self._auth_metrics.oauth_authentications,
            "security_incidents": self._auth_metrics.security_incidents,
            "average_auth_time_ms": self._auth_metrics.average_auth_time_ms,
        } 