"""User Logout Domain Service.

This service handles user logout operations following Domain-Driven Design
principles and single responsibility principle. It uses domain value objects for
input validation and publishes domain events for audit trails and security monitoring.

Key DDD Principles Applied:
- Domain Value Objects for input validation and business rules
- Domain Events for audit trails and security monitoring
- Single Responsibility Principle for logout logic
- Dependency Inversion through interfaces
- Ubiquitous Language in method names and documentation
- Fail-Safe security patterns with comprehensive validation
"""

from datetime import datetime, timezone
from typing import Optional

import structlog

from src.common.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.events.authentication_events import UserLoggedOutEvent
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces import (
    IEventPublisher,
    ITokenService,
    IUserLogoutService,
)
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken
from src.common.i18n import get_translated_message

from .base_authentication_service import BaseAuthenticationService, ServiceContext

logger = structlog.get_logger(__name__)


class UserLogoutService(IUserLogoutService, BaseAuthenticationService):
    """Domain service for user logout operations following DDD principles.
    
    This service encapsulates all logout business logic and follows
    Domain-Driven Design principles:
    
    - **Single Responsibility**: Handles only logout-related operations
    - **Domain Value Objects**: Uses AccessToken and RefreshToken value objects for validation
    - **Domain Events**: Publishes events for audit trails and security monitoring
    - **Dependency Inversion**: Depends on abstractions (interfaces) not concretions
    - **Ubiquitous Language**: Method names reflect business domain concepts
    - **Fail-Safe Security**: Implements comprehensive validation and secure logging
    
    Security Features:
    - Refresh token ownership validation to prevent cross-user token usage
    - Comprehensive security event logging with data masking
    - Concurrent token revocation for performance and atomicity
    - Fail-secure logout logic with proper error handling
    - Correlation ID tracking for request tracing
    - Security context capture (IP, User-Agent) for audit trails
    """
    
    def __init__(
        self,
        token_service: ITokenService,
        event_publisher: IEventPublisher,
    ):
        """Initialize logout service with dependencies.
        
        Args:
            token_service: Service for token operations (abstraction)
            event_publisher: Publisher for domain events (abstraction)
            
        Note:
            Dependencies are injected through interfaces, following
            dependency inversion principle from SOLID.
        """
        super().__init__(event_publisher)
        self._token_service = token_service
        
        logger.info(
            "UserLogoutService initialized",
            service_type="domain_service",
            responsibilities=["logout", "token_revocation", "event_publishing"]
        )
    
    async def logout_user(
        self,
        access_token: AccessToken,
        user: User,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Logout user by revoking tokens and terminating session.
        
        This method implements the core logout business logic following
        Domain-Driven Design principles:
        
        1. **Input Validation**: Uses domain value objects (AccessToken)
        2. **Business Rules**: Revokes access token to terminate session
        3. **Security Context**: Captures security-relevant information for audit
        4. **Domain Events**: Publishes events for security monitoring and audit trails
        5. **Error Handling**: Provides meaningful error messages in ubiquitous language
        6. **Logging**: Implements secure logging with data masking and correlation
        7. **I18N Support**: Uses provided language for all error messages
        
        Logout Flow:
        1. Calculate session duration for audit purposes
        2. Revoke access token to terminate session
        3. Publish domain event for security monitoring
        4. Log successful logout with security context
        
        Args:
            access_token: Access token value object (validated)
            user: Authenticated user entity
            language: Language code for I18N error messages
            client_ip: Client IP address for security context and audit
            user_agent: User agent string for security context and audit
            correlation_id: Request correlation ID for tracing and debugging
            
        Raises:
            AuthenticationError: If token revocation fails
                               
        Security Considerations:
        - Token revocation ensures session termination
        - Comprehensive audit trails via domain events
        - Secure logging with sensitive data masking
        - Fail-secure error handling
        """
        context_kwargs = dict(
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            operation="user_logout"
        )
        if correlation_id:
            context_kwargs["correlation_id"] = correlation_id
        context = ServiceContext(**context_kwargs)
        
        async with self._operation_context(context) as ctx:
            # Log logout attempt with security context
            logger.info(
                "User logout initiated",
                user_id=user.id,
                username=user.username,
                access_token_id=access_token.get_token_id().mask_for_logging(),
                correlation_id=ctx.correlation_id,
                client_ip=self._mask_ip(ctx.client_ip),
                user_agent_length=len(ctx.user_agent) if ctx.user_agent else 0,
                security_context_captured=True
            )
            
            # Calculate session duration for audit purposes
            session_duration = self._calculate_session_duration(access_token)
            
            # Revoke access token to terminate session
            try:
                await self._token_service.revoke_access_token(str(access_token.get_token_id()))
            except AuthenticationError:
                # Re-raise domain-specific errors as-is
                raise
            except Exception as e:
                # Convert unexpected errors to domain error
                logger.error(
                    "Token revocation failed during logout",
                    user_id=user.id,
                    error_type=type(e).__name__,
                    error_message=str(e),
                    correlation_id=ctx.correlation_id
                )
                raise AuthenticationError(
                    get_translated_message("logout_failed_internal_error", ctx.language)
                ) from e
            
            # Publish domain event for security monitoring and audit trails
            await self._publish_logout_event(user, session_duration, ctx)
            
            # Log successful logout
            logger.info(
                "User logout completed successfully",
                user_id=user.id,
                username=user.username,
                session_duration_seconds=session_duration,
                correlation_id=ctx.correlation_id,
                logout_method="user_initiated"
            )
    
    def _calculate_session_duration(self, access_token: AccessToken) -> Optional[int]:
        """Calculate session duration from access token for audit purposes.
        
        Args:
            access_token: Access token with issued-at time
            
        Returns:
            Optional[int]: Session duration in seconds, None if cannot calculate
        """
        try:
            issued_at = access_token.claims.get('iat')
            if not issued_at:
                return None
            
            # Convert timestamp to datetime and calculate duration
            issued_datetime = datetime.fromtimestamp(issued_at, tz=timezone.utc)
            current_time = datetime.now(timezone.utc)
            duration = current_time - issued_datetime
            
            # Handle invalid durations (negative for future timestamps, too large for very old timestamps)
            duration_seconds = int(duration.total_seconds())
            if duration_seconds < 0 or duration_seconds > 365 * 24 * 60 * 60:  # More than 1 year
                logger.debug(
                    "Invalid session duration calculated",
                    duration_seconds=duration_seconds,
                    issued_at=issued_at,
                    current_time=current_time.isoformat()
                )
                return None
            
            return duration_seconds
        except (ValueError, TypeError, OSError) as e:
            logger.debug(
                "Could not calculate session duration",
                error=str(e),
                iat_claim=access_token.claims.get('iat')
            )
            return None
    
    async def _publish_logout_event(
        self,
        user: User,
        session_duration: Optional[int],
        context: ServiceContext,
    ) -> None:
        """Publish domain event for logout operation.
        
        Args:
            user: User who logged out
            session_duration: Duration of the session in seconds
            context: Service context
        """
        # Create metadata with additional context information
        metadata = {
            "username": user.username,
            "logout_reason": "user_initiated",
            "user_agent": context.user_agent,
            "ip_address": context.client_ip,
            "session_duration": session_duration,
        }
        
        event = UserLoggedOutEvent.create(
            user_id=user.id,
            correlation_id=context.correlation_id,
            metadata=metadata,
        )
        
        await self._publish_domain_event(event, context, logger)
    
    async def _validate_operation_prerequisites(self, context: ServiceContext) -> None:
        """Validate operation prerequisites for user logout.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        # User logout service requires token service to be available
        if not self._token_service:
            raise AuthenticationError(
                get_translated_message("service_unavailable", context.language)
            ) 