"""Event Handler for Unified Authentication Service.

This module contains event handling logic for authentication events
including success and failure event publishing and logging.
"""

import time
import structlog
from typing import Optional

from src.domain.entities.user import User
from src.domain.entities.oauth_profile import OAuthProfile
from src.domain.value_objects.username import Username
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.events.authentication_events import (
    UserLoggedInEvent,
    AuthenticationFailedEvent,
    UserLoggedOutEvent
)
from src.common.events import IEventPublisher
from .context import AuthenticationContext

logger = structlog.get_logger(__name__)


class AuthenticationEventHandler:
    """Handles authentication events and logging.
    
    This class encapsulates all event handling logic for authentication
    including success and failure event publishing and security logging.
    """
    
    def __init__(self, event_publisher: Optional[IEventPublisher], secure_logger):
        """Initialize authentication event handler.
        
        Args:
            event_publisher: Publisher for domain events
            secure_logger: Secure logging service
        """
        self._event_publisher = event_publisher
        self._secure_logger = secure_logger
    
    async def handle_authentication_success(self, user: User, context: AuthenticationContext) -> None:
        """Handle successful authentication.
        
        Args:
            user: Authenticated user
            context: Authentication context
        """
        # Publish success event
        if self._event_publisher:
            event = UserLoggedInEvent.create(
                user_id=user.id,
                email=user.email,
                correlation_id=context.correlation_id,
                metadata={
                    "client_ip": context.client_ip,
                    "user_agent": context.user_agent
                }
            )
            await self._event_publisher.publish(event)
        
        # Log security event
        self._secure_logger.log_authentication_attempt(
            username=user.username,
            success=True,
            correlation_id=context.correlation_id,
            ip_address=context.client_ip,
            user_agent=context.user_agent
        )
        
        logger.info(
            "User authentication successful",
            user_id=user.id,
            username=user.username,
            correlation_id=context.correlation_id
        )
    
    async def handle_authentication_failure(
        self,
        username: Username,
        failure_reason: str,
        context: AuthenticationContext
    ) -> None:
        """Handle authentication failure.
        
        Args:
            username: Attempted username
            failure_reason: Reason for failure
            context: Authentication context
        """
        # Publish failure event
        if self._event_publisher:
            event = AuthenticationFailedEvent.create(
                reason=failure_reason,
                email=str(username),
                correlation_id=context.correlation_id,
                metadata={
                    "client_ip": context.client_ip,
                    "user_agent": context.user_agent
                }
            )
            await self._event_publisher.publish(event)
        
        # Log security event
        self._secure_logger.log_authentication_attempt(
            username=str(username),
            success=False,
            failure_reason=failure_reason,
            correlation_id=context.correlation_id,
            ip_address=context.client_ip,
            user_agent=context.user_agent
        )
        
        logger.warning(
            "User authentication failed",
            username=username.mask_for_logging(),
            failure_reason=failure_reason,
            correlation_id=context.correlation_id
        )
    
    async def handle_oauth_success(
        self,
        user: User,
        oauth_profile: OAuthProfile,
        context: AuthenticationContext
    ) -> None:
        """Handle successful OAuth authentication.
        
        Args:
            user: Authenticated user
            oauth_profile: OAuth profile
            context: Authentication context
        """
        # Publish success event (using UserLoggedInEvent for OAuth as well)
        if self._event_publisher:
            event = UserLoggedInEvent.create(
                user_id=user.id,
                email=user.email,
                correlation_id=context.correlation_id,
                metadata={
                    "oauth_profile_id": oauth_profile.id,
                    "provider": oauth_profile.provider,
                    "client_ip": context.client_ip,
                    "user_agent": context.user_agent
                }
            )
            await self._event_publisher.publish(event)
        
        logger.info(
            "OAuth authentication successful",
            user_id=user.id,
            provider=oauth_profile.provider,
            correlation_id=context.correlation_id
        )
    
    async def handle_oauth_failure(
        self,
        provider: OAuthProvider,
        failure_reason: str,
        context: AuthenticationContext
    ) -> None:
        """Handle OAuth authentication failure.
        
        Args:
            provider: OAuth provider
            failure_reason: Reason for failure
            context: Authentication context
        """
        # Publish failure event
        if self._event_publisher:
            event = AuthenticationFailedEvent.create(
                reason=failure_reason,
                correlation_id=context.correlation_id,
                metadata={
                    "provider": provider.value,
                    "client_ip": context.client_ip,
                    "user_agent": context.user_agent
                }
            )
            await self._event_publisher.publish(event)
        
        logger.warning(
            "OAuth authentication failed",
            provider=provider.value,
            failure_reason=failure_reason,
            correlation_id=context.correlation_id
        ) 