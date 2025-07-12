"""Password Change Service following Domain-Driven Design principles.

This service handles password changes for authenticated users with comprehensive
security validation, domain events, and audit trails.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog

from src.common.exceptions import (
    AuthenticationError,
    InvalidOldPasswordError,
    PasswordPolicyError,
    PasswordReuseError,
)
from src.domain.entities.user import User
from src.domain.events.authentication_events import PasswordChangedEvent
from src.domain.interfaces.repositories import IUserRepository
from src.domain.interfaces.authentication.password_change import IPasswordChangeService
from src.domain.interfaces import IEventPublisher
from src.domain.value_objects.password import Password
from src.common.i18n import get_translated_message

from .base_authentication_service import BaseAuthenticationService, ServiceContext

logger = structlog.get_logger(__name__)


class PasswordChangeService(IPasswordChangeService, BaseAuthenticationService):
    """Clean architecture password change service following DDD principles.
    
    This service implements secure password change operations with:
    - Domain value object validation
    - Comprehensive security checks
    - Domain event publishing for audit trails
    - Proper error handling and logging
    - Clean separation of concerns
    
    The service follows Domain-Driven Design by:
    - Using Password value objects for validation
    - Publishing PasswordChangedEvent domain events
    - Delegating to repository interfaces
    - Maintaining business rule integrity
    - Providing rich audit information
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
    ):
        """Initialize password change service with dependencies.
        
        Args:
            user_repository: Repository for user data operations
            event_publisher: Service for publishing domain events
        """
        super().__init__(event_publisher)
        self._user_repository = user_repository
        
        logger.info("PasswordChangeService initialized with clean architecture")

    async def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Change user password with comprehensive security validation.
        
        This method implements secure password change following DDD principles:
        
        1. **Input Validation**: Uses domain value objects for validation
        2. **Business Rules**: Enforces password policies and security rules
        3. **Domain Events**: Publishes events for audit trails and monitoring
        4. **Security Context**: Captures security information for audit
        5. **Error Handling**: Provides clear, translated error messages
        
        Security Features:
        - Password value object validation
        - Old password verification
        - Password reuse prevention
        - Comprehensive audit logging
        - Domain event publishing
        
        Args:
            user_id: ID of the user changing password
            old_password: Current password for verification
            new_password: New password to set
            language: Language code for error messages
            client_ip: Client IP address for audit
            user_agent: User agent string for audit
            correlation_id: Correlation ID for request tracking
            
        Raises:
            ValueError: If input parameters are invalid
            AuthenticationError: If user not found or inactive
            InvalidOldPasswordError: If old password is incorrect
            PasswordReuseError: If new password same as old password
            PasswordPolicyError: If new password doesn't meet policy
        """
        # Generate correlation ID if not provided
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        context = ServiceContext(
            correlation_id=correlation_id,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            operation="password_change"
        )
        
        async with self._operation_context(context) as ctx:
            # Step 1: Validate input parameters
            self._validate_required_parameters({
                "old_password": old_password,
                "new_password": new_password
            }, ctx)
            
            # Step 2: Retrieve and validate user
            user = await self._get_and_validate_user(user_id, ctx)
            
            # Step 3: Create domain value objects for password validation
            old_password_obj = Password(old_password)
            new_password_obj = Password(new_password)
            
            logger.debug("Domain value objects created successfully", correlation_id=ctx.correlation_id)
            
            # Step 4: Verify old password
            await self._verify_old_password(user, old_password_obj, ctx)
            
            # Step 5: Check password reuse
            self._check_password_reuse(old_password_obj, new_password_obj, ctx)
            
            # Step 6: Update user password
            await self._update_user_password(user, new_password_obj, ctx)
            
            # Step 7: Publish domain event for audit trails
            await self._publish_password_changed_event(user, ctx)
            
            logger.info(
                "Password change completed successfully",
                username=user.username[:3] + "***" if user.username else "unknown",
                correlation_id=ctx.correlation_id
            )

    async def _get_and_validate_user(
        self, 
        user_id: int, 
        context: ServiceContext
    ) -> User:
        """Retrieve and validate user exists and is active.
        
        Args:
            user_id: User ID to retrieve
            context: Service context
            
        Returns:
            User: Retrieved and validated user
            
        Raises:
            AuthenticationError: If user not found or inactive
        """
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            logger.warning("Password change attempted for non-existent user", correlation_id=context.correlation_id)
            raise AuthenticationError(
                get_translated_message("user_not_found", context.language)
            )

        if not user.is_active:
            logger.warning(
                "Password change attempted for inactive user",
                username=user.username[:3] + "***" if user.username else "unknown",
                correlation_id=context.correlation_id
            )
            raise AuthenticationError(
                get_translated_message("user_account_inactive", context.language)
            )
            
        return user

    async def _verify_old_password(
        self, 
        user: User, 
        old_password: Password, 
        context: ServiceContext
    ) -> None:
        """Verify the old password is correct.
        
        Args:
            user: User entity
            old_password: Old password value object
            context: Service context
            
        Raises:
            InvalidOldPasswordError: If old password is incorrect
        """
        if not user.verify_password(str(old_password)):
            logger.warning(
                "Password change failed - invalid old password",
                username=user.username[:3] + "***" if user.username else "unknown",
                correlation_id=context.correlation_id
            )
            raise InvalidOldPasswordError(
                get_translated_message("invalid_old_password", context.language)
            )

    def _check_password_reuse(
        self, 
        old_password: Password, 
        new_password: Password, 
        context: ServiceContext
    ) -> None:
        """Check that new password is different from old password.
        
        Args:
            old_password: Old password value object
            new_password: New password value object
            context: Service context
            
        Raises:
            PasswordReuseError: If new password is same as old password
        """
        if str(old_password) == str(new_password):
            logger.warning(
                "Password change failed - password reuse attempted",
                correlation_id=context.correlation_id
            )
            raise PasswordReuseError(
                get_translated_message("password_reuse_not_allowed", context.language)
            )

    async def _update_user_password(
        self, 
        user: User, 
        new_password: Password,
        context: ServiceContext
    ) -> None:
        """Update user password in repository.
        
        Args:
            user: User entity
            new_password: New password value object
            context: Service context
        """
        # Update user password
        user.hashed_password = new_password.to_hashed().value
        await self._user_repository.save(user)
        
        logger.debug(
            "User password updated successfully",
            username=user.username[:3] + "***" if user.username else "unknown",
            correlation_id=context.correlation_id
        )

    async def _publish_password_changed_event(
        self,
        user: User,
        context: ServiceContext
    ) -> None:
        """Publish domain event for password change.
        
        Args:
            user: User who changed password
            context: Service context
        """
        event = PasswordChangedEvent(
            user_id=user.id,
            username=user.username,
            correlation_id=context.correlation_id,
            user_agent=context.user_agent,
            ip_address=context.client_ip,
            changed_at=datetime.now(timezone.utc)
        )
        
        await self._publish_domain_event(event, context, logger)

    async def _validate_operation_prerequisites(self, context: ServiceContext) -> None:
        """Validate operation prerequisites for password change.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        # Password change service requires user repository to be available
        if not self._user_repository:
            raise AuthenticationError(
                get_translated_message("service_unavailable", context.language)
            ) 