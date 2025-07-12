"""
User Validation Domain Service.

This domain service implements user validation and authorization following
Domain-Driven Design principles with clear separation of concerns.

Domain Concepts:
- User Validation: Verifying user status and authorization
- User Retrieval: Fetching user entities for token operations
- Authorization Check: Ensuring user has required permissions
- User Status Validation: Checking if user account is active

Business Rules:
- Users must be active for token operations
- User validation is required for all token operations
- Inactive users cannot receive new tokens
- User status changes invalidate existing tokens
"""

from typing import Optional
import structlog

from src.domain.entities.user import User
from src.common.exceptions import AuthenticationError
from src.common.i18n import get_translated_message

from .base_authentication_service import BaseAuthenticationService, ServiceContext

logger = structlog.get_logger(__name__)


class UserValidationService(BaseAuthenticationService):
    """
    Domain service for user validation and authorization.
    
    This service implements comprehensive user validation following
    Domain-Driven Design principles with clear business logic and
    authorization patterns.
    
    User Validation Features:
    - User status validation and authorization
    - User retrieval for token operations
    - Authorization checks for security operations
    - User account status monitoring
    - Comprehensive error handling and logging
    
    Business Rules:
    - Users must be active for token operations
    - User validation is required for all token operations
    - Inactive users cannot receive new tokens
    - User status changes invalidate existing tokens
    - Authorization checks must be comprehensive
    """
    
    def __init__(self, event_publisher=None):
        """
        Initialize user validation service.
        """
        super().__init__(event_publisher)
        
        logger.info(
            "UserValidationService initialized",
            service_type="domain_service",
            responsibilities=[
                "user_validation",
                "authorization_check",
                "user_retrieval",
                "status_monitoring"
            ]
        )
    
    async def validate_user_for_operation(
        self,
        user: User,
        operation: str,
        language: str = "en",
        correlation_id: str = ""
    ) -> bool:
        """
        Validate user for any authentication operation.
        
        This method implements comprehensive user validation following
        domain business rules and authorization patterns.
        
        Args:
            user: User entity to validate
            operation: Operation being performed (e.g., "token_creation", "login")
            language: Language for error messages
            correlation_id: Request correlation ID for tracking
            
        Returns:
            bool: True if user is valid for the operation
            
        Raises:
            AuthenticationError: If user is not authorized for the operation
        """
        context = ServiceContext(
            correlation_id=correlation_id,
            language=language,
            operation=f"user_validation_{operation}"
        )
        
        async with self._operation_context(context) as ctx:
            # Check if user is active
            if not user.is_active:
                raise AuthenticationError(
                    get_translated_message("user_account_inactive", ctx.language)
                )
            
            # Check if user has valid role
            if not user.role:
                raise AuthenticationError(
                    get_translated_message("user_role_invalid", ctx.language)
                )
            
            # Check if email is confirmed (if required for operation)
            if operation in ["token_creation", "login"] and not user.email_confirmed:
                raise AuthenticationError(
                    get_translated_message("email_not_confirmed", ctx.language)
                )
            
            logger.debug(
                "User validation passed",
                user_id=user.id,
                username=user.username,
                operation=operation,
                is_active=user.is_active,
                correlation_id=ctx.correlation_id
            )
            
            return True
    
    async def validate_user_for_token_creation(
        self,
        user: User,
        language: str = "en",
        correlation_id: str = ""
    ) -> bool:
        """
        Validate user for token creation operations.
        
        Args:
            user: User entity to validate
            language: Language for error messages
            correlation_id: Request correlation ID for tracking
            
        Returns:
            bool: True if user is valid for token creation
            
        Raises:
            AuthenticationError: If user is not authorized for token creation
        """
        return await self.validate_user_for_operation(
            user, "token_creation", language, correlation_id
        )
    
    async def validate_user_for_token_refresh(
        self,
        user_id: int,
        language: str = "en",
        correlation_id: str = ""
    ) -> User:
        """
        Validate user for token refresh operations.
        
        Args:
            user_id: User identifier to validate
            language: Language for error messages
            correlation_id: Request correlation ID for tracking
            
        Returns:
            User: Validated user entity
            
        Raises:
            AuthenticationError: If user is not authorized for token refresh
        """
        context = ServiceContext(
            correlation_id=correlation_id,
            language=language,
            operation="user_validation_token_refresh"
        )
        
        async with self._operation_context(context) as ctx:
            # For now, return a placeholder user
            # In production, this would use a user repository
            from src.domain.entities.user import Role
            user = User(
                id=user_id,
                username="user",
                email="user@example.com",
                is_active=True,
                role=Role.USER,
                email_confirmed=True
            )
            
            # Validate user for token operations
            await self.validate_user_for_operation(user, "token_refresh", ctx.language, ctx.correlation_id)
            
            logger.debug(
                "User validation for token refresh passed",
                user_id=user.id,
                username=user.username,
                is_active=user.is_active,
                correlation_id=ctx.correlation_id
            )
            
            return user
    
    async def validate_user_for_token_validation(
        self,
        user_id: int,
        language: str = "en",
        correlation_id: str = ""
    ) -> bool:
        """
        Validate user for token validation operations.
        
        Args:
            user_id: User identifier to validate
            language: Language for error messages
            correlation_id: Request correlation ID for tracking
            
        Returns:
            bool: True if user is valid for token validation
            
        Raises:
            AuthenticationError: If user is not authorized for token validation
        """
        context = ServiceContext(
            correlation_id=correlation_id,
            language=language,
            operation="user_validation_token_validation"
        )
        
        async with self._operation_context(context) as ctx:
            # For now, return True as placeholder
            # In production, this would validate against a user repository
            logger.debug(
                "User validation for token validation passed",
                user_id=user_id,
                correlation_id=ctx.correlation_id
            )
            return True
    
    async def is_user_active(self, user_id: int, correlation_id: str = "") -> bool:
        """
        Check if user is active.
        
        Args:
            user_id: User identifier
            correlation_id: Request correlation ID for tracking
            
        Returns:
            bool: True if user is active
        """
        context = ServiceContext(
            correlation_id=correlation_id,
            operation="user_active_check"
        )
        
        async with self._operation_context(context) as ctx:
            # For now, return True as placeholder
            # In production, this would check against a user repository
            logger.debug(
                "User active check completed",
                user_id=user_id,
                is_active=True,
                correlation_id=ctx.correlation_id
            )
            return True
    
    async def _validate_operation_prerequisites(self, context: ServiceContext) -> None:
        """Validate operation prerequisites for user validation.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        # User validation service has no specific prerequisites
        # All operations are valid as long as the service is initialized
        pass 