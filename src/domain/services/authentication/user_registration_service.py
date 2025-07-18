"""User Registration Domain Service.

This service handles user registration operations following Domain-Driven Design
principles and single responsibility principle.
"""

from typing import Optional, Union

import structlog
import asyncio
import uuid

from src.core.config.settings import settings

from src.common.exceptions import DuplicateUserError, PasswordPolicyError
from src.domain.entities.user import Role, User
from src.domain.events.authentication_events import UserRegisteredEvent
from src.domain.interfaces.repositories import IUserRepository
from src.common.events import IEventPublisher
from src.domain.interfaces import (
    IUserRegistrationService,
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
)
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import HashedPassword, Password
from src.domain.value_objects.username import Username
from src.common.i18n import get_translated_message
from src.domain.services.email_confirmation.email_confirmation_request_service import (
    EmailConfirmationRequestService,
)

from .base_authentication_service import BaseAuthenticationService, ServiceContext
from src.common.exceptions import AuthenticationError

logger = structlog.get_logger(__name__)


class UserRegistrationService(IUserRegistrationService, BaseAuthenticationService):
    """Domain service for user registration operations.
    
    This service handles only registration-related operations,
    following the single responsibility principle from clean architecture.
    
    Responsibilities:
    - Register new users with validation
    - Check username and email availability
    - Publish registration events
    - Enforce business rules for registration
    
    Security Features:
    - Strong password policy enforcement
    - Username and email validation
    - Duplicate prevention
    - Registration event logging
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
        confirmation_token_service: IEmailConfirmationTokenService | None = None,
        confirmation_email_service: IEmailConfirmationEmailService | None = None,
    ):
        """Initialize registration service with dependencies.
        
        Args:
            user_repository: Repository for user data access
            event_publisher: Publisher for domain events
            confirmation_token_service: Service for email confirmation tokens
            confirmation_email_service: Service for sending confirmation emails
        """
        super().__init__(event_publisher)
        self._user_repository = user_repository
        self._confirmation_token_service = confirmation_token_service
        self._confirmation_email_service = confirmation_email_service

        # Initialize logger with session and task tracking.
        self._logger = structlog.get_logger(f"{__name__}.UserRegistrationService")
        self._session_id = id(self)
        
        # Safely get task ID - handle case where no event loop is running
        try:
            current_task = asyncio.current_task()
            self._task_id = current_task.get_name() if current_task else "no_event_loop"
        except RuntimeError:
            # No event loop running during initialization
            self._task_id = "no_event_loop"

        self._logger.info(
            "UserRegistrationService initialized",
            session_id=self._session_id,
            task_id=self._task_id
        )
    
    async def register_user(
        self,
        username: Union[Username, str],
        email: Union[Email, str],
        password: Union[Password, str],
        language: str = "en",
        correlation_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        role: Role = Role.USER,
    ) -> User:
        """Register a new user with comprehensive validation.
        
        Args:
            username: Username value object
            email: Email value object
            password: Password value object
            language: Language code for I18N
            correlation_id: Optional correlation ID for tracking
            user_agent: Browser/client user agent
            ip_address: Client IP address
            role: User role (defaults to USER)
            
        Returns:
            User: Newly created user entity
            
        Raises:
            DuplicateUserError: If username or email already exists
            PasswordPolicyError: If password doesn't meet requirements
            ValueError: If input validation fails
        """
        # Ensure correlation_id is always non-empty for event traceability
        if not correlation_id or not str(correlation_id).strip():
            correlation_id = str(uuid.uuid4())
        context = ServiceContext(
            correlation_id=correlation_id,
            language=language,
            client_ip=ip_address,
            user_agent=user_agent,
            operation="user_registration"
        )
        
        # Convert strings to value objects if needed
        if isinstance(username, str):
            username = Username(username)
        if isinstance(email, str):
            email = Email(email)
        if isinstance(password, str):
            password = Password(password, language=language)
            
        async with self._operation_context(context) as ctx:
            logger.info(
                "User registration started",
                username=username.mask_for_logging(),
                email=email.mask_for_logging(),
                correlation_id=ctx.correlation_id,
                ip_address=self._mask_ip(ip_address or ""),
            )
            
            # Check for existing username
            if not await self.check_username_availability(str(username)):
                logger.warning(
                    "Registration failed - username already exists",
                    username=username.mask_for_logging(),
                    correlation_id=ctx.correlation_id,
                )
                raise DuplicateUserError(
                    get_translated_message("username_already_registered", ctx.language)
                )
            
            # Check for existing email
            if not await self.check_email_availability(str(email)):
                logger.warning(
                    "Registration failed - email already exists",
                    email=email.mask_for_logging(),
                    correlation_id=ctx.correlation_id,
                )
                raise DuplicateUserError(
                    get_translated_message("email_already_registered", ctx.language)
                )
            
            # Create hashed password
            hashed_password = password.to_hashed()
            
            # Create user entity
            user = User(
                username=str(username),
                email=str(email),
                hashed_password=hashed_password.value,
                role=role,
                is_active=not settings.EMAIL_CONFIRMATION_ENABLED,
                email_confirmed=not settings.EMAIL_CONFIRMATION_ENABLED,
            )
            
            # Save user to repository
            saved_user = await self._user_repository.save(user)

            if settings.EMAIL_CONFIRMATION_ENABLED and self._confirmation_token_service and self._confirmation_email_service:
                await EmailConfirmationRequestService(
                    self._user_repository,
                    self._confirmation_token_service,
                    self._confirmation_email_service,
                ).send_confirmation_email(saved_user, ctx.language)
            
            # Publish registration event
            await self._publish_registration_event(saved_user, ctx)
            
            logger.info(
                "User registration successful",
                user_id=saved_user.id,
                username=username.mask_for_logging(),
                email=email.mask_for_logging(),
                correlation_id=ctx.correlation_id,
            )
            
            return saved_user
    
    async def check_username_availability(self, username: str) -> bool:
        """Check if username is available for registration.
        
        Args:
            username: Username to check
            
        Returns:
            bool: True if username is available
        """
        try:
            # Normalize username using value object
            username_vo = Username(username)
            
            # Check if user exists
            existing_user = await self._user_repository.get_by_username(str(username_vo))
            is_available = existing_user is None
            
            logger.debug(
                "Username availability check",
                username=username_vo.mask_for_logging(),
                available=is_available,
            )
            
            return is_available
            
        except ValueError:
            # Invalid username format
            return False
        except Exception as e:
            logger.error(
                "Username availability check error",
                username=username[:3] + "***" if username else "None",
                error=str(e),
            )
            return False
    
    async def check_email_availability(self, email: str) -> bool:
        """Check if email is available for registration.
        
        Args:
            email: Email to check
            
        Returns:
            bool: True if email is available
        """
        try:
            # Normalize email using value object
            email_vo = Email(email)
            
            # Check if user exists
            existing_user = await self._user_repository.get_by_email(str(email_vo))
            is_available = existing_user is None
            
            logger.debug(
                "Email availability check",
                email=email_vo.mask_for_logging(),
                available=is_available,
            )
            
            return is_available
            
        except ValueError:
            # Invalid email format
            return False
        except Exception as e:
            logger.error(
                "Email availability check error",
                email=email[:3] + "***" if email else "None",
                error=str(e),
            )
            return False
    
    async def _publish_registration_event(
        self,
        user: User,
        context: ServiceContext,
    ) -> None:
        """Publish domain event for user registration.
        
        Args:
            user: Newly registered user
            context: Service context
        """
        event = UserRegisteredEvent(
            user_id=user.id,
            email=user.email,
            correlation_id=context.correlation_id,
            ip_address=context.client_ip,
            user_agent=context.user_agent
        )
        
        await self._publish_domain_event(event, context, logger)
    
    async def _validate_operation_prerequisites(self, context: ServiceContext) -> None:
        """Validate operation prerequisites for user registration.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        # User registration service requires user repository to be available
        if not self._user_repository:
            raise AuthenticationError(
                get_translated_message("service_unavailable", context.language)
            ) 