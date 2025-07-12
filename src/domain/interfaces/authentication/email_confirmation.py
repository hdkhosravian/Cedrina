"""Email confirmation service interfaces.

This module defines email confirmation service interfaces following
Domain-Driven Design principles. These interfaces encapsulate the business
logic for email confirmation workflows, token management, and user activation.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the email confirmation domain
- Interface Segregation: Clients depend only on interfaces they use
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional

from src.domain.entities.user import User
from src.domain.value_objects.confirmation_token import ConfirmationToken
from src.domain.value_objects.security_context import SecurityContext


class IEmailConfirmationTokenService(ABC):
    """Interface for email confirmation token lifecycle management.
    
    This service is responsible for the entire lifecycle of an email confirmation
    token, from secure generation to validation and invalidation. It acts as
    a centralized authority for managing the state of email confirmation requests.
    
    DDD Principles:
    - Single Responsibility: Handles only email confirmation token operations
    - Domain Value Objects: Uses ConfirmationToken and SecurityContext value objects
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure token generation and validation
    """
    
    @abstractmethod
    async def generate_token(self, user: User, security_context: SecurityContext) -> ConfirmationToken:
        """Generate a confirmation token and assign to user.
        
        Args:
            user: User entity for token generation
            security_context: Validated security context for audit trails
            
        Returns:
            ConfirmationToken: Generated confirmation token
            
        Raises:
            TokenGenerationError: If token generation fails
            ValidationError: If security context is invalid
        """
        raise NotImplementedError

    @abstractmethod
    def validate_token(self, user: User, token: str) -> bool:
        """Validate provided confirmation token.
        
        Args:
            user: User entity for token validation
            token: Token string to validate
            
        Returns:
            bool: True if token is valid, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    def invalidate_token(self, user: User) -> None:
        """Invalidate confirmation token.
        
        Args:
            user: User entity whose token should be invalidated
        """
        raise NotImplementedError


class IEmailConfirmationEmailService(ABC):
    """Interface for email confirmation email notifications.
    
    This service acts as an abstraction over the external email sending
    mechanism for email confirmations. It defines a simple contract for
    sending confirmation emails, allowing the domain logic to remain
    independent of the specific email provider or technology used.
    
    DDD Principles:
    - Single Responsibility: Handles only email confirmation email operations
    - Domain Value Objects: Uses ConfirmationToken and SecurityContext value objects
    - Ubiquitous Language: Method names reflect business concepts
    - Dependency Inversion: Abstracts external email infrastructure
    """
    
    @abstractmethod
    async def send_confirmation_email(
        self, user: User, token: ConfirmationToken, security_context: SecurityContext, language: str = "en"
    ) -> bool:
        """Send email confirmation message.
        
        Args:
            user: User entity for email sending
            token: Confirmation token to include in email
            security_context: Validated security context for audit trails
            language: Language code for email localization
            
        Returns:
            bool: True if email was sent successfully
            
        Raises:
            EmailDeliveryError: If email delivery fails
            ValidationError: If security context is invalid
        """
        raise NotImplementedError


class IEmailConfirmationRequestService(ABC):
    """Interface for email confirmation request orchestration.
    
    This service orchestrates the email confirmation request workflow,
    including token generation and email delivery for new user registrations
    and resend requests.
    
    DDD Principles:
    - Single Responsibility: Handles only email confirmation request orchestration
    - Ubiquitous Language: Method names reflect business concepts
    - Domain Events: Publishes events for audit trails and security monitoring
    - Fail-Safe Security: Implements secure token generation and delivery
    """

    @abstractmethod
    async def send_confirmation_email(
        self, user: User, security_context: SecurityContext, language: str = "en"
    ) -> bool:
        """Generate a confirmation token and send a confirmation email.

        Args:
            user: The user requiring confirmation.
            security_context: Validated security context for audit trails.
            language: Preferred language for email content.

        Returns:
            True if the email was queued successfully, False otherwise.
            
        Raises:
            EmailDeliveryError: If email delivery fails
            ValidationError: If security context is invalid
        """
        raise NotImplementedError

    @abstractmethod
    async def resend_confirmation_email(
        self, email: str, security_context: SecurityContext, language: str = "en"
    ) -> None:
        """Resend a confirmation email if the user is still inactive.

        Args:
            email: Email address of the user requiring confirmation.
            security_context: Validated security context for audit trails.
            language: Preferred language for email content.
            
        Raises:
            UserNotFoundError: If no user found with provided email
            ValidationError: If security context is invalid
        """
        raise NotImplementedError


class IEmailConfirmationService(ABC):
    """Interface for email confirmation execution.
    
    This service handles the execution of email confirmations using valid tokens,
    including token validation and user account activation.
    
    DDD Principles:
    - Single Responsibility: Handles only email confirmation execution
    - Ubiquitous Language: Method names reflect business concepts
    - Domain Events: Publishes events for audit trails and security monitoring
    - Fail-Safe Security: Implements token validation and account activation
    """

    @abstractmethod
    async def confirm_email(self, token: str, security_context: SecurityContext, language: str = "en") -> User:
        """Confirm a user's email using the provided token.

        Args:
            token: Confirmation token received from the user.
            security_context: Validated security context for audit trails.
            language: Language code used for translated messages.

        Returns:
            The updated User entity with is_active and email_confirmed set to True.

        Raises:
            UserNotFoundError: If no matching user is found or the token is invalid.
            ValidationError: If security context is invalid
        """
        raise NotImplementedError
