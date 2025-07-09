"""Email confirmation service interfaces."""
from abc import ABC, abstractmethod
from typing import Dict, Optional

from src.domain.entities.user import User
from src.domain.value_objects.confirmation_token import ConfirmationToken


class IEmailConfirmationTokenService(ABC):
    @abstractmethod
    async def generate_token(self, user: User) -> ConfirmationToken:
        """Generate a confirmation token and assign to user."""
        raise NotImplementedError

    @abstractmethod
    def validate_token(self, user: User, token: str) -> bool:
        """Validate provided confirmation token."""
        raise NotImplementedError

    @abstractmethod
    def invalidate_token(self, user: User) -> None:
        """Invalidate confirmation token."""
        raise NotImplementedError


class IEmailConfirmationEmailService(ABC):
    @abstractmethod
    async def send_confirmation_email(
        self, user: User, token: ConfirmationToken, language: str = "en"
    ) -> bool:
        """Send email confirmation message."""
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
        self, user: User, language: str = "en"
    ) -> bool:
        """Generate a confirmation token and send a confirmation email.

        Args:
            user: The user requiring confirmation.
            language: Preferred language for email content.

        Returns:
            True if the email was queued successfully, False otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    async def resend_confirmation_email(
        self, email: str, language: str = "en"
    ) -> None:
        """Resend a confirmation email if the user is still inactive.

        Args:
            email: Email address of the user requiring confirmation.
            language: Preferred language for email content.
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
    async def confirm_email(self, token: str, language: str = "en") -> User:
        """Confirm a user's email using the provided token.

        Args:
            token: Confirmation token received from the user.
            language: Language code used for translated messages.

        Returns:
            The updated User entity with is_active and email_confirmed set to True.

        Raises:
            UserNotFoundError: If no matching user is found or the token is invalid.
        """
        raise NotImplementedError
