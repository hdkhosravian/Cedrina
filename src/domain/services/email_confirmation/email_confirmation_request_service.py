"""Domain service for sending and resending email confirmation messages."""

from typing import Optional

import structlog

from src.common.exceptions import EmailServiceError
from src.domain.entities.user import User
from src.domain.interfaces import (
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
    IUserRepository,
)
from src.domain.value_objects.security_context import SecurityContext
from src.common.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class EmailConfirmationRequestService:
    """Coordinate generation and delivery of email confirmation tokens."""
    def __init__(
        self,
        user_repository: IUserRepository,
        token_service: IEmailConfirmationTokenService,
        email_service: IEmailConfirmationEmailService,
    ) -> None:
        self._user_repository = user_repository
        self._token_service = token_service
        self._email_service = email_service

    async def send_confirmation_email(
        self, user: User, language: str = "en"
    ) -> bool:
        """Generate a confirmation token and send a confirmation email.

        Args:
            user: The user requiring confirmation.
            language: Preferred language for email content.

        Returns:
            ``True`` if the email was queued successfully, ``False`` otherwise.
        """
        # Create security context for token generation
        security_context = SecurityContext.create_for_request(
            client_ip="127.0.0.1",
            user_agent="system",
            correlation_id=""
        )
        
        token = await self._token_service.generate_token(user, security_context)
        await self._user_repository.save(user)
        try:
            await self._email_service.send_confirmation_email(user, token, security_context, language)
            return True
        except EmailServiceError as e:
            logger.error("Confirmation email sending failed", error=str(e))
            return False

    async def resend_confirmation_email(
        self, email: str, language: str = "en"
    ) -> None:
        """Resend a confirmation email if the user is still inactive."""

        user = await self._user_repository.get_by_email(email)
        if user and not user.is_active:
            await self.send_confirmation_email(user, language)
