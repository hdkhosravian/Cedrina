"""Infrastructure Services Module.

This module provides concrete implementations of infrastructure services following
clean architecture principles. These services handle technical concerns like
authentication, email, and data persistence.

Services:
- Authentication Services: Token management, session handling, OAuth integration
- Email Services: Password reset and confirmation email handling
- Password Reset Services: Token generation and email delivery
- Event Publishing: Domain event publishing for audit trails

All services implement domain interfaces and are injected through dependency
injection containers, following the dependency inversion principle.
"""

from .authentication import (
    DomainTokenService,
    UnifiedSessionService,
    OAuthService,
    PasswordEncryptionService,
)
from .password_reset_email_service import PasswordResetEmailService
from .password_reset_token_service import PasswordResetTokenService
from .email_confirmation_token_service import EmailConfirmationTokenService
from .email_confirmation_email_service import EmailConfirmationEmailService
from .event_publisher import InMemoryEventPublisher

__all__ = [
    "DomainTokenService",
    "UnifiedSessionService",
    "OAuthService",
    "PasswordEncryptionService",
    "PasswordResetEmailService",
    "PasswordResetTokenService",
    "EmailConfirmationTokenService",
    "EmailConfirmationEmailService",
    "InMemoryEventPublisher",
] 