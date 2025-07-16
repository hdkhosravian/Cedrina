"""Infrastructure Services Module.

This module provides concrete implementations of infrastructure services following
clean architecture principles. These services handle technical concerns like
authentication, email, and data persistence.

Services:
- Authentication Services: Token management, session handling, OAuth integration
- Email Services: Password reset and confirmation email handling
- Password Reset Services: Token generation and email delivery
- Event Publishing: Domain event publishing for audit trails
- Security Services: Field encryption and data protection

All services implement domain interfaces and are injected through dependency
injection containers, following the dependency inversion principle.

Key Features:
- Base Infrastructure Service: Common functionality for all services
- Structured logging with service context
- Standardized error handling and conversion
- Security context validation
- Configuration management
"""

# Authentication Services
from .authentication import (
    DomainTokenService,
    JWTService,
    UnifiedSessionService,
    OAuthService,
    PasswordEncryptionService,
)

# Email Services
from .password_reset_email_service import PasswordResetEmailService
from .password_reset_token_service import PasswordResetTokenService
from .email_confirmation_token_service import EmailConfirmationTokenService
from .email_confirmation_email_service import EmailConfirmationEmailService

# Event Publishing
from .event_publisher import InMemoryEventPublisher

# Base Infrastructure Service
from .base_service import BaseInfrastructureService

# Security Services
from .security import FieldEncryptionService

__all__ = [
    # Base Infrastructure Service
    "BaseInfrastructureService",
    
    # Authentication Services
    "DomainTokenService",
    "JWTService",
    "UnifiedSessionService",
    "OAuthService",
    "PasswordEncryptionService",
    
    # Email Services
    "PasswordResetEmailService",
    "PasswordResetTokenService",
    "EmailConfirmationTokenService",
    "EmailConfirmationEmailService",
    
    # Event Publishing
    "InMemoryEventPublisher",
    
    # Security Services
    "FieldEncryptionService",
] 