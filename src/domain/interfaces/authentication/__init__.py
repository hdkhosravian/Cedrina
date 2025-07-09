"""Authentication Interfaces.

This module defines interfaces for authentication-related services following
Domain-Driven Design principles and dependency inversion.
"""

# Core authentication interfaces
from .user_authentication import IUserAuthenticationService
from .user_registration import IUserRegistrationService
from .user_logout import IUserLogoutService
from .password_change import IPasswordChangeService

# Password management interfaces
from .password_reset import (
    IPasswordResetTokenService,
    IPasswordResetEmailService,
    IPasswordResetRequestService,
    IPasswordResetService,
)
from .email_confirmation import (
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
    IEmailConfirmationRequestService,
    IEmailConfirmationService,
)

# OAuth interfaces
from .oauth import IOAuthService
from .error_classification import IErrorClassificationService

__all__ = [
    # Core authentication interfaces
    "IUserAuthenticationService",
    "IUserRegistrationService",
    "IUserLogoutService",
    "IPasswordChangeService",
    
    # Password management interfaces
    "IPasswordResetTokenService",
    "IPasswordResetEmailService",
    "IPasswordResetRequestService",
    "IPasswordResetService",
    "IEmailConfirmationTokenService",
    "IEmailConfirmationEmailService",
    "IEmailConfirmationRequestService",
    "IEmailConfirmationService",

    # OAuth interfaces
    "IOAuthService",
    "IErrorClassificationService",
]
