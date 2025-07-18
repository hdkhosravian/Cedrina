"""Core application components.

This module provides centralized access to core application components
following clean architecture principles.
"""

from .application import create_application
from .initialization import initialize_application
from .exceptions import (
    CedrinaError,
    AuthenticationError,
    SecurityViolationError,
    DatabaseError,
    UserAlreadyExistsError,
    InvalidCredentialsError,
    PasswordPolicyError,
    RateLimitError,
    RateLimitExceededError,
    DuplicateUserError,
    PermissionError,
    PasswordValidationError,
    InvalidOldPasswordError,
    PasswordReuseError,
    EmailServiceError,
    TemplateRenderError,
    PasswordResetError,
    ForgotPasswordError,
    UserNotFoundError,
    ValidationError,
    SessionLimitExceededError,
    EncryptionError,
    DecryptionError,
)

__all__ = [
    # Application factory
    "create_application",
    "initialize_application",
    
    # Core exceptions
    "CedrinaError",
    "AuthenticationError",
    "SecurityViolationError",
    "DatabaseError",
    "UserAlreadyExistsError",
    "InvalidCredentialsError",
    "PasswordPolicyError",
    "RateLimitError",
    "RateLimitExceededError",
    "DuplicateUserError",
    "PermissionError",
    "PasswordValidationError",
    "InvalidOldPasswordError",
    "PasswordReuseError",
    "EmailServiceError",
    "TemplateRenderError",
    "PasswordResetError",
    "ForgotPasswordError",
    "UserNotFoundError",
    "ValidationError",
    "SessionLimitExceededError",
    "EncryptionError",
    "DecryptionError",
]
