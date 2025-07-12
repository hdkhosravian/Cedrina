"""Common exception classes for the Cedrina application.

This module defines all custom exceptions used throughout the application,
following a hierarchical structure that maps to appropriate HTTP status codes.

This module must not import from any other part of the codebase.
"""

from dataclasses import dataclass
from typing import Final

__all__: Final = [
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

class CedrinaError(Exception):
    """Base exception class for all custom errors in the Cedrina application."""
    message: str
    code: str = "generic_error"
    def __init__(self, message: str, code: str = "generic_error"):
        self.message = message
        self.code = code
        Exception.__init__(self, self.message)
    def __str__(self) -> str:
        return self.message

class AuthenticationError(CedrinaError):
    def __init__(self, message: str, code: str = "authentication_error"):
        super().__init__(message, code)

class InvalidCredentialsError(AuthenticationError):
    def __init__(self, message: str, code: str = "invalid_credentials"):
        super().__init__(message, code)

class SecurityViolationError(AuthenticationError):
    def __init__(self, message: str, code: str = "security_violation"):
        super().__init__(message, code)

class PermissionError(CedrinaError):
    def __init__(self, message: str, code: str = "permission_denied"):
        super().__init__(message, code)

class ValidationError(CedrinaError):
    def __init__(self, message: str, code: str = "validation_error"):
        super().__init__(message, code)

class PasswordValidationError(ValidationError):
    def __init__(self, message: str, code: str = "password_validation_error"):
        super().__init__(message, code)

class InvalidOldPasswordError(PasswordValidationError):
    def __init__(self, message: str, code: str = "invalid_old_password"):
        super().__init__(message, code)

class PasswordReuseError(PasswordValidationError):
    def __init__(self, message: str, code: str = "password_reuse_error"):
        super().__init__(message, code)

class DatabaseError(CedrinaError):
    def __init__(self, message: str, code: str = "database_error"):
        super().__init__(message, code)

class UserAlreadyExistsError(CedrinaError):
    def __init__(self, message: str, code: str = "user_already_exists"):
        super().__init__(message, code)

class PasswordPolicyError(ValidationError):
    def __init__(self, message: str, code: str = "password_policy_error"):
        super().__init__(message, code)

class RateLimitError(CedrinaError):
    def __init__(self, message: str | None = None, code: str = "rate_limit_exceeded"):
        super().__init__(message or "Rate limit exceeded", code)

class RateLimitExceededError(RateLimitError):
    def __init__(self, message: str | None = None, code: str = "rate_limit_exceeded"):
        super().__init__(message, code)

class DuplicateUserError(UserAlreadyExistsError):
    def __init__(self, message: str, code: str = "duplicate_user_error"):
        super().__init__(message, code)

class EmailServiceError(CedrinaError):
    def __init__(self, message: str, code: str = "email_service_error"):
        super().__init__(message, code)

class TemplateRenderError(EmailServiceError):
    def __init__(self, message: str, code: str = "template_render_error"):
        super().__init__(message, code)

class PasswordResetError(CedrinaError):
    def __init__(self, message: str, code: str = "password_reset_error"):
        super().__init__(message, code)

class ForgotPasswordError(PasswordResetError):
    def __init__(self, message: str, code: str = "forgot_password_error"):
        super().__init__(message, code)

class UserNotFoundError(CedrinaError):
    def __init__(self, message: str = "User not found", code: str = "user_not_found"):
        super().__init__(message, code)

class SessionLimitExceededError(AuthenticationError):
    def __init__(self, message: str, code: str = "session_limit_exceeded"):
        super().__init__(message, code)

class EncryptionError(CedrinaError):
    message: str = "A critical error occurred during data encryption."
    code: str = "encryption_error"
    def __init__(self, message: str = "A critical error occurred during data encryption.", code: str = "encryption_error"):
        super().__init__(message, code)

class DecryptionError(CedrinaError):
    message: str = "A critical error occurred during data decryption."
    code: str = "decryption_error"
    def __init__(self, message: str = "A critical error occurred during data decryption.", code: str = "decryption_error"):
        super().__init__(message, code) 