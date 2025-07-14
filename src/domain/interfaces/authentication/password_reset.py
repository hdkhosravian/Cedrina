"""Password reset service interfaces.

This module defines the password reset service interfaces following
Domain-Driven Design principles. These interfaces encapsulate the business
logic for password reset workflows, token management, and email notifications.

Key DDD Principles Applied:
- Single Responsibility: Each interface has one clear purpose
- Ubiquitous Language: Interface names reflect business domain concepts
- Dependency Inversion: Domain depends on abstractions, not concretions
- Bounded Context: All interfaces belong to the password reset domain
- Interface Segregation: Clients depend only on interfaces they use

Password Reset Domain Services:
- Password Reset Token Service: Secure token generation and validation
- Password Reset Email Service: Email notification and template rendering
- Password Reset Request Service: Orchestration of reset request workflow
- Password Reset Service: Execution of password reset with valid tokens
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional

from pydantic import EmailStr

from src.domain.entities.user import User
from src.domain.value_objects.reset_token import ResetToken
from src.domain.value_objects.security_context import SecurityContext


class IPasswordResetTokenService(ABC):
    """Interface for password reset token lifecycle management.
    
    This service is responsible for the entire lifecycle of a password reset
    token, from secure generation to validation and invalidation. It acts as
    a centralized authority for managing the state of password reset requests,
    ensuring they are handled securely and efficiently.
    
    DDD Principles:
    - Single Responsibility: Handles only password reset token operations
    - Domain Value Objects: Uses ResetToken and SecurityContext value objects
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure token generation and validation
    """

    @abstractmethod
    async def generate_token(self, user: User, security_context: SecurityContext) -> ResetToken:
        """Generates a secure, unique password reset token for a user.

        This method should create a cryptographically strong token, associate it
        with the user, and set an expiration time. It should also enforce rate
        limiting to prevent abuse.

        Args:
            user: The `User` entity for whom to generate the token.
            security_context: Security context for audit trails and rate limiting.

        Returns:
            A `ResetToken` value object containing the token and its metadata.

        Raises:
            RateLimitExceededError: If the user has requested too many tokens
                in a short period.
            ValidationError: If the user or security context is invalid.
        """
        raise NotImplementedError

    @abstractmethod
    async def validate_token(self, user: User, token: str, security_context: SecurityContext) -> bool:
        """Validates a password reset token provided by a user.

        This method should compare the provided token against the stored token
        hash in a secure, constant-time manner to prevent timing attacks. It
        should also check for token expiration.

        Args:
            user: The `User` entity associated with the token.
            token: The raw password reset token from the user.
            security_context: Security context for audit trails.

        Returns:
            `True` if the token is valid, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    async def invalidate_token(self, user: User, security_context: SecurityContext, reason: str = "used") -> None:
        """Invalidates a user's password reset token.

        This should be called after a successful password reset to ensure the
        token cannot be reused.

        Args:
            user: The `User` entity whose token should be invalidated.
            security_context: Security context for audit trails.
            reason: A string indicating why the token is being invalidated
                (e.g., "used", "expired").
        """
        raise NotImplementedError

    @abstractmethod
    async def is_token_expired(self, user: User, security_context: SecurityContext) -> bool:
        """Checks if a user's password reset token has expired.

        Args:
            user: The `User` entity to check.
            security_context: Security context for audit trails.

        Returns:
            `True` if the token is expired, `False` otherwise.
        """
        raise NotImplementedError


class IPasswordResetEmailService(ABC):
    """Interface for password reset email notifications.
    
    This service acts as an abstraction over the external email sending
    mechanism. It defines a simple contract for sending a password reset email,
    allowing the domain logic to remain independent of the specific email
    provider or technology used in the infrastructure layer.
    
    DDD Principles:
    - Single Responsibility: Handles only password reset email operations
    - Domain Value Objects: Uses ResetToken and SecurityContext value objects
    - Ubiquitous Language: Method names reflect business concepts
    - Dependency Inversion: Abstracts external email infrastructure
    """

    @abstractmethod
    async def send_password_reset_email(
        self, user: User, token: ResetToken, security_context: SecurityContext, language: str = "en"
    ) -> bool:
        """Sends a password reset email to the user.

        Args:
            user: The `User` entity to whom the email will be sent.
            token: The `ResetToken` to be included in the email link.
            security_context: Security context for audit trails.
            language: The preferred language for the email template.

        Returns:
            `True` if the email was sent successfully, `False` otherwise.

        Raises:
            EmailDeliveryError: If email delivery fails
            ValidationError: If the user, token, or security context is invalid.
        """
        raise NotImplementedError


class IPasswordResetRequestService(ABC):
    """Interface for password reset request orchestration.
    
    This service orchestrates the complete password reset request workflow,
    including user lookup, rate limiting, token generation, and email delivery.
    It acts as the primary entry point for password reset requests.
    
    DDD Principles:
    - Single Responsibility: Handles only password reset request orchestration
    - Ubiquitous Language: Method names reflect business concepts
    - Domain Events: Publishes events for audit trails and security monitoring
    - Fail-Safe Security: Implements rate limiting and enumeration protection
    """

    @abstractmethod
    async def request_password_reset(
        self,
        email: EmailStr,
        security_context: SecurityContext,
        language: str = "en",
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """Request a password reset for the given email address.
        
        This method orchestrates the complete password reset request workflow:
        1. Look up the user
        2. Check rate limits
        3. Generate secure token
        4. Send reset email
        5. Publish domain events
        
        Args:
            email: Email address to send password reset to
            security_context: Security context for audit trails and rate limiting
            language: Language code for email localization
            user_agent: Optional user agent for security tracking
            ip_address: Optional IP address for security tracking
            correlation_id: Optional correlation ID for request tracking
            
        Returns:
            Dict containing success message and status
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded
            EmailServiceError: If email delivery fails
            ForgotPasswordError: For other operational errors
            ValidationError: If the email or security context is invalid.
        """
        raise NotImplementedError


class IPasswordResetService(ABC):
    """Interface for password reset execution.
    
    This service handles the execution of password resets using valid tokens,
    including token validation, password strength checking, and user updates.
    It acts as the primary entry point for password reset execution.
    
    DDD Principles:
    - Single Responsibility: Handles only password reset execution
    - Ubiquitous Language: Method names reflect business concepts
    - Domain Events: Publishes events for audit trails and security monitoring
    - Fail-Safe Security: Implements secure token validation and password updates
    """

    @abstractmethod
    async def reset_password(
        self,
        token: str,
        new_password: str,
        security_context: SecurityContext,
        language: str = "en",
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """Reset user password using a valid token.
        
        This method handles the complete password reset execution workflow:
        1. Validate the reset token
        2. Check token expiration
        3. Validate new password strength
        4. Update user password
        5. Invalidate the token
        6. Publish domain events
        
        Args:
            token: The password reset token from the user
            new_password: The new password to set
            security_context: Security context for audit trails and validation
            language: Language code for error messages
            user_agent: Optional user agent for security tracking
            ip_address: Optional IP address for security tracking
            correlation_id: Optional correlation ID for request tracking
            
        Returns:
            Dict containing success message and status
            
        Raises:
            PasswordResetError: If password reset fails
            UserNotFoundError: If user associated with token is not found
            ForgotPasswordError: For other operational errors
            ValidationError: If the token, password, or security context is invalid.
        """
        raise NotImplementedError 