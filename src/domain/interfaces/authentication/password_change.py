"""Password change service interface.

This module defines the password change service interface following
Domain-Driven Design principles. This interface encapsulates the business
logic for user password change operations.

Key DDD Principles Applied:
- Single Responsibility: Handles only password change logic
- Domain Value Objects: Uses Password and SecurityContext value objects
- Domain Events: Publishes PasswordChanged event
- Ubiquitous Language: Method names reflect business concepts
"""

from abc import ABC, abstractmethod


class IPasswordChangeService(ABC):
    """Interface for user password change operations.
    
    This domain service encapsulates the logic for securely changing a user's
    password. It ensures that the user is properly authenticated (by verifying
    their old password) and that the new password adheres to all defined
    password policies. It publishes a `PasswordChanged` event on success.
    
    DDD Principles:
    - Single Responsibility: Handles only password change logic
    - Domain Value Objects: Uses Password value objects for validation
    - Domain Events: Publishes PasswordChanged event
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure password validation and audit trails
    """

    @abstractmethod
    async def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Changes a user's password after verifying their current one.

        This method ensures secure password change by:
        1. Validating the user exists and is active
        2. Verifying the old password is correct
        3. Validating the new password meets policy requirements
        4. Securely updating the password hash
        5. Publishing PasswordChanged domain event
        6. Recording security context for audit trails

        Args:
            user_id: The ID of the user changing their password.
            old_password: The user's current password for verification.
            new_password: The desired new password.
            language: The language for error messages (i18n).
            client_ip: Client IP address for audit trails.
            user_agent: User agent string for audit trails.
            correlation_id: Correlation ID for request tracking.

        Raises:
            AuthenticationError: If the user_id does not correspond to an existing user.
            InvalidOldPasswordError: If the provided `old_password` is incorrect.
            PasswordReuseError: If the `new_password` is the same as the old one.
            PasswordPolicyError: If the `new_password` does not meet policy requirements.
            ValueError: If input parameters are invalid.
        """
        raise NotImplementedError 