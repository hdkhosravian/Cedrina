"""User logout service interface.

This module defines the user logout service interface following
Domain-Driven Design principles. This interface encapsulates the business
logic for user logout operations.

Key DDD Principles Applied:
- Single Responsibility: Handles only logout logic
- Domain Value Objects: Uses AccessToken and SecurityContext value objects
- Domain Events: Publishes UserLoggedOut event
- Ubiquitous Language: Method names reflect business concepts
"""

from abc import ABC, abstractmethod

from src.domain.entities.user import User
from src.domain.value_objects.jwt_token import AccessToken
from src.domain.value_objects.security_context import SecurityContext


class IUserLogoutService(ABC):
    """Interface for user logout operations.
    
    This domain service encapsulates the logic for securely logging a user out
    of the system. This is not just about clearing client-side state; it
    involves server-side revocation of tokens and sessions to ensure that
    compromised tokens cannot be reused. It also publishes a `UserLoggedOut`
    event for auditing purposes.
    
    DDD Principles:
    - Single Responsibility: Handles only logout logic
    - Domain Value Objects: Uses AccessToken and SecurityContext value objects
    - Domain Events: Publishes UserLoggedOut event
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure token revocation and audit trails
    """

    @abstractmethod
    async def logout_user(
        self,
        access_token: AccessToken,
        user: User,
        language: str = "en",
        client_ip: str = None,
        user_agent: str = None,
        correlation_id: str = None,
    ) -> None:
        """Logs a user out by revoking both access and refresh tokens.

        This method ensures secure logout by:
        1. Validating the access token
        2. Finding the associated refresh token from the access token
        3. Revoking both tokens to prevent future use
        4. Clearing any server-side session data
        5. Publishing UserLoggedOut domain event
        6. Recording security context for audit trails

        Args:
            access_token: The user's `AccessToken` to be revoked.
            user: The `User` entity who is logging out.
            language: The language for any potential messages.
            client_ip: Client IP address for security logging.
            user_agent: User agent string for security logging.
            correlation_id: Correlation ID for request tracking.

        Raises:
            TokenRevocationError: If token revocation fails
            ValidationError: If security context is invalid
        """
        raise NotImplementedError 