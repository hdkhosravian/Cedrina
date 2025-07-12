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
        security_context: SecurityContext,
        language: str = "en"
    ) -> None:
        """Logs a user out by revoking their tokens and session.

        This method ensures secure logout by:
        1. Validating the access token
        2. Revoking the token and associated refresh tokens
        3. Clearing any server-side session data
        4. Publishing UserLoggedOut domain event
        5. Recording security context for audit trails

        Args:
            access_token: The user's `AccessToken` to be revoked.
            user: The `User` entity who is logging out.
            security_context: Validated security context for audit trails.
            language: The language for any potential messages.

        Raises:
            TokenRevocationError: If token revocation fails
            ValidationError: If security context is invalid
        """
        raise NotImplementedError 