"""User registration service interface.

This module defines the user registration service interface following
Domain-Driven Design principles. This interface encapsulates the business
logic for user registration operations.

Key DDD Principles Applied:
- Single Responsibility: Handles only user registration logic
- Domain Value Objects: Uses Username, Email, Password, and SecurityContext value objects
- Domain Events: Publishes UserRegistered event
- Ubiquitous Language: Method names reflect business concepts
"""

from abc import ABC, abstractmethod
from typing import Optional

from src.domain.entities.user import Role, User
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username
from src.domain.value_objects.security_context import SecurityContext


class IUserRegistrationService(ABC):
    """Interface for user registration operations.
    
    This domain service encapsulates the business logic for creating a new user.
    It ensures that all invariants for a new user are met before persistence,
    such as checking for username and email availability. It also publishes a
    `UserRegistered` event upon successful creation.
    
    DDD Principles:
    - Single Responsibility: Handles only user registration logic
    - Domain Value Objects: Uses Username, Email, Password, and SecurityContext value objects
    - Domain Events: Publishes UserRegistered event
    - Ubiquitous Language: Method names reflect business concepts
    - Fail-Safe Security: Implements secure user creation and audit trails
    """

    @abstractmethod
    async def register_user(
        self,
        username: Username,
        email: Email,
        password: Password,
        security_context: SecurityContext,
        language: str = "en",
        role: Optional[Role] = None,
    ) -> User:
        """Creates and persists a new user.

        This method ensures secure user registration by:
        1. Validating all input value objects
        2. Checking username and email availability
        3. Securely hashing the password
        4. Creating the user entity with proper defaults
        5. Publishing UserRegistered domain event
        6. Recording security context for audit trails

        Args:
            username: The desired `Username` value object.
            email: The user's `Email` value object.
            password: The `Password` value object for the new account.
            security_context: Validated security context for audit trails.
            language: The language for any communication (e.g., welcome email).
            role: The `Role` to assign to the new user. Defaults to the
                standard user role if not provided.

        Returns:
            The newly created `User` entity.

        Raises:
            DuplicateUserError: If the chosen username or email is already in use.
            ValidationError: If security context is invalid.
        """
        raise NotImplementedError

    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """Checks if a username is available for a new registration.

        Args:
            username: The username to check.

        Returns:
            `True` if the username is available, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """Checks if an email address is available for a new registration.

        Args:
            email: The email address to check.

        Returns:
            `True` if the email is available, `False` otherwise.
        """
        raise NotImplementedError 