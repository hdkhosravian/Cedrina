"""
User Repository Interface.

This module defines the abstract interface for user persistence operations,
following domain-driven design principles and clean architecture patterns.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from src.domain.entities.user import User


class IUserRepository(ABC):
    """Interface defining the contract for user persistence operations.

    This repository is responsible for managing the lifecycle of the `User`
    aggregate root. It provides a collection-like interface for accessing and
    storing `User` entities, abstracting the underlying data store.

    Following DDD principles, this interface belongs to the domain layer and
    defines the contract that infrastructure implementations must fulfill.
    """

    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Retrieves a user by their unique identifier.

        Args:
            user_id: The unique integer ID of the user.

        Returns:
            An optional `User` entity. Returns `None` if no user is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Retrieves a user by their username (case-insensitively).

        Args:
            username: The username to search for.

        Returns:
            An optional `User` entity. Returns `None` if no user is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieves a user by their email address (case-insensitively).

        Args:
            email: The email address to search for.

        Returns:
            An optional `User` entity. Returns `None` if no user is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_reset_token(self, token: str) -> Optional[User]:
        """Retrieves a user by a valid password reset token.

        Args:
            token: The password reset token to search for.

        Returns:
            An optional `User` entity. Returns `None` if the token is invalid
            or does not correspond to any user.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_by_confirmation_token(self, token: str) -> Optional[User]:
        """Retrieve a user by email confirmation token.

        Args:
            token: The email confirmation token to search for.

        Returns:
            An optional `User` entity. Returns `None` if the token is invalid
            or does not correspond to any user.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_users_with_reset_tokens(self) -> List[User]:
        """Retrieves all users who have an active password reset token.

        Returns:
            A list of `User` entities that have a non-expired reset token.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def save(self, user: User) -> User:
        """Persists a new user or updates an existing one.

        This method handles both creation and updates. If the `User` entity has
        an ID, it's an update; otherwise, it's a new creation.

        Args:
            user: The `User` entity to persist.

        Returns:
            The persisted `User` entity, potentially with updated state
            (e.g., a new ID or updated timestamps).
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, user: User) -> None:
        """Deletes a user from the repository.

        Args:
            user: The `User` entity to delete.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """Checks if a username is already in use.

        Args:
            username: The username to check.

        Returns:
            `True` if the username is available, `False` otherwise.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """Checks if an email address is already in use.

        Args:
            email: The email address to check.

        Returns:
            `True` if the email is available, `False` otherwise.
        """
        raise NotImplementedError 