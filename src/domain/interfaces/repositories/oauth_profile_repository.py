"""
OAuth Profile Repository Interface.

This module defines the abstract interface for OAuth profile persistence operations,
following domain-driven design principles and clean architecture patterns.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from src.domain.entities.oauth_profile import OAuthProfile, Provider


class IOAuthProfileRepository(ABC):
    """Interface defining the contract for OAuth profile persistence.

    This repository manages the lifecycle of `OAuthProfile` entities, which link
    a `User` to an external authentication provider.

    Following DDD principles, this interface belongs to the domain layer and
    defines the contract that infrastructure implementations must fulfill.
    """
    
    @abstractmethod
    async def get_by_provider_and_user_id(
        self, 
        provider: Provider, 
        provider_user_id: str
    ) -> Optional[OAuthProfile]:
        """Retrieves an OAuth profile by provider and the provider-specific user ID.
        
        Args:
            provider: The OAuth provider (e.g., Google, Microsoft).
            provider_user_id: The user's unique identifier from that provider.
            
        Returns:
            An optional `OAuthProfile` entity. Returns `None` if no matching
            profile is found.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_user_id(self, user_id: int) -> List[OAuthProfile]:
        """Retrieves all OAuth profiles associated with a user.
        
        Args:
            user_id: The unique ID of the user.
            
        Returns:
            A list of `OAuthProfile` entities linked to the user.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def create(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Creates and persists a new OAuth profile.
        
        Args:
            oauth_profile: The `OAuthProfile` entity to create.
            
        Returns:
            The created `OAuthProfile` with its new ID.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def update(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Updates an existing OAuth profile.
        
        Args:
            oauth_profile: The `OAuthProfile` entity with updated information.
            
        Returns:
            The updated `OAuthProfile` entity.
        """
        raise NotImplementedError
    
    @abstractmethod
    async def delete(self, oauth_profile_id: int) -> None:
        """Deletes an OAuth profile by its unique identifier.
        
        Args:
            oauth_profile_id: The ID of the `OAuthProfile` to delete.
        """
        raise NotImplementedError 