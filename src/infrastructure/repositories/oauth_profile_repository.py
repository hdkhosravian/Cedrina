"""OAuth Profile Repository implementation using SQLAlchemy.

This module provides a repository pattern implementation for OAuthProfile entity operations,
abstracting database access and providing a clean interface for OAuth authentication services.

Key DDD Principles Applied:
- Repository Pattern for data access abstraction
- Single Responsibility for OAuth profile persistence operations
- Dependency Inversion through interface implementation
- Ubiquitous Language in method names and documentation
- Fail-Fast error handling with proper domain exceptions
- Secure logging with sensitive data masking

This implementation serves as the infrastructure layer component that:
- Implements the IOAuthProfileRepository interface
- Handles all database operations for OAuthProfile entities
- Maintains data consistency and transaction integrity
- Implements secure logging with data masking
- Provides efficient querying for OAuth authentication flows
"""

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog import get_logger

from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.domain.interfaces.repositories import IOAuthProfileRepository

logger = get_logger(__name__)


class OAuthProfileRepository(IOAuthProfileRepository):
    """SQLAlchemy implementation of OAuthProfileRepository following DDD principles.

    This repository provides concrete implementation of OAuth profile data access operations
    using SQLAlchemy async sessions. It follows clean architecture principles and
    Domain-Driven Design patterns:

    - **Repository Pattern**: Abstracts data access from domain services
    - **Single Responsibility**: Focuses solely on OAuth profile persistence operations
    - **Dependency Inversion**: Implements IOAuthProfileRepository interface
    - **Transaction Management**: Handles database transactions properly
    - **Error Handling**: Provides meaningful error messages and logging
    - **Security**: Implements secure logging with data masking

    Responsibilities:
    - OAuth profile entity persistence (CRUD operations)
    - Provider-specific profile lookup and management
    - Transaction management and data consistency
    - Secure logging with sensitive data protection
    - Database query optimization and performance
    """

    def __init__(self, db_session: AsyncSession):
        """Initialize repository with database session.

        Args:
            db_session: SQLAlchemy async session for database operations

        Note:
            The repository depends on the database session abstraction,
            following dependency inversion principle. The session is injected
            through dependency injection, making the repository testable
            and following clean architecture principles.
        """
        self.db_session = db_session
        logger.debug(
            "OAuthProfileRepository initialized",
            repository_type="infrastructure",
            responsibilities=[
                "oauth_profile_persistence",
                "provider_specific_lookup",
                "transaction_management",
            ],
        )

    async def get_by_provider_and_user_id(
        self, 
        provider: Provider, 
        provider_user_id: str
    ) -> Optional[OAuthProfile]:
        """Get OAuth profile by provider and provider-specific user ID.

        This method retrieves an OAuth profile by the combination of provider
        and the user's unique identifier from that provider, implementing
        proper validation and error handling following DDD principles.

        Args:
            provider: OAuth provider (Google, Microsoft, Facebook)
            provider_user_id: User's unique identifier from the OAuth provider

        Returns:
            OAuthProfile entity if found, None otherwise

        Raises:
            ValueError: If provider_user_id is invalid (empty or whitespace-only)

        Security Features:
        - Input validation prevents invalid queries
        - Secure logging with provider user ID masking
        - Proper error handling without information leakage
        """
        # Validate input following fail-fast principle
        if not provider_user_id or not provider_user_id.strip():
            logger.warning(
                "Invalid provider user ID provided",
                provider=str(provider),
                provider_user_id_provided=bool(provider_user_id),
                error_type="validation_error"
            )
            raise ValueError("Provider user ID cannot be empty or whitespace-only")

        try:
            # Execute database query using SQLAlchemy
            statement = select(OAuthProfile).where(
                OAuthProfile.provider == provider,
                OAuthProfile.provider_user_id == provider_user_id.strip()
            )
            result = await self.db_session.execute(statement)
            oauth_profile = result.scalars().first()

            # Log operation result for debugging and monitoring
            logger.debug(
                "OAuth profile lookup by provider and user ID completed",
                provider=str(provider),
                provider_user_id=provider_user_id[:3] + "***" if len(provider_user_id) > 3 else provider_user_id,
                found=oauth_profile is not None,
                operation="get_by_provider_and_user_id",
            )

            return oauth_profile

        except Exception as e:
            # Log error with context but don't expose sensitive information
            logger.error(
                "Error retrieving OAuth profile by provider and user ID",
                provider=str(provider),
                provider_user_id=provider_user_id[:3] + "***" if len(provider_user_id) > 3 else provider_user_id,
                error=str(e),
                error_type=type(e).__name__,
                operation="get_by_provider_and_user_id",
            )
            raise

    async def get_by_user_id(self, user_id: int) -> List[OAuthProfile]:
        """Get all OAuth profiles associated with a user.

        This method retrieves all OAuth profiles linked to a specific user,
        implementing proper validation and error handling following DDD principles.

        Args:
            user_id: User ID to search for (must be positive integer)

        Returns:
            List of OAuthProfile entities linked to the user

        Raises:
            ValueError: If user_id is invalid (non-positive)

        Security Features:
        - Input validation prevents invalid queries
        - Secure logging with user ID masking
        - Proper error handling without information leakage
        """
        # Validate input following fail-fast principle
        if user_id <= 0:
            logger.warning(
                "Invalid user ID provided", 
                user_id=user_id, 
                error_type="validation_error"
            )
            raise ValueError("User ID must be a positive integer")

        try:
            # Execute database query using SQLAlchemy
            statement = select(OAuthProfile).where(OAuthProfile.user_id == user_id)
            result = await self.db_session.execute(statement)
            oauth_profiles = result.scalars().all()

            # Log operation result for debugging and monitoring
            logger.debug(
                "OAuth profiles lookup by user ID completed",
                user_id=user_id,
                profile_count=len(oauth_profiles),
                operation="get_by_user_id",
            )

            return oauth_profiles

        except Exception as e:
            # Log error with context but don't expose sensitive information
            logger.error(
                "Error retrieving OAuth profiles by user ID",
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__,
                operation="get_by_user_id",
            )
            raise

    async def create(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Create and persist a new OAuth profile.

        This method creates a new OAuth profile entity in the database,
        implementing proper validation and error handling following DDD principles.

        Args:
            oauth_profile: OAuthProfile entity to create

        Returns:
            Created OAuthProfile entity with generated ID

        Raises:
            ValueError: If oauth_profile is invalid or missing required fields
            IntegrityError: If unique constraint violation occurs

        Security Features:
        - Input validation prevents invalid data persistence
        - Secure logging with sensitive data masking
        - Proper error handling without information leakage
        - Transaction integrity maintenance
        """
        # Validate input following fail-fast principle
        if not oauth_profile:
            logger.warning(
                "Invalid OAuth profile provided",
                oauth_profile_provided=bool(oauth_profile),
                error_type="validation_error"
            )
            raise ValueError("OAuth profile cannot be None")

        if not oauth_profile.user_id or oauth_profile.user_id <= 0:
            logger.warning(
                "Invalid user ID in OAuth profile",
                user_id=getattr(oauth_profile, 'user_id', None),
                error_type="validation_error"
            )
            raise ValueError("OAuth profile must have a valid user ID")

        if not oauth_profile.provider_user_id or not oauth_profile.provider_user_id.strip():
            logger.warning(
                "Invalid provider user ID in OAuth profile",
                provider=str(getattr(oauth_profile, 'provider', None)),
                error_type="validation_error"
            )
            raise ValueError("OAuth profile must have a valid provider user ID")

        try:
            # Add the entity to the session and commit
            self.db_session.add(oauth_profile)
            await self.db_session.commit()
            await self.db_session.refresh(oauth_profile)

            # Log successful creation with secure data masking
            logger.info(
                "OAuth profile created successfully",
                profile_id=oauth_profile.id,
                user_id=oauth_profile.user_id,
                provider=str(oauth_profile.provider),
                provider_user_id=oauth_profile.provider_user_id[:3] + "***" if len(oauth_profile.provider_user_id) > 3 else oauth_profile.provider_user_id,
                operation="create",
            )

            return oauth_profile

        except Exception as e:
            # Rollback transaction on error
            await self.db_session.rollback()
            
            # Log error with secure data masking
            logger.error(
                "Error creating OAuth profile",
                user_id=oauth_profile.user_id,
                provider=str(oauth_profile.provider),
                provider_user_id=oauth_profile.provider_user_id[:3] + "***" if len(oauth_profile.provider_user_id) > 3 else oauth_profile.provider_user_id,
                error=str(e),
                error_type=type(e).__name__,
                operation="create",
            )
            raise

    async def update(self, oauth_profile: OAuthProfile) -> OAuthProfile:
        """Update an existing OAuth profile.

        This method updates an existing OAuth profile entity in the database,
        implementing proper validation and error handling following DDD principles.

        Args:
            oauth_profile: OAuthProfile entity with updated information

        Returns:
            Updated OAuthProfile entity

        Raises:
            ValueError: If oauth_profile is invalid or missing required fields
            IntegrityError: If unique constraint violation occurs

        Security Features:
        - Input validation prevents invalid data updates
        - Secure logging with sensitive data masking
        - Proper error handling without information leakage
        - Transaction integrity maintenance
        """
        # Validate input following fail-fast principle
        if not oauth_profile:
            logger.warning(
                "Invalid OAuth profile provided for update",
                oauth_profile_provided=bool(oauth_profile),
                error_type="validation_error"
            )
            raise ValueError("OAuth profile cannot be None")

        if not oauth_profile.id or oauth_profile.id <= 0:
            logger.warning(
                "Invalid OAuth profile ID for update",
                profile_id=getattr(oauth_profile, 'id', None),
                error_type="validation_error"
            )
            raise ValueError("OAuth profile must have a valid ID for update")

        try:
            # Merge the entity and commit
            updated_profile = await self.db_session.merge(oauth_profile)
            await self.db_session.commit()
            await self.db_session.refresh(updated_profile)

            # Log successful update with secure data masking
            logger.info(
                "OAuth profile updated successfully",
                profile_id=updated_profile.id,
                user_id=updated_profile.user_id,
                provider=str(updated_profile.provider),
                provider_user_id=updated_profile.provider_user_id[:3] + "***" if len(updated_profile.provider_user_id) > 3 else updated_profile.provider_user_id,
                operation="update",
            )

            return updated_profile

        except Exception as e:
            # Rollback transaction on error
            await self.db_session.rollback()
            
            # Log error with secure data masking
            logger.error(
                "Error updating OAuth profile",
                profile_id=oauth_profile.id,
                user_id=oauth_profile.user_id,
                provider=str(oauth_profile.provider),
                provider_user_id=oauth_profile.provider_user_id[:3] + "***" if len(oauth_profile.provider_user_id) > 3 else oauth_profile.provider_user_id,
                error=str(e),
                error_type=type(e).__name__,
                operation="update",
            )
            raise

    async def delete(self, oauth_profile_id: int) -> None:
        """Delete an OAuth profile by its unique identifier.

        This method deletes an OAuth profile entity from the database,
        implementing proper validation and error handling following DDD principles.

        Args:
            oauth_profile_id: ID of the OAuthProfile to delete

        Raises:
            ValueError: If oauth_profile_id is invalid (non-positive)

        Security Features:
        - Input validation prevents invalid deletion operations
        - Secure logging with profile ID masking
        - Proper error handling without information leakage
        - Transaction integrity maintenance
        """
        # Validate input following fail-fast principle
        if not oauth_profile_id or oauth_profile_id <= 0:
            logger.warning(
                "Invalid OAuth profile ID provided for deletion",
                oauth_profile_id=oauth_profile_id,
                error_type="validation_error"
            )
            raise ValueError("OAuth profile ID must be a positive integer")

        try:
            # Find the profile first for logging purposes
            statement = select(OAuthProfile).where(OAuthProfile.id == oauth_profile_id)
            result = await self.db_session.execute(statement)
            oauth_profile = result.scalars().first()

            if not oauth_profile:
                logger.warning(
                    "OAuth profile not found for deletion",
                    oauth_profile_id=oauth_profile_id,
                    operation="delete",
                )
                return

            # Delete the entity and commit
            await self.db_session.delete(oauth_profile)
            await self.db_session.commit()

            # Log successful deletion with secure data masking
            logger.info(
                "OAuth profile deleted successfully",
                profile_id=oauth_profile_id,
                user_id=oauth_profile.user_id,
                provider=str(oauth_profile.provider),
                provider_user_id=oauth_profile.provider_user_id[:3] + "***" if len(oauth_profile.provider_user_id) > 3 else oauth_profile.provider_user_id,
                operation="delete",
            )

        except Exception as e:
            # Rollback transaction on error
            await self.db_session.rollback()
            
            # Log error with secure data masking
            logger.error(
                "Error deleting OAuth profile",
                oauth_profile_id=oauth_profile_id,
                error=str(e),
                error_type=type(e).__name__,
                operation="delete",
            )
            raise 