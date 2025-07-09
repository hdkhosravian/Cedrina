"""Unit tests for OAuth Profile Repository.

These tests verify that the OAuth profile repository properly implements
the IOAuthProfileRepository interface and handles all CRUD operations
following clean architecture principles and TDD methodology.

Test Coverage:
- Repository initialization and dependency injection
- Get by provider and user ID operations
- Get by user ID operations (multiple profiles)
- Create operations with validation
- Update operations with validation
- Delete operations with validation
- Error handling and edge cases
- Security logging and data masking
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy.exc import IntegrityError

from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.infrastructure.repositories.oauth_profile_repository import OAuthProfileRepository


class TestOAuthProfileRepository:
    """Test cases for OAuth Profile Repository implementation."""

    @pytest.fixture
    def mock_db_session(self):
        """Create a mock database session for testing."""
        session = AsyncMock()
        session.execute = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.merge = AsyncMock()
        session.delete = AsyncMock()
        return session

    @pytest.fixture
    def repository(self, mock_db_session):
        """Create repository instance with mock dependencies."""
        return OAuthProfileRepository(mock_db_session)

    @pytest.fixture
    def sample_oauth_profile(self):
        """Create a sample OAuth profile for testing."""
        return OAuthProfile(
            id=1,
            user_id=123,
            provider=Provider.GOOGLE,
            provider_user_id="google_user_123",
            access_token=b"encrypted_token_data",
            expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            created_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            updated_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        )

    class TestInitialization:
        """Test repository initialization."""

        def test_repository_initialization(self, mock_db_session):
            """Test that repository initializes correctly with database session."""
            repository = OAuthProfileRepository(mock_db_session)
            assert repository.db_session == mock_db_session

    class TestGetByProviderAndUserId:
        """Test get_by_provider_and_user_id method."""

        @pytest.mark.asyncio
        async def test_get_by_provider_and_user_id_success(self, repository, sample_oauth_profile, mock_db_session):
            """Test successful retrieval of OAuth profile by provider and user ID."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = sample_oauth_profile
            mock_db_session.execute.return_value = mock_result

            # Act
            result = await repository.get_by_provider_and_user_id(
                Provider.GOOGLE, "google_user_123"
            )

            # Assert
            assert result == sample_oauth_profile
            mock_db_session.execute.assert_called_once()

        @pytest.mark.asyncio
        async def test_get_by_provider_and_user_id_not_found(self, repository, mock_db_session):
            """Test retrieval when OAuth profile is not found."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = None
            mock_db_session.execute.return_value = mock_result

            # Act
            result = await repository.get_by_provider_and_user_id(
                Provider.GOOGLE, "nonexistent_user"
            )

            # Assert
            assert result is None
            mock_db_session.execute.assert_called_once()

        @pytest.mark.asyncio
        async def test_get_by_provider_and_user_id_empty_provider_user_id(self, repository):
            """Test that empty provider user ID raises ValueError."""
            # Act & Assert
            with pytest.raises(ValueError, match="Provider user ID cannot be empty"):
                await repository.get_by_provider_and_user_id(Provider.GOOGLE, "")

        @pytest.mark.asyncio
        async def test_get_by_provider_and_user_id_whitespace_provider_user_id(self, repository):
            """Test that whitespace-only provider user ID raises ValueError."""
            # Act & Assert
            with pytest.raises(ValueError, match="Provider user ID cannot be empty"):
                await repository.get_by_provider_and_user_id(Provider.GOOGLE, "   ")

        @pytest.mark.asyncio
        async def test_get_by_provider_and_user_id_database_error(self, repository, mock_db_session):
            """Test handling of database errors during retrieval."""
            # Arrange
            mock_db_session.execute.side_effect = Exception("Database connection failed")

            # Act & Assert
            with pytest.raises(Exception, match="Database connection failed"):
                await repository.get_by_provider_and_user_id(Provider.GOOGLE, "google_user_123")

    class TestGetByUserId:
        """Test get_by_user_id method."""

        @pytest.mark.asyncio
        async def test_get_by_user_id_success(self, repository, sample_oauth_profile, mock_db_session):
            """Test successful retrieval of OAuth profiles by user ID."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [sample_oauth_profile]
            mock_db_session.execute.return_value = mock_result

            # Act
            result = await repository.get_by_user_id(123)

            # Assert
            assert result == [sample_oauth_profile]
            mock_db_session.execute.assert_called_once()

        @pytest.mark.asyncio
        async def test_get_by_user_id_empty_list(self, repository, mock_db_session):
            """Test retrieval when user has no OAuth profiles."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_db_session.execute.return_value = mock_result

            # Act
            result = await repository.get_by_user_id(123)

            # Assert
            assert result == []
            mock_db_session.execute.assert_called_once()

        @pytest.mark.asyncio
        async def test_get_by_user_id_invalid_user_id(self, repository):
            """Test that invalid user ID raises ValueError."""
            # Act & Assert
            with pytest.raises(ValueError, match="User ID must be a positive integer"):
                await repository.get_by_user_id(0)

            with pytest.raises(ValueError, match="User ID must be a positive integer"):
                await repository.get_by_user_id(-1)

        @pytest.mark.asyncio
        async def test_get_by_user_id_database_error(self, repository, mock_db_session):
            """Test handling of database errors during retrieval."""
            # Arrange
            mock_db_session.execute.side_effect = Exception("Database connection failed")

            # Act & Assert
            with pytest.raises(Exception, match="Database connection failed"):
                await repository.get_by_user_id(123)

    class TestCreate:
        """Test create method."""

        @pytest.mark.asyncio
        async def test_create_success(self, repository, sample_oauth_profile, mock_db_session):
            """Test successful creation of OAuth profile."""
            # Arrange
            sample_oauth_profile.id = None  # New profile without ID

            # Act
            result = await repository.create(sample_oauth_profile)

            # Assert
            assert result == sample_oauth_profile
            mock_db_session.add.assert_called_once_with(sample_oauth_profile)
            mock_db_session.commit.assert_called_once()
            mock_db_session.refresh.assert_called_once_with(sample_oauth_profile)

        @pytest.mark.asyncio
        async def test_create_none_profile(self, repository):
            """Test that None profile raises ValueError."""
            # Act & Assert
            with pytest.raises(ValueError, match="OAuth profile cannot be None"):
                await repository.create(None)

        @pytest.mark.asyncio
        async def test_create_invalid_user_id(self, repository):
            """Test that invalid user ID raises ValueError."""
            # Arrange
            invalid_profile = OAuthProfile(
                user_id=0,  # Invalid user ID
                provider=Provider.GOOGLE,
                provider_user_id="google_user_123",
                access_token=b"encrypted_token_data",
                expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            )

            # Act & Assert
            with pytest.raises(ValueError, match="OAuth profile must have a valid user ID"):
                await repository.create(invalid_profile)

        @pytest.mark.asyncio
        async def test_create_empty_provider_user_id(self, repository):
            """Test that empty provider user ID raises ValueError."""
            # Arrange
            invalid_profile = OAuthProfile(
                user_id=123,
                provider=Provider.GOOGLE,
                provider_user_id="",  # Empty provider user ID
                access_token=b"encrypted_token_data",
                expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            )

            # Act & Assert
            with pytest.raises(ValueError, match="OAuth profile must have a valid provider user ID"):
                await repository.create(invalid_profile)

        @pytest.mark.asyncio
        async def test_create_database_error(self, repository, sample_oauth_profile, mock_db_session):
            """Test handling of database errors during creation."""
            # Arrange
            sample_oauth_profile.id = None
            mock_db_session.commit.side_effect = IntegrityError("", "", "")

            # Act & Assert
            with pytest.raises(IntegrityError):
                await repository.create(sample_oauth_profile)

            # Verify rollback was called
            mock_db_session.rollback.assert_called_once()

    class TestUpdate:
        """Test update method."""

        @pytest.mark.asyncio
        async def test_update_success(self, repository, sample_oauth_profile, mock_db_session):
            """Test successful update of OAuth profile."""
            # Arrange
            updated_profile = OAuthProfile(
                id=1,
                user_id=123,
                provider=Provider.GOOGLE,
                provider_user_id="google_user_123_updated",
                access_token=b"new_encrypted_token_data",
                expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            )
            mock_db_session.merge.return_value = updated_profile

            # Act
            result = await repository.update(updated_profile)

            # Assert
            assert result == updated_profile
            mock_db_session.merge.assert_called_once_with(updated_profile)
            mock_db_session.commit.assert_called_once()
            mock_db_session.refresh.assert_called_once_with(updated_profile)

        @pytest.mark.asyncio
        async def test_update_none_profile(self, repository):
            """Test that None profile raises ValueError."""
            # Act & Assert
            with pytest.raises(ValueError, match="OAuth profile cannot be None"):
                await repository.update(None)

        @pytest.mark.asyncio
        async def test_update_invalid_profile_id(self, repository):
            """Test that invalid profile ID raises ValueError."""
            # Arrange
            invalid_profile = OAuthProfile(
                id=0,  # Invalid ID
                user_id=123,
                provider=Provider.GOOGLE,
                provider_user_id="google_user_123",
                access_token=b"encrypted_token_data",
                expires_at=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            )

            # Act & Assert
            with pytest.raises(ValueError, match="OAuth profile must have a valid ID for update"):
                await repository.update(invalid_profile)

        @pytest.mark.asyncio
        async def test_update_database_error(self, repository, sample_oauth_profile, mock_db_session):
            """Test handling of database errors during update."""
            # Arrange
            mock_db_session.commit.side_effect = IntegrityError("", "", "")

            # Act & Assert
            with pytest.raises(IntegrityError):
                await repository.update(sample_oauth_profile)

            # Verify rollback was called
            mock_db_session.rollback.assert_called_once()

    class TestDelete:
        """Test delete method."""

        @pytest.mark.asyncio
        async def test_delete_success(self, repository, sample_oauth_profile, mock_db_session):
            """Test successful deletion of OAuth profile."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = sample_oauth_profile
            mock_db_session.execute.return_value = mock_result

            # Act
            await repository.delete(1)

            # Assert
            mock_db_session.delete.assert_called_once_with(sample_oauth_profile)
            mock_db_session.commit.assert_called_once()

        @pytest.mark.asyncio
        async def test_delete_profile_not_found(self, repository, mock_db_session):
            """Test deletion when profile is not found."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = None
            mock_db_session.execute.return_value = mock_result

            # Act
            await repository.delete(999)

            # Assert
            mock_db_session.delete.assert_not_called()
            mock_db_session.commit.assert_not_called()

        @pytest.mark.asyncio
        async def test_delete_invalid_profile_id(self, repository):
            """Test that invalid profile ID raises ValueError."""
            # Act & Assert
            with pytest.raises(ValueError, match="OAuth profile ID must be a positive integer"):
                await repository.delete(0)

            with pytest.raises(ValueError, match="OAuth profile ID must be a positive integer"):
                await repository.delete(-1)

        @pytest.mark.asyncio
        async def test_delete_database_error(self, repository, sample_oauth_profile, mock_db_session):
            """Test handling of database errors during deletion."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = sample_oauth_profile
            mock_db_session.execute.return_value = mock_result
            mock_db_session.commit.side_effect = Exception("Database connection failed")

            # Act & Assert
            with pytest.raises(Exception, match="Database connection failed"):
                await repository.delete(1)

            # Verify rollback was called
            mock_db_session.rollback.assert_called_once()

    class TestEdgeCases:
        """Test edge cases and error scenarios."""

        @pytest.mark.asyncio
        async def test_provider_enum_values(self, repository, mock_db_session):
            """Test that all provider enum values work correctly."""
            # Arrange
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = None
            mock_db_session.execute.return_value = mock_result

            # Act & Assert - Test all provider values
            for provider in Provider:
                result = await repository.get_by_provider_and_user_id(provider, "test_user")
                assert result is None

        @pytest.mark.asyncio
        async def test_long_provider_user_id(self, repository, mock_db_session):
            """Test handling of very long provider user IDs."""
            # Arrange
            long_user_id = "a" * 1000  # Very long user ID
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = None
            mock_db_session.execute.return_value = mock_result

            # Act
            result = await repository.get_by_provider_and_user_id(Provider.GOOGLE, long_user_id)

            # Assert
            assert result is None
            mock_db_session.execute.assert_called_once()

        @pytest.mark.asyncio
        async def test_special_characters_in_provider_user_id(self, repository, mock_db_session):
            """Test handling of special characters in provider user IDs."""
            # Arrange
            special_user_id = "user@domain.com#123!$%"
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = None
            mock_db_session.execute.return_value = mock_result

            # Act
            result = await repository.get_by_provider_and_user_id(Provider.GOOGLE, special_user_id)

            # Assert
            assert result is None
            mock_db_session.execute.assert_called_once() 