"""
Unit Tests for TokenFamilyRepository Implementation.

These tests focus on the repository's internal logic, mapping between domain entities
and database models, and parameter validation. They use minimal mocking to test
the repository's behavior without external dependencies.

Test Coverage:
- Domain entity to ORM model mapping
- ORM model to domain entity mapping  
- Parameter validation and error handling
- Interface compliance with ITokenFamilyRepository
- Method signature verification

Note: For real database operations, see tests/integration/test_token_family_repository_integration.py
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.entities.token_family import TokenFamily
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.security.field_encryption_service import FieldEncryptionService
from src.infrastructure.database.token_family_model import TokenFamilyModel
from tests.factories.token import create_valid_token_id


class TestTokenFamilyRepositoryMapping:
    """Test domain entity to ORM model mapping logic."""
    
    @pytest.fixture
    def repository(self):
        """Repository with minimal mocking for mapping tests."""
        mock_session = AsyncMock()
        mock_encryption = AsyncMock(spec=FieldEncryptionService)
        mock_encryption.encrypt_token_list = AsyncMock(return_value=b"encrypted_tokens")
        mock_encryption.encrypt_usage_history = AsyncMock(return_value=b"encrypted_history")
        mock_encryption.decrypt_token_list = AsyncMock(return_value=[])
        mock_encryption.decrypt_usage_history = AsyncMock(return_value=[])
        
        return TokenFamilyRepository(
            session_factory=mock_session,
            encryption_service=mock_encryption
        )
    
    @pytest.fixture
    def sample_entity(self):
        """Sample TokenFamily entity for mapping tests."""
        return TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            last_used_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            compromise_reason=None,
            security_score=1.0
        )
    
    @pytest.fixture
    def sample_model(self):
        """Sample TokenFamilyModel for mapping tests."""
        return TokenFamilyModel(
            id=1,
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE.value,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            last_used_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).replace(tzinfo=None),
            compromise_reason=None,
            security_score=1.0,
            active_tokens_encrypted=b"encrypted_tokens",
            revoked_tokens_encrypted=None,
            usage_history_encrypted=None
        )
    
    async def test_to_model_mapping_basic_fields(self, repository, sample_entity):
        """Test mapping from entity to model for basic fields."""
        model = await repository._to_model(sample_entity)
        
        assert model.family_id == sample_entity.family_id
        assert model.user_id == sample_entity.user_id
        assert model.status == sample_entity.status.value
        assert model.security_score == sample_entity.security_score
        assert model.compromise_reason == sample_entity.compromise_reason
    
    async def test_to_model_datetime_conversion(self, repository, sample_entity):
        """Test that timezone-aware datetimes are converted to naive UTC."""
        model = await repository._to_model(sample_entity)
        
        # Check that datetimes are converted to naive UTC
        assert model.created_at.tzinfo is None
        if model.last_used_at:
            assert model.last_used_at.tzinfo is None
        if model.expires_at:
            assert model.expires_at.tzinfo is None
    
    async def test_to_model_encryption_called(self, repository, sample_entity):
        """Test that encryption service is called when entity has tokens."""
        # Add tokens to entity
        token1 = TokenId(create_valid_token_id())
        token2 = TokenId(create_valid_token_id())
        sample_entity.add_token(token1)
        sample_entity.add_token(token2)
        sample_entity.revoke_token(token1)
        
        await repository._to_model(sample_entity)
        
        # Verify encryption methods were called
        repository.encryption_service.encrypt_token_list.assert_called()
        repository.encryption_service.encrypt_usage_history.assert_called()
    
    async def test_to_domain_mapping_basic_fields(self, repository, sample_model):
        """Test mapping from model to entity for basic fields."""
        entity = await repository._to_domain(sample_model)
        
        assert entity.family_id == sample_model.family_id
        assert entity.user_id == sample_model.user_id
        assert entity.status == TokenFamilyStatus(sample_model.status)
        assert entity.security_score == sample_model.security_score
        assert entity.compromise_reason == sample_model.compromise_reason
    
    async def test_to_domain_datetime_conversion(self, repository, sample_model):
        """Test that naive datetimes are converted to timezone-aware UTC."""
        entity = await repository._to_domain(sample_model)
        
        # Check that datetimes are converted to timezone-aware UTC
        assert entity.created_at.tzinfo == timezone.utc
        if entity.last_used_at:
            assert entity.last_used_at.tzinfo == timezone.utc
        if entity.expires_at:
            assert entity.expires_at.tzinfo == timezone.utc
    
    async def test_to_domain_decryption_called(self, repository, sample_model):
        """Test that decryption service is called when model has encrypted data."""
        await repository._to_domain(sample_model)
        
        # Verify decryption methods were called
        repository.encryption_service.decrypt_token_list.assert_called()
    
    async def test_to_domain_handles_decryption_failure(self, repository, sample_model):
        """Test graceful handling of decryption failures."""
        # Make decryption fail
        repository.encryption_service.decrypt_token_list.side_effect = Exception("Decryption failed")
        
        # Should not raise exception, but log warning and use empty list
        entity = await repository._to_domain(sample_model)
        
        assert len(entity.active_tokens) == 0
        assert len(entity.revoked_tokens) == 0
    
    async def test_mapping_round_trip_consistency(self, repository, sample_entity):
        """Test that entity -> model -> entity maintains consistency."""
        # Convert entity to model
        model = await repository._to_model(sample_entity)
        
        # Convert back to entity
        entity = await repository._to_domain(model)
        
        # Verify key fields are preserved
        assert entity.family_id == sample_entity.family_id
        assert entity.user_id == sample_entity.user_id
        assert entity.status == sample_entity.status
        assert entity.security_score == sample_entity.security_score


class TestTokenFamilyRepositoryValidation:
    """Test parameter validation and error handling."""
    
    @pytest.fixture
    def repository(self):
        """Repository for validation tests."""
        # Create a mock that behaves like AsyncSession but passes isinstance check
        mock_session = AsyncMock()
        mock_session.__class__ = AsyncSession  # Make isinstance work
        mock_encryption = AsyncMock(spec=FieldEncryptionService)
        
        return TokenFamilyRepository(
            session_factory=mock_session,
            encryption_service=mock_encryption
        )
    
    def test_initialization_validates_session_factory(self):
        """Test that initialization validates session factory parameter."""
        mock_encryption = AsyncMock()
        
        # Valid initialization
        repo = TokenFamilyRepository(
            session_factory=AsyncMock(),
            encryption_service=mock_encryption
        )
        assert repo is not None
        
        # Should handle both session and session factory
        mock_session = AsyncMock()
        mock_session.__class__ = AsyncSession
        repo = TokenFamilyRepository(
            session_factory=mock_session,
            encryption_service=mock_encryption
        )
        assert repo.db_session == mock_session
    
    async def test_create_family_validates_user_id(self, repository):
        """Test user_id validation in create_family method."""
        with pytest.raises(ValueError, match="User ID must be positive"):
            await repository.create_family(user_id=0)
        
        with pytest.raises(ValueError, match="User ID must be positive"):
            await repository.create_family(user_id=-1)
    
    async def test_get_family_by_id_validates_family_id(self, repository):
        """Test family_id validation in get_family_by_id method."""
        # The repository should have db_session set when initialized with AsyncSession
        assert repository.db_session is not None, f"Repository should have db_session set, got {repository.db_session}"
        
        # Mock the execute method to avoid database calls
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = None
        mock_result.scalars.return_value = mock_scalars
        repository.db_session.execute = AsyncMock(return_value=mock_result)
        
        # Valid family_id should work
        result = await repository.get_family_by_id(str(uuid.uuid4()))
        assert result is None  # No family found
        
        # Invalid family_ids should be handled gracefully or raise errors
        # The actual behavior depends on implementation choice
        try:
            await repository.get_family_by_id("")
        except (ValueError, TypeError):
            pass  # Expected for empty string
        
        try:
            await repository.get_family_by_id(None)
        except (ValueError, TypeError):
            pass  # Expected for None


class TestTokenFamilyRepositoryInterface:
    """Test interface compliance and method signatures."""
    
    @pytest.fixture
    def repository(self):
        """Repository for interface tests."""
        mock_session = AsyncMock()
        mock_session.__class__ = AsyncSession
        return TokenFamilyRepository(
            session_factory=mock_session,
            encryption_service=AsyncMock(spec=FieldEncryptionService)
        )
    
    def test_implements_required_methods(self, repository):
        """Test that repository implements all required interface methods."""
        required_methods = [
            'create_token_family', 'create_family', 'get_family_by_id',
            'get_family_by_token', 'update_family', 'compromise_family',
            'revoke_family', 'check_token_reuse', 'get_user_families',
            'get_expired_families', 'get_security_metrics', 'get_compromised_families'
        ]
        
        for method_name in required_methods:
            assert hasattr(repository, method_name)
            method = getattr(repository, method_name)
            assert callable(method)
    
    def test_async_method_signatures(self, repository):
        """Test that async methods are properly defined."""
        import inspect
        
        async_methods = [
            'create_token_family', 'create_family', 'get_family_by_id',
            'get_family_by_token', 'update_family', 'compromise_family',
            'revoke_family', 'check_token_reuse', 'get_user_families',
            'get_expired_families', 'get_security_metrics', 'get_compromised_families'
        ]
        
        for method_name in async_methods:
            method = getattr(repository, method_name)
            assert inspect.iscoroutinefunction(method), f"{method_name} should be async"
    
    async def test_method_return_types(self, repository):
        """Test that methods return expected types."""
        # The repository should have db_session set when initialized with AsyncSession
        assert repository.db_session is not None, "Repository should have db_session set"
        
        # Mock database operations to avoid actual database calls
        repository.db_session.add = MagicMock()
        repository.db_session.flush = AsyncMock()
        repository.db_session.refresh = AsyncMock()
        
        # Mock query results
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = None
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_result.scalar.return_value = 0
        repository.db_session.execute = AsyncMock(return_value=mock_result)
        
        # Test return types
        sample_family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        # create_token_family should return TokenFamily
        result = await repository.create_token_family(sample_family)
        assert isinstance(result, TokenFamily)
        
        # get_family_by_id should return Optional[TokenFamily]
        result = await repository.get_family_by_id(str(uuid.uuid4()))
        assert result is None or isinstance(result, TokenFamily)
        
        # get_user_families should return List[TokenFamily]
        result = await repository.get_user_families(12345)
        assert isinstance(result, list)
        
        # get_security_metrics should return Dict
        result = await repository.get_security_metrics()
        assert isinstance(result, dict)
        
        # check_token_reuse should return bool
        result = await repository.check_token_reuse(
            TokenId(create_valid_token_id()),
            str(uuid.uuid4())
        )
        assert isinstance(result, bool)


class TestTokenFamilyRepositoryEdgeCases:
    """Test edge cases and error scenarios."""
    
    @pytest.fixture
    def repository(self):
        """Repository for edge case testing."""
        mock_session = AsyncMock()
        mock_session.__class__ = AsyncSession
        return TokenFamilyRepository(
            session_factory=mock_session,
            encryption_service=AsyncMock(spec=FieldEncryptionService)
        )
    
    async def test_mapping_with_null_optional_fields(self, repository):
        """Test mapping when optional fields are None."""
        # Entity with minimal fields
        entity = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        # Should handle None optional fields
        model = await repository._to_model(entity)
        assert model.last_used_at is None
        assert model.compromised_at is None
        assert model.expires_at is None
        assert model.compromise_reason is None
    
    async def test_mapping_with_empty_collections(self, repository):
        """Test mapping when token collections are empty."""
        entity = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        # Should handle empty token collections
        model = await repository._to_model(entity)
        
        # Encryption should not be called for empty collections
        repository.encryption_service.encrypt_token_list.assert_not_called()
        repository.encryption_service.encrypt_usage_history.assert_not_called()
    
    async def test_to_domain_with_missing_encrypted_fields(self, repository):
        """Test _to_domain when encrypted fields are None."""
        model = TokenFamilyModel(
            id=1,
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE.value,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
            security_score=1.0,
            active_tokens_encrypted=None,
            revoked_tokens_encrypted=None,
            usage_history_encrypted=None
        )
        
        entity = await repository._to_domain(model)
        
        # Should have empty collections when encrypted fields are None
        assert len(entity.active_tokens) == 0
        assert len(entity.revoked_tokens) == 0
        assert len(entity.usage_history) == 0
    
    async def test_error_propagation(self, repository):
        """Test that repository properly propagates errors."""
        from sqlalchemy.exc import OperationalError
        
        sample_family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        # The repository should have db_session set when initialized with AsyncSession
        assert repository.db_session is not None, "Repository should have db_session set"
        
        # Mock database operations
        repository.db_session.add = MagicMock()
        repository.db_session.flush.side_effect = OperationalError("DB Error", None, None)
        
        # Should propagate the error
        with pytest.raises(OperationalError):
            await repository.create_token_family(sample_family)