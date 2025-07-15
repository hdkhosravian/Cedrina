"""
Contract Tests for TokenFamilyRepository.

These tests validate the TokenFamilyRepository interface and method signatures
without testing actual database behavior. They ensure the repository correctly
implements the domain interface and handles parameter validation.

Test Coverage:
- Interface compliance with ITokenFamilyRepository
- Parameter validation and type checking
- Method signature verification
- Basic error handling for invalid inputs
- Mock interaction patterns

Note: These are NOT integration tests. For real database behavior,
see tests/integration/test_token_family_repository_integration.py
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.entities.token_family import TokenFamily
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.security.field_encryption_service import FieldEncryptionService
from src.infrastructure.database.token_family_model import TokenFamilyModel
from tests.factories.token import create_valid_token_id


@pytest.mark.unit
class TestTokenFamilyRepositoryContract:
    """Contract tests for TokenFamilyRepository interface compliance."""
    
    @pytest.fixture
    def mock_session(self):
        """Mock database session for interface testing."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.refresh = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_encryption_service(self):
        """Mock encryption service for interface testing."""
        service = AsyncMock(spec=FieldEncryptionService)
        service.encrypt_token_list = AsyncMock(return_value=b"encrypted_data")
        service.decrypt_token_list = AsyncMock(return_value=[])
        service.encrypt_usage_history = AsyncMock(return_value=b"encrypted_history")
        service.decrypt_usage_history = AsyncMock(return_value=[])
        return service
    
    @pytest.fixture
    def repository(self, mock_session, mock_encryption_service):
        """Repository instance for contract testing."""
        # Make sure the mock session passes isinstance check
        mock_session.__class__ = AsyncSession
        return TokenFamilyRepository(
            session_factory=mock_session,
            encryption_service=mock_encryption_service
        )
    
    @pytest.fixture
    def sample_token_family(self):
        """Sample token family for testing."""
        return TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=12345,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
    
    def test_repository_implements_interface_methods(self, repository):
        """Test that repository has all required interface methods."""
        # Check method existence and signatures
        assert hasattr(repository, 'create_token_family')
        assert hasattr(repository, 'get_family_by_id')
        assert hasattr(repository, 'get_family_by_token')
        assert hasattr(repository, 'update_family')
        assert hasattr(repository, 'compromise_family')
        assert hasattr(repository, 'check_token_reuse')
        assert hasattr(repository, 'get_user_families')
        assert hasattr(repository, 'get_expired_families')
        assert hasattr(repository, 'get_security_metrics')
        assert hasattr(repository, 'get_compromised_families')
    
    async def test_create_token_family_parameter_validation(self, repository):
        """Test parameter validation for create_token_family."""
        # Test with None parameter
        with pytest.raises((TypeError, AttributeError)):
            await repository.create_token_family(None)
        
        # Test with wrong type
        with pytest.raises((TypeError, AttributeError)):
            await repository.create_token_family("not_a_token_family")
    
    async def test_get_family_by_id_parameter_validation(self, repository):
        """Test parameter validation for get_family_by_id."""
        # Mock the execute method to avoid database calls
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = None
        mock_result.scalars.return_value = mock_scalars
        repository.db_session.execute = AsyncMock(return_value=mock_result)
        
        # Test with None - this should raise an error during query execution
        with pytest.raises((ValueError, TypeError)):
            await repository.get_family_by_id(None)
        
        # Test with empty string - this should work but return None
        result = await repository.get_family_by_id("")
        assert result is None
        
        # Test with wrong type - this should work but return None
        result = await repository.get_family_by_id(123)
        assert result is None
    
    async def test_create_family_parameter_validation(self, repository):
        """Test parameter validation for create_family method."""
        # Test with invalid user_id
        with pytest.raises(ValueError, match="User ID must be positive"):
            await repository.create_family(user_id=0)
        
        with pytest.raises(ValueError, match="User ID must be positive"):
            await repository.create_family(user_id=-1)
    
    async def test_compromise_family_interface_compliance(self, repository):
        """Test compromise_family method interface compliance."""
        # Should accept all required parameters
        family_id = str(uuid.uuid4())
        reason = "Test compromise"
        token_id = TokenId(create_valid_token_id())
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Mock the get_family_by_id to return None (family not found)
        repository.get_family_by_id = AsyncMock(return_value=None)
        
        # Should return False when family not found
        result = await repository.compromise_family(
            family_id=family_id,
            reason=reason,
            detected_token=token_id,
            security_context=security_context,
            correlation_id="test-123"
        )
        
        assert result is False
    
    async def test_check_token_reuse_interface_compliance(self, repository):
        """Test check_token_reuse method interface compliance."""
        token_id = TokenId(create_valid_token_id())
        family_id = str(uuid.uuid4())
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Mock the get_family_by_id to return None
        repository.get_family_by_id = AsyncMock(return_value=None)
        
        # Should return True (suspicious) when family not found
        result = await repository.check_token_reuse(
            token_id=token_id,
            family_id=family_id,
            security_context=security_context,
            correlation_id="test-123"
        )
        
        assert result is True
    
    async def test_get_user_families_parameter_validation(self, repository):
        """Test get_user_families parameter validation."""
        # Mock the execute method to avoid database calls
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        repository.db_session.execute = AsyncMock(return_value=mock_result)
        
        # Test with string user_id - this should work but return empty list
        result = await repository.get_user_families(user_id="invalid")
        assert result == []
        
        # Test with None user_id - this should work but return empty list
        result = await repository.get_user_families(user_id=None)
        assert result == []
    
    async def test_get_security_metrics_parameter_validation(self, repository):
        """Test get_security_metrics parameter validation."""
        # Should handle optional parameters
        mock_result = MagicMock()
        mock_result.scalar.return_value = 0
        repository.db_session.execute = AsyncMock(return_value=mock_result)
        
        # Should work with no parameters
        metrics = await repository.get_security_metrics()
        assert isinstance(metrics, dict)
        
        # Should work with user_id
        metrics = await repository.get_security_metrics(user_id=12345)
        assert isinstance(metrics, dict)
        
        # Should work with time_window_hours
        metrics = await repository.get_security_metrics(time_window_hours=48)
        assert isinstance(metrics, dict)
    
    async def test_update_family_parameter_validation(self, repository):
        """Test update_family parameter validation."""
        # Test with None
        with pytest.raises((TypeError, AttributeError)):
            await repository.update_family(None)
        
        # Test with wrong type
        with pytest.raises((TypeError, AttributeError)):
            await repository.update_family("not_a_family")
    
    async def test_to_domain_method_parameter_validation(self, repository):
        """Test _to_domain method parameter validation."""
        # Test with None
        with pytest.raises((TypeError, AttributeError)):
            await repository._to_domain(None)
        
        # Test with wrong type
        with pytest.raises((TypeError, AttributeError)):
            await repository._to_domain("not_a_model")
    
    async def test_to_model_method_parameter_validation(self, repository):
        """Test _to_model method parameter validation."""
        # Test with None
        with pytest.raises((TypeError, AttributeError)):
            await repository._to_model(None)
        
        # Test with wrong type
        with pytest.raises((TypeError, AttributeError)):
            await repository._to_model("not_an_entity")
    
    def test_repository_initialization_parameter_validation(self):
        """Test repository initialization parameter validation."""
        # Test with None session factory
        with pytest.raises((TypeError, AttributeError)):
            TokenFamilyRepository(session_factory=None)
        
        # Test with invalid session factory type
        with pytest.raises((TypeError, AttributeError)):
            TokenFamilyRepository(session_factory="invalid")
    
    async def test_method_return_types(self, repository, sample_token_family):
        """Test that methods return expected types."""
        # Mock successful operations
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.first.return_value = None
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_result.scalar.return_value = 0
        repository.db_session.execute = AsyncMock(return_value=mock_result)
        
        # create_token_family should return TokenFamily
        result = await repository.create_token_family(sample_token_family)
        assert isinstance(result, TokenFamily)
        
        # get_family_by_id should return TokenFamily or None
        result = await repository.get_family_by_id(str(uuid.uuid4()))
        assert result is None or isinstance(result, TokenFamily)
        
        # get_user_families should return list
        result = await repository.get_user_families(12345)
        assert isinstance(result, list)
        
        # get_expired_families should return list
        result = await repository.get_expired_families()
        assert isinstance(result, list)
        
        # get_security_metrics should return dict
        result = await repository.get_security_metrics()
        assert isinstance(result, dict)
        
        # get_compromised_families should return list
        result = await repository.get_compromised_families()
        assert isinstance(result, list)
        
        # check_token_reuse should return bool
        result = await repository.check_token_reuse(
            TokenId(create_valid_token_id()),
            str(uuid.uuid4())
        )
        assert isinstance(result, bool)
    
    async def test_error_handling_interface_compliance(self, repository, sample_token_family):
        """Test that repository handles errors according to interface."""
        # Mock database error
        from sqlalchemy.exc import OperationalError
        repository.db_session.add = MagicMock()
        repository.db_session.flush.side_effect = OperationalError("DB Error", None, None)
        
        # Should propagate database errors
        with pytest.raises(OperationalError):
            await repository.create_token_family(sample_token_family)
    
    def test_repository_has_required_attributes(self, repository):
        """Test that repository has required attributes."""
        assert hasattr(repository, 'db_session')
        assert hasattr(repository, 'encryption_service')
        
        # Should have either db_session or session_factory
        assert (repository.db_session is not None or 
                repository.session_factory is not None)
    
    async def test_async_method_compliance(self, repository):
        """Test that all public methods are properly async."""
        import inspect
        
        # Get all public methods
        methods = [method for method in dir(repository) 
                  if not method.startswith('_') and callable(getattr(repository, method))]
        
        # Check that main methods are async
        async_methods = [
            'create_token_family', 'create_family', 'get_family_by_id', 
            'get_family_by_token', 'update_family', 'compromise_family',
            'revoke_family', 'check_token_reuse', 'get_user_families',
            'get_expired_families', 'get_security_metrics', 'get_compromised_families'
        ]
        
        for method_name in async_methods:
            method = getattr(repository, method_name)
            assert inspect.iscoroutinefunction(method), f"{method_name} should be async"