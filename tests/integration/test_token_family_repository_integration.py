"""
Integration Tests for TokenFamilyRepository with Real Database Operations.

This test suite validates TokenFamilyRepository with actual PostgreSQL database operations,
real encryption services, and production-like scenarios. These tests ensure the repository
behaves correctly with real database constraints, transactions, and concurrency.

Test Coverage:
- Real database CRUD operations
- Actual encryption/decryption with real keys
- Database transaction handling and rollbacks
- Concurrent access patterns with real connection pooling
- Database constraint validation
- Real error scenarios (connection failures, constraint violations)
- Performance validation with actual database operations

Architecture:
- Uses real AsyncSession with test database
- Real FieldEncryptionService with test encryption keys
- Actual PostgreSQL constraints and indexes
- Real transaction isolation and rollback testing
"""

import asyncio
import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from src.domain.entities.token_family import TokenFamily
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.security.field_encryption_service import FieldEncryptionService
from src.infrastructure.database.token_family_model import TokenFamilyModel
from tests.factories.token import create_valid_token_id


@pytest.mark.integration
class TestTokenFamilyRepositoryIntegration:
    """Integration tests with real database operations."""
    
    @pytest.fixture
    async def real_encryption_service(self):
        """Real encryption service with test keys."""
        # Use real encryption service with test configuration
        service = FieldEncryptionService()
        return service
    
    @pytest.fixture
    async def token_family_repository(self, async_session: AsyncSession, real_encryption_service):
        """Repository with real database session and encryption."""
        from src.infrastructure.database.session_factory import AsyncSessionFactoryImpl
        
        # For concurrent operations, use a session factory instead of direct session
        session_factory = AsyncSessionFactoryImpl()
        return TokenFamilyRepository(
            session_factory=session_factory,
            encryption_service=real_encryption_service
        )
    
    @pytest.fixture
    async def test_user(self, async_session: AsyncSession):
        """Create a test user in the database."""
        from src.domain.entities.user import User
        from tests.factories.user import create_fake_user
        import uuid
        
        # Generate unique username and email to avoid conflicts
        unique_id = uuid.uuid4().hex[:8]
        unique_username = f"testuser_{unique_id}"
        unique_email = f"testuser_{unique_id}@example.com"
        user = create_fake_user(
            username=unique_username, 
            email=unique_email,
            created_at=datetime.now()
        )
        async_session.add(user)
        await async_session.commit()
        await async_session.refresh(user)
        return user
    
    @pytest.fixture
    async def test_users(self, async_session: AsyncSession):
        """Create multiple test users in the database."""
        from src.domain.entities.user import User
        from tests.factories.user import create_fake_user
        import uuid
        
        users = []
        for i in range(20):  # Create 20 users to cover all test needs
            # Generate unique identifiers for each user
            unique_id = uuid.uuid4().hex[:8]
            unique_username = f"testuser_{unique_id}_{i}"
            unique_email = f"testuser_{unique_id}_{i}@example.com"
            user = create_fake_user(
                username=unique_username, 
                email=unique_email,
                created_at=datetime.now()
            )
            users.append(user)
            async_session.add(user)
        
        await async_session.commit()
        for user in users:
            await async_session.refresh(user)
        return users
    
    @pytest.fixture
    async def sample_token_family(self, test_user):
        """Sample token family for testing."""
        return TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=test_user.id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            last_used_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            security_score=1.0
        )
    
    async def test_create_and_retrieve_token_family(
        self, 
        token_family_repository: TokenFamilyRepository,
        sample_token_family: TokenFamily,
        async_session: AsyncSession
    ):
        """Test creating and retrieving token family with real database."""
        # Create token family (repository uses its own session factory)
        created_family = await token_family_repository.create_token_family(sample_token_family)
        
        # Verify creation
        assert created_family is not None
        assert created_family.family_id == sample_token_family.family_id
        assert created_family.user_id == sample_token_family.user_id
        assert created_family.status == TokenFamilyStatus.ACTIVE
        
        # Note: No explicit commit needed since repository uses session factory
        # Each operation is in its own transaction with auto-commit
        
        # Retrieve from database (uses a new session from factory)
        retrieved_family = await token_family_repository.get_family_by_id(sample_token_family.family_id)
        
        # Verify retrieval
        assert retrieved_family is not None
        assert retrieved_family.family_id == sample_token_family.family_id
        assert retrieved_family.user_id == sample_token_family.user_id
        assert retrieved_family.status == TokenFamilyStatus.ACTIVE
    
    async def test_create_family_with_tokens_real_encryption(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user,
        async_session: AsyncSession
    ):
        """Test creating family with tokens using real encryption."""
        # Create family with tokens
        family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=test_user.id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            last_used_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            security_score=1.0
        )
        
        # Add tokens to family
        token1 = TokenId(create_valid_token_id())
        token2 = TokenId(create_valid_token_id())
        family.add_token(token1)
        family.add_token(token2)
        
        # Create in database with real encryption
        created_family = await token_family_repository.create_token_family(family)
        await async_session.commit()
        
        # Verify tokens are encrypted in database
        result = await async_session.execute(
            select(TokenFamilyModel).where(TokenFamilyModel.family_id == family.family_id)
        )
        model = result.scalars().first()
        
        # Check that encrypted data exists
        assert model.active_tokens_encrypted is not None
        assert len(model.active_tokens_encrypted) > 0
        
        # Retrieve and verify decryption works
        retrieved_family = await token_family_repository.get_family_by_id(family.family_id)
        assert len(retrieved_family.active_tokens) == 2
        assert token1 in retrieved_family.active_tokens
        assert token2 in retrieved_family.active_tokens
    
    async def test_concurrent_family_operations_real_database(
        self,
        token_family_repository: TokenFamilyRepository,
        test_users,
        async_session: AsyncSession
    ):
        """Test concurrent operations with real database connection pooling."""
        # Create multiple families concurrently
        families = []
        for i in range(10):
            family = TokenFamily(
                family_id=str(uuid.uuid4()),
                user_id=test_users[i].id,
                status=TokenFamilyStatus.ACTIVE,
                created_at=datetime.now(timezone.utc),
                last_used_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                security_score=1.0
            )
            families.append(family)
        
        # Create all families concurrently
        creation_tasks = [
            token_family_repository.create_token_family(family)
            for family in families
        ]
        
        created_families = await asyncio.gather(*creation_tasks, return_exceptions=True)
        
        # Verify all were created successfully
        assert len(created_families) == 10
        for result in created_families:
            assert isinstance(result, TokenFamily)
            assert not isinstance(result, Exception)
        
        # Note: No explicit commit needed since repository uses session factory
        # Each create_token_family operation commits its own transaction
        
        # Verify all families exist in database
        for family in families:
            retrieved = await token_family_repository.get_family_by_id(family.family_id)
            assert retrieved is not None
            assert retrieved.user_id == family.user_id
    
    async def test_database_constraint_violations(
        self,
        token_family_repository: TokenFamilyRepository,
        test_users,
        async_session: AsyncSession
    ):
        """Test handling of real database constraint violations."""
        family_id = str(uuid.uuid4())
        
        # Create first family
        family1 = TokenFamily(
            family_id=family_id,
            user_id=test_users[0].id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        await token_family_repository.create_token_family(family1)
        await async_session.commit()
        
        # Try to create duplicate family (should fail due to unique constraint)
        family2 = TokenFamily(
            family_id=family_id,  # Same family_id
            user_id=test_users[1].id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        # This should raise an IntegrityError due to unique constraint
        with pytest.raises(IntegrityError):
            await token_family_repository.create_token_family(family2)
            await async_session.commit()
        
        # Rollback the failed transaction
        await async_session.rollback()
    
    async def test_database_transaction_rollback_real_scenario(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user,
        async_session: AsyncSession
    ):
        """Test real database transaction rollback scenarios."""
        # NOTE: Since repository uses session factory, each operation commits its own transaction
        # This test demonstrates that the repository itself handles its own transaction boundaries
        family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=test_user.id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        # Create the family (this commits in its own transaction)
        created_family = await token_family_repository.create_token_family(family)
        assert created_family is not None
        
        # Now simulate an error in the test's session (different from repository's session)
        try:
            # Execute invalid SQL to force an error in the test session
            await async_session.execute(text("SELECT * FROM non_existent_table"))
            await async_session.commit()
        except Exception:
            # Rollback the test session on error
            await async_session.rollback()
        
        # Verify family was still persisted because repository uses its own transaction
        retrieved = await token_family_repository.get_family_by_id(family.family_id)
        assert retrieved is not None
        assert retrieved.family_id == family.family_id
    
    async def test_family_update_with_real_database(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user,
        async_session: AsyncSession
    ):
        """Test updating family with real database operations."""
        # Create family
        family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=test_user.id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        created_family = await token_family_repository.create_token_family(family)
        await async_session.commit()
        
        # Update family status
        created_family._status = TokenFamilyStatus.COMPROMISED
        created_family._compromise_reason = "Security violation detected"
        created_family._security_score = 0.0
        
        # Update in database
        updated_family = await token_family_repository.update_family(created_family)
        await async_session.commit()
        
        # Verify update
        assert updated_family.status == TokenFamilyStatus.COMPROMISED
        assert updated_family.compromise_reason == "Security violation detected"
        assert updated_family.security_score == 0.0
        
        # Retrieve and verify persistence
        retrieved_family = await token_family_repository.get_family_by_id(family.family_id)
        assert retrieved_family.status == TokenFamilyStatus.COMPROMISED
        assert retrieved_family.compromise_reason == "Security violation detected"
        assert retrieved_family.security_score == 0.0
    
    async def test_get_user_families_with_real_queries(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user,
        async_session: AsyncSession
    ):
        """Test retrieving user families with real database queries."""
        user_id = test_user.id
        
        # Create multiple families for the user
        families = []
        for i in range(5):
            family = TokenFamily(
                family_id=str(uuid.uuid4()),
                user_id=user_id,
                status=TokenFamilyStatus.ACTIVE if i < 3 else TokenFamilyStatus.COMPROMISED,
                created_at=datetime.now(timezone.utc),
                security_score=1.0 if i < 3 else 0.0
            )
            families.append(family)
            await token_family_repository.create_token_family(family)
        
        await async_session.commit()
        
        # Get all families for user
        all_families = await token_family_repository.get_user_families(user_id)
        assert len(all_families) == 5
        
        # Get only active families
        active_families = await token_family_repository.get_user_families(
            user_id, 
            status=TokenFamilyStatus.ACTIVE
        )
        assert len(active_families) == 3
        
        # Get only compromised families
        compromised_families = await token_family_repository.get_user_families(
            user_id,
            status=TokenFamilyStatus.COMPROMISED
        )
        assert len(compromised_families) == 2
    
    async def test_get_expired_families_real_datetime_queries(
        self,
        token_family_repository: TokenFamilyRepository,
        test_users,
        async_session: AsyncSession
    ):
        """Test getting expired families with real datetime queries."""
        current_time = datetime.now(timezone.utc)
        
        # Create expired family
        expired_family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=test_users[0].id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=current_time - timedelta(days=10),
            expires_at=current_time - timedelta(days=1),  # Expired
            security_score=1.0
        )
        
        # Create active family
        active_family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=test_users[1].id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=current_time,
            expires_at=current_time + timedelta(days=7),  # Not expired
            security_score=1.0
        )
        
        await token_family_repository.create_token_family(expired_family)
        await token_family_repository.create_token_family(active_family)
        await async_session.commit()
        
        # Get expired families
        expired_families = await token_family_repository.get_expired_families()
        
        # Should find the expired family
        expired_family_ids = [f.family_id for f in expired_families]
        assert expired_family.family_id in expired_family_ids
        assert active_family.family_id not in expired_family_ids
    
    async def test_token_reuse_detection_real_scenario(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user,
        async_session: AsyncSession
    ):
        """Test token reuse detection with real database operations."""
        # Create family with token
        family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=test_user.id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            security_score=1.0
        )
        
        token_id = TokenId(create_valid_token_id())
        family.add_token(token_id)
        
        # Save to database
        created_family = await token_family_repository.create_token_family(family)
        await async_session.commit()
        
        # Revoke the token (simulate token refresh)
        created_family.revoke_token(token_id)
        await token_family_repository.update_family(created_family)
        await async_session.commit()
        
        # Check for reuse (should detect reuse)
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-123"
        )
        
        reuse_detected = await token_family_repository.check_token_reuse(
            token_id=token_id,
            family_id=family.family_id,
            security_context=security_context,
            correlation_id="test-123"
        )
        
        assert reuse_detected is True
    
    async def test_security_metrics_real_aggregation(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user,
        async_session: AsyncSession
    ):
        """Test security metrics with real database aggregation queries."""
        user_id = test_user.id
        
        # Create families with different statuses
        families_data = [
            (TokenFamilyStatus.ACTIVE, 1.0),
            (TokenFamilyStatus.ACTIVE, 1.0),
            (TokenFamilyStatus.COMPROMISED, 0.0),
            (TokenFamilyStatus.REVOKED, 0.5),
        ]
        
        for status, score in families_data:
            family = TokenFamily(
                family_id=str(uuid.uuid4()),
                user_id=user_id,
                status=status,
                created_at=datetime.now(timezone.utc),
                security_score=score
            )
            await token_family_repository.create_token_family(family)
        
        await async_session.commit()
        
        # Get security metrics
        metrics = await token_family_repository.get_security_metrics(
            user_id=user_id,
            time_window_hours=24
        )
        
        # Verify metrics
        assert metrics["total_families_created"] == 4
        assert metrics["families_active"] == 2
        assert metrics["families_compromised"] == 1
        assert metrics["families_revoked"] == 1
        assert metrics["compromise_rate_percent"] == 25.0  # 1 out of 4
        assert 0.5 <= metrics["average_security_score"] <= 0.7  # Average of 1,1,0,0.5
    
    async def test_performance_large_dataset(
        self,
        token_family_repository: TokenFamilyRepository,
        test_users,
        async_session: AsyncSession
    ):
        """Test performance with larger dataset of real operations."""
        import time
        
        # Create many families
        start_time = time.time()
        
        families = []
        for i in range(100):  # Reasonable size for integration test
            family = TokenFamily(
                family_id=str(uuid.uuid4()),
                user_id=test_users[i % 10].id,  # Distribute across 10 users
                status=TokenFamilyStatus.ACTIVE,
                created_at=datetime.now(timezone.utc),
                security_score=1.0
            )
            families.append(family)
        
        # Batch create
        creation_tasks = [
            token_family_repository.create_token_family(family)
            for family in families
        ]
        
        created_families = await asyncio.gather(*creation_tasks)
        await async_session.commit()
        
        creation_time = time.time() - start_time
        
        # Performance assertions (reasonable for integration test)
        assert creation_time < 30.0  # Should complete within 30 seconds
        assert len(created_families) == 100
        
        # Test retrieval performance
        start_time = time.time()
        
        retrieved_families = await token_family_repository.get_user_families(12345, limit=50)
        
        retrieval_time = time.time() - start_time
        
        # Retrieval should be fast
        assert retrieval_time < 5.0  # Should complete within 5 seconds
        assert len(retrieved_families) > 0