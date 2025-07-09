"""
Integration Tests for Unified Token Architecture.

This test suite validates the complete token family security architecture including:
- Token family creation and management
- Database-only token storage with encryption
- Token family security patterns and reuse detection
- Family-wide revocation on security violations
- Performance and security metrics
- Migration from Redis-based to database-only architecture

Architecture Coverage:
- Domain entities (TokenFamily) with business logic
- Repository layer with encrypted persistence
- Domain services (TokenFamilySecurityService)
- Infrastructure services (UnifiedTokenService, FieldEncryptionService)
- Database integration with PostgreSQL and encrypted storage
- Complete ACID transaction support

Security Testing:
- Token reuse detection and family compromise
- Encrypted field storage and retrieval
- Security metrics and monitoring
- Performance validation for sub-millisecond operations
- Comprehensive audit trails and forensic analysis
"""

import asyncio
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from cryptography.fernet import Fernet

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from src.core.config.settings import settings
from src.domain.entities.user import User, Role
from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus, TokenUsageEvent
from src.domain.value_objects.jwt_token import TokenId
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.security.field_encryption_service import FieldEncryptionService
from src.infrastructure.services.authentication.unified_token_service import UnifiedTokenService
from src.domain.services.authentication.token_family_security_service import TokenFamilySecurityService
from src.core.exceptions import AuthenticationError


class TestUnifiedTokenArchitecture:
    """
    Integration tests for the complete unified token architecture.
    
    Tests the full stack from domain entities through infrastructure services
    to ensure proper integration of token family security patterns with
    database-only storage and encryption.
    """
    
    @pytest_asyncio.fixture
    async def db_session(self, async_db_session: AsyncSession) -> AsyncSession:
        """Get database session for testing."""
        return async_db_session
    
    @pytest_asyncio.fixture
    async def test_user(self, db_session: AsyncSession) -> User:
        """Create a test user for token operations."""
        user = User(
            username="test_user",
            email="test@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user
    
    @pytest_asyncio.fixture
    async def encryption_service(self) -> FieldEncryptionService:
        """Create field encryption service with test key."""
        test_key = Fernet.generate_key().decode()
        return FieldEncryptionService(encryption_key=test_key)
    
    @pytest_asyncio.fixture
    async def token_family_repository(
        self, 
        db_session: AsyncSession,
        encryption_service: FieldEncryptionService
    ) -> TokenFamilyRepository:
        """Create token family repository with encryption."""
        return TokenFamilyRepository(db_session, encryption_service)
    
    @pytest_asyncio.fixture
    async def token_family_security_service(
        self, 
        token_family_repository: TokenFamilyRepository
    ) -> TokenFamilySecurityService:
        """Create token family security service."""
        return TokenFamilySecurityService(token_family_repository)
    
    @pytest_asyncio.fixture
    async def unified_token_service(
        self,
        db_session: AsyncSession,
        token_family_repository: TokenFamilyRepository,
        token_family_security_service: TokenFamilySecurityService
    ) -> UnifiedTokenService:
        """Create unified token service."""
        return UnifiedTokenService(
            db_session=db_session,
            token_family_repository=token_family_repository,
            token_family_security_service=token_family_security_service
        )
    
    @pytest.mark.asyncio
    async def test_token_family_creation_with_encryption(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user: User
    ):
        """Test token family creation with encrypted storage."""
        # Create token family with initial token
        initial_token = TokenId.generate()
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        token_family = await token_family_repository.create_family(
            user_id=test_user.id,
            initial_token_id=initial_token,
            expires_at=expires_at,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-001"
        )
        
        # Verify token family properties
        assert token_family.user_id == test_user.id
        assert token_family.status == TokenFamilyStatus.ACTIVE
        assert token_family.family_id is not None
        assert len(token_family.active_tokens) == 1
        assert token_family.active_tokens[0] == initial_token
        assert len(token_family.usage_history) == 1
        assert token_family.usage_history[0].event_type == TokenUsageEvent.ISSUED
        
        # Verify encrypted data is stored in database
        assert token_family.active_tokens_encrypted is not None
        assert token_family.usage_history_encrypted is not None
        assert isinstance(token_family.active_tokens_encrypted, bytes)
        assert len(token_family.active_tokens_encrypted) > 0
    
    @pytest.mark.asyncio
    async def test_token_family_retrieval_with_decryption(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user: User
    ):
        """Test token family retrieval with automatic decryption."""
        # Create token family
        initial_token = TokenId.generate()
        token_family = await token_family_repository.create_family(
            user_id=test_user.id,
            initial_token_id=initial_token
        )
        
        family_id = token_family.family_id
        
        # Retrieve token family (should decrypt automatically)
        retrieved_family = await token_family_repository.get_family_by_id(family_id)
        
        assert retrieved_family is not None
        assert retrieved_family.family_id == family_id
        assert len(retrieved_family.active_tokens) == 1
        assert retrieved_family.active_tokens[0] == initial_token
        assert len(retrieved_family.usage_history) == 1
    
    @pytest.mark.asyncio
    async def test_unified_token_service_create_token_pair(
        self,
        unified_token_service: UnifiedTokenService,
        test_user: User
    ):
        """Test unified token service creates token pairs with family security."""
        # Create token pair
        token_pair = await unified_token_service.create_token_pair_with_family(
            user=test_user,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-002"
        )
        
        # Verify token pair structure
        assert "access_token" in token_pair
        assert "refresh_token" in token_pair
        assert "family_id" in token_pair
        assert "jti" in token_pair
        assert token_pair["token_type"] == "bearer"
        
        # Verify tokens are valid JWT format
        access_token = token_pair["access_token"]
        refresh_token = token_pair["refresh_token"]
        
        assert len(access_token.split('.')) == 3  # JWT has 3 parts
        assert len(refresh_token.split('.')) == 3
        
        # Verify family was created in database
        family_id = token_pair["family_id"]
        assert family_id is not None
        assert len(family_id) == 36  # UUID format
    
    @pytest.mark.asyncio
    async def test_token_refresh_with_family_security(
        self,
        unified_token_service: UnifiedTokenService,
        test_user: User
    ):
        """Test token refresh with family security validation."""
        # Create initial token pair
        initial_pair = await unified_token_service.create_token_pair_with_family(
            user=test_user,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-003"
        )
        
        # Refresh tokens
        refreshed_pair = await unified_token_service.refresh_tokens_with_family_security(
            refresh_token=initial_pair["refresh_token"],
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-003-refresh"
        )
        
        # Verify new token pair
        assert refreshed_pair["family_id"] == initial_pair["family_id"]
        assert refreshed_pair["jti"] != initial_pair["jti"]
        assert refreshed_pair["access_token"] != initial_pair["access_token"]
        assert refreshed_pair["refresh_token"] != initial_pair["refresh_token"]
        
        # Verify old tokens are revoked (attempt to refresh again should fail)
        with pytest.raises(AuthenticationError):
            await unified_token_service.refresh_tokens_with_family_security(
                refresh_token=initial_pair["refresh_token"],
                client_ip="192.168.1.100",
                user_agent="Test Agent",
                correlation_id="test-003-invalid"
            )
    
    @pytest.mark.asyncio
    async def test_token_reuse_detection_and_family_compromise(
        self,
        unified_token_service: UnifiedTokenService,
        token_family_repository: TokenFamilyRepository,
        test_user: User
    ):
        """Test token reuse detection triggers family compromise."""
        # Create initial token pair
        initial_pair = await unified_token_service.create_token_pair_with_family(
            user=test_user,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-004"
        )
        
        # Refresh tokens to revoke the initial ones
        refreshed_pair = await unified_token_service.refresh_tokens_with_family_security(
            refresh_token=initial_pair["refresh_token"],
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-004-refresh"
        )
        
        # Attempt to use the old refresh token (reuse attack)
        with pytest.raises(AuthenticationError) as exc_info:
            await unified_token_service.refresh_tokens_with_family_security(
                refresh_token=initial_pair["refresh_token"],
                client_ip="192.168.1.101",  # Different IP suggests attack
                user_agent="Malicious Agent",
                correlation_id="test-004-attack"
            )
        
        # Verify family is compromised
        family_id = initial_pair["family_id"]
        token_family = await token_family_repository.get_family_by_id(family_id)
        
        assert token_family.status == TokenFamilyStatus.COMPROMISED
        assert token_family.compromised_at is not None
        assert "reuse" in token_family.compromise_reason.lower()
        
        # Verify no new tokens can be created for compromised family
        with pytest.raises(AuthenticationError):
            await unified_token_service.refresh_tokens_with_family_security(
                refresh_token=refreshed_pair["refresh_token"],
                client_ip="192.168.1.100",
                user_agent="Test Agent",
                correlation_id="test-004-post-compromise"
            )
    
    @pytest.mark.asyncio
    async def test_token_validation_with_family_security(
        self,
        unified_token_service: UnifiedTokenService,
        test_user: User
    ):
        """Test token validation with family security checks."""
        # Create token pair
        token_pair = await unified_token_service.create_token_pair_with_family(
            user=test_user,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-005"
        )
        
        # Validate access token
        payload = await unified_token_service.validate_token_with_family_security(
            token=token_pair["access_token"],
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-005-validate"
        )
        
        # Verify payload
        assert payload["sub"] == str(test_user.id)
        assert payload["jti"] == token_pair["jti"]
        assert payload["family_id"] == token_pair["family_id"]
        assert payload["username"] == test_user.username
        assert payload["email"] == test_user.email
    
    @pytest.mark.asyncio
    async def test_encryption_service_integration(
        self,
        encryption_service: FieldEncryptionService
    ):
        """Test field encryption service with token family data."""
        # Create test data
        token_list = [TokenId.generate() for _ in range(3)]
        
        # Encrypt token list
        encrypted_data = await encryption_service.encrypt_token_list(token_list)
        
        # Verify encryption
        assert isinstance(encrypted_data, bytes)
        assert len(encrypted_data) > 0
        
        # Decrypt token list
        decrypted_tokens = await encryption_service.decrypt_token_list(encrypted_data)
        
        # Verify decryption
        assert len(decrypted_tokens) == 3
        assert all(isinstance(token, TokenId) for token in decrypted_tokens)
        assert all(orig.value == decr.value for orig, decr in zip(token_list, decrypted_tokens))
    
    @pytest.mark.asyncio
    async def test_performance_token_validation_speed(
        self,
        unified_token_service: UnifiedTokenService,
        test_user: User
    ):
        """Test token validation performance meets sub-millisecond requirement."""
        # Create token pair
        token_pair = await unified_token_service.create_token_pair_with_family(
            user=test_user,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-006"
        )
        
        # Measure validation performance
        start_time = datetime.now(timezone.utc)
        
        for i in range(10):  # Multiple validations to test consistency
            await unified_token_service.validate_token_with_family_security(
                token=token_pair["access_token"],
                client_ip="192.168.1.100",
                user_agent="Test Agent",
                correlation_id=f"test-006-perf-{i}"
            )
        
        end_time = datetime.now(timezone.utc)
        total_time_ms = (end_time - start_time).total_seconds() * 1000
        avg_time_ms = total_time_ms / 10
        
        # Verify performance (should be well under 1ms per validation)
        assert avg_time_ms < 1.0, f"Average validation time {avg_time_ms}ms exceeds 1ms threshold"
    
    @pytest.mark.asyncio
    async def test_security_metrics_collection(
        self,
        token_family_repository: TokenFamilyRepository,
        test_user: User
    ):
        """Test security metrics collection and analysis."""
        # Create multiple token families with different states
        families = []
        
        # Active family
        active_family = await token_family_repository.create_family(
            user_id=test_user.id,
            initial_token_id=TokenId.generate()
        )
        families.append(active_family)
        
        # Compromised family
        compromised_family = await token_family_repository.create_family(
            user_id=test_user.id,
            initial_token_id=TokenId.generate()
        )
        await token_family_repository.compromise_family(
            family_id=compromised_family.family_id,
            reason="Test compromise",
            correlation_id="test-007-compromise"
        )
        families.append(compromised_family)
        
        # Get security metrics
        metrics = await token_family_repository.get_security_metrics(
            user_id=test_user.id,
            time_window_hours=24
        )
        
        # Verify metrics structure
        assert "total_families_created" in metrics
        assert "families_by_status" in metrics
        assert "compromise_rate_percent" in metrics
        assert "average_security_score" in metrics
        
        # Verify metric values
        assert metrics["total_families_created"] >= 2
        assert metrics["families_by_status"]["active"] >= 1
        assert metrics["families_by_status"]["compromised"] >= 1
        assert metrics["compromise_rate_percent"] > 0
    
    @pytest.mark.asyncio
    async def test_database_transaction_integrity(
        self,
        unified_token_service: UnifiedTokenService,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test ACID transaction integrity during token operations."""
        # Start a transaction
        async with db_session.begin():
            # Create token pair within transaction
            token_pair = await unified_token_service.create_token_pair_with_family(
                user=test_user,
                client_ip="192.168.1.100",
                user_agent="Test Agent",
                correlation_id="test-008"
            )
            
            # Verify family exists within transaction
            family_id = token_pair["family_id"]
            family_count = await db_session.execute(
                text("SELECT COUNT(*) FROM token_families WHERE family_id = :family_id"),
                {"family_id": family_id}
            )
            assert family_count.scalar() == 1
            
            # Simulate transaction rollback by raising exception
            if True:  # Always rollback for test
                raise Exception("Test rollback")
        
        # Verify rollback worked - family should not exist
        family_count = await db_session.execute(
            text("SELECT COUNT(*) FROM token_families WHERE family_id = :family_id"),
            {"family_id": family_id}
        )
        assert family_count.scalar() == 0
    
    @pytest.mark.asyncio
    async def test_concurrent_token_operations(
        self,
        unified_token_service: UnifiedTokenService,
        test_user: User
    ):
        """Test concurrent token operations for race condition safety."""
        async def create_and_refresh_tokens(correlation_id: str):
            """Create and refresh tokens concurrently."""
            # Create token pair
            token_pair = await unified_token_service.create_token_pair_with_family(
                user=test_user,
                client_ip="192.168.1.100",
                user_agent="Test Agent",
                correlation_id=correlation_id
            )
            
            # Refresh tokens
            refreshed_pair = await unified_token_service.refresh_tokens_with_family_security(
                refresh_token=token_pair["refresh_token"],
                client_ip="192.168.1.100",
                user_agent="Test Agent",
                correlation_id=f"{correlation_id}-refresh"
            )
            
            return refreshed_pair
        
        # Run concurrent operations
        tasks = [
            create_and_refresh_tokens(f"test-009-{i}")
            for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify all operations succeeded
        assert len(results) == 5
        assert all("access_token" in result for result in results)
        assert all("family_id" in result for result in results)
        
        # Verify all families are unique
        family_ids = [result["family_id"] for result in results]
        assert len(set(family_ids)) == 5  # All unique
    
    @pytest.mark.asyncio
    async def test_migration_compatibility_legacy_tokens(
        self,
        unified_token_service: UnifiedTokenService,
        test_user: User
    ):
        """Test compatibility with legacy tokens during migration."""
        # Create a legacy-style token without family (simulated)
        legacy_access_token = await unified_token_service.create_access_token(
            user=test_user,
            # No family_id provided - simulates legacy token
        )
        
        # Validate legacy token (should work without family security)
        payload = await unified_token_service.validate_token_with_family_security(
            token=legacy_access_token,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-010-legacy"
        )
        
        # Verify legacy token validation
        assert payload["sub"] == str(test_user.id)
        assert "family_id" not in payload  # Legacy tokens don't have family ID
        
        # Legacy tokens should still be functional but without advanced security
        assert payload["username"] == test_user.username
        assert payload["email"] == test_user.email 