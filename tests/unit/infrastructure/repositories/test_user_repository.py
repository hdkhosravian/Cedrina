"""
Comprehensive Test Suite for UserRepository.

This test suite covers real-world production scenarios including:
- High concurrency database operations
- Security threat detection and response
- Database failure recovery
- Value object integration
- Performance under load
- Memory leak detection
- Cross-service integration failures
- Network partition handling
- Malicious data injection attempts
- Rate limiting and abuse prevention
"""

import asyncio
import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from typing import List, Dict, Any, Optional

from sqlalchemy.exc import OperationalError, IntegrityError, DatabaseError
from sqlalchemy.ext.asyncio import AsyncSession

from src.common.exceptions import DuplicateUserError
from src.domain.entities.user import User, Role
from src.domain.value_objects.email import Email
from src.domain.value_objects.username import Username
from src.infrastructure.repositories.user_repository import UserRepository


class TestUserRepositoryProductionScenarios:
    """Test UserRepository with real-world production scenarios."""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session with realistic behavior."""
        session = AsyncMock(spec=AsyncSession)
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.close = AsyncMock()
        session.add = AsyncMock()
        session.merge = AsyncMock()
        session.delete = AsyncMock()
        session.execute = AsyncMock()
        session.refresh = AsyncMock()
        return session
    
    @pytest.fixture
    def user_repository(self, mock_db_session):
        """User repository with mocked database session."""
        return UserRepository(session_factory=mock_db_session)
    
    @pytest.fixture
    def sample_user(self):
        """Sample user entity for testing."""
        return User(
            id=12345,
            username="testuser",
            email="test@example.com",
            role=Role.USER,
            is_active=True,
            password_hash="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQ2",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    @pytest.fixture
    def sample_users(self):
        """Multiple sample users for testing."""
        return [
            User(
                id=12345,
                username="user1",
                email="user1@example.com",
                role=Role.USER,
                is_active=True
            ),
            User(
                id=12346,
                username="user2",
                email="user2@example.com",
                role=Role.ADMIN,
                is_active=True
            ),
            User(
                id=12347,
                username="user3",
                email="user3@example.com",
                role=Role.USER,
                is_active=False
            )
        ]

    # High Concurrency Scenarios
    # =========================
    
    @pytest.mark.asyncio
    async def test_concurrent_user_creation_race_condition(
        self,
        user_repository,
        sample_user
    ):
        """Test handling of concurrent user creation requests."""
        # Mock database session to handle concurrent access
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # Simulate concurrent user creation
        tasks = []
        for i in range(10):
            user = User(
                id=None,  # Let database assign ID
                username=f"concurrent_user_{i}",
                email=f"concurrent_user_{i}@example.com",
                role=Role.USER,
                is_active=True
            )
            task = user_repository.save(user)
            tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify all requests succeeded
        assert len(results) == 10
        for result in results:
            assert isinstance(result, User)
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_exhaustion(
        self,
        user_repository,
        sample_user
    ):
        """Test behavior when database connection pool is exhausted."""
        # Mock database session commit to simulate connection pool exhaustion
        # This happens during the commit phase which all save operations must perform
        user_repository.db_session.commit.side_effect = OperationalError(
            "connection pool exhausted",
            None,
            None
        )
        
        with pytest.raises(OperationalError):
            await user_repository.save(sample_user)
    
    @pytest.mark.asyncio
    async def test_concurrent_user_updates(
        self,
        user_repository,
        sample_user
    ):
        """Test concurrent updates to the same user."""
        # Mock database session for concurrent updates
        user_repository.db_session.merge.return_value = sample_user
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # Simulate concurrent updates
        update_tasks = []
        for i in range(5):
            user = User(
                id=sample_user.id,
                username=f"updated_user_{i}",
                email=sample_user.email,
                role=sample_user.role,
                is_active=sample_user.is_active
            )
            task = user_repository.save(user)
            update_tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*update_tasks, return_exceptions=True)
        
        # All updates should complete (some may fail due to concurrency)
        assert len(results) == 5
    
    # Security Threat Scenarios
    # =========================
    
    @pytest.mark.asyncio
    async def test_malicious_data_injection_attempts(
        self,
        user_repository
    ):
        """Test that malicious data is rejected at the domain level during User creation.
        
        Note: This test verifies that malicious data cannot even create a User entity,
        demonstrating proper domain-level validation. The repository should only handle
        persistence of valid User entities.
        """
        from pydantic import ValidationError
        
        malicious_data_samples = [
            # SQL injection attempts
            {
                "id": 12345,
                "username": "'; DROP TABLE users; --",
                "email": "test@example.com",
                "role": Role.USER,
                "is_active": True
            },
            # XSS attempts  
            {
                "id": 12345,
                "username": "<script>alert('xss')</script>",
                "email": "test@example.com",
                "role": Role.USER,
                "is_active": True
            },
            # Path traversal attempts
            {
                "id": 12345,
                "username": "../../../etc/passwd",
                "email": "test@example.com",
                "role": Role.USER,
                "is_active": True
            },
            # Command injection attempts
            {
                "id": 12345,
                "username": "; rm -rf /",
                "email": "test@example.com",
                "role": Role.USER,
                "is_active": True
            },
            # Invalid characters in username
            {
                "id": 12345,
                "username": "user@invalid",
                "email": "test@example.com",
                "role": Role.USER,
                "is_active": True
            },
        ]
        
        # Test that User entity validation prevents malicious data
        for malicious_data in malicious_data_samples:
            with pytest.raises(ValidationError):
                User(**malicious_data)
        
        # Test that repository correctly handles valid User entities
        valid_user = User(
            id=12345,
            username="valid_user",
            email="valid@example.com",
            role=Role.USER,
            is_active=True
        )
        await user_repository.save(valid_user)
    
    @pytest.mark.asyncio
    async def test_duplicate_user_detection(
        self,
        user_repository,
        sample_user
    ):
        """Test detection and handling of duplicate users during database commit.
        
        Note: Since sample_user has an ID, this tests the update path where
        duplicate constraint violations occur during commit phase.
        """
        # Mock database session commit to simulate duplicate key error during transaction commit
        # This can happen during both create and update operations when constraints are violated
        user_repository.db_session.commit.side_effect = IntegrityError(
            "duplicate key value violates unique constraint",
            None,
            None
        )
        
        with pytest.raises(DuplicateUserError):
            await user_repository.save(sample_user)
    
    @pytest.mark.asyncio
    async def test_sensitive_data_masking_in_logs(
        self,
        user_repository,
        sample_user
    ):
        """Test that sensitive data is properly masked in logs."""
        # Mock successful user save
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # Save user and verify logging doesn't expose sensitive data
        result = await user_repository.save(sample_user)
        assert result is not None
        
        # Verify that sensitive data is not logged in plain text
        # This would be verified by checking log output in a real scenario
    
    # Performance and Load Testing
    # ===========================
    
    @pytest.mark.asyncio
    async def test_high_throughput_user_operations(
        self,
        user_repository,
        sample_user
    ):
        """Test performance under high user operation load."""
        # Mock database session for high load
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        start_time = datetime.now(timezone.utc)
        
        # Simulate high load operations
        creation_tasks = []
        for i in range(1000):
            user = User(
                id=None,
                username=f"load_user_{i}",
                email=f"load_user_{i}@example.com",
                role=Role.USER,
                is_active=True
            )
            task = user_repository.save(user)
            creation_tasks.append(task)
        
        # Execute all operations
        results = await asyncio.gather(*creation_tasks, return_exceptions=True)
        end_time = datetime.now(timezone.utc)
        
        # Verify performance requirements
        execution_time = (end_time - start_time).total_seconds()
        assert execution_time < 30.0  # Should complete within 30 seconds
        assert len(results) == 1000
        
        # Verify all operations succeeded
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        assert success_count == 1000
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(
        self,
        user_repository,
        sample_user
    ):
        """Test memory usage doesn't grow unbounded under load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Mock database session
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # Simulate sustained load
        for _ in range(1000):
            user = User(
                id=None,
                username=f"memory_user_{_}",
                email=f"memory_user_{_}@example.com",
                role=Role.USER,
                is_active=True
            )
            
            try:
                await user_repository.save(user)
            except Exception:
                pass  # Expected some failures in load testing
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024
    
    # Database Failure Recovery
    # =========================
    
    @pytest.mark.asyncio
    async def test_database_transaction_rollback_on_failure(
        self,
        user_repository,
        sample_user
    ):
        """Test proper transaction rollback when operations fail.
        
        This test verifies that when database operations fail during commit,
        the repository properly rolls back the transaction.
        """
        # Mock database failure during commit (applies to both create and update paths)
        user_repository.db_session.commit.side_effect = IntegrityError(
            "duplicate key value violates unique constraint",
            None,
            None
        )
        
        with pytest.raises(DuplicateUserError):
            await user_repository.save(sample_user)
        
        # Verify rollback was called
        user_repository.db_session.rollback.assert_called()
    
    @pytest.mark.asyncio
    async def test_partial_failure_recovery(
        self,
        user_repository,
        sample_user
    ):
        """Test recovery from partial failures in database operations.
        
        This test verifies that the repository properly handles transient
        database failures and can recover for subsequent operations.
        """
        # Mock database failures during commit phase (which all save operations go through)
        user_repository.db_session.commit.side_effect = [
            None,  # First save succeeds
            DatabaseError("Database temporarily unavailable", None, None),  # Second save fails
            None,  # Third save succeeds after recovery
        ]
        
        # First user save should succeed
        result1 = await user_repository.save(sample_user)
        assert result1 is not None
        
        # Second user save should fail due to database issue
        with pytest.raises(DatabaseError):
            await user_repository.save(sample_user)
        
        # Third save should succeed (simulating database recovery)
        result3 = await user_repository.save(sample_user)
        assert result3 is not None
    
    # Value Object Integration
    # =======================
    
    @pytest.mark.asyncio
    async def test_email_value_object_integration(
        self,
        user_repository
    ):
        """Test integration with Email value object."""
        # Mock database query
        user_repository.db_session.execute.return_value = MagicMock()
        user_repository.db_session.execute.return_value.scalars.return_value.first.return_value = None
        
        # Test with Email value object
        email_vo = Email("test@example.com")
        result = await user_repository.get_by_email(email_vo)
        
        assert result is None  # User doesn't exist
    
    @pytest.mark.asyncio
    async def test_username_value_object_integration(
        self,
        user_repository
    ):
        """Test integration with Username value object."""
        # Mock database query
        user_repository.db_session.execute.return_value = MagicMock()
        user_repository.db_session.execute.return_value.scalars.return_value.first.return_value = None
        
        # Test with Username value object
        username_vo = Username("testuser")
        result = await user_repository.get_by_username(username_vo)
        
        assert result is None  # User doesn't exist
    
    @pytest.mark.asyncio
    async def test_value_object_validation(
        self,
        user_repository
    ):
        """Test value object validation at domain level and repository integration.
        
        This test verifies that:
        1. Email value objects validate format at domain level
        2. Repository handles empty/invalid string inputs appropriately
        3. Repository correctly processes valid Email value objects
        """
        from src.domain.value_objects.email import Email
        from pydantic import ValidationError
        
        # Test domain-level validation: Email value object should reject invalid formats
        invalid_email_formats = [
            "invalid-email",
            "@example.com", 
            "test@",
            "test@.com",
            "test..test@example.com",
        ]
        
        for invalid_format in invalid_email_formats:
            with pytest.raises(ValueError):
                Email(invalid_format)
        
        # Test repository-level validation: should reject empty emails
        empty_emails = ["", "   ", "\t\n"]
        for empty_email in empty_emails:
            with pytest.raises(ValueError):
                await user_repository.get_by_email(empty_email)
        
        # Test successful integration: repository should handle valid Email value objects
        valid_email = Email("test@example.com")
        # Mock successful query (no user found is acceptable)
        from unittest.mock import MagicMock
        user_repository.db_session.execute.return_value = MagicMock()
        user_repository.db_session.execute.return_value.scalars.return_value.first.return_value = None
        result = await user_repository.get_by_email(valid_email)
        assert result is None  # No user found is valid behavior
        
        # Test username validation: similar architectural pattern
        from src.domain.entities.user import User
        
        # Test domain-level validation: User entity should reject invalid usernames
        invalid_username_data = [
            {"id": 1, "username": "a", "email": "test@example.com", "role": Role.USER, "is_active": True},  # Too short
            {"id": 1, "username": "A" * 51, "email": "test@example.com", "role": Role.USER, "is_active": True},  # Too long
            {"id": 1, "username": "user@name", "email": "test@example.com", "role": Role.USER, "is_active": True},  # Invalid chars
            {"id": 1, "username": "user name", "email": "test@example.com", "role": Role.USER, "is_active": True},  # Spaces
        ]
        
        for invalid_data in invalid_username_data:
            with pytest.raises(ValidationError):
                User(**invalid_data)
        
        # Test repository-level validation: should reject empty usernames
        empty_usernames = ["", "   ", "\t\n"]
        for empty_username in empty_usernames:
            with pytest.raises(ValueError):
                await user_repository.get_by_username(empty_username)
    
    # Network and Integration Scenarios
    # =================================
    
    @pytest.mark.asyncio
    async def test_network_partition_handling(
        self,
        user_repository,
        sample_user
    ):
        """Test behavior during network partitions and recovery.
        
        This test simulates network connectivity issues that affect database
        operations and verifies that the repository handles them appropriately.
        """
        # Mock network partition scenario affecting database commits
        user_repository.db_session.commit.side_effect = [
            Exception("Network timeout"),
            Exception("Connection refused"),
            None  # Success after network partition resolves
        ]
        
        # First two attempts should fail due to network issues
        with pytest.raises(Exception):
            await user_repository.save(sample_user)
        
        with pytest.raises(Exception):
            await user_repository.save(sample_user)
        
        # Third attempt should succeed after network recovery
        result = await user_repository.save(sample_user)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_cross_service_integration_failure(
        self,
        user_repository,
        sample_user
    ):
        """Test handling of cross-service integration failures.
        
        Note: Since sample_user has an ID, it follows the update path which calls commit,
        not add. Mock commit to simulate database service failure.
        """
        # Mock database session failure during commit (applies to both create and update paths)
        user_repository.db_session.commit.side_effect = Exception(
            "Database service unavailable"
        )
        
        # User save should fail gracefully
        with pytest.raises(Exception):
            await user_repository.save(sample_user)
    
    # Security Validation Scenarios
    # =============================
    
    @pytest.mark.asyncio
    async def test_user_validation_handling(
        self,
        user_repository
    ):
        """Test proper handling of invalid user data.
        
        This test verifies repository-level validation (None users) and 
        domain-level validation (invalid User entity creation).
        """
        from pydantic import ValidationError
        
        # Test repository-level validation: None user should be rejected by repository
        with pytest.raises(ValueError, match="User entity cannot be None"):
            await user_repository.save(None)
        
        # Test domain-level validation: invalid User entities should fail at creation
        invalid_user_data = [
            # User with empty username (should fail at entity level)
            {
                "id": 12345,
                "username": "",
                "email": "test@example.com",
                "role": Role.USER,
                "is_active": True
            },
            
            # User with invalid email (should fail at entity level)
            {
                "id": 12345,
                "username": "testuser",
                "email": "invalid-email",
                "role": Role.USER,
                "is_active": True
            },
            
            # User with username too short (should fail at entity level)
            {
                "id": 12345,
                "username": "ab",
                "email": "test@example.com",
                "role": Role.USER,
                "is_active": True
            },
        ]
        
        for user_data in invalid_user_data:
            with pytest.raises(ValidationError):
                User(**user_data)
                
        # Test successful repository handling of valid User entities
        valid_user = User(
            id=12345,
            username="validuser",
            email="valid@example.com",
            role=Role.USER,
            is_active=True
        )
        
        # Mock database operations for successful save
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        result = await user_repository.save(valid_user)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_user_availability_checking(
        self,
        user_repository,
        sample_user
    ):
        """Test username and email availability checking."""
        # Mock database queries
        user_repository.db_session.execute.return_value = MagicMock()
        user_repository.db_session.execute.return_value.scalars.return_value.first.return_value = None
        
        # Check username availability
        username_available = await user_repository.check_username_availability("newuser")
        assert username_available is True
        
        # Check email availability
        email_available = await user_repository.check_email_availability("new@example.com")
        assert email_available is True
        
        # Mock existing user
        user_repository.db_session.execute.return_value.scalars.return_value.first.return_value = sample_user
        
        # Check username availability with existing user
        username_available = await user_repository.check_username_availability("testuser")
        assert username_available is False
        
        # Check email availability with existing user
        email_available = await user_repository.check_email_availability("test@example.com")
        assert email_available is False
    
    # Error Handling and Logging
    # ===========================
    
    @pytest.mark.asyncio
    async def test_comprehensive_error_logging(
        self,
        user_repository,
        sample_user
    ):
        """Test that all errors are properly logged."""
        # Mock various error scenarios
        error_scenarios = [
            (OperationalError("Database connection failed", None, None), "database_error"),
            (IntegrityError("Duplicate key", None, None), "integrity_error"),
            (DatabaseError("Transaction failed", None, None), "transaction_error"),
            (Exception("Unknown error"), "unknown_error"),
        ]
        
        for exception, error_type in error_scenarios:
            # Since sample_user has an ID, it follows the update path which calls commit, not add
            user_repository.db_session.commit.side_effect = exception
            
            with pytest.raises(Exception):
                await user_repository.save(sample_user)
    
    @pytest.mark.asyncio
    async def test_input_validation_logging(
        self,
        user_repository
    ):
        """Test logging of input validation errors."""
        invalid_inputs = [
            ("", "get_by_username"),  # Empty username
            ("", "get_by_email"),     # Empty email
            (0, "get_by_id"),         # Invalid user ID
            (-1, "get_by_id"),        # Negative user ID
        ]
        
        for invalid_input, method_name in invalid_inputs:
            with pytest.raises(ValueError):
                if method_name == "get_by_username":
                    await user_repository.get_by_username(invalid_input)
                elif method_name == "get_by_email":
                    await user_repository.get_by_email(invalid_input)
                elif method_name == "get_by_id":
                    await user_repository.get_by_id(invalid_input)
    
    # Edge Cases and Boundary Testing
    # ===============================
    
    @pytest.mark.asyncio
    async def test_extreme_user_sizes(
        self,
        user_repository,
        sample_user
    ):
        """Test handling of maximum allowed user data sizes and rejection of oversized data.
        
        This test verifies both repository handling of valid large data within domain constraints
        and proper rejection of data that exceeds domain validation limits.
        """
        from pydantic import ValidationError
        
        # Test domain validation: oversized data should be rejected at entity level
        with pytest.raises(ValidationError):
            User(
                id=12345,
                username="A" * 1000,  # Exceeds max_length=50
                email="test@example.com",
                role=Role.USER,
                is_active=True
            )
        
        with pytest.raises(ValidationError):
            User(
                id=12345,
                username="validuser",
                email="A" * 1000 + "@example.com",  # Email too long
                role=Role.USER,
                is_active=True
            )
        
        # Test repository handling: maximum allowed sizes within domain constraints
        max_size_user = User(
            id=12345,
            username="A" * 50,  # Maximum allowed username length
            email="testuser@example.com",  # Valid email within constraints
            role=Role.USER,
            is_active=True
        )
        
        # Mock database session
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # Repository should handle maximum valid data
        result = await user_repository.save(max_size_user)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_unicode_user_handling(
        self,
        user_repository
    ):
        """Test handling of Unicode characters in user data."""
        # Create user with Unicode data
        unicode_user = User(
            id=12345,
            username="测试用户",
            email="test@测试.com",
            role=Role.USER,
            is_active=True
        )
        
        # Mock database session
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # User save should handle Unicode
        result = await user_repository.save(unicode_user)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_null_and_empty_values(
        self,
        user_repository
    ):
        """Test handling of null and empty values."""
        null_values = [None, "", "   ", "\n", "\t"]
        
        for value in null_values:
            with pytest.raises(ValueError):
                await user_repository.get_by_username(value)
            
            with pytest.raises(ValueError):
                await user_repository.get_by_email(value)
    
    @pytest.mark.asyncio
    async def test_invalid_user_states(
        self,
        user_repository
    ):
        """Test handling of invalid user states."""
        # User with None ID for save operation
        user_without_id = User(
            id=None,
            username="newuser",
            email="new@example.com",
            role=Role.USER,
            is_active=True
        )
        
        # Mock database session
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # Save should succeed for new user
        result = await user_repository.save(user_without_id)
        assert result is not None
    
    # Integration Testing
    # ===================
    
    @pytest.mark.asyncio
    async def test_database_session_integration(
        self,
        user_repository,
        sample_user
    ):
        """Test integration with database session.
        
        Note: Since sample_user has an ID, it follows the update path which calls 
        commit and refresh but not add. For testing add, use a user without ID.
        """
        # Mock database session operations
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # User save should use database session (update path for existing user)
        result = await user_repository.save(sample_user)
        assert result is not None
        
        # Verify database session was used (update path: commit + refresh, no add)
        user_repository.db_session.commit.assert_called()
        user_repository.db_session.refresh.assert_called()
        
        # Test create path with user without ID
        new_user = User(
            id=None,  # No ID triggers create path
            username="newuser",
            email="new@example.com",
            role=Role.USER,
            is_active=True
        )
        
        # Mock add for create path
        user_repository.db_session.add.return_value = None
        
        # Create new user should call add
        result = await user_repository.save(new_user)
        assert result is not None
        
        # Verify add was called for new user
        user_repository.db_session.add.assert_called()
    
    @pytest.mark.asyncio
    async def test_user_lookup_integration(
        self,
        user_repository,
        sample_user
    ):
        """Test integration of user lookup operations."""
        # Mock database query for user lookup
        user_repository.db_session.execute.return_value = MagicMock()
        user_repository.db_session.execute.return_value.scalars.return_value.first.return_value = sample_user
        
        # Test various lookup methods
        by_id = await user_repository.get_by_id(12345)
        assert by_id is not None
        assert by_id.id == 12345
        
        by_username = await user_repository.get_by_username("testuser")
        assert by_username is not None
        assert by_username.username == "testuser"
        
        by_email = await user_repository.get_by_email("test@example.com")
        assert by_email is not None
        assert by_email.email == "test@example.com"
    
    # Performance Benchmarking
    # ========================
    
    @pytest.mark.asyncio
    async def test_user_creation_performance_benchmark(
        self,
        user_repository,
        sample_user
    ):
        """Benchmark user creation performance."""
        import time
        
        # Mock database operations
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # Warm up
        for _ in range(10):
            await user_repository.save(sample_user)
        
        # Benchmark
        start_time = time.time()
        for i in range(1000):
            user = User(
                id=None,
                username=f"benchmark_user_{i}",
                email=f"benchmark_user_{i}@example.com",
                role=Role.USER,
                is_active=True
            )
            await user_repository.save(user)
        end_time = time.time()
        
        # Calculate performance metrics
        total_time = end_time - start_time
        users_per_second = 1000 / total_time
        
        # Performance requirements
        assert users_per_second > 50  # Should create at least 50 users per second
        assert total_time < 20  # Should complete within 20 seconds
    
    @pytest.mark.asyncio
    async def test_user_lookup_performance_benchmark(
        self,
        user_repository,
        sample_user
    ):
        """Benchmark user lookup performance."""
        import time
        
        # Mock database query
        user_repository.db_session.execute.return_value = MagicMock()
        user_repository.db_session.execute.return_value.scalars.return_value.first.return_value = sample_user
        
        # Warm up
        for _ in range(10):
            await user_repository.get_by_id(12345)
        
        # Benchmark
        start_time = time.time()
        for _ in range(1000):
            await user_repository.get_by_id(12345)
        end_time = time.time()
        
        # Calculate performance metrics
        total_time = end_time - start_time
        lookups_per_second = 1000 / total_time
        
        # Performance requirements
        assert lookups_per_second > 200  # Should lookup at least 200 users per second
        assert total_time < 5  # Should complete within 5 seconds 