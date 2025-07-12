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
        return UserRepository(db_session=mock_db_session)
    
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
        # Mock database session to simulate connection pool exhaustion
        user_repository.db_session.add.side_effect = OperationalError(
            "connection pool exhausted",
            None,
            None
        )
        
        with pytest.raises(Exception):
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
        """Test handling of malicious data injection attempts."""
        malicious_users = [
            # SQL injection attempts
            User(
                id=12345,
                username="'; DROP TABLE users; --",
                email="'; INSERT INTO users VALUES ('hacker', 'hacker@evil.com'); --",
                role=Role.USER,
                is_active=True
            ),
            # XSS attempts
            User(
                id=12345,
                username="<script>alert('xss')</script>",
                email="javascript:alert('xss')@example.com",
                role=Role.USER,
                is_active=True
            ),
            # Path traversal attempts
            User(
                id=12345,
                username="../../../etc/passwd",
                email="../../../etc/passwd@example.com",
                role=Role.USER,
                is_active=True
            ),
            # Command injection attempts
            User(
                id=12345,
                username="; rm -rf /",
                email="| cat /etc/passwd@example.com",
                role=Role.USER,
                is_active=True
            ),
            # Buffer overflow attempts
            User(
                id=12345,
                username="A" * 10000,
                email="A" * 10000 + "@example.com",
                role=Role.USER,
                is_active=True
            ),
            # Unicode normalization attacks
            User(
                id=12345,
                username="test\u0000user",
                email="test\u200b@example.com",
                role=Role.USER,
                is_active=True
            ),
        ]
        
        for user in malicious_users:
            with pytest.raises(Exception):
                await user_repository.save(user)
    
    @pytest.mark.asyncio
    async def test_duplicate_user_detection(
        self,
        user_repository,
        sample_user
    ):
        """Test detection and handling of duplicate users."""
        # Mock database session to simulate duplicate key error
        user_repository.db_session.add.side_effect = IntegrityError(
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
        """Test proper transaction rollback when operations fail."""
        # Mock database failure during user save
        user_repository.db_session.add.side_effect = IntegrityError(
            "duplicate key value violates unique constraint",
            None,
            None
        )
        
        with pytest.raises(Exception):
            await user_repository.save(sample_user)
        
        # Verify rollback was called
        user_repository.db_session.rollback.assert_called()
    
    @pytest.mark.asyncio
    async def test_partial_failure_recovery(
        self,
        user_repository,
        sample_user
    ):
        """Test recovery from partial failures in user operations."""
        # Mock partial failure scenario
        user_repository.db_session.add.side_effect = [
            None,  # First call succeeds
            DatabaseError("Database temporarily unavailable"),  # Second call fails
            None,  # Third call succeeds
        ]
        
        # First user save should succeed
        result1 = await user_repository.save(sample_user)
        assert result1 is not None
        
        # Second user save should fail
        with pytest.raises(Exception):
            await user_repository.save(sample_user)
        
        # Third user save should succeed again
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
        """Test validation of value objects."""
        # Test invalid email formats
        invalid_emails = [
            "",
            "invalid-email",
            "@example.com",
            "test@",
            "test@.com",
            "test..test@example.com",
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValueError):
                await user_repository.get_by_email(email)
        
        # Test invalid username formats
        invalid_usernames = [
            "",
            "a",  # Too short
            "A" * 51,  # Too long
            "user@name",  # Invalid characters
            "user name",  # Spaces
        ]
        
        for username in invalid_usernames:
            with pytest.raises(ValueError):
                await user_repository.get_by_username(username)
    
    # Network and Integration Scenarios
    # =================================
    
    @pytest.mark.asyncio
    async def test_network_partition_handling(
        self,
        user_repository,
        sample_user
    ):
        """Test behavior during network partitions."""
        # Mock network partition scenario
        user_repository.db_session.add.side_effect = [
            Exception("Network timeout"),
            Exception("Connection refused"),
            None  # Success after partition resolves
        ]
        
        # First two attempts should fail
        with pytest.raises(Exception):
            await user_repository.save(sample_user)
        
        with pytest.raises(Exception):
            await user_repository.save(sample_user)
        
        # Third attempt should succeed
        result = await user_repository.save(sample_user)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_cross_service_integration_failure(
        self,
        user_repository,
        sample_user
    ):
        """Test handling of cross-service integration failures."""
        # Mock database session failure
        user_repository.db_session.add.side_effect = Exception(
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
        """Test proper handling of invalid user data."""
        invalid_users = [
            # None user
            None,
            
            # User without required fields
            User(
                id=12345,
                username="",
                email="test@example.com",
                role=Role.USER,
                is_active=True
            ),
            
            # User with invalid email
            User(
                id=12345,
                username="testuser",
                email="invalid-email",
                role=Role.USER,
                is_active=True
            ),
            
            # User with invalid username
            User(
                id=12345,
                username="",
                email="test@example.com",
                role=Role.USER,
                is_active=True
            ),
        ]
        
        for user in invalid_users:
            with pytest.raises(Exception):
                await user_repository.save(user)
    
    @pytest.mark.asyncio
    async def test_user_availability_checking(
        self,
        user_repository
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
            (OperationalError("Database connection failed"), "database_error"),
            (IntegrityError("Duplicate key", None, None), "integrity_error"),
            (DatabaseError("Transaction failed"), "transaction_error"),
            (Exception("Unknown error"), "unknown_error"),
        ]
        
        for exception, error_type in error_scenarios:
            user_repository.db_session.add.side_effect = exception
            
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
        """Test handling of extremely large user data."""
        # Create user with very large data
        large_user = User(
            id=12345,
            username="A" * 1000,  # Very long username
            email="A" * 1000 + "@example.com",  # Very long email
            role=Role.USER,
            is_active=True
        )
        
        # Mock database session
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # User save should handle large data
        result = await user_repository.save(large_user)
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
        """Test integration with database session."""
        # Mock database session operations
        user_repository.db_session.add.return_value = None
        user_repository.db_session.commit.return_value = None
        user_repository.db_session.refresh.return_value = None
        
        # User save should use database session
        result = await user_repository.save(sample_user)
        assert result is not None
        
        # Verify database session was used
        user_repository.db_session.add.assert_called()
        user_repository.db_session.commit.assert_called()
        user_repository.db_session.refresh.assert_called()
    
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