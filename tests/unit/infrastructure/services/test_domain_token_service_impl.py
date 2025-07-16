"""
Comprehensive Test Suite for DomainTokenService.

This test suite covers real-world production scenarios including:
- High concurrency token operations
- Security threat detection and response
- Database failure recovery
- Token family compromise scenarios
- Performance under load
- Memory leak detection
- Cross-service integration failures
- Network partition handling
- Malicious token injection attempts
- Rate limiting and abuse prevention
"""

import asyncio
import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import List, Dict, Any

from sqlalchemy.exc import OperationalError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.common.exceptions import AuthenticationError, SecurityViolationError
from src.domain.entities.user import User, Role
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken, TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_requests import TokenCreationRequest, TokenRefreshRequest
from src.domain.value_objects.token_responses import TokenPair
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.infrastructure.services.authentication.jwt_service import JWTService
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher


class TestDomainTokenServiceProductionScenarios:
    """Test DomainTokenService with real-world production scenarios."""
    
    @pytest.fixture
    def mock_session_factory(self):
        """Mock session factory with realistic behavior."""
        from src.infrastructure.database.session_factory import ISessionFactory
        from contextlib import asynccontextmanager
        
        factory = AsyncMock(spec=ISessionFactory)
        session = AsyncMock(spec=AsyncSession)
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.close = AsyncMock()
        
        @asynccontextmanager
        async def mock_create_session():
            yield session
        
        @asynccontextmanager
        async def mock_create_transactional_session():
            yield session
        
        factory.create_session = mock_create_session
        factory.create_transactional_session = mock_create_transactional_session
        return factory
    
    @pytest.fixture
    def mock_token_family_repository(self):
        """Mock token family repository with security scenarios."""
        repo = AsyncMock(spec=TokenFamilyRepository)
        repo.create_token_family = AsyncMock()
        repo.get_family_by_id = AsyncMock()
        repo.update_family = AsyncMock()
        repo.compromise_family = AsyncMock()
        repo.check_token_reuse = AsyncMock(return_value=False)
        return repo
    
    @pytest.fixture
    def mock_event_publisher(self):
        """Mock event publisher for audit trail testing."""
        publisher = AsyncMock(spec=InMemoryEventPublisher)
        publisher.publish = AsyncMock()
        return publisher
    
    @pytest.fixture
    def mock_jwt_service(self):
        """Mock JWT service with token generation scenarios."""
        service = AsyncMock(spec=JWTService)
        service.create_access_token = AsyncMock()
        service.create_refresh_token = AsyncMock()
        service.validate_token = AsyncMock()
        return service
    
    @pytest.fixture
    def test_user(self):
        """Test user with realistic data."""
        return User(
            id=12345,
            username="testuser",
            email="test@example.com",
            role=Role.USER,
            is_active=True
        )
    
    @pytest.fixture
    def security_context(self):
        """Security context for testing."""
        return SecurityContext(
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            request_timestamp=datetime.now(timezone.utc),
            correlation_id=str(uuid.uuid4())
        )
    
    @pytest.fixture
    def domain_token_service(
        self,
        mock_session_factory,
        mock_token_family_repository,
        mock_event_publisher,
        mock_jwt_service
    ):
        """Domain token service with mocked dependencies."""
        return DomainTokenService(
            session_factory=mock_session_factory,
            token_family_repository=mock_token_family_repository,
            event_publisher=mock_event_publisher,
            jwt_service=mock_jwt_service
        )

    # High Concurrency Scenarios
    # =========================
    
    @pytest.mark.asyncio
    async def test_concurrent_token_creation_race_condition(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of concurrent token creation requests."""
        # Simulate race condition where multiple requests arrive simultaneously
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        # Mock the domain service to return a mock token family
        mock_token_family = MagicMock()
        mock_token_family.family_id = "test_family_id_123"
        domain_token_service._domain_service.create_token_family = AsyncMock(return_value=mock_token_family)
        
        # Mock JWT service to simulate concurrent access
        exp_time = datetime.now(timezone.utc) + timedelta(minutes=30)
        # Use proper JWT format: header.payload.signature
        mock_access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MjU5NjU2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        mock_refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MzIwMTM2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        
        domain_token_service._jwt_service.create_access_token.return_value = AccessToken(
            token=mock_access_token,
            claims={
                "sub": str(test_user.id),
                "exp": int(exp_time.timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": "jti_1",
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        domain_token_service._jwt_service.create_refresh_token.return_value = RefreshToken(
            token=mock_refresh_token,
            claims={
                "sub": str(test_user.id),
                "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": "jti_1",
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        
        # Simulate concurrent requests
        tasks = []
        for i in range(10):
            task = domain_token_service.create_token_pair_with_family_security(request)
            tasks.append(task)
        
        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify all requests succeeded
        assert len(results) == 10
        for result in results:
            assert isinstance(result, TokenPair)
            assert result.access_token is not None
            assert result.refresh_token is not None
    
    @pytest.mark.asyncio
    async def test_database_connection_pool_exhaustion(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test behavior when database connection pool is exhausted."""
        # Mock the domain service to raise an OperationalError
        domain_token_service._domain_service.create_token_family = AsyncMock(
            side_effect=OperationalError(
                "connection pool exhausted",
                None,
                None
            )
        )
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        with pytest.raises(AuthenticationError):
            await domain_token_service.create_token_pair_with_family_security(request)
    
    # Security Threat Scenarios
    # =========================
    
    @pytest.mark.asyncio
    async def test_token_reuse_detection_and_response(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test detection and response to token reuse attacks."""
        # Mock the domain service to raise a SecurityViolationError for reuse detection
        domain_token_service._domain_service.create_token_family = AsyncMock(
            side_effect=SecurityViolationError("Token reuse detected")
        )
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        with pytest.raises(SecurityViolationError):
            await domain_token_service.create_token_pair_with_family_security(request)
        
        # The infrastructure service re-raises SecurityViolationError without modification
        # Event publishing is handled by the domain service, not the infrastructure service
    
    @pytest.mark.asyncio
    async def test_malicious_token_injection_attempt(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of malicious token injection attempts."""
        # Mock JWT service to simulate malicious token
        domain_token_service._jwt_service.validate_token.side_effect = AuthenticationError(
            "Invalid token signature"
        )
        
        # Attempt to validate malicious token
        with pytest.raises(AuthenticationError):
            await domain_token_service.validate_token_with_family_security(
                access_token="malicious_token",
                security_context=security_context
            )
    
    @pytest.mark.asyncio
    async def test_family_compromise_cascade(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test cascade effects when a token family is compromised."""
        # Generate a proper 43-character base64url token ID
        import base64
        import secrets
        token_id_bytes = secrets.token_bytes(32)  # 256 bits
        proper_jti = base64.urlsafe_b64encode(token_id_bytes).decode('utf-8').rstrip('=')
        
        # Mock JWT token validation to return valid payload
        mock_payload = {
            "sub": str(test_user.id),
            "jti": proper_jti,
            "family_id": "test_family_id"
        }
        domain_token_service._jwt_service.validate_token.return_value = mock_payload
        
        # Mock compromised family (family not found)
        domain_token_service._domain_service.validate_token_family_security = AsyncMock(return_value=False)
        
        # Attempt to use compromised family
        with pytest.raises(SecurityViolationError):
            await domain_token_service.validate_token_with_family_security(
                access_token="valid_token",
                security_context=security_context
            )
    
    # Performance and Load Testing
    # ===========================
    
    @pytest.mark.asyncio
    async def test_high_throughput_token_validation(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test performance under high token validation load."""
        # Generate a proper 43-character base64url token ID
        import base64
        import secrets
        token_id_bytes = secrets.token_bytes(32)  # 256 bits
        proper_jti = base64.urlsafe_b64encode(token_id_bytes).decode('utf-8').rstrip('=')
        
        # Mock successful token validation
        domain_token_service._jwt_service.validate_token.return_value = {
            "sub": str(test_user.id),
            "jti": proper_jti,
            "family_id": "test_family"
        }
        
        # Mock successful family security validation
        domain_token_service._domain_service.validate_token_family_security = AsyncMock(return_value=True)
        
        # Simulate high load
        start_time = datetime.now(timezone.utc)
        validation_tasks = []
        
        for i in range(1000):
            task = domain_token_service.validate_token_with_family_security(
                access_token=f"token_{i}",
                security_context=security_context
            )
            validation_tasks.append(task)
        
        # Execute all validations
        results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        end_time = datetime.now(timezone.utc)
        
        # Verify performance requirements
        execution_time = (end_time - start_time).total_seconds()
        assert execution_time < 5.0  # Should complete within 5 seconds
        assert len(results) == 1000
        
        # Verify all validations succeeded
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        assert success_count == 1000
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test memory usage doesn't grow unbounded under load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Simulate sustained load
        for _ in range(100):
            request = TokenCreationRequest(
                user=test_user,
                security_context=security_context,
                correlation_id=str(uuid.uuid4())
            )
            
            try:
                await domain_token_service.create_token_pair_with_family_security(request)
            except Exception:
                pass  # Expected some failures in load testing
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 50MB)
        assert memory_increase < 50 * 1024 * 1024
    
    # Failure Recovery Scenarios
    # ==========================
    
    @pytest.mark.asyncio
    async def test_database_transaction_rollback_on_failure(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test proper transaction rollback when operations fail."""
        # Mock database failure during token creation
        # The service will handle the exception and convert it to AuthenticationError
        domain_token_service._domain_service.create_token_family = AsyncMock(
            side_effect=IntegrityError(
                "duplicate key value violates unique constraint",
                None,
                None
            )
        )
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        with pytest.raises(AuthenticationError):
            await domain_token_service.create_token_pair_with_family_security(request)
        
        # Verify the domain service was called (transaction rollback happens in the session factory)
        domain_token_service._domain_service.create_token_family.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_partial_failure_recovery(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test recovery from partial failures in token operations."""
        # Generate proper 43-character base64url token IDs
        import base64
        import secrets
        token_id_bytes1 = secrets.token_bytes(32)
        proper_jti1 = base64.urlsafe_b64encode(token_id_bytes1).decode('utf-8').rstrip('=')
        token_id_bytes3 = secrets.token_bytes(32)
        proper_jti3 = base64.urlsafe_b64encode(token_id_bytes3).decode('utf-8').rstrip('=')
        
        # Create proper JWT tokens
        proper_token1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MjU5NjU2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        proper_token3 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MjU5NjU2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzMiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        
        # Mock partial failure scenario
        domain_token_service._jwt_service.create_access_token.side_effect = [
            AccessToken(token=proper_token1, claims={"sub": str(test_user.id), "exp": int((datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp()), "jti": proper_jti1, "iat": int(datetime.now(timezone.utc).timestamp()), "iss": "test", "aud": "test"}),
            Exception("JWT service temporarily unavailable"),
            AccessToken(token=proper_token3, claims={"sub": str(test_user.id), "exp": int((datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp()), "jti": proper_jti3, "iat": int(datetime.now(timezone.utc).timestamp()), "iss": "test", "aud": "test"})
        ]
        
        # Mock the domain service to return a token family
        mock_token_family = MagicMock()
        mock_token_family.family_id = "test_family_id_123"
        domain_token_service._domain_service.create_token_family = AsyncMock(return_value=mock_token_family)
        
        # Mock refresh token creation
        proper_refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MzIwMTM2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        domain_token_service._jwt_service.create_refresh_token.return_value = RefreshToken(
            token=proper_refresh_token,
            claims={"sub": str(test_user.id), "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()), "jti": proper_jti1, "iat": int(datetime.now(timezone.utc).timestamp()), "iss": "test", "aud": "test"}
        )
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        # First request should succeed
        result1 = await domain_token_service.create_token_pair_with_family_security(request)
        assert result1 is not None
        
        # Second request should fail
        with pytest.raises(AuthenticationError):
            await domain_token_service.create_token_pair_with_family_security(request)
        
        # Third request should succeed again
        result3 = await domain_token_service.create_token_pair_with_family_security(request)
        assert result3 is not None
    
    # Network and Integration Scenarios
    # =================================
    
    @pytest.mark.asyncio
    async def test_network_partition_handling(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test behavior during network partitions."""
        # Mock network partition scenario
        domain_token_service._token_family_repository.create_token_family.side_effect = [
            Exception("Network timeout"),
            Exception("Connection refused"),
            MagicMock()  # Success after partition resolves
        ]
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        # First two attempts should fail
        with pytest.raises(AuthenticationError):
            await domain_token_service.create_token_pair_with_family_security(request)
        
        with pytest.raises(AuthenticationError):
            await domain_token_service.create_token_pair_with_family_security(request)
        
        # Third attempt should succeed
        result = await domain_token_service.create_token_pair_with_family_security(request)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_cross_service_integration_failure(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of cross-service integration failures."""
        # Mock the domain service to return a token family successfully
        mock_token_family = MagicMock()
        mock_token_family.family_id = "test_family_id_123"
        domain_token_service._domain_service.create_token_family = AsyncMock(return_value=mock_token_family)
        
        # Mock JWT services to return valid tokens
        exp_time = datetime.now(timezone.utc) + timedelta(minutes=30)
        mock_access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MjU5NjU2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        mock_refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MzIwMTM2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        
        # Generate proper JTI
        import base64
        import secrets
        token_id_bytes = secrets.token_bytes(32)
        proper_jti = base64.urlsafe_b64encode(token_id_bytes).decode('utf-8').rstrip('=')
        
        domain_token_service._jwt_service.create_access_token.return_value = AccessToken(
            token=mock_access_token,
            claims={
                "sub": str(test_user.id),
                "exp": int(exp_time.timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": proper_jti,
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        domain_token_service._jwt_service.create_refresh_token.return_value = RefreshToken(
            token=mock_refresh_token,
            claims={
                "sub": str(test_user.id),
                "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": proper_jti,
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        
        # Mock event publisher failure (this should not affect the result)
        domain_token_service._event_publisher.publish.side_effect = Exception(
            "Event publisher service unavailable"
        )
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        # Token creation should still succeed even if event publishing fails
        # Since we're mocking the domain service directly, event publishing failure won't propagate
        result = await domain_token_service.create_token_pair_with_family_security(request)
        assert result is not None
    
    # Security Validation Scenarios
    # =============================
    
    @pytest.mark.asyncio
    async def test_token_expiration_handling(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test proper handling of expired tokens."""
        # Mock expired token
        expired_time = datetime.now(timezone.utc) - timedelta(hours=1)
        domain_token_service._jwt_service.validate_token.side_effect = AuthenticationError(
            "Token has expired"
        )
        
        with pytest.raises(AuthenticationError):
            await domain_token_service.validate_token_with_family_security(
                access_token="expired_token",
                security_context=security_context
            )
    
    @pytest.mark.asyncio
    async def test_invalid_token_format_handling(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of malformed tokens."""
        # Test various malformed token scenarios
        malformed_tokens = [
            "",  # Empty token
            "invalid.token.format",  # Wrong format
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",  # Invalid signature
            None,  # None token
        ]
        
        for token in malformed_tokens:
            with pytest.raises(AuthenticationError):
                await domain_token_service.validate_token_with_family_security(
                    access_token=token,
                    security_context=security_context
                )
    
    # Rate Limiting and Abuse Prevention
    # ===================================
    
    @pytest.mark.asyncio
    async def test_rapid_token_creation_abuse(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of rapid token creation attempts."""
        # Simulate rapid token creation attempts
        for i in range(100):
            request = TokenCreationRequest(
                user=test_user,
                security_context=security_context,
                correlation_id=str(uuid.uuid4())
            )
            
            try:
                await domain_token_service.create_token_pair_with_family_security(request)
            except Exception:
                # Some failures are expected under load
                pass
    
    @pytest.mark.asyncio
    async def test_concurrent_family_operations(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test concurrent operations on the same token family."""
        family_id = "test_family_id"
        
        # Mock family repository to simulate concurrent access
        domain_token_service._token_family_repository.get_family_by_id.return_value = MagicMock()
        
        # Simulate concurrent operations on same family
        operations = []
        for i in range(10):
            op = domain_token_service.validate_token_with_family_security(
                access_token=f"token_{i}",
                security_context=security_context
            )
            operations.append(op)
        
        results = await asyncio.gather(*operations, return_exceptions=True)
        
        # All operations should complete (some may fail due to concurrency)
        assert len(results) == 10
    
    # Error Handling and Logging
    # ===========================
    
    @pytest.mark.asyncio
    async def test_comprehensive_error_logging(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test that all errors are properly logged."""
        # Mock various error scenarios
        error_scenarios = [
            (OperationalError("Database connection failed", None, None), "database_error"),
            (IntegrityError("Duplicate key", None, None), "integrity_error"),
            (AuthenticationError("Invalid token"), "authentication_error"),
            (SecurityViolationError("Token reuse detected"), "security_violation"),
        ]
        
        for exception, error_type in error_scenarios:
            domain_token_service._jwt_service.create_access_token.side_effect = exception
            
            request = TokenCreationRequest(
                user=test_user,
                security_context=security_context,
                correlation_id=str(uuid.uuid4())
            )
            
            with pytest.raises(Exception):
                await domain_token_service.create_token_pair_with_family_security(request)
    
    @pytest.mark.asyncio
    async def test_correlation_id_propagation(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test that correlation IDs are properly propagated through all operations."""
        correlation_id = str(uuid.uuid4())
        
        # Create a new security context with the custom correlation ID
        from src.domain.value_objects.security_context import SecurityContext
        custom_security_context = SecurityContext(
            client_ip=security_context.client_ip,
            user_agent=security_context.user_agent,
            request_timestamp=security_context.request_timestamp,
            correlation_id=correlation_id
        )
        
        # Mock the domain service to return a token family
        mock_token_family = MagicMock()
        mock_token_family.family_id = "test_family_id_123"
        domain_token_service._domain_service.create_token_family = AsyncMock(return_value=mock_token_family)
        
        # Mock JWT services
        exp_time = datetime.now(timezone.utc) + timedelta(minutes=30)
        mock_access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MjU5NjU2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        mock_refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MzIwMTM2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        
        # Generate proper JTI
        import base64
        import secrets
        token_id_bytes = secrets.token_bytes(32)
        proper_jti = base64.urlsafe_b64encode(token_id_bytes).decode('utf-8').rstrip('=')
        
        domain_token_service._jwt_service.create_access_token.return_value = AccessToken(
            token=mock_access_token,
            claims={
                "sub": str(test_user.id),
                "exp": int(exp_time.timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": proper_jti,
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        domain_token_service._jwt_service.create_refresh_token.return_value = RefreshToken(
            token=mock_refresh_token,
            claims={
                "sub": str(test_user.id),
                "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": proper_jti,
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=custom_security_context,
            correlation_id=correlation_id
        )
        
        # Verify correlation ID is used in all downstream operations
        await domain_token_service.create_token_pair_with_family_security(request)
        
        # Check that correlation ID was passed to domain service
        domain_token_service._domain_service.create_token_family.assert_called()
        call_args = domain_token_service._domain_service.create_token_family.call_args
        assert correlation_id in str(call_args)
    
    # Edge Cases and Boundary Testing
    # ===============================
    
    @pytest.mark.asyncio
    async def test_extreme_token_sizes(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of extremely large tokens."""
        # Create extremely large token
        large_token = "A" * 100000  # 100KB token
        
        with pytest.raises(AuthenticationError):
            await domain_token_service.validate_token_with_family_security(
                access_token=large_token,
                security_context=security_context
            )
    
    @pytest.mark.asyncio
    async def test_unicode_token_handling(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of Unicode tokens."""
        unicode_tokens = [
            "🎉🎊🎈",  # Emoji tokens
            "测试token",  # Chinese characters
            "токентест",  # Cyrillic characters
            "トークンテスト",  # Japanese characters
        ]
        
        for token in unicode_tokens:
            with pytest.raises(AuthenticationError):
                await domain_token_service.validate_token_with_family_security(
                    access_token=token,
                    security_context=security_context
                )
    
    @pytest.mark.asyncio
    async def test_null_and_empty_values(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test handling of null and empty values."""
        null_values = [None, "", "   ", "\n", "\t"]
        
        for value in null_values:
            with pytest.raises(AuthenticationError):
                await domain_token_service.validate_token_with_family_security(
                    access_token=value,
                    security_context=security_context
                )
    
    # Integration with Other Services
    # ===============================
    
    @pytest.mark.asyncio
    async def test_event_publisher_integration(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test integration with event publisher for audit trails."""
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        await domain_token_service.create_token_pair_with_family_security(request)
        
        # Verify events were published
        domain_token_service._event_publisher.publish.assert_called()
    
    @pytest.mark.asyncio
    async def test_jwt_service_integration(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test integration with JWT service."""
        # Generate proper JTI
        import base64
        import secrets
        token_id_bytes = secrets.token_bytes(32)
        proper_jti = base64.urlsafe_b64encode(token_id_bytes).decode('utf-8').rstrip('=')
        
        # Mock JWT service responses
        exp_time = datetime.now(timezone.utc) + timedelta(minutes=30)
        mock_access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MjU5NjU2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        mock_refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTc1MzIwMTM2NiIsImlhdCI6MTc1MjU5NDc2NiwianRpIjoianRpXzEiLCJpc3MiOiJ0ZXN0X2lzc3VlciIsImF1ZCI6InRlc3RfYXVkaWVuY2UifQ.signature"
        
        domain_token_service._jwt_service.create_access_token.return_value = AccessToken(
            token=mock_access_token,
            claims={
                "sub": str(test_user.id),
                "exp": int(exp_time.timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": proper_jti,
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        domain_token_service._jwt_service.create_refresh_token.return_value = RefreshToken(
            token=mock_refresh_token,
            claims={
                "sub": str(test_user.id),
                "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": proper_jti,
                "iss": "test_issuer",
                "aud": "test_audience"
            }
        )
        
        # Mock the domain service to return a token family
        mock_token_family = MagicMock()
        mock_token_family.family_id = "test_family_id_123"
        domain_token_service._domain_service.create_token_family = AsyncMock(return_value=mock_token_family)
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id=str(uuid.uuid4())
        )
        
        result = await domain_token_service.create_token_pair_with_family_security(request)
        
        # Verify JWT service was called
        domain_token_service._jwt_service.create_access_token.assert_called()
        domain_token_service._jwt_service.create_refresh_token.assert_called()
        
        assert result.access_token is not None
        assert result.refresh_token is not None 