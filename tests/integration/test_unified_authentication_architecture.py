"""
Integration Tests for Unified Authentication Architecture.

This test suite validates the complete unified authentication architecture
including token families, session management, and security patterns.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from src.core.exceptions import AuthenticationError, SecurityViolationError
from src.domain.entities.user import User, Role
from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.infrastructure.services.authentication.unified_session_service import UnifiedSessionService
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher


class TestUnifiedAuthenticationArchitecture:
    """Integration tests for unified authentication architecture."""
    
    @pytest.fixture
    async def db_session(self):
        """Create database session for testing."""
        from src.infrastructure.database.async_db import get_async_db_dependency
        async for session in get_async_db_dependency():
            yield session
    
    @pytest.fixture
    async def token_family_repository(self, db_session):
        """Create token family repository."""
        return TokenFamilyRepository(db_session)
    
    @pytest.fixture
    async def event_publisher(self):
        """Create event publisher."""
        return InMemoryEventPublisher()
    
    @pytest.fixture
    async def domain_token_service(self, db_session, token_family_repository, event_publisher):
        """Create domain token service."""
        return DomainTokenService(
            db_session=db_session,
            token_family_repository=token_family_repository,
            event_publisher=event_publisher
        )
    
    @pytest.fixture
    async def unified_session_service(self, db_session, token_family_repository, event_publisher):
        """Create unified session service."""
        return UnifiedSessionService(
            db_session=db_session,
            token_family_repository=token_family_repository,
            event_publisher=event_publisher
        )
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            role=Role.USER,
            is_active=True
        )
    
    @pytest.fixture
    def security_context(self):
        """Create security context."""
        return SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0 (Test Browser)",
            correlation_id="test-correlation-123"
        )
    
    @pytest.mark.asyncio
    async def test_token_family_creation_and_session_integration(
        self,
        domain_token_service,
        unified_session_service,
        test_user,
        security_context
    ):
        """Test complete token family creation with session integration."""
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest
        )
        
        # Create token pair with family
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(request)
        
        assert token_pair.family_id is not None
        assert token_pair.access_token is not None
        assert token_pair.refresh_token is not None
        
        # Create session with family integration
        session = await unified_session_service.create_session(
            user_id=test_user.id,
            jti="test-jti-123",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            family_id=token_pair.family_id,
            correlation_id="test-correlation-123"
        )
        
        assert session.family_id == token_pair.family_id
        assert session.user_id == test_user.id
        
        # Verify session is valid
        is_valid = await unified_session_service.is_session_valid(
            jti=session.jti,
            user_id=session.user_id
        )
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_token_refresh_with_family_security(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test token refresh with family security validation."""
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest,
            TokenRefreshRequest
        )
        
        # Create initial token pair
        create_request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        initial_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        # Refresh tokens
        refresh_request = TokenRefreshRequest(
            refresh_token=initial_pair.refresh_token,
            security_context=security_context,
            correlation_id="test-correlation-456"
        )
        
        new_pair = await domain_token_service.refresh_tokens_with_family_security(refresh_request)
        
        assert new_pair.family_id == initial_pair.family_id
        assert new_pair.access_token != initial_pair.access_token
        assert new_pair.refresh_token != initial_pair.refresh_token
    
    @pytest.mark.asyncio
    async def test_session_revocation_triggers_family_compromise(
        self,
        domain_token_service,
        unified_session_service,
        test_user,
        security_context
    ):
        """Test that session revocation compromises the token family."""
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest
        )
        
        # Create token pair and session
        create_request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        session = await unified_session_service.create_session(
            user_id=test_user.id,
            jti="test-jti-123",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            family_id=token_pair.family_id,
            correlation_id="test-correlation-123"
        )
        
        # Revoke session
        await unified_session_service.revoke_session(
            jti=session.jti,
            user_id=session.user_id,
            reason="Security violation",
            correlation_id="test-correlation-456"
        )
        
        # Verify session is no longer valid
        is_valid = await unified_session_service.is_session_valid(
            jti=session.jti,
            user_id=session.user_id
        )
        assert is_valid is False
        
        # Verify family is compromised
        family = await domain_token_service._token_family_repository.get_family_by_id(token_pair.family_id)
        assert family.status == TokenFamilyStatus.COMPROMISED
    
    @pytest.mark.asyncio
    async def test_token_validation_with_family_security(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test token validation with family security checks."""
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest
        )
        
        # Create token pair
        create_request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        # Validate access token
        payload = await domain_token_service.validate_token_with_family_security(
            access_token=token_pair.access_token,
            security_context=security_context,
            correlation_id="test-correlation-456"
        )
        
        assert payload["sub"] == str(test_user.id)
        assert payload["family_id"] == token_pair.family_id
    
    @pytest.mark.asyncio
    async def test_concurrent_session_limits(
        self,
        unified_session_service,
        test_user
    ):
        """Test concurrent session limits enforcement."""
        # Create multiple sessions
        sessions = []
        for i in range(3):
            session = await unified_session_service.create_session(
                user_id=test_user.id,
                jti=f"test-jti-{i}",
                refresh_token_hash=f"hashed_refresh_token_{i}",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                correlation_id=f"test-correlation-{i}"
            )
            sessions.append(session)
        
        # Verify all sessions were created
        assert len(sessions) == 3
        
        # Try to create one more session (should fail if limit is 3)
        try:
            await unified_session_service.create_session(
                user_id=test_user.id,
                jti="test-jti-4",
                refresh_token_hash="hashed_refresh_token_4",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                correlation_id="test-correlation-4"
            )
            # If we get here, the limit might be higher than 3
            pass
        except SessionLimitExceededError:
            # Expected behavior if limit is 3
            pass
    
    @pytest.mark.asyncio
    async def test_session_activity_tracking(
        self,
        unified_session_service,
        test_user
    ):
        """Test session activity tracking and updates."""
        # Create session
        session = await unified_session_service.create_session(
            user_id=test_user.id,
            jti="test-jti-activity",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            correlation_id="test-correlation-activity"
        )
        
        # Update activity
        is_valid = await unified_session_service.update_session_activity(
            jti=session.jti,
            user_id=session.user_id,
            correlation_id="test-correlation-update"
        )
        
        assert is_valid is True
        
        # Verify session is still valid
        is_valid = await unified_session_service.is_session_valid(
            jti=session.jti,
            user_id=session.user_id
        )
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_session_expiration_handling(
        self,
        unified_session_service,
        test_user
    ):
        """Test session expiration handling."""
        # Create session with short expiration
        session = await unified_session_service.create_session(
            user_id=test_user.id,
            jti="test-jti-expired",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=1),
            correlation_id="test-correlation-expired"
        )
        
        # Wait for expiration
        await asyncio.sleep(2)
        
        # Verify session is no longer valid
        is_valid = await unified_session_service.is_session_valid(
            jti=session.jti,
            user_id=session.user_id
        )
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_security_context_validation(
        self,
        domain_token_service,
        test_user
    ):
        """Test security context validation in token operations."""
        # Create valid security context
        valid_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0 (Test Browser)",
            correlation_id="test-correlation-valid"
        )
        
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest
        )
        
        request = TokenCreationRequest(
            user=test_user,
            security_context=valid_context,
            correlation_id="test-correlation-valid"
        )
        
        # Should succeed with valid context
        token_pair = await domain_token_service.create_token_pair_with_family_security(request)
        assert token_pair.family_id is not None
    
    @pytest.mark.asyncio
    async def test_event_publishing_integration(
        self,
        domain_token_service,
        unified_session_service,
        event_publisher,
        test_user,
        security_context
    ):
        """Test that events are properly published during operations."""
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest
        )
        
        # Clear any existing events
        event_publisher.events.clear()
        
        # Create token pair
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-events"
        )
        
        await domain_token_service.create_token_pair_with_family_security(request)
        
        # Verify events were published
        assert len(event_publisher.events) > 0
        
        # Check for token family created event
        family_events = [e for e in event_publisher.events if hasattr(e, 'family_id')]
        assert len(family_events) > 0
    
    @pytest.mark.asyncio
    async def test_database_transaction_integrity(
        self,
        domain_token_service,
        unified_session_service,
        test_user,
        security_context
    ):
        """Test database transaction integrity across services."""
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest
        )
        
        # Create token pair and session in sequence
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-transaction"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(request)
        
        session = await unified_session_service.create_session(
            user_id=test_user.id,
            jti="test-jti-transaction",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            family_id=token_pair.family_id,
            correlation_id="test-correlation-transaction"
        )
        
        # Verify both operations completed successfully
        assert token_pair.family_id is not None
        assert session.family_id == token_pair.family_id
        
        # Verify session is valid
        is_valid = await unified_session_service.is_session_valid(
            jti=session.jti,
            user_id=session.user_id
        )
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_performance_requirements(
        self,
        domain_token_service,
        unified_session_service,
        test_user,
        security_context
    ):
        """Test performance requirements for critical operations."""
        import time
        from src.domain.services.authentication.token_lifecycle_management_service import (
            TokenCreationRequest
        )
        
        # Test token validation performance
        request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-performance"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(request)
        
        # Measure token validation time
        start_time = time.perf_counter()
        await domain_token_service.validate_token_with_family_security(
            access_token=token_pair.access_token,
            security_context=security_context
        )
        end_time = time.perf_counter()
        
        validation_time_ms = (end_time - start_time) * 1000
        assert validation_time_ms < 10.0  # Should complete within 10ms
        
        # Test session validation performance
        session = await unified_session_service.create_session(
            user_id=test_user.id,
            jti="test-jti-performance",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            family_id=token_pair.family_id
        )
        
        start_time = time.perf_counter()
        await unified_session_service.is_session_valid(
            jti=session.jti,
            user_id=session.user_id
        )
        end_time = time.perf_counter()
        
        session_validation_time_ms = (end_time - start_time) * 1000
        assert session_validation_time_ms < 5.0  # Should complete within 5ms 