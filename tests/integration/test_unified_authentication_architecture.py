"""
Integration Tests for Unified Authentication Architecture.

This test suite validates the complete unified authentication architecture
including token families, session management, and security patterns.
"""

import pytest
import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from src.common.exceptions import AuthenticationError, SecurityViolationError
from src.domain.entities.user import User, Role
from src.domain.entities.token_family import TokenFamily
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.infrastructure.services.authentication.unified_session_service import UnifiedSessionService
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher


class TestUnifiedAuthenticationArchitecture:
    """Integration tests for unified authentication architecture."""
    
    @pytest.fixture
    async def db_session(self):
        """Create database session for testing with proper transaction management."""
        from src.infrastructure.database.async_db import _build_async_url
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        
        # Build fresh async URL
        async_url = _build_async_url()
        
        # Create a fresh engine for this test
        test_engine = create_async_engine(async_url, echo=False, future=True, pool_pre_ping=True)
        
        # Create a fresh session factory
        TestAsyncSessionFactory = sessionmaker(
            bind=test_engine, class_=AsyncSession, expire_on_commit=False
        )
        
        async with TestAsyncSessionFactory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
        
        await test_engine.dispose()
    
    @pytest.fixture
    def encryption_service(self):
        """Create shared encryption service for consistent keys."""
        from src.infrastructure.services.security.field_encryption_service import FieldEncryptionService
        return FieldEncryptionService()
    
    @pytest.fixture
    async def token_family_repository(self, db_session, encryption_service):
        """Create token family repository with shared encryption service."""
        return TokenFamilyRepository(db_session, encryption_service)
    
    @pytest.fixture
    async def event_publisher(self):
        """Create event publisher."""
        return InMemoryEventPublisher()
    
    @pytest.fixture
    async def session_factory(self, db_session):
        """Create session factory for domain token service."""
        from src.infrastructure.database.session_factory import ISessionFactory
        from contextlib import asynccontextmanager
        
        class TestSessionFactory(ISessionFactory):
            def __init__(self, session):
                self.session = session
            
            @asynccontextmanager
            async def create_session(self):
                yield self.session
                
            @asynccontextmanager
            async def create_transactional_session(self):
                yield self.session
        
        return TestSessionFactory(db_session)
    
    @pytest.fixture
    async def user_repository(self, db_session):
        """Create user repository."""
        from src.infrastructure.repositories.user_repository import UserRepository
        return UserRepository(db_session)
    
    @pytest.fixture
    async def domain_token_service(self, session_factory, user_repository, token_family_repository, event_publisher):
        """Create domain token service."""
        return DomainTokenService(
            session_factory=session_factory,
            user_repository=user_repository,
            token_family_repository=token_family_repository,
            event_publisher=event_publisher
        )
    
    @pytest.fixture
    async def unified_session_service(self, db_session, event_publisher, token_family_repository):
        """Create unified session service using the shared database session and repository."""
        service = UnifiedSessionService(
            db_session=db_session,
            token_family_repository=token_family_repository,
            event_publisher=event_publisher
        )
        return service
    
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
        security_context,
        db_session
    ):
        """Test complete token family creation with session integration."""
        from src.domain.value_objects.token_requests import TokenCreationRequest
        from src.domain.entities.user import User, Role
        
        # Create unique test user for this specific test and persist to database
        unique_user = User(
            username=f"testuser_{uuid.uuid4().hex[:8]}",
            email=f"test_{uuid.uuid4().hex[:8]}@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(unique_user)
        await db_session.commit()
        await db_session.refresh(unique_user)
        
        # Create token pair with family
        request = TokenCreationRequest(
            user=unique_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(request)
        
        assert token_pair.family_id is not None
        assert token_pair.access_token is not None
        assert token_pair.refresh_token is not None
        
        # Create session with family integration
        session = await unified_session_service.create_session(
            user_id=unique_user.id,
            jti=f"test-jti-{uuid.uuid4().hex[:8]}",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            family_id=token_pair.family_id,
            correlation_id="test-correlation-123"
        )
        
        assert session.family_id == token_pair.family_id
        assert session.user_id == unique_user.id
        
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
        from src.domain.value_objects.token_requests import TokenCreationRequest, TokenRefreshRequest
        
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
        security_context,
        db_session
    ):
        """Test that session revocation compromises the token family."""
        from src.domain.value_objects.token_requests import TokenCreationRequest
        from src.domain.entities.user import User, Role
        
        # Create unique test user for this specific test and persist to database
        unique_user = User(
            username=f"testuser_{uuid.uuid4().hex[:8]}",
            email=f"test_{uuid.uuid4().hex[:8]}@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(unique_user)
        await db_session.commit()
        await db_session.refresh(unique_user)
        
        # Create token pair and session
        create_request = TokenCreationRequest(
            user=unique_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        session = await unified_session_service.create_session(
            user_id=unique_user.id,
            jti=f"test-jti-{uuid.uuid4().hex[:8]}",
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
        
        # Verify family is compromised
        family = await domain_token_service._token_family_repository.get_family_by_id(token_pair.family_id)
        assert family.status_enum == TokenFamilyStatus.COMPROMISED
    
    @pytest.mark.asyncio
    async def test_token_validation_with_family_security(
        self,
        domain_token_service,
        test_user,
        security_context
    ):
        """Test token validation with family security checks."""
        from src.domain.value_objects.token_requests import TokenCreationRequest
        
        # Create token pair
        create_request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        # Validate token
        validation_result = await domain_token_service.validate_token_with_family_security(
            access_token=token_pair.access_token,
            security_context=security_context
        )
        
        # Validate the returned payload
        assert validation_result is not None
        assert validation_result["sub"] == str(test_user.id)
        assert "jti" in validation_result
        assert "family_id" in validation_result
    
    @pytest.mark.asyncio
    async def test_concurrent_session_limits(
        self,
        unified_session_service,
        db_session
    ):
        """Test concurrent session limits enforcement."""
        # Create unique test user for this specific test to avoid session accumulation
        from src.domain.entities.user import User, Role
        unique_user = User(
            username=f"testuser_{uuid.uuid4().hex[:8]}",
            email=f"test_{uuid.uuid4().hex[:8]}@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(unique_user)
        await db_session.commit()
        await db_session.refresh(unique_user)
        
        # Create multiple sessions (within limit)
        sessions = []
        for i in range(3):
            session = await unified_session_service.create_session(
                user_id=unique_user.id,
                jti=f"test-jti-{uuid.uuid4().hex[:8]}-{i}",
                refresh_token_hash=f"hashed_refresh_token_{i}",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                correlation_id=f"test-correlation-{i}"
            )
            sessions.append(session)
        
        # Verify all sessions were created
        assert len(sessions) == 3
        
        # Verify session limits are enforced
        active_sessions = await unified_session_service.get_user_active_sessions(unique_user.id)
        assert len(active_sessions) <= 5  # Assuming max 5 concurrent sessions
    
    @pytest.mark.asyncio
    async def test_session_activity_tracking(
        self,
        unified_session_service,
        db_session
    ):
        """Test session activity tracking functionality."""
        # Create unique test user for this specific test
        from src.domain.entities.user import User, Role
        unique_user = User(
            username=f"testuser_{uuid.uuid4().hex[:8]}",
            email=f"test_{uuid.uuid4().hex[:8]}@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(unique_user)
        await db_session.commit()
        await db_session.refresh(unique_user)
        
        # Create session
        session = await unified_session_service.create_session(
            user_id=unique_user.id,
            jti=f"test-jti-activity-{uuid.uuid4().hex[:8]}",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            correlation_id="test-correlation-activity"
        )
        
        # Update activity
        await unified_session_service.update_session_activity(
            jti=session.jti,
            user_id=session.user_id,
            correlation_id="test-correlation-update"
        )
        
        # Verify activity was updated
        updated_session = await unified_session_service.get_session(session.jti, session.user_id)
        assert updated_session.last_activity_at is not None
    
    @pytest.mark.asyncio
    async def test_session_expiration_handling(
        self,
        unified_session_service,
        db_session
    ):
        """Test session expiration handling."""
        # Create unique test user for this specific test
        from src.domain.entities.user import User, Role
        unique_user = User(
            username=f"testuser_{uuid.uuid4().hex[:8]}",
            email=f"test_{uuid.uuid4().hex[:8]}@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(unique_user)
        await db_session.commit()
        await db_session.refresh(unique_user)
        
        # Create session with short expiration
        session = await unified_session_service.create_session(
            user_id=unique_user.id,
            jti=f"test-jti-expire-{uuid.uuid4().hex[:8]}",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=1),
            correlation_id="test-correlation-expire"
        )
        
        # Wait for expiration
        await asyncio.sleep(2)
        
        # Verify session is expired
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
        from src.domain.value_objects.token_requests import TokenCreationRequest
        
        # Create security context with suspicious IP
        suspicious_context = SecurityContext.create_for_request(
            client_ip="192.168.1.200",
            user_agent="Suspicious Bot",
            correlation_id="test-correlation-suspicious"
        )
        
        # Create token pair
        create_request = TokenCreationRequest(
            user=test_user,
            security_context=suspicious_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        # Verify token was created despite suspicious context
        assert token_pair.access_token is not None
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
        """Test event publishing integration."""
        from src.domain.value_objects.token_requests import TokenCreationRequest
        
        # Create token pair
        create_request = TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        # Verify events were published
        events = event_publisher.get_published_events()
        assert len(events) > 0
        
        # Check for token creation event
        token_events = [e for e in events if "token" in type(e).__name__.lower()]
        assert len(token_events) > 0
    
    @pytest.mark.asyncio
    async def test_database_transaction_integrity(
        self,
        domain_token_service,
        unified_session_service,
        security_context,
        db_session
    ):
        """Test database transaction integrity across operations."""
        from src.domain.value_objects.token_requests import TokenCreationRequest
        from src.domain.entities.user import User, Role
        
        # Create unique test user for this specific test
        unique_user = User(
            username=f"testuser_{uuid.uuid4().hex[:8]}",
            email=f"test_{uuid.uuid4().hex[:8]}@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(unique_user)
        await db_session.commit()
        await db_session.refresh(unique_user)
        
        # Create token pair
        create_request = TokenCreationRequest(
            user=unique_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        
        # Create session
        session = await unified_session_service.create_session(
            user_id=unique_user.id,
            jti=f"test-jti-transaction-{uuid.uuid4().hex[:8]}",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            family_id=token_pair.family_id,
            correlation_id="test-correlation-123"
        )
        
        # Verify both operations succeeded
        assert token_pair.family_id is not None
        assert session.family_id == token_pair.family_id
        
        # Verify data consistency
        family = await domain_token_service._token_family_repository.get_family_by_id(token_pair.family_id)
        assert family is not None
        assert family.status_enum == TokenFamilyStatus.ACTIVE
    
    @pytest.mark.asyncio
    async def test_performance_requirements(
        self,
        domain_token_service,
        unified_session_service,
        security_context,
        db_session
    ):
        """Test performance requirements for token operations."""
        from src.domain.value_objects.token_requests import TokenCreationRequest
        from src.domain.entities.user import User, Role
        import time
        
        # Create unique test user for this specific test
        unique_user = User(
            username=f"testuser_{uuid.uuid4().hex[:8]}",
            email=f"test_{uuid.uuid4().hex[:8]}@example.com",
            role=Role.USER,
            is_active=True
        )
        db_session.add(unique_user)
        await db_session.commit()
        await db_session.refresh(unique_user)
        
        # Measure token creation time
        create_request = TokenCreationRequest(
            user=unique_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        start_time = time.time()
        token_pair = await domain_token_service.create_token_pair_with_family_security(create_request)
        creation_time = time.time() - start_time
        
        # Verify performance requirements (should complete within 1 second)
        assert creation_time < 1.0
        
        # Measure session creation time
        start_time = time.time()
        session = await unified_session_service.create_session(
            user_id=unique_user.id,
            jti=f"test-jti-performance-{uuid.uuid4().hex[:8]}",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            family_id=token_pair.family_id,
            correlation_id="test-correlation-123"
        )
        session_time = time.time() - start_time
        
        # Verify session creation performance
        assert session_time < 1.0 