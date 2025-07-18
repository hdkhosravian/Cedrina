"""
Unit tests for Unified Session Service.

This module tests the unified session service that manages user sessions
with comprehensive security features and database integration.

Test Coverage:
- Session creation and management
- Session limit enforcement
- Database error handling
- Event publishing
- Security logging
- Production scenarios
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone

from src.infrastructure.services.authentication.unified_session_service import UnifiedSessionService
from src.domain.entities.session import Session
from src.domain.events.authentication_events import SessionRevokedEvent
from src.common.exceptions import AuthenticationError, SessionLimitExceededError


class TestUnifiedSessionService:
    """Test suite for UnifiedSessionService."""
    
    @pytest.fixture
    def mock_token_family_repository(self):
        """Mock token family repository."""
        repository = AsyncMock()
        repository.compromise_family = AsyncMock()
        return repository
    
    @pytest.fixture
    def mock_event_publisher(self):
        """Mock event publisher."""
        publisher = AsyncMock()
        publisher.publish = AsyncMock()
        return publisher
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session with proper async context manager."""
        session = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        session.execute = AsyncMock()
        session.flush = AsyncMock()
        session.close = AsyncMock()
        
        # Create a proper async context manager mock
        context_manager = AsyncMock()
        context_manager.__aenter__ = AsyncMock(return_value=session)
        context_manager.__aexit__ = AsyncMock(return_value=None)
        
        # Mock the session manager to return our context manager
        with patch('src.infrastructure.database.session_manager.get_transactional_session', return_value=context_manager):
            yield session
    
    @pytest.fixture
    def service(self, mock_db_session, mock_token_family_repository, mock_event_publisher):
        """Create service instance with mocked dependencies."""
        return UnifiedSessionService(
            db_session=mock_db_session,
            token_family_repository=mock_token_family_repository,
            event_publisher=mock_event_publisher
        )
    
    @pytest.fixture
    def test_session(self):
        """Create test session entity."""
        return Session(
            id=1,
            user_id=1,
            jti="test-jti-123",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1),
            last_activity_at=datetime.now(timezone.utc).replace(tzinfo=None),
            family_id="test-family-id"
        )
    
    @pytest.fixture
    def mock_user(self):
        """Create mock user."""
        user = MagicMock()
        user.id = 1
        user.username = "testuser"
        return user
    
    def test_unified_session_service_creation(self, service):
        """Test service initialization."""
        assert service is not None
        assert hasattr(service, 'create_session')
        assert hasattr(service, 'revoke_session')
        assert hasattr(service, 'is_session_valid')  # Changed from validate_session
        assert hasattr(service, 'get_session')
        assert hasattr(service, 'update_session_activity')
        assert hasattr(service, 'get_user_active_sessions')
        assert hasattr(service, 'cleanup_expired_sessions')
    
    @pytest.mark.asyncio
    async def test_create_session_success(
        self,
        service,
        mock_db_session,
        mock_event_publisher
    ):
        """Test successful session creation."""
        user_id = 1
        jti = "test-jti-123"
        refresh_token_hash = "hashed_refresh_token"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        family_id = "test-family-id"
        correlation_id = "test-correlation-123"
        
        # Mock session limit check - use the transactional method that's actually called
        with patch.object(service, '_get_active_session_count_transactional', return_value=0):
            result = await service.create_session(
                user_id=user_id,
                jti=jti,
                refresh_token_hash=refresh_token_hash,
                expires_at=expires_at,
                family_id=family_id,
                correlation_id=correlation_id
            )
        
        # Verify session was created
        assert result is not None
        assert result.user_id == user_id
        assert result.jti == jti
        assert result.refresh_token_hash == refresh_token_hash
        assert result.family_id == family_id
        
        # Verify database operations
        mock_db_session.add.assert_called_once()
        mock_db_session.flush.assert_called_once()
        
        # Verify event publishing
        mock_event_publisher.publish.assert_called()
    
    @pytest.mark.asyncio
    async def test_create_session_exceeds_limit(
        self,
        service,
        mock_db_session
    ):
        """Test session creation fails when user exceeds limit."""
        user_id = 1
        jti = "test-jti-123"
        refresh_token_hash = "hashed_refresh_token"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Mock session limit exceeded - use the transactional method that's actually called
        with patch.object(service, '_get_active_session_count_transactional', return_value=5):
            with pytest.raises(SessionLimitExceededError):
                await service.create_session(
                    user_id=user_id,
                    jti=jti,
                    refresh_token_hash=refresh_token_hash,
                    expires_at=expires_at
                )
        
        # Verify no database operations occurred
        mock_db_session.add.assert_not_called()
        mock_db_session.flush.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_create_session_database_error(
        self,
        service,
        mock_db_session
    ):
        """Test session creation handles database errors."""
        user_id = 1
        jti = "test-jti-123"
        refresh_token_hash = "hashed_refresh_token"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # Mock database error
        mock_db_session.flush.side_effect = Exception("Database error")
        
        # Mock session limit check - use the transactional method that's actually called
        with patch.object(service, '_get_active_session_count_transactional', return_value=0):
            with pytest.raises(AuthenticationError):
                await service.create_session(
                    user_id=user_id,
                    jti=jti,
                    refresh_token_hash=refresh_token_hash,
                    expires_at=expires_at
                )
    
    @pytest.mark.asyncio
    async def test_revoke_session_success(
        self,
        service,
        mock_db_session,
        mock_token_family_repository,
        mock_event_publisher,
        test_session
    ):
        """Test successful session revocation."""
        session_id = 1
        user_id = 1
        correlation_id = "test-correlation-123"
        
        # Mock session retrieval - use the correct method name
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.revoke_session(
                jti="test-jti-123",
                user_id=user_id,
                language="en",
                correlation_id=correlation_id
            )
            
            # Verify session was revoked
            assert test_session.revoked_at is not None
            assert test_session.revoke_reason == "Manual revocation"  # Changed from revoked_reason
            
            # Verify event was published
            mock_event_publisher.publish.assert_called_once()
            published_event = mock_event_publisher.publish.call_args[0][0]
            assert isinstance(published_event, SessionRevokedEvent)
            assert published_event.session_id == "test-jti-123"
            assert published_event.user_id == user_id
            assert published_event.correlation_id == correlation_id
    
    @pytest.mark.asyncio
    async def test_revoke_session_not_found(
        self,
        service,
        mock_db_session
    ):
        """Test session revocation when session not found."""
        session_id = 999
        user_id = 1
        correlation_id = "test-correlation-123"
        
        # Mock session not found - use the correct method name
        with patch.object(service, 'get_session', return_value=None):
            result = await service.revoke_session(
                jti="test-jti-999",
                user_id=user_id,
                language="en",
                correlation_id=correlation_id
            )
            
            # Should not raise exception, just return None
            assert result is None
    
    @pytest.mark.asyncio
    async def test_validate_session_success(
        self,
        service,
        test_session
    ):
        """Test successful session validation."""
        session_id = 1
        user_id = 1
        
        # Mock session retrieval - use the correct method name
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.is_session_valid(
                jti="test-jti-123",
                user_id=user_id
            )
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_session_not_found(
        self,
        service
    ):
        """Test session validation when session not found."""
        session_id = 999
        user_id = 1
        
        # Mock session not found - use the correct method name
        with patch.object(service, 'get_session', return_value=None):
            result = await service.is_session_valid(
                jti="test-jti-999",
                user_id=user_id
            )
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_session_expired(
        self,
        service
    ):
        """Test session validation with expired session."""
        session_id = 1
        user_id = 1
        
        # Create expired session
        expired_session = Session(
            id=1,
            user_id=1,
            jti="test-jti-123",
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1),  # Expired
            last_activity_at=datetime.now(timezone.utc).replace(tzinfo=None),
            family_id="test-family-id"
        )
        
        # Mock session retrieval - use the correct method name
        with patch.object(service, 'get_session', return_value=expired_session):
            result = await service.is_session_valid(
                jti="test-jti-123",
                user_id=user_id
            )
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_session_wrong_user(
        self,
        service,
        test_session
    ):
        """Test session validation with wrong user."""
        session_id = 1
        user_id = 999  # Different user
        
        # Mock session retrieval to return None for wrong user (as real implementation would)
        with patch.object(service, 'get_session', return_value=None):
            result = await service.is_session_valid(
                jti="test-jti-123",
                user_id=user_id
            )
            
            # The service should return False for wrong user
            assert result is False
    
    @pytest.mark.asyncio
    async def test_get_active_session_count(
        self,
        service,
        mock_db_session
    ):
        """Test getting active session count."""
        user_id = 1
        expected_count = 3
        
        # Mock database query result
        mock_result = MagicMock()
        mock_result.scalar.return_value = expected_count
        mock_db_session.execute.return_value = mock_result
        
        result = await service._get_active_session_count(user_id)
        
        assert result == expected_count
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_session_by_id(
        self,
        service,
        mock_db_session,
        test_session
    ):
        """Test getting session by ID."""
        session_id = 1
        
        # Mock database query result
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_session
        mock_db_session.execute.return_value = mock_result
        
        result = await service.get_session("test-jti-123", 1)
        
        assert result == test_session
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_session_by_id_not_found(
        self,
        service,
        mock_db_session
    ):
        """Test getting session by ID when not found."""
        session_id = 999
        
        # Mock database query result
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result
        
        result = await service.get_session("test-jti-999", 999)
        
        assert result is None
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_session_creation_with_events(
        self,
        service,
        mock_db_session,
        mock_event_publisher
    ):
        """Test session creation with proper event publishing."""
        user_id = 1
        jti = "test-jti-123"
        refresh_token_hash = "hashed_refresh_token"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        family_id = "test-family-id"
        correlation_id = "test-correlation-123"
        
        with patch.object(service, '_get_active_session_count_transactional', return_value=0):
            await service.create_session(
                user_id=user_id,
                jti=jti,
                refresh_token_hash=refresh_token_hash,
                expires_at=expires_at,
                family_id=family_id,
                correlation_id=correlation_id
            )
        
        # Verify event was published
        mock_event_publisher.publish.assert_called()
        call_args = mock_event_publisher.publish.call_args[0][0]
        assert call_args.user_id == user_id
        assert call_args.session_id is not None
    
    @pytest.mark.asyncio
    async def test_session_revocation_with_events(
        self,
        service,
        mock_db_session,
        mock_token_family_repository,
        mock_event_publisher,
        test_session
    ):
        """Test session revocation with proper event publishing."""
        session_id = 1
        user_id = 1
        correlation_id = "test-correlation-123"
        
        # Mock session retrieval - use the correct method name
        with patch.object(service, 'get_session', return_value=test_session):
            await service.revoke_session(
                jti="test-jti-123",
                user_id=user_id,
                language="en",
                correlation_id=correlation_id,
                reason="Security violation"
            )
            
            # Verify session was revoked with custom reason
            assert test_session.revoked_at is not None
            assert test_session.revoke_reason == "Security violation"  # Changed from revoked_reason
            
            # Verify event was published
            mock_event_publisher.publish.assert_called_once()
            published_event = mock_event_publisher.publish.call_args[0][0]
            assert isinstance(published_event, SessionRevokedEvent)
            assert published_event.session_id == "test-jti-123"
            assert published_event.user_id == user_id
            assert published_event.correlation_id == correlation_id 