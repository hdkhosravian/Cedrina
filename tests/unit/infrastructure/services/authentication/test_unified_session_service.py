"""
Unit Tests for Unified Session Service.

This test suite validates the UnifiedSessionService following TDD principles
and comprehensive security testing for database-only session management.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from src.core.exceptions import AuthenticationError, SessionLimitExceededError
from src.domain.entities.session import Session
from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus
from src.domain.events.authentication_events import (
    SessionCreatedEvent,
    SessionRevokedEvent,
    SessionExpiredEvent,
    SessionActivityUpdatedEvent
)
from src.infrastructure.services.authentication.unified_session_service import UnifiedSessionService


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
        """Mock database session."""
        session = AsyncMock()
        session.commit = AsyncMock()
        session.add = MagicMock()
        session.execute = AsyncMock()
        
        # Create a proper async context manager mock
        context_manager = AsyncMock()
        context_manager.__aenter__ = AsyncMock(return_value=session)
        context_manager.__aexit__ = AsyncMock(return_value=None)
        session.begin = MagicMock(return_value=context_manager)
        
        return session
    
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
    
    # === Session Creation Tests ===
    
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
        
        # Mock session limit check
        with patch.object(service, '_get_active_session_count', return_value=0):
            result = await service.create_session(
                user_id=user_id,
                jti=jti,
                refresh_token_hash=refresh_token_hash,
                expires_at=expires_at,
                family_id=family_id,
                correlation_id=correlation_id
            )
        
        assert isinstance(result, Session)
        assert result.user_id == user_id
        assert result.jti == jti
        assert result.family_id == family_id
        
        # Verify event was published
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, SessionCreatedEvent)
        assert published_event.user_id == user_id
        assert published_event.jti == jti
        assert published_event.family_id == family_id
    
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
        
        # Mock session limit exceeded
        with patch.object(service, '_get_active_session_count', return_value=5):
            with pytest.raises(SessionLimitExceededError):
                await service.create_session(
                    user_id=user_id,
                    jti=jti,
                    refresh_token_hash=refresh_token_hash,
                    expires_at=expires_at
                )
    
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
        mock_db_session.commit.side_effect = Exception("Database error")
        
        with patch.object(service, '_get_active_session_count', return_value=0):
            with pytest.raises(AuthenticationError):
                await service.create_session(
                    user_id=user_id,
                    jti=jti,
                    refresh_token_hash=refresh_token_hash,
                    expires_at=expires_at
                )
    
    # === Session Activity Update Tests ===
    
    @pytest.mark.asyncio
    async def test_update_session_activity_success(
        self,
        service,
        mock_db_session,
        mock_event_publisher,
        test_session
    ):
        """Test successful session activity update."""
        jti = "test-jti-123"
        user_id = 1
        correlation_id = "test-correlation-123"
        
        # Mock session retrieval
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.update_session_activity(
                jti=jti,
                user_id=user_id,
                correlation_id=correlation_id
            )
        
        assert result is True
        
        # Verify event was published
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, SessionActivityUpdatedEvent)
        assert published_event.user_id == user_id
        assert published_event.jti == jti
    
    @pytest.mark.asyncio
    async def test_update_session_activity_session_not_found(
        self,
        service
    ):
        """Test activity update when session not found."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock session not found
        with patch.object(service, 'get_session', return_value=None):
            result = await service.update_session_activity(jti=jti, user_id=user_id)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_update_session_activity_session_revoked(
        self,
        service,
        test_session
    ):
        """Test activity update when session is revoked."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock revoked session
        test_session.revoked_at = datetime.now(timezone.utc)
        
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.update_session_activity(jti=jti, user_id=user_id)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_update_session_activity_session_expired(
        self,
        service,
        test_session,
        mock_event_publisher
    ):
        """Test activity update when session is expired."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock expired session
        test_session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        with patch.object(service, 'get_session', return_value=test_session):
            with patch.object(service, '_handle_session_expiration', new_callable=AsyncMock):
                result = await service.update_session_activity(jti=jti, user_id=user_id)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_update_session_activity_inactivity_timeout(
        self,
        service,
        test_session
    ):
        """Test activity update when session times out due to inactivity."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock session with old activity
        test_session.last_activity_at = datetime.now(timezone.utc) - timedelta(hours=2)
        
        with patch.object(service, 'get_session', return_value=test_session):
            with patch.object(service, 'revoke_session', new_callable=AsyncMock):
                result = await service.update_session_activity(jti=jti, user_id=user_id)
        
        assert result is False
    
    # === Session Revocation Tests ===
    
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
        jti = "test-jti-123"
        user_id = 1
        reason = "Security violation"
        correlation_id = "test-correlation-123"
        
        with patch.object(service, 'get_session', return_value=test_session):
            await service.revoke_session(
                jti=jti,
                user_id=user_id,
                reason=reason,
                correlation_id=correlation_id
            )
        
        # Verify family was compromised
        mock_token_family_repository.compromise_family.assert_called_once_with(
            family_id=test_session.family_id,
            reason=f"Session revoked: {reason}",
            correlation_id=correlation_id
        )
        
        # Verify event was published
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, SessionRevokedEvent)
        assert published_event.user_id == user_id
        assert published_event.jti == jti
        assert published_event.reason == reason
    
    @pytest.mark.asyncio
    async def test_revoke_session_not_found(
        self,
        service
    ):
        """Test session revocation when session not found."""
        jti = "test-jti-123"
        user_id = 1
        
        with patch.object(service, 'get_session', return_value=None):
            # Should not raise exception
            await service.revoke_session(jti=jti, user_id=user_id)
    
    @pytest.mark.asyncio
    async def test_revoke_session_no_family_id(
        self,
        service,
        mock_db_session,
        mock_token_family_repository,
        mock_event_publisher
    ):
        """Test session revocation without family ID."""
        jti = "test-jti-123"
        user_id = 1
        
        # Create session without family_id
        session = Session(
            id=1,
            user_id=user_id,
            jti=jti,
            refresh_token_hash="hashed_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            last_activity_at=datetime.now(timezone.utc),
            family_id=None
        )
        
        with patch.object(service, 'get_session', return_value=session):
            await service.revoke_session(jti=jti, user_id=user_id)
        
        # Verify family was not compromised
        mock_token_family_repository.compromise_family.assert_not_called()
        
        # Verify event was still published
        mock_event_publisher.publish.assert_called_once()
    
    # === Session Retrieval Tests ===
    
    @pytest.mark.asyncio
    async def test_get_session_success(
        self,
        service,
        mock_db_session,
        test_session
    ):
        """Test successful session retrieval."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock database query result
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = test_session
        mock_db_session.execute.return_value = mock_result
        
        result = await service.get_session(jti=jti, user_id=user_id)
        
        assert result == test_session
    
    @pytest.mark.asyncio
    async def test_get_session_not_found(
        self,
        service,
        mock_db_session
    ):
        """Test session retrieval when not found."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock database query result
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result
        
        result = await service.get_session(jti=jti, user_id=user_id)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_session_database_error(
        self,
        service,
        mock_db_session
    ):
        """Test session retrieval handles database errors."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock database error
        mock_db_session.execute.side_effect = Exception("Database error")
        
        result = await service.get_session(jti=jti, user_id=user_id)
        
        assert result is None
    
    # === Session Validation Tests ===
    
    @pytest.mark.asyncio
    async def test_is_session_valid_success(
        self,
        service,
        test_session
    ):
        """Test session validation for valid session."""
        jti = "test-jti-123"
        user_id = 1
        
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.is_session_valid(jti=jti, user_id=user_id)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_session_valid_not_found(
        self,
        service
    ):
        """Test session validation when session not found."""
        jti = "test-jti-123"
        user_id = 1
        
        with patch.object(service, 'get_session', return_value=None):
            result = await service.is_session_valid(jti=jti, user_id=user_id)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_is_session_valid_revoked(
        self,
        service,
        test_session
    ):
        """Test session validation for revoked session."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock revoked session
        test_session.revoked_at = datetime.now(timezone.utc)
        
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.is_session_valid(jti=jti, user_id=user_id)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_is_session_valid_expired(
        self,
        service,
        test_session
    ):
        """Test session validation for expired session."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock expired session
        test_session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.is_session_valid(jti=jti, user_id=user_id)
        
        assert result is False
    
    # === Session Cleanup Tests ===
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions_success(
        self,
        service,
        mock_db_session
    ):
        """Test successful cleanup of expired sessions."""
        # Mock expired sessions
        expired_sessions = [
            Session(
                id=1,
                user_id=1,
                jti="expired-jti-1",
                refresh_token_hash="hash1",
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
                last_activity_at=datetime.now(timezone.utc) - timedelta(hours=2)
            ),
            Session(
                id=2,
                user_id=2,
                jti="expired-jti-2",
                refresh_token_hash="hash2",
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
                last_activity_at=datetime.now(timezone.utc) - timedelta(hours=2)
            )
        ]
        
        # Mock database query result
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = expired_sessions
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(service, '_handle_session_expiration', new_callable=AsyncMock):
            result = await service.cleanup_expired_sessions()
        
        assert result == 2
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions_no_sessions(
        self,
        service,
        mock_db_session
    ):
        """Test cleanup when no expired sessions exist."""
        # Mock no expired sessions
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result
        
        result = await service.cleanup_expired_sessions()
        
        assert result == 0
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions_database_error(
        self,
        service,
        mock_db_session
    ):
        """Test cleanup handles database errors."""
        # Mock database error
        mock_db_session.execute.side_effect = Exception("Database error")
        
        result = await service.cleanup_expired_sessions()
        
        assert result == 0
    
    # === Performance Tests ===
    
    @pytest.mark.asyncio
    async def test_session_validation_performance(
        self,
        service,
        test_session
    ):
        """Test session validation performance."""
        import time
        
        jti = "test-jti-123"
        user_id = 1
        
        with patch.object(service, 'get_session', return_value=test_session):
            start_time = time.perf_counter()
            result = await service.is_session_valid(jti=jti, user_id=user_id)
            end_time = time.perf_counter()
        
        validation_time_ms = (end_time - start_time) * 1000
        assert validation_time_ms < 10.0  # Should complete within 10ms
        assert result is True
    
    # === Edge Case Tests ===
    
    @pytest.mark.asyncio
    async def test_session_creation_with_none_family_id(
        self,
        service,
        mock_db_session,
        mock_event_publisher
    ):
        """Test session creation with None family_id."""
        user_id = 1
        jti = "test-jti-123"
        refresh_token_hash = "hashed_refresh_token"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        family_id = None
        correlation_id = "test-correlation-123"
        
        with patch.object(service, '_get_active_session_count', return_value=0):
            result = await service.create_session(
                user_id=user_id,
                jti=jti,
                refresh_token_hash=refresh_token_hash,
                expires_at=expires_at,
                family_id=family_id,
                correlation_id=correlation_id
            )
        
        assert isinstance(result, Session)
        assert result.family_id is None
        
        # Verify event was published with None family_id
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.family_id is None
    
    @pytest.mark.asyncio
    async def test_session_activity_update_database_error(
        self,
        service,
        mock_db_session,
        test_session
    ):
        """Test activity update handles database errors."""
        jti = "test-jti-123"
        user_id = 1
        
        # Mock database error
        mock_db_session.commit.side_effect = Exception("Database error")
        
        with patch.object(service, 'get_session', return_value=test_session):
            result = await service.update_session_activity(jti=jti, user_id=user_id)
        
        assert result is False 