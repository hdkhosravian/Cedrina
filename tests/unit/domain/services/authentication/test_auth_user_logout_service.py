"""Comprehensive tests for UserLogoutService.

This test suite validates the user logout service following
advanced Test-Driven Development (TDD) principles and enterprise-grade
testing standards.

Test Categories:
- User Logout Success/Failure Scenarios
- Token Revocation and Session Management
- Domain Event Publishing
- Error Handling and Classification
- Performance and Concurrency
- Real-World Edge Cases
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

from src.common.exceptions import AuthenticationError
from src.domain.entities.user import User, Role
from src.domain.events.authentication_events import UserLoggedOutEvent
from src.domain.services.authentication.user_logout_service import UserLogoutService
from src.domain.value_objects.jwt_token import AccessToken, TokenId


class TestUserLogoutService:
    """Comprehensive test suite for UserLogoutService."""
    
    @pytest.fixture
    def mock_token_service(self):
        """Create mock token service."""
        service = AsyncMock()
        service.revoke_access_token = AsyncMock()
        return service
    
    @pytest.fixture
    def mock_event_publisher(self):
        """Create mock event publisher."""
        publisher = AsyncMock()
        publisher.publish = AsyncMock()
        return publisher
    
    @pytest.fixture
    def service(self, mock_token_service, mock_event_publisher):
        """Create UserLogoutService instance."""
        return UserLogoutService(
            token_service=mock_token_service,
            event_publisher=mock_event_publisher
        )
    
    @pytest.fixture
    def mock_user(self):
        """Create test user."""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password="hashed_password",
            is_active=True,
            role=Role.USER,
            email_confirmed=True
        )
    
    @pytest.fixture
    def mock_access_token(self):
        """Create mock access token."""
        from tests.factories.token import create_valid_token_id
        
        valid_token_id = create_valid_token_id()
        token = MagicMock(spec=AccessToken)
        token.get_token_id.return_value = TokenId(valid_token_id)
        token.claims = {
            'iat': int(datetime.now(timezone.utc).timestamp()),
            'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            'sub': '1',
            'jti': valid_token_id
        }
        return token

    # ============================================================================
    # USER LOGOUT SUCCESS TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_logout_user_success(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test successful user logout."""
        # Arrange
        correlation_id = "test-correlation-id"
        
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            client_ip="192.168.1.1",
            user_agent="Test Browser",
            correlation_id=correlation_id
        )
        
        # Assert
        mock_token_service.revoke_access_token.assert_called_once_with(mock_access_token.get_token_id().value)
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event was published
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, UserLoggedOutEvent)
        assert published_event.user_id == mock_user.id
        assert published_event.username == mock_user.username
        assert published_event.correlation_id == correlation_id
    
    @pytest.mark.asyncio
    async def test_logout_user_with_generated_correlation_id(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout with auto-generated correlation ID."""
        # Arrange
        from tests.factories.token import create_valid_token_id
        valid_token_id = create_valid_token_id()
        mock_access_token.claims = {
            'iat': int(datetime.now(timezone.utc).timestamp()),
            'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            'sub': '1',
            'jti': valid_token_id
        }
        
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en"
        )
        
        # Assert
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.correlation_id is not None

    # ============================================================================
    # TOKEN REVOCATION TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_logout_user_with_token_revocation_error(self, service, mock_token_service, mock_user, mock_access_token):
        """Test user logout when token revocation fails."""
        # Arrange
        mock_token_service.revoke_access_token.side_effect = AuthenticationError("Token revocation failed")
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="Token revocation failed"):
            await service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_logout_user_with_token_service_error(self, service, mock_token_service, mock_user, mock_access_token):
        """Test user logout when token service throws error."""
        # Arrange
        mock_token_service.revoke_access_token.side_effect = Exception("Token service unavailable")
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="logout_failed_internal_error"):
            await service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language="en"
            )

    # ============================================================================
    # SESSION DURATION CALCULATION TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_calculate_session_duration_with_valid_iat(self, service, mock_access_token):
        """Test session duration calculation with valid issued-at time."""
        # Arrange
        issued_at = int(datetime.now(timezone.utc).timestamp())
        mock_access_token.claims = {'iat': issued_at}
        
        # Act
        duration = service._calculate_session_duration(mock_access_token)
        
        # Assert
        assert duration is not None
        assert isinstance(duration, int)
        assert duration >= 0
    
    @pytest.mark.asyncio
    async def test_calculate_session_duration_without_iat(self, service, mock_access_token):
        """Test session duration calculation without issued-at time."""
        # Arrange
        mock_access_token.claims = {}
        
        # Act
        duration = service._calculate_session_duration(mock_access_token)
        
        # Assert
        assert duration is None
    
    @pytest.mark.asyncio
    async def test_calculate_session_duration_with_invalid_iat(self, service, mock_access_token):
        """Test session duration calculation with invalid issued-at time."""
        # Arrange
        mock_access_token.claims = {'iat': 'invalid'}
        
        # Act
        duration = service._calculate_session_duration(mock_access_token)
        
        # Assert
        assert duration is None

    # ============================================================================
    # DOMAIN EVENT TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_user_logged_out_event_publishing(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test that user logged out event is published correctly."""
        # Arrange
        correlation_id = "test-correlation-id"
        issued_at = int(datetime.now(timezone.utc).timestamp())
        mock_access_token.claims = {'iat': issued_at}
        
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            client_ip="192.168.1.1",
            user_agent="Test Browser",
            correlation_id=correlation_id
        )
        
        # Assert
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        
        assert isinstance(published_event, UserLoggedOutEvent)
        assert published_event.user_id == mock_user.id
        assert published_event.username == mock_user.username
        assert published_event.correlation_id == correlation_id
        assert published_event.user_agent == "Test Browser"
        assert published_event.ip_address == "192.168.1.1"
        assert published_event.logout_reason == "user_initiated"
        assert published_event.session_duration is not None

    # ============================================================================
    # ERROR HANDLING TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_logout_user_with_event_publisher_error(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout when event publisher throws error."""
        # Arrange
        mock_event_publisher.publish.side_effect = Exception("Event publishing failed")
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="logout_failed_internal_error"):
            await service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_logout_user_with_unexpected_error(self, service, mock_token_service, mock_user, mock_access_token):
        """Test user logout with unexpected error."""
        # Arrange
        mock_token_service.revoke_access_token.side_effect = Exception("Unexpected error")
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="logout_failed_internal_error"):
            await service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language="en"
            )

    # ============================================================================
    # PERFORMANCE TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_logout_user_performance(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout performance."""
        import time
        
        # Act
        start_time = time.time()
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en"
        )
        end_time = time.time()
        
        # Assert
        assert (end_time - start_time) < 0.1  # Should complete within 100ms
    
    @pytest.mark.asyncio
    async def test_concurrent_user_logouts(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test concurrent user logouts."""
        import asyncio
        
        # Act
        tasks = [
            service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language="en",
                correlation_id=f"test-{i}"
            )
            for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Assert
        assert len(results) == 5
        assert all(not isinstance(result, Exception) for result in results)
        assert mock_event_publisher.publish.call_count == 5

    # ============================================================================
    # EDGE CASES AND BOUNDARY CONDITIONS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_logout_user_with_null_context_values(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout with null context values."""
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            client_ip=None,
            user_agent=None,
            correlation_id=None
        )
        
        # Assert
        mock_token_service.revoke_access_token.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_logout_user_with_empty_context_values(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout with empty context values."""
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            client_ip="",
            user_agent="",
            correlation_id=""
        )
        
        # Assert
        mock_token_service.revoke_access_token.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_logout_user_with_very_long_context_values(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout with very long context values."""
        # Arrange
        long_client_ip = "192.168.1." + "1" * 1000
        long_user_agent = "Mozilla/5.0 " + "A" * 1000
        long_correlation_id = "x" * 1000
        
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            client_ip=long_client_ip,
            user_agent=long_user_agent,
            correlation_id=long_correlation_id
        )
        
        # Assert
        mock_token_service.revoke_access_token.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_logout_user_with_different_languages(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout with different languages."""
        languages = ["en", "es", "fr", "de", "ar"]
        
        for language in languages:
            # Act
            await service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language=language
            )
            
            # Assert
            mock_token_service.revoke_access_token.assert_called()
            mock_event_publisher.publish.assert_called()
            mock_token_service.revoke_access_token.reset_mock()
            mock_event_publisher.publish.reset_mock()

    # ============================================================================
    # SECURITY TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_logout_user_with_malicious_user_agent(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout with malicious user agent."""
        # Arrange
        malicious_user_agent = "<script>alert('xss')</script>"
        
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            user_agent=malicious_user_agent
        )
        
        # Assert
        mock_token_service.revoke_access_token.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_logout_user_with_sql_injection_attempt(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test user logout with SQL injection attempt."""
        # Arrange
        malicious_correlation_id = "'; DROP TABLE users; --"
        
        # Act
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            correlation_id=malicious_correlation_id
        )
        
        # Assert
        mock_token_service.revoke_access_token.assert_called_once()
        mock_event_publisher.publish.assert_called_once()

    # ============================================================================
    # REAL-WORLD SCENARIOS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_user_logout_workflow_scenario(self, service, mock_token_service, mock_event_publisher, mock_user, mock_access_token):
        """Test complete user logout workflow scenario."""
        # Arrange
        issued_at = int((datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp())
        mock_access_token.claims = {'iat': issued_at}
        
        # Act - Simulate user logout after security alert
        await service.logout_user(
            access_token=mock_access_token,
            user=mock_user,
            language="en",
            client_ip="192.168.1.100",
            user_agent="Chrome/91.0.4472.124",
            correlation_id="security-alert-2024-001"
        )
        
        # Assert
        mock_token_service.revoke_access_token.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event details
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.user_id == 1
        assert published_event.correlation_id == "security-alert-2024-001"
        assert published_event.ip_address == "192.168.1.100"
        assert published_event.user_agent == "Chrome/91.0.4472.124"
        assert published_event.session_duration is not None
        assert published_event.session_duration >= 1800  # At least 30 minutes
    
    @pytest.mark.asyncio
    async def test_logout_user_with_session_duration_variations(self, service, mock_token_service, mock_event_publisher, mock_user):
        """Test user logout with various session duration scenarios."""
        session_scenarios = [
            # (issued_at_minutes_ago, expected_duration_minutes)
            (1, 1),      # 1 minute session
            (30, 30),    # 30 minute session
            (60, 60),    # 1 hour session
            (1440, 1440), # 24 hour session
        ]
        
        for minutes_ago, expected_minutes in session_scenarios:
            # Arrange
            issued_at = int((datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).timestamp())
            from tests.factories.token import create_valid_token_id
            valid_token_id = create_valid_token_id()
            mock_access_token = MagicMock(spec=AccessToken)
            mock_access_token.get_token_id.return_value = TokenId(valid_token_id)
            mock_access_token.claims = {'iat': issued_at}
            
            # Act
            await service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language="en"
            )
            
            # Assert
            published_event = mock_event_publisher.publish.call_args[0][0]
            assert published_event.session_duration is not None
            assert published_event.session_duration >= expected_minutes * 60 - 5  # Allow 5 second tolerance
            assert published_event.session_duration <= expected_minutes * 60 + 5  # Allow 5 second tolerance
            
            # Reset mocks for next iteration
            mock_token_service.revoke_access_token.reset_mock()
            mock_event_publisher.publish.reset_mock()
    
    @pytest.mark.asyncio
    async def test_logout_user_with_invalid_session_duration(self, service, mock_token_service, mock_event_publisher, mock_user):
        """Test user logout with invalid session duration scenarios."""
        invalid_scenarios = [
            # No iat claim
            {},
            # Invalid iat value
            {'iat': 'invalid'},
            # Future iat value
            {'iat': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())},
            # Very old iat value (more than 1 year)
            {'iat': int((datetime.now(timezone.utc) - timedelta(days=400)).timestamp())},
        ]
        
        for claims in invalid_scenarios:
            # Arrange
            from tests.factories.token import create_valid_token_id
            valid_token_id = create_valid_token_id()
            mock_access_token = MagicMock(spec=AccessToken)
            mock_access_token.get_token_id.return_value = TokenId(valid_token_id)
            mock_access_token.claims = claims
            
            # Act
            await service.logout_user(
                access_token=mock_access_token,
                user=mock_user,
                language="en"
            )
            
            # Assert
            published_event = mock_event_publisher.publish.call_args[0][0]
            assert published_event.session_duration is None
            
            # Reset mocks for next iteration
            mock_token_service.revoke_access_token.reset_mock()
            mock_event_publisher.publish.reset_mock() 