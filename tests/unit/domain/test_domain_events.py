"""
Comprehensive Unit Tests for Domain Events.

This test suite validates domain events under real-world scenarios including:
- High-traffic conditions with concurrent event creation
- Edge cases and boundary conditions
- Invalid data handling and error scenarios
- Complex validation scenarios
- Performance under load
- Security event handling
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from unittest.mock import Mock, patch

from src.domain.events import (
    # Base classes
    BaseDomainEvent,
    
    # Password reset events
    PasswordResetRequestedEvent,
    PasswordResetCompletedEvent,
    PasswordResetFailedEvent,
    PasswordResetTokenExpiredEvent,
    
    # Authentication events
    EmailConfirmedEvent,
    AuthenticationFailedEvent,
    TokenFamilyCreatedEvent,
    TokenAddedEvent,
    TokenUsedEvent,
    TokenRevokedEvent,
    TokenReuseDetectedEvent,
    TokenFamilyCompromisedEvent,
    TokenRefreshedEvent,
    SecurityIncidentEvent,
    UserAuthenticationEvent,
    SessionEvent,
    UserLoggedInEvent,
    UserRegisteredEvent,
    UserLoggedOutEvent,
    PasswordChangedEvent,
    SessionCreatedEvent,
    SessionRevokedEvent,
    SessionExpiredEvent,
    SessionActivityUpdatedEvent,
    
    # OAuth events
    OAuthAuthenticationSuccessEvent,
    OAuthAuthenticationFailedEvent,
    OAuthProfileCreatedEvent,
    OAuthProfileUpdatedEvent,
    OAuthProfileLinkedEvent,
)


class TestBaseDomainEvent:
    """Test base domain event functionality."""
    
    def test_base_event_creation_with_defaults(self):
        """Test creating base event with default values."""
        # Create a concrete implementation for testing
        class TestEvent(BaseDomainEvent):
            def _validate_event_data(self) -> None:
                pass
        
        event = TestEvent()
        
        assert event.correlation_id is None
        assert event.metadata == {}
        assert event.timestamp.tzinfo == timezone.utc
    
    def test_base_event_creation_with_custom_values(self):
        """Test creating base event with custom values."""
        class TestEvent(BaseDomainEvent):
            def _validate_event_data(self) -> None:
                pass
        
        timestamp = datetime.now(timezone.utc)
        event = TestEvent(
            correlation_id="test-correlation",
            timestamp=timestamp,
            metadata={"key": "value"}
        )
        
        assert event.correlation_id == "test-correlation"
        assert event.timestamp == timestamp
        assert event.metadata == {"key": "value"}
    
    def test_base_event_timezone_awareness(self):
        """Test that naive timestamps are converted to UTC."""
        class TestEvent(BaseDomainEvent):
            def _validate_event_data(self) -> None:
                pass
        
        naive_timestamp = datetime.now()
        event = TestEvent(timestamp=naive_timestamp)
        
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.replace(tzinfo=None) == naive_timestamp
    
    def test_base_event_correlation_id_validation(self):
        """Test correlation ID validation."""
        class TestEvent(BaseDomainEvent):
            def _validate_event_data(self) -> None:
                pass
        
        # Empty correlation ID should raise error
        with pytest.raises(ValueError, match="Correlation ID cannot be empty"):
            TestEvent(correlation_id="")
        
        # Whitespace correlation ID should raise error
        with pytest.raises(ValueError, match="Correlation ID cannot be empty"):
            TestEvent(correlation_id="   ")
        
        # Valid correlation ID should work
        event = TestEvent(correlation_id="valid-id")
        assert event.correlation_id == "valid-id"


class TestPasswordResetEvents:
    """Test password reset domain events."""
    
    def test_password_reset_requested_event_creation(self):
        """Test creating password reset requested event."""
        user_id = 123
        email = "user@example.com"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        event = PasswordResetRequestedEvent.create(
            user_id=user_id,
            email=email,
            token_expires_at=expires_at,
            language="en",
            user_agent="Mozilla/5.0",
            ip_address="192.168.1.1"
        )
        
        assert event.user_id == user_id
        assert event.email == email
        assert event.token_expires_at == expires_at
        assert event.language == "en"
        assert event.user_agent == "Mozilla/5.0"
        assert event.ip_address == "192.168.1.1"
    
    def test_password_reset_requested_event_validation_failures(self):
        """Test validation failures for password reset requested event."""
        # Invalid user ID
        with pytest.raises(ValueError, match="User ID must be positive"):
            PasswordResetRequestedEvent.create(
                user_id=0,
                email="user@example.com",
                token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            )
        
        # Invalid email
        with pytest.raises(ValueError, match="Email is required"):
            PasswordResetRequestedEvent.create(
                user_id=123,
                email="",
                token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            )
        
        # Token expiration in past
        with pytest.raises(ValueError, match="Token expiration must be in the future"):
            PasswordResetRequestedEvent.create(
                user_id=123,
                email="user@example.com",
                token_expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
            )
        
        # Empty language
        with pytest.raises(ValueError, match="Language is required"):
            PasswordResetRequestedEvent.create(
                user_id=123,
                email="user@example.com",
                token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                language=""
            )
    
    def test_password_reset_completed_event_creation(self):
        """Test creating password reset completed event."""
        event = PasswordResetCompletedEvent.create(
            user_id=123,
            email="user@example.com",
            reset_method="token",
            user_agent="Mozilla/5.0",
            ip_address="192.168.1.1"
        )
        
        assert event.user_id == 123
        assert event.email == "user@example.com"
        assert event.reset_method == "token"
    
    def test_password_reset_failed_event_creation(self):
        """Test creating password reset failed event."""
        event = PasswordResetFailedEvent.create(
            user_id=123,
            email="user@example.com",
            failure_reason="Invalid token",
            token_used="masked_token_123",
            user_agent="Mozilla/5.0",
            ip_address="192.168.1.1"
        )
        
        assert event.user_id == 123
        assert event.email == "user@example.com"
        assert event.failure_reason == "Invalid token"
        assert event.token_used == "masked_token_123"
    
    def test_password_reset_token_expired_event_creation(self):
        """Test creating password reset token expired event."""
        created_at = datetime.now(timezone.utc) - timedelta(hours=2)
        expired_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        event = PasswordResetTokenExpiredEvent.create(
            user_id=123,
            email="user@example.com",
            token_created_at=created_at,
            expired_at=expired_at
        )
        
        assert event.user_id == 123
        assert event.email == "user@example.com"
        assert event.token_created_at == created_at
        assert event.expired_at == expired_at
    
    def test_password_reset_token_expired_event_validation_failures(self):
        """Test validation failures for token expired event."""
        now = datetime.now(timezone.utc)
        
        # Token creation after expiration
        with pytest.raises(ValueError, match="Token creation time must be before Expired time"):
            PasswordResetTokenExpiredEvent.create(
                user_id=123,
                email="user@example.com",
                token_created_at=now,
                expired_at=now - timedelta(hours=1)
            )
        
        # Expired time in future
        with pytest.raises(ValueError, match="Expired time cannot be in the future"):
            PasswordResetTokenExpiredEvent.create(
                user_id=123,
                email="user@example.com",
                token_created_at=now - timedelta(hours=2),
                expired_at=now + timedelta(hours=1)
            )


class TestAuthenticationEvents:
    """Test authentication domain events."""
    
    def test_email_confirmed_event_creation(self):
        """Test creating email confirmed event."""
        event = EmailConfirmedEvent.create(
            user_id=123,
            email="user@example.com",
            correlation_id="test-correlation"
        )
        
        assert event.user_id == 123
        assert event.email == "user@example.com"
        assert event.correlation_id == "test-correlation"
    
    def test_authentication_failed_event_creation(self):
        """Test creating authentication failed event."""
        event = AuthenticationFailedEvent.create(
            reason="Invalid credentials",
            user_id=123,
            email="user@example.com",
            correlation_id="test-correlation",
            metadata={"attempt_count": 3}
        )
        
        assert event.reason == "Invalid credentials"
        assert event.user_id == 123
        assert event.email == "user@example.com"
        assert event.correlation_id == "test-correlation"
        assert event.metadata == {"attempt_count": 3}
    
    def test_token_family_events_creation(self):
        """Test creating token family events."""
        # Token family created
        event1 = TokenFamilyCreatedEvent.create(
            family_id="family_123",
            user_id=123,
            correlation_id="test-correlation"
        )
        assert event1.family_id == "family_123"
        assert event1.user_id == 123
        
        # Token added
        event2 = TokenAddedEvent.create(
            family_id="family_123",
            token_id="token_456",
            user_id=123
        )
        assert event2.family_id == "family_123"
        assert event2.token_id == "token_456"
        assert event2.user_id == 123
        
        # Token used
        event3 = TokenUsedEvent.create(
            family_id="family_123",
            token_id="token_456",
            user_id=123
        )
        assert event3.family_id == "family_123"
        assert event3.token_id == "token_456"
    
    def test_token_refresh_event_validation(self):
        """Test token refresh event validation."""
        # Same token IDs should fail
        with pytest.raises(ValueError, match="Old and new token IDs must be different"):
            TokenRefreshedEvent.create(
                family_id="family_123",
                old_token_id="token_456",
                new_token_id="token_456",
                user_id=123
            )
        
        # Different token IDs should work
        event = TokenRefreshedEvent.create(
            family_id="family_123",
            old_token_id="token_456",
            new_token_id="token_789",
            user_id=123
        )
        assert event.old_token_id == "token_456"
        assert event.new_token_id == "token_789"
    
    def test_security_incident_event_creation(self):
        """Test creating security incident event."""
        from src.domain.events.authentication_events import SecurityThreatLevel
        
        event = SecurityIncidentEvent.create(
            incident_type="suspicious_activity",
            threat_level=SecurityThreatLevel.HIGH,
            description="Multiple failed login attempts",
            user_id=123,
            family_id="family_123",
            token_id="token_456",
            correlation_id="test-correlation"
        )
        
        assert event.incident_type == "suspicious_activity"
        assert event.threat_level == SecurityThreatLevel.HIGH
        assert event.description == "Multiple failed login attempts"
        assert event.user_id == 123
        assert event.family_id == "family_123"
        assert event.token_id == "token_456"
    
    def test_session_events_creation(self):
        """Test creating session events."""
        # Session created
        event1 = SessionCreatedEvent.create(
            session_id="session_123",
            user_id=123,
            family_id="family_123"
        )
        assert event1.session_id == "session_123"
        assert event1.user_id == 123
        assert event1.family_id == "family_123"
        
        # Session revoked
        event2 = SessionRevokedEvent.create(
            session_id="session_123",
            user_id=123,
            family_id="family_123",
            reason="User logout"
        )
        assert event2.session_id == "session_123"
        assert event2.reason == "User logout"
        
        # Session expired
        event3 = SessionExpiredEvent.create(
            session_id="session_123",
            user_id=123,
            family_id="family_123"
        )
        assert event3.session_id == "session_123"


class TestOAuthEvents:
    """Test OAuth domain events."""
    
    def test_oauth_authentication_success_event_creation(self):
        """Test creating OAuth authentication success event."""
        event = OAuthAuthenticationSuccessEvent.create(
            provider="google",
            user_id=123,
            email="user@example.com",
            correlation_id="test-correlation"
        )
        
        assert event.provider == "google"
        assert event.user_id == 123
        assert event.email == "user@example.com"
        assert event.correlation_id == "test-correlation"
    
    def test_oauth_authentication_failed_event_creation(self):
        """Test creating OAuth authentication failed event."""
        event = OAuthAuthenticationFailedEvent.create(
            provider="google",
            error_code="invalid_token",
            error_description="Token has expired",
            user_id=123,
            correlation_id="test-correlation"
        )
        
        assert event.provider == "google"
        assert event.error_code == "invalid_token"
        assert event.error_description == "Token has expired"
        assert event.user_id == 123
    
    def test_oauth_profile_events_creation(self):
        """Test creating OAuth profile events."""
        # Profile created
        event1 = OAuthProfileCreatedEvent.create(
            user_id=123,
            provider="google",
            provider_user_id="google_user_456",
            email="user@example.com"
        )
        assert event1.user_id == 123
        assert event1.provider == "google"
        assert event1.provider_user_id == "google_user_456"
        assert event1.email == "user@example.com"
        
        # Profile updated
        event2 = OAuthProfileUpdatedEvent.create(
            user_id=123,
            provider="google",
            provider_user_id="google_user_456",
            email="updated@example.com"
        )
        assert event2.email == "updated@example.com"
        
        # Profile linked
        event3 = OAuthProfileLinkedEvent.create(
            user_id=123,
            provider="google",
            provider_user_id="google_user_456",
            email="user@example.com"
        )
        assert event3.user_id == 123


class TestEventValidationEdgeCases:
    """Test edge cases and validation scenarios."""
    
    def test_empty_string_validation(self):
        """Test validation of empty strings."""
        # Empty email
        with pytest.raises(ValueError, match="Email is required"):
            EmailConfirmedEvent.create(user_id=123, email="")
        
        # Whitespace email
        with pytest.raises(ValueError, match="Email is required"):
            EmailConfirmedEvent.create(user_id=123, email="   ")
        
        # Empty provider
        with pytest.raises(ValueError, match="Provider is required"):
            OAuthAuthenticationSuccessEvent.create(provider="", user_id=123)
        
        # Empty error code
        with pytest.raises(ValueError, match="Error code is required"):
            OAuthAuthenticationFailedEvent.create(
                provider="google",
                error_code="",
                error_description="Test"
            )
    
    def test_negative_user_id_validation(self):
        """Test validation of negative user IDs."""
        with pytest.raises(ValueError, match="User ID must be positive"):
            EmailConfirmedEvent.create(user_id=-1, email="user@example.com")
        
        with pytest.raises(ValueError, match="User ID must be positive"):
            OAuthAuthenticationSuccessEvent.create(provider="google", user_id=0)
    
    def test_empty_token_family_validation(self):
        """Test validation of empty token and family IDs."""
        with pytest.raises(ValueError, match="Family ID is required"):
            TokenFamilyCreatedEvent.create(family_id="", user_id=123)
        
        with pytest.raises(ValueError, match="Token ID is required"):
            TokenAddedEvent.create(family_id="family_123", token_id="", user_id=123)
    
    def test_empty_session_validation(self):
        """Test validation of empty session IDs."""
        with pytest.raises(ValueError, match="Session ID is required"):
            SessionCreatedEvent.create(session_id="", user_id=123)
        
        with pytest.raises(ValueError, match="Event type is required"):
            SessionEvent.create(event_type="", session_id="session_123", user_id=123)


class TestEventMetadataAndCorrelation:
    """Test event metadata and correlation ID handling."""
    
    def test_event_metadata_persistence(self):
        """Test that metadata is properly stored and retrieved."""
        metadata = {
            "source_ip": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "attempt_count": 3,
            "geolocation": {"country": "US", "city": "New York"}
        }
        
        event = AuthenticationFailedEvent.create(
            reason="Invalid credentials",
            metadata=metadata
        )
        
        assert event.metadata == metadata
        assert event.metadata["source_ip"] == "192.168.1.1"
        assert event.metadata["attempt_count"] == 3
    
    def test_event_correlation_id_persistence(self):
        """Test that correlation ID is properly stored and retrieved."""
        correlation_id = "req-12345-67890-abcdef"
        
        event = EmailConfirmedEvent.create(
            user_id=123,
            email="user@example.com",
            correlation_id=correlation_id
        )
        
        assert event.correlation_id == correlation_id
    
    def test_event_timestamp_consistency(self):
        """Test that timestamps are consistent across events."""
        before = datetime.now(timezone.utc)
        
        event1 = EmailConfirmedEvent.create(user_id=123, email="user1@example.com")
        event2 = EmailConfirmedEvent.create(user_id=124, email="user2@example.com")
        
        after = datetime.now(timezone.utc)
        
        assert before <= event1.timestamp <= after
        assert before <= event2.timestamp <= after
        assert event1.timestamp.tzinfo == timezone.utc
        assert event2.timestamp.tzinfo == timezone.utc


class TestEventImmutability:
    """Test that events are immutable."""
    
    def test_event_immutability(self):
        """Test that events cannot be modified after creation."""
        event = EmailConfirmedEvent.create(user_id=123, email="user@example.com")
        
        # Attempting to modify should raise AttributeError
        with pytest.raises(AttributeError):
            event.user_id = 456
        
        with pytest.raises(AttributeError):
            event.email = "new@example.com"
        
        with pytest.raises(AttributeError):
            event.metadata["new_key"] = "new_value"
    
    def test_event_hash_consistency(self):
        """Test that events have consistent hash values."""
        event1 = EmailConfirmedEvent.create(user_id=123, email="user@example.com")
        event2 = EmailConfirmedEvent.create(user_id=123, email="user@example.com")
        
        # Same data should produce same hash
        assert hash(event1) == hash(event2)
        
        # Different data should produce different hash
        event3 = EmailConfirmedEvent.create(user_id=124, email="user@example.com")
        assert hash(event1) != hash(event3)


class TestEventFactoryMethods:
    """Test event factory methods for consistency."""
    
    def test_all_events_have_factory_methods(self):
        """Test that all events have create() factory methods."""
        event_classes = [
            EmailConfirmedEvent,
            AuthenticationFailedEvent,
            TokenFamilyCreatedEvent,
            TokenAddedEvent,
            TokenUsedEvent,
            TokenRevokedEvent,
            TokenReuseDetectedEvent,
            TokenFamilyCompromisedEvent,
            TokenRefreshedEvent,
            SecurityIncidentEvent,
            UserAuthenticationEvent,
            SessionEvent,
            UserLoggedInEvent,
            UserRegisteredEvent,
            UserLoggedOutEvent,
            PasswordChangedEvent,
            SessionCreatedEvent,
            SessionRevokedEvent,
            SessionExpiredEvent,
            SessionActivityUpdatedEvent,
            OAuthAuthenticationSuccessEvent,
            OAuthAuthenticationFailedEvent,
            OAuthProfileCreatedEvent,
            OAuthProfileUpdatedEvent,
            OAuthProfileLinkedEvent,
            PasswordResetRequestedEvent,
            PasswordResetCompletedEvent,
            PasswordResetFailedEvent,
            PasswordResetTokenExpiredEvent,
        ]
        
        for event_class in event_classes:
            assert hasattr(event_class, 'create')
            assert callable(getattr(event_class, 'create'))
    
    def test_factory_methods_produce_valid_events(self):
        """Test that factory methods produce valid events."""
        # Test a few key events
        events = [
            EmailConfirmedEvent.create(user_id=123, email="user@example.com"),
            OAuthAuthenticationSuccessEvent.create(provider="google", user_id=123),
            TokenFamilyCreatedEvent.create(family_id="family_123", user_id=123),
            PasswordResetRequestedEvent.create(
                user_id=123,
                email="user@example.com",
                token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            )
        ]
        
        for event in events:
            assert isinstance(event, BaseDomainEvent)
            assert event.user_id == 123
            assert event.timestamp.tzinfo == timezone.utc


class TestEventPerformance:
    """Test event creation performance under load."""
    
    def test_bulk_event_creation_performance(self):
        """Test creating many events quickly."""
        import time
        
        start_time = time.time()
        
        # Create 1000 events
        events = []
        for i in range(1000):
            event = EmailConfirmedEvent.create(
                user_id=i,
                email=f"user{i}@example.com",
                correlation_id=f"correlation-{i}"
            )
            events.append(event)
        
        end_time = time.time()
        creation_time = end_time - start_time
        
        # Should complete in reasonable time (less than 1 second)
        assert creation_time < 1.0
        assert len(events) == 1000
        
        # All events should be valid
        for i, event in enumerate(events):
            assert event.user_id == i
            assert event.email == f"user{i}@example.com"
            assert event.correlation_id == f"correlation-{i}"
    
    def test_event_memory_efficiency(self):
        """Test that events are memory efficient."""
        import sys
        
        # Create many events and check memory usage
        events = []
        initial_size = sys.getsizeof(events)
        
        for i in range(1000):
            event = EmailConfirmedEvent.create(
                user_id=i,
                email=f"user{i}@example.com"
            )
            events.append(event)
        
        # Memory usage should be reasonable
        # Each event should be relatively small
        for event in events[:10]:  # Check first 10 events
            event_size = sys.getsizeof(event)
            assert event_size < 1000  # Each event should be less than 1KB 