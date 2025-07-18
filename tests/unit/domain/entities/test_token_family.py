"""
Unit tests for TokenFamily entity and related security patterns.

These tests validate the token family security pattern implementation including:
- Token family lifecycle management
- Reuse detection and family compromise
- Security event tracking and analysis
- Usage pattern analysis
- Family-wide revocation on security violations

Test Coverage:
- Entity creation and initialization
- Token addition and usage validation
- Reuse attack detection and response
- Token refresh operations
- Family compromise scenarios
- Security metadata and analytics
- Edge cases and error conditions
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock

from src.domain.entities.token_family import TokenFamily
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.token_usage_event import TokenUsageEvent
from src.domain.value_objects.token_usage_record import TokenUsageRecord
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext


class TestTokenUsageRecord:
    """Test cases for TokenUsageRecord value object."""
    
    def test_create_usage_record_with_all_fields(self):
        """Test creating usage record with all fields."""
        token_id = TokenId.generate()
        timestamp = datetime.now(timezone.utc)
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0",
            correlation_id="test-correlation-123"
        )
        
        record = TokenUsageRecord(
            token_id=token_id,
            event_type=TokenUsageEvent.ISSUED,
            timestamp=timestamp,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        assert record.token_id == token_id
        assert record.event_type == TokenUsageEvent.ISSUED
        assert record.timestamp == timestamp
        assert record.get_client_ip() == "192.168.1.100"
        assert record.get_user_agent() == "Mozilla/5.0"
        assert record.correlation_id == "test-correlation-123"
    
    def test_create_usage_record_minimal(self):
        """Test creating usage record with minimal fields."""
        token_id = TokenId.generate()
        
        record = TokenUsageRecord(
            token_id=token_id,
            event_type=TokenUsageEvent.USED,
            timestamp=datetime.now(timezone.utc)
        )
        
        assert record.token_id == token_id
        assert record.event_type == TokenUsageEvent.USED
        assert record.get_client_ip() is None
        assert record.get_user_agent() is None
        assert record.correlation_id is None
    
    def test_usage_record_validation(self):
        """Test usage record validation."""
        with pytest.raises(ValueError, match="Token ID is required"):
            TokenUsageRecord(
                token_id=None,
                event_type=TokenUsageEvent.ISSUED,
                timestamp=datetime.now(timezone.utc)
            )


class TestTokenFamily:
    """Test cases for TokenFamily entity."""
    
    @pytest.fixture
    def valid_user_id(self):
        """Valid user ID for testing."""
        return 12345
    
    @pytest.fixture
    def test_token_id(self):
        """Generate test token ID."""
        return TokenId.generate()
    
    @pytest.fixture
    def basic_family(self, valid_user_id):
        """Create basic token family for testing."""
        return TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=valid_user_id
        )
    
    def test_create_token_family_with_defaults(self, valid_user_id):
        """Test creating token family with default values."""
        family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=valid_user_id
        )
        
        assert family.user_id == valid_user_id
        assert family.status == TokenFamilyStatus.ACTIVE
        assert family.family_id is not None
        assert len(family.family_id) > 0
        assert family.created_at is not None
        assert family.last_used_at is None
        assert family.compromised_at is None
        assert family.expires_at is None
        assert len(family.active_tokens) == 0
        assert len(family.revoked_tokens) == 0
        assert len(family.usage_history) == 0
        assert family.compromise_reason is None
        assert family.security_score == 1.0
    
    def test_create_token_family_with_expiration(self, valid_user_id):
        """Test creating token family with expiration time."""
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        family = TokenFamily(
            family_id=str(uuid.uuid4()),
            user_id=valid_user_id,
            expires_at=expires_at
        )
        
        assert family.expires_at == expires_at
    
    def test_invalid_user_id_raises_error(self):
        """Test that invalid user ID raises ValueError."""
        with pytest.raises(ValueError, match="User ID must be positive"):
            TokenFamily(family_id=str(uuid.uuid4()), user_id=0)
        
        with pytest.raises(ValueError, match="User ID must be positive"):
            TokenFamily(family_id=str(uuid.uuid4()), user_id=-1)
    
    def test_add_token_to_family(self, basic_family, test_token_id):
        """Test adding token to family."""
        family = basic_family
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent",
            correlation_id="test-123"
        )
        
        family.add_token(
            token_id=test_token_id,
            security_context=security_context,
            correlation_id="test-123"
        )
        
        assert test_token_id in family.active_tokens
        assert len(family.active_tokens) == 1
        assert len(family.usage_history) == 1
        assert family.last_used_at is not None
        
        # Check usage record
        usage_record = family.usage_history[0]
        assert usage_record.token_id == test_token_id
        assert usage_record.event_type == TokenUsageEvent.ISSUED
        assert usage_record.get_client_ip() == "192.168.1.100"
        assert usage_record.get_user_agent() == "Test Agent"
        assert usage_record.correlation_id == "test-123"
    
    def test_add_duplicate_token_raises_error(self, basic_family, test_token_id):
        """Test that adding duplicate token raises error."""
        family = basic_family
        
        # Add token first time
        family.add_token(test_token_id)
        
        # Try to add same token again
        with pytest.raises(ValueError, match="already exists in family"):
            family.add_token(test_token_id)
    
    def test_add_token_to_compromised_family_raises_error(self, basic_family, test_token_id):
        """Test that adding token to compromised family raises error."""
        family = basic_family
        family._status = TokenFamilyStatus.COMPROMISED
        
        with pytest.raises(ValueError, match="Cannot add tokens to compromised family"):
            family.add_token(test_token_id)
    
    def test_add_token_to_revoked_family_raises_error(self, basic_family, test_token_id):
        """Test that adding token to revoked family raises error."""
        family = basic_family
        family._status = TokenFamilyStatus.REVOKED
        
        with pytest.raises(ValueError, match="Cannot add tokens to revoked family"):
            family.add_token(test_token_id)
    
    def test_use_token_success(self, basic_family, test_token_id):
        """Test successful token usage."""
        family = basic_family
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.200",
            user_agent="Test Agent",
            correlation_id="use-123"
        )
        
        # Add token first
        family.add_token(test_token_id)
        
        # Use the token
        result = family.use_token(
            token_id=test_token_id,
            security_context=security_context,
            correlation_id="use-123"
        )
        
        assert result is True
        assert test_token_id in family.active_tokens
        assert len(family.usage_history) == 2  # ISSUED + USED
        
        # Check usage record
        usage_record = family.usage_history[1]
        assert usage_record.token_id == test_token_id
        assert usage_record.event_type == TokenUsageEvent.USED
        assert usage_record.get_client_ip() == "192.168.1.200"
        assert usage_record.correlation_id == "use-123"
    
    def test_use_revoked_token_triggers_reuse_attack(self, basic_family, test_token_id):
        """Test that using revoked token triggers reuse attack."""
        family = basic_family
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Add and then revoke token
        family.add_token(test_token_id)
        family.revoke_token(test_token_id)
        
        # Try to use revoked token
        result = family.use_token(
            token_id=test_token_id,
            security_context=security_context
        )
        
        assert result is False
        assert family.is_compromised()
        assert family.compromise_reason == "Revoked token reuse detected"
        
        # Check that all tokens are now revoked
        assert len(family.active_tokens) == 0
        assert test_token_id in family.revoked_tokens
    
    def test_use_unknown_token_triggers_reuse_attack(self, basic_family):
        """Test that using unknown token triggers reuse attack."""
        family = basic_family
        unknown_token = TokenId.generate()
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Try to use unknown token
        result = family.use_token(
            token_id=unknown_token,
            security_context=security_context
        )
        
        assert result is False
        assert family.is_compromised()
        assert family.compromise_reason == "Unknown token used in family"
    
    def test_refresh_token_success(self, basic_family):
        """Test successful token refresh."""
        family = basic_family
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Add old token
        family.add_token(old_token)
        
        # Refresh token
        result = family.refresh_token(
            old_token_id=old_token,
            new_token_id=new_token,
            security_context=security_context
        )
        
        assert result is True
        assert old_token in family.revoked_tokens
        assert new_token in family.active_tokens
        assert len(family.usage_history) == 5  # ISSUED + USED + REVOKED + ISSUED + REFRESHED
    
    def test_refresh_token_with_reuse_attack_fails(self, basic_family):
        """Test that refreshing with reused token fails."""
        family = basic_family
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Add old token and revoke it
        family.add_token(old_token)
        family.revoke_token(old_token)
        
        # Try to refresh with revoked token
        result = family.refresh_token(
            old_token_id=old_token,
            new_token_id=new_token,
            security_context=security_context
        )
        
        assert result is False
        assert family.is_compromised()
    
    def test_refresh_token_on_compromised_family_fails(self, basic_family):
        """Test that refreshing on compromised family fails."""
        family = basic_family
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        
        # Compromise family
        family.compromise_family("Test compromise")
        
        # Try to refresh token
        result = family.refresh_token(
            old_token_id=old_token,
            new_token_id=new_token
        )
        
        assert result is False
    
    def test_revoke_token(self, basic_family, test_token_id):
        """Test revoking token from family."""
        family = basic_family
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Add token first
        family.add_token(test_token_id)
        
        # Revoke token
        family.revoke_token(
            token_id=test_token_id,
            security_context=security_context
        )
        
        assert test_token_id not in family.active_tokens
        assert test_token_id in family.revoked_tokens
        assert len(family.usage_history) == 2  # ISSUED + REVOKED
        
        # Check usage record
        usage_record = family.usage_history[1]
        assert usage_record.token_id == test_token_id
        assert usage_record.event_type == TokenUsageEvent.REVOKED
    
    def test_revoke_token_twice_is_safe(self, basic_family, test_token_id):
        """Test that revoking token twice is safe."""
        family = basic_family
        
        # Add token first
        family.add_token(test_token_id)
        
        # Revoke token twice
        family.revoke_token(test_token_id)
        family.revoke_token(test_token_id)  # Should not raise error
        
        assert test_token_id in family.revoked_tokens
        assert test_token_id not in family.active_tokens
    
    def test_compromise_family(self, basic_family):
        """Test compromising entire family."""
        family = basic_family
        token1 = TokenId.generate()
        token2 = TokenId.generate()
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Test Agent"
        )
        
        # Add tokens
        family.add_token(token1)
        family.add_token(token2)
        
        # Compromise family
        family.compromise_family(
            reason="Test compromise",
            detected_token=token1,
            security_context=security_context
        )
        
        assert family.is_compromised()
        assert family.compromise_reason == "Test compromise"
        assert family.compromised_at is not None
        assert family.security_score == 0.0
        assert len(family.active_tokens) == 0
        assert token1 in family.revoked_tokens
        assert token2 in family.revoked_tokens
        
        # Check usage record
        usage_record = family.usage_history[-1]
        assert usage_record.token_id == token1
        assert usage_record.event_type == TokenUsageEvent.COMPROMISED
    
    def test_is_active_with_active_status(self, basic_family):
        """Test is_active with active status."""
        family = basic_family
        assert family.is_active() is True
    
    def test_is_active_with_compromised_status(self, basic_family):
        """Test is_active with compromised status."""
        family = basic_family
        family._status = TokenFamilyStatus.COMPROMISED
        assert family.is_active() is False
    
    def test_is_active_with_expired_family(self, basic_family):
        """Test is_active with expired family."""
        family = basic_family
        family._status = TokenFamilyStatus.EXPIRED
        assert family.is_active() is False
    
    def test_is_compromised(self, basic_family):
        """Test is_compromised method."""
        family = basic_family
        assert family.is_compromised() is False
        
        family._status = TokenFamilyStatus.COMPROMISED
        assert family.is_compromised() is True
    
    def test_get_security_metadata(self, basic_family, test_token_id):
        """Test getting security metadata."""
        family = basic_family
        family.add_token(test_token_id)
        
        metadata = family.get_security_metadata()
        
        assert "family_id" in metadata
        assert "user_id" in metadata
        assert "status" in metadata
        assert "security_score" in metadata
        assert "active_tokens_count" in metadata
        assert "revoked_tokens_count" in metadata
        assert "usage_history_count" in metadata
    
    def test_get_security_metadata_compromised(self, basic_family, test_token_id):
        """Test getting security metadata for compromised family."""
        family = basic_family
        family.add_token(test_token_id)
        family.compromise_family("Test compromise")
        
        metadata = family.get_security_metadata()
        
        assert metadata["status"] == "compromised"
        assert metadata["security_score"] == 0.0
        assert metadata["compromise_reason"] == "Test compromise"
    
    def test_get_usage_pattern_analysis_no_usage(self, basic_family):
        """Test usage pattern analysis with no usage."""
        family = basic_family
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["total_events"] == 0
        assert analysis["suspicious_activity"] is False
        assert analysis["risk_level"] == "low"
    
    def test_get_usage_pattern_analysis_normal(self, basic_family, test_token_id):
        """Test usage pattern analysis with normal usage."""
        family = basic_family
        family.add_token(test_token_id)
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["total_events"] == 1
        assert analysis["suspicious_activity"] is False
        assert analysis["risk_level"] == "low"
    
    def test_get_usage_pattern_analysis_suspicious_high_frequency(self, basic_family):
        """Test usage pattern analysis with suspicious high frequency."""
        family = basic_family
        
        # Add many tokens quickly (simulating high frequency)
        for i in range(10):
            token = TokenId.generate()
            family.add_token(token)
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["total_events"] == 10
        assert analysis["suspicious_activity"] is True
        assert analysis["risk_level"] == "medium"
    
    def test_get_usage_pattern_analysis_suspicious_multiple_ips(self, basic_family):
        """Test usage pattern analysis with suspicious multiple IPs."""
        family = basic_family
        
        # Add tokens with different IPs (simulating multiple IPs)
        for i in range(5):
            token = TokenId.generate()
            security_context = SecurityContext.create_for_request(
                client_ip=f"192.168.1.{i}",
                user_agent="Test Agent"
            )
            family.add_token(token, security_context=security_context)
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["suspicious_activity"] is True
        assert analysis["risk_level"] == "high"
    
    def test_get_usage_pattern_analysis_critical_reuse_detected(self, basic_family, test_token_id):
        """Test usage pattern analysis with critical reuse detected."""
        family = basic_family
        family.add_token(test_token_id)
        family.revoke_token(test_token_id)
        
        # Try to use revoked token (triggers reuse attack)
        family.use_token(test_token_id)
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["suspicious_activity"] is True
        assert analysis["risk_level"] == "critical"
        assert "reuse_detected" in analysis["warnings"] 