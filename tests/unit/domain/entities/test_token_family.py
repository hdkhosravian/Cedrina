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
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock

from src.domain.entities.token_family import (
    TokenFamily,
    TokenFamilyStatus,
    TokenUsageEvent,
    TokenUsageRecord
)
from src.domain.value_objects.jwt_token import TokenId


class TestTokenUsageRecord:
    """Test cases for TokenUsageRecord value object."""
    
    def test_create_usage_record_with_all_fields(self):
        """Test creating usage record with all fields."""
        token_id = TokenId.generate()
        timestamp = datetime.now(timezone.utc)
        
        record = TokenUsageRecord(
            token_id=token_id,
            event_type=TokenUsageEvent.ISSUED,
            timestamp=timestamp,
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0",
            correlation_id="test-correlation-123"
        )
        
        assert record.token_id == token_id
        assert record.event_type == TokenUsageEvent.ISSUED
        assert record.timestamp == timestamp
        assert record.client_ip == "192.168.1.100"
        assert record.user_agent == "Mozilla/5.0"
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
        assert record.client_ip is None
        assert record.user_agent is None
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
        return TokenFamily(user_id=valid_user_id)
    
    def test_create_token_family_with_defaults(self, valid_user_id):
        """Test creating token family with default values."""
        family = TokenFamily(user_id=valid_user_id)
        
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
            user_id=valid_user_id,
            expires_at=expires_at
        )
        
        assert family.expires_at == expires_at
    
    def test_invalid_user_id_raises_error(self):
        """Test that invalid user ID raises ValueError."""
        with pytest.raises(ValueError, match="User ID must be positive"):
            TokenFamily(user_id=0)
        
        with pytest.raises(ValueError, match="User ID must be positive"):
            TokenFamily(user_id=-1)
    
    def test_add_token_to_family(self, basic_family, test_token_id):
        """Test adding token to family."""
        family = basic_family
        
        family.add_token(
            token_id=test_token_id,
            client_ip="192.168.1.100",
            user_agent="Test Agent",
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
        assert usage_record.client_ip == "192.168.1.100"
        assert usage_record.user_agent == "Test Agent"
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
        family.status = TokenFamilyStatus.COMPROMISED
        
        with pytest.raises(ValueError, match="Cannot add tokens to compromised family"):
            family.add_token(test_token_id)
    
    def test_add_token_to_revoked_family_raises_error(self, basic_family, test_token_id):
        """Test that adding token to revoked family raises error."""
        family = basic_family
        family.status = TokenFamilyStatus.REVOKED
        
        with pytest.raises(ValueError, match="Cannot add tokens to revoked family"):
            family.add_token(test_token_id)
    
    def test_use_token_success(self, basic_family, test_token_id):
        """Test successful token usage."""
        family = basic_family
        
        # Add token first
        family.add_token(test_token_id)
        
        # Use the token
        result = family.use_token(
            token_id=test_token_id,
            client_ip="192.168.1.200",
            correlation_id="use-123"
        )
        
        assert result is True
        assert len(family.usage_history) == 2  # ISSUED + USED
        assert family.last_used_at is not None
        
        # Check USED event
        used_event = family.usage_history[1]
        assert used_event.event_type == TokenUsageEvent.USED
        assert used_event.client_ip == "192.168.1.200"
        assert used_event.correlation_id == "use-123"
    
    def test_use_revoked_token_triggers_reuse_attack(self, basic_family, test_token_id):
        """Test that using revoked token triggers reuse attack detection."""
        family = basic_family
        
        # Add and revoke token
        family.add_token(test_token_id)
        family.revoke_token(test_token_id)
        
        # Try to use revoked token
        result = family.use_token(
            token_id=test_token_id,
            correlation_id="attack-123"
        )
        
        assert result is False
        assert family.status == TokenFamilyStatus.COMPROMISED
        assert family.compromised_at is not None
        assert family.compromise_reason == "Revoked token reuse detected"
        assert family.security_score == 0.0
        
        # Check for reuse detection event
        reuse_events = [
            event for event in family.usage_history
            if event.event_type == TokenUsageEvent.REUSE_DETECTED
        ]
        assert len(reuse_events) == 1
        assert reuse_events[0].token_id == test_token_id
    
    def test_use_unknown_token_triggers_reuse_attack(self, basic_family):
        """Test that using unknown token triggers reuse attack detection."""
        family = basic_family
        unknown_token = TokenId.generate()
        
        # Try to use unknown token
        result = family.use_token(
            token_id=unknown_token,
            correlation_id="attack-456"
        )
        
        assert result is False
        assert family.status == TokenFamilyStatus.COMPROMISED
        assert "Unknown token used in family" in family.compromise_reason
    
    def test_refresh_token_success(self, basic_family):
        """Test successful token refresh."""
        family = basic_family
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        
        # Add old token
        family.add_token(old_token)
        
        # Refresh token
        result = family.refresh_token(
            old_token_id=old_token,
            new_token_id=new_token,
            correlation_id="refresh-123"
        )
        
        assert result is True
        assert old_token in family.revoked_tokens
        assert old_token not in family.active_tokens
        assert new_token in family.active_tokens
        assert new_token not in family.revoked_tokens
        
        # Check events: ISSUED (old) + USED (old) + REVOKED (old) + ISSUED (new) + REFRESHED (new)
        assert len(family.usage_history) == 5
        
        refresh_events = [
            event for event in family.usage_history
            if event.event_type == TokenUsageEvent.REFRESHED
        ]
        assert len(refresh_events) == 1
        assert refresh_events[0].token_id == new_token
    
    def test_refresh_token_with_reuse_attack_fails(self, basic_family):
        """Test that refresh fails when reuse attack is detected."""
        family = basic_family
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        
        # Add and revoke old token to simulate reuse attack
        family.add_token(old_token)
        family.revoke_token(old_token)
        
        # Try to refresh with revoked token
        result = family.refresh_token(
            old_token_id=old_token,
            new_token_id=new_token
        )
        
        assert result is False
        assert family.status == TokenFamilyStatus.COMPROMISED
        assert new_token not in family.active_tokens
    
    def test_refresh_token_on_compromised_family_fails(self, basic_family):
        """Test that refresh fails on compromised family."""
        family = basic_family
        family.status = TokenFamilyStatus.COMPROMISED
        
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        
        result = family.refresh_token(
            old_token_id=old_token,
            new_token_id=new_token
        )
        
        assert result is False
    
    def test_revoke_token(self, basic_family, test_token_id):
        """Test token revocation."""
        family = basic_family
        
        # Add token
        family.add_token(test_token_id)
        
        # Revoke token
        family.revoke_token(
            token_id=test_token_id,
            correlation_id="revoke-123"
        )
        
        assert test_token_id not in family.active_tokens
        assert test_token_id in family.revoked_tokens
        
        # Check revocation event
        revoked_events = [
            event for event in family.usage_history
            if event.event_type == TokenUsageEvent.REVOKED
        ]
        assert len(revoked_events) == 1
        assert revoked_events[0].token_id == test_token_id
        assert revoked_events[0].correlation_id == "revoke-123"
    
    def test_revoke_token_twice_is_safe(self, basic_family, test_token_id):
        """Test that revoking token twice is safe."""
        family = basic_family
        
        # Add token
        family.add_token(test_token_id)
        
        # Revoke twice
        family.revoke_token(test_token_id)
        family.revoke_token(test_token_id)
        
        # Should only appear once in revoked list
        assert family.revoked_tokens.count(test_token_id) == 1
    
    def test_compromise_family(self, basic_family):
        """Test family compromise."""
        family = basic_family
        token1 = TokenId.generate()
        token2 = TokenId.generate()
        detected_token = TokenId.generate()
        
        # Add some tokens
        family.add_token(token1)
        family.add_token(token2)
        
        # Compromise family
        family.compromise_family(
            reason="Test compromise",
            detected_token=detected_token,
            correlation_id="compromise-123"
        )
        
        assert family.status == TokenFamilyStatus.COMPROMISED
        assert family.compromised_at is not None
        assert family.compromise_reason == "Test compromise"
        assert family.security_score == 0.0
        
        # All active tokens should be revoked
        assert len(family.active_tokens) == 0
        assert token1 in family.revoked_tokens
        assert token2 in family.revoked_tokens
        
        # Check for reuse detection event
        reuse_events = [
            event for event in family.usage_history
            if event.event_type == TokenUsageEvent.REUSE_DETECTED
        ]
        assert len(reuse_events) == 1
        assert reuse_events[0].token_id == detected_token
    
    def test_is_active_with_active_status(self, basic_family):
        """Test is_active with ACTIVE status."""
        family = basic_family
        assert family.is_active() is True
    
    def test_is_active_with_compromised_status(self, basic_family):
        """Test is_active with COMPROMISED status."""
        family = basic_family
        family.status = TokenFamilyStatus.COMPROMISED
        assert family.is_active() is False
    
    def test_is_active_with_expired_family(self, basic_family):
        """Test is_active with expired family."""
        family = basic_family
        family.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        assert family.is_active() is False
        assert family.status == TokenFamilyStatus.EXPIRED
    
    def test_is_compromised(self, basic_family):
        """Test is_compromised method."""
        family = basic_family
        
        assert family.is_compromised() is False
        
        family.status = TokenFamilyStatus.COMPROMISED
        assert family.is_compromised() is True
    
    def test_get_security_metadata(self, basic_family, test_token_id):
        """Test security metadata generation."""
        family = basic_family
        family.add_token(test_token_id)
        
        metadata = family.get_security_metadata()
        
        assert metadata["family_id"] == family.family_id
        assert metadata["status"] == "active"
        assert metadata["security_score"] == 1.0
        assert metadata["active_token_count"] == 1
        assert metadata["revoked_token_count"] == 0
        assert metadata["usage_event_count"] == 1
        assert metadata["compromise_reason"] is None
        assert "created_at" in metadata
    
    def test_get_security_metadata_compromised(self, basic_family, test_token_id):
        """Test security metadata for compromised family."""
        family = basic_family
        family.add_token(test_token_id)
        family.compromise_family("Test compromise")
        
        metadata = family.get_security_metadata()
        
        assert metadata["status"] == "compromised"
        assert metadata["security_score"] == 0.0
        assert metadata["compromise_reason"] == "Test compromise"
        assert metadata["compromised_at"] is not None
    
    def test_get_usage_pattern_analysis_no_usage(self, basic_family):
        """Test usage pattern analysis with no usage."""
        family = basic_family
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["pattern"] == "no_usage"
        assert analysis["risk_score"] == 0.0
    
    def test_get_usage_pattern_analysis_normal(self, basic_family, test_token_id):
        """Test usage pattern analysis with normal usage."""
        family = basic_family
        family.add_token(test_token_id, client_ip="192.168.1.100")
        family.use_token(test_token_id, client_ip="192.168.1.100")
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["pattern"] == "normal"
        assert analysis["risk_score"] < 0.5
        assert analysis["recent_event_count"] == 2
        assert analysis["unique_ip_count"] == 1
        assert analysis["total_events"] == 2
    
    def test_get_usage_pattern_analysis_suspicious_high_frequency(self, basic_family):
        """Test usage pattern analysis with suspicious high frequency."""
        family = basic_family
        
        # Simulate high frequency usage
        for i in range(150):
            token = TokenId.generate()
            family.add_token(token, client_ip="192.168.1.100")
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["pattern"] == "suspicious"
        assert analysis["risk_score"] >= 0.3
        assert analysis["recent_event_count"] > 100
    
    def test_get_usage_pattern_analysis_suspicious_multiple_ips(self, basic_family):
        """Test usage pattern analysis with suspicious multiple IPs."""
        family = basic_family
        
        # Simulate usage from many different IPs
        for i in range(15):
            token = TokenId.generate()
            family.add_token(token, client_ip=f"192.168.1.{i}")
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["pattern"] == "suspicious"
        assert analysis["risk_score"] >= 0.4
        assert analysis["unique_ip_count"] > 10
    
    def test_get_usage_pattern_analysis_critical_reuse_detected(self, basic_family, test_token_id):
        """Test usage pattern analysis with reuse detection."""
        family = basic_family
        
        # Add and revoke token to trigger reuse attack
        family.add_token(test_token_id)
        family.revoke_token(test_token_id)
        family.use_token(test_token_id)  # This will trigger reuse detection
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["pattern"] == "suspicious"
        assert analysis["risk_score"] == 1.0  # Maximum risk 