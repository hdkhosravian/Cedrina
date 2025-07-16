"""
Tests for TokenFamily aggregate following TDD principles.

This test suite validates the TokenFamily aggregate which serves as the
aggregate root for token family security patterns in the authentication domain.

Test Coverage:
- TokenFamily creation and initialization
- Token operations (add, use, revoke, refresh)
- Security patterns (reuse detection, family compromise)
- Status transitions and validation
- Usage pattern analysis
- Factory methods and repository support
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

from src.domain.entities.token_family import TokenFamily
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.token_usage_event import TokenUsageEvent
from src.domain.value_objects.token_usage_record import TokenUsageRecord


class TestTokenFamilyCreation:
    """Test token family creation and initialization."""
    
    def test_create_token_family_with_valid_data(self):
        """Test creating a token family with valid data."""
        family_id = str(uuid4())
        user_id = 1
        
        family = TokenFamily(
            family_id=family_id,
            user_id=user_id
        )
        
        assert family.family_id == family_id
        assert family.user_id == user_id
        assert family.status == TokenFamilyStatus.ACTIVE
        assert family.security_score == 1.0
        assert family.active_tokens == []
        assert family.revoked_tokens == []
        assert family.usage_history == []
        assert family.compromise_reason is None
        assert family.compromised_at is None
        assert family.last_used_at is None
    
    def test_create_token_family_with_empty_family_id_raises_error(self):
        """Test that empty family ID raises ValueError."""
        with pytest.raises(ValueError, match="Family ID is required"):
            TokenFamily(
                family_id="",
                user_id=1
            )
    
    def test_create_token_family_with_invalid_user_id_raises_error(self):
        """Test that invalid user ID raises ValueError."""
        with pytest.raises(ValueError, match="User ID must be positive"):
            TokenFamily(
                family_id=str(uuid4()),
                user_id=0
            )
        
        with pytest.raises(ValueError, match="User ID must be positive"):
            TokenFamily(
                family_id=str(uuid4()),
                user_id=-1
            )
    
    def test_create_token_family_with_invalid_security_score_raises_error(self):
        """Test that invalid security score raises ValueError."""
        with pytest.raises(ValueError, match="Security score must be between 0.0 and 1.0"):
            TokenFamily(
                family_id=str(uuid4()),
                user_id=1,
                security_score=1.5
            )
        
        with pytest.raises(ValueError, match="Security score must be between 0.0 and 1.0"):
            TokenFamily(
                family_id=str(uuid4()),
                user_id=1,
                security_score=-0.1
            )
    
    def test_create_token_family_with_all_parameters(self):
        """Test creating token family with all parameters."""
        family_id = str(uuid4())
        user_id = 1
        created_at = datetime.now(timezone.utc)
        last_used_at = created_at
        expires_at = created_at + timedelta(days=30)
        
        family = TokenFamily(
            family_id=family_id,
            user_id=user_id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=created_at,
            last_used_at=last_used_at,
            expires_at=expires_at,
            security_score=0.8
        )
        
        assert family.family_id == family_id
        assert family.user_id == user_id
        assert family.status == TokenFamilyStatus.ACTIVE
        assert family.created_at == created_at
        assert family.last_used_at == last_used_at
        assert family.expires_at == expires_at
        assert family.security_score == 0.8


class TestTokenFamilyTokenOperations:
    """Test token operations in token family."""
    
    @pytest.fixture
    def family(self):
        """Create a test token family."""
        return TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
    
    @pytest.fixture
    def security_context(self):
        """Create a test security context."""
        return SecurityContext.create_for_request(
            client_ip="192.168.1.1",
            user_agent="Test Agent",
            correlation_id=str(uuid4())
        )
    
    def test_add_token_to_active_family(self, family, security_context):
        """Test adding a token to an active family."""
        token_id = TokenId.generate()
        
        family.add_token(token_id, security_context)
        
        assert token_id in family.active_tokens
        assert len(family.active_tokens) == 1
        assert len(family.usage_history) == 1
        assert family.usage_history[0].token_id == token_id
        assert family.usage_history[0].event_type == TokenUsageEvent.ISSUED
        assert family.last_used_at is not None
    
    def test_add_duplicate_token_raises_error(self, family):
        """Test that adding duplicate token raises ValueError."""
        token_id = TokenId.generate()
        
        family.add_token(token_id)
        
        with pytest.raises(ValueError, match="already exists in family"):
            family.add_token(token_id)
    
    def test_add_token_to_compromised_family_raises_error(self, family):
        """Test that adding token to compromised family raises ValueError."""
        token_id = TokenId.generate()
        
        # Compromise the family
        family.compromise_family("Test compromise")
        
        with pytest.raises(ValueError, match="Cannot add tokens to compromised family"):
            family.add_token(token_id)
    
    def test_use_active_token(self, family, security_context):
        """Test using an active token."""
        token_id = TokenId.generate()
        
        family.add_token(token_id)
        result = family.use_token(token_id, security_context)
        
        assert result is True
        assert len(family.usage_history) == 2  # ISSUED + USED
        assert family.usage_history[1].event_type == TokenUsageEvent.USED
        assert family.last_used_at is not None
    
    def test_use_revoked_token_compromises_family(self, family, security_context):
        """Test that using a revoked token compromises the family."""
        token_id = TokenId.generate()
        
        family.add_token(token_id)
        family.revoke_token(token_id)
        
        result = family.use_token(token_id, security_context)
        
        assert result is False
        assert family.is_compromised()
        assert family.compromise_reason == "Revoked token reuse detected"
        assert family.security_score == 0.0
    
    def test_use_unknown_token_compromises_family(self, family, security_context):
        """Test that using unknown token compromises the family."""
        unknown_token = TokenId.generate()
        
        result = family.use_token(unknown_token, security_context)
        
        assert result is False
        assert family.is_compromised()
        assert family.compromise_reason == "Unknown token used in family"
    
    def test_revoke_active_token(self, family, security_context):
        """Test revoking an active token."""
        token_id = TokenId.generate()
        
        family.add_token(token_id)
        family.revoke_token(token_id, security_context)
        
        assert token_id not in family.active_tokens
        assert token_id in family.revoked_tokens
        assert len(family.usage_history) == 2  # ISSUED + REVOKED
        assert family.usage_history[1].event_type == TokenUsageEvent.REVOKED
    
    def test_revoke_nonexistent_token_raises_error(self, family):
        """Test that revoking nonexistent token raises ValueError."""
        nonexistent_token = TokenId.generate()
        
        with pytest.raises(ValueError, match="is not active"):
            family.revoke_token(nonexistent_token)
    
    def test_revoke_already_revoked_token_no_error(self, family):
        """Test that revoking already revoked token doesn't raise error."""
        token_id = TokenId.generate()
        
        family.add_token(token_id)
        family.revoke_token(token_id)
        
        # Should not raise error
        family.revoke_token(token_id)
        
        assert token_id in family.revoked_tokens
    
    def test_refresh_token_success(self, family, security_context):
        """Test successful token refresh."""
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        
        family.add_token(old_token)
        result = family.refresh_token(old_token, new_token, security_context)
        
        assert result is True
        assert old_token not in family.active_tokens
        assert old_token in family.revoked_tokens
        assert new_token in family.active_tokens
        assert len(family.usage_history) == 5  # ISSUED + USED + REVOKED + ISSUED + REFRESHED
    
    def test_refresh_token_in_compromised_family_fails(self, family):
        """Test that token refresh fails in compromised family."""
        old_token = TokenId.generate()
        new_token = TokenId.generate()
        
        family.add_token(old_token)
        family.compromise_family("Test compromise")
        
        result = family.refresh_token(old_token, new_token)
        
        assert result is False
        assert new_token not in family.active_tokens


class TestTokenFamilySecurityPatterns:
    """Test security patterns in token family."""
    
    @pytest.fixture
    def family(self):
        """Create a test token family."""
        return TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
    
    @pytest.fixture
    def security_context(self):
        """Create a test security context."""
        return SecurityContext.create_for_request(
            client_ip="192.168.1.1",
            user_agent="Test Agent",
            correlation_id=str(uuid4())
        )
    
    def test_compromise_family_manually(self, family, security_context):
        """Test manually compromising a family."""
        token_id = TokenId.generate()
        family.add_token(token_id)
        
        family.compromise_family("Manual compromise", token_id, security_context)
        
        assert family.is_compromised()
        assert family.compromise_reason == "Manual compromise"
        assert family.security_score == 0.0
        assert family.compromised_at is not None
        assert len(family.active_tokens) == 0
        assert token_id in family.revoked_tokens
    
    def test_compromise_already_compromised_family_no_change(self, family):
        """Test that compromising already compromised family doesn't change state."""
        family.compromise_family("First compromise")
        first_compromise_time = family.compromised_at
        
        family.compromise_family("Second compromise")
        
        assert family.compromise_reason == "First compromise"
        assert family.compromised_at == first_compromise_time
    
    def test_detect_reuse_attack(self, family, security_context):
        """Test reuse attack detection."""
        token_id = TokenId.generate()
        
        family.add_token(token_id)
        family.revoke_token(token_id)
        
        # This should trigger reuse detection
        family.use_token(token_id, security_context)
        
        # Find the reuse detection event
        reuse_events = [
            record for record in family.usage_history
            if record.event_type == TokenUsageEvent.REUSE_DETECTED
        ]
        
        assert len(reuse_events) == 1
        assert reuse_events[0].token_id == token_id
        assert family.is_compromised()
    
    def test_reuse_detection_with_multiple_tokens(self, family, security_context):
        """Test reuse detection with multiple tokens in family."""
        token1 = TokenId.generate()
        token2 = TokenId.generate()
        
        family.add_token(token1)
        family.add_token(token2)
        family.revoke_token(token1)
        
        # Use valid token - should work
        result1 = family.use_token(token2, security_context)
        assert result1 is True
        
        # Use revoked token - should compromise family
        result2 = family.use_token(token1, security_context)
        assert result2 is False
        assert family.is_compromised()
        
        # All tokens should be revoked
        assert len(family.active_tokens) == 0
        assert len(family.revoked_tokens) == 2


class TestTokenFamilyStatusMethods:
    """Test token family status methods."""
    
    @pytest.fixture
    def family(self):
        """Create a test token family."""
        return TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
    
    def test_is_active_when_active(self, family):
        """Test is_active returns True for active family."""
        assert family.is_active() is True
        assert family.is_compromised() is False
        assert family.is_revoked() is False
        assert family.is_expired() is False
    
    def test_is_compromised_when_compromised(self, family):
        """Test is_compromised returns True for compromised family."""
        family.compromise_family("Test compromise")
        
        assert family.is_active() is False
        assert family.is_compromised() is True
        assert family.is_revoked() is False
        assert family.is_expired() is False
    
    def test_has_token_checks_all_collections(self, family):
        """Test has_token checks both active and revoked tokens."""
        active_token = TokenId.generate()
        revoked_token = TokenId.generate()
        unknown_token = TokenId.generate()
        
        family.add_token(active_token)
        family.add_token(revoked_token)
        family.revoke_token(revoked_token)
        
        assert family.has_token(active_token) is True
        assert family.has_token(revoked_token) is True
        assert family.has_token(unknown_token) is False
    
    def test_is_token_active_checks_active_collection(self, family):
        """Test is_token_active checks only active tokens."""
        active_token = TokenId.generate()
        revoked_token = TokenId.generate()
        
        family.add_token(active_token)
        family.add_token(revoked_token)
        family.revoke_token(revoked_token)
        
        assert family.is_token_active(active_token) is True
        assert family.is_token_active(revoked_token) is False
    
    def test_is_token_revoked_checks_revoked_collection(self, family):
        """Test is_token_revoked checks only revoked tokens."""
        active_token = TokenId.generate()
        revoked_token = TokenId.generate()
        
        family.add_token(active_token)
        family.add_token(revoked_token)
        family.revoke_token(revoked_token)
        
        assert family.is_token_revoked(active_token) is False
        assert family.is_token_revoked(revoked_token) is True
    
    def test_update_expiration_expires_family(self, family):
        """Test update_expiration expires the family when time is reached."""
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        family._expires_at = past_time
        
        family.update_expiration()
        
        assert family.is_expired() is True
        assert family.status == TokenFamilyStatus.EXPIRED
    
    def test_update_expiration_keeps_compromised_status(self, family):
        """Test update_expiration doesn't change compromised status."""
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        family._expires_at = past_time
        family.compromise_family("Test compromise")
        
        family.update_expiration()
        
        assert family.is_compromised() is True
        assert family.status == TokenFamilyStatus.COMPROMISED


class TestTokenFamilyFactoryMethods:
    """Test token family factory methods."""
    
    def test_create_new_family_without_initial_token(self):
        """Test creating new family without initial token."""
        family_id = str(uuid4())
        user_id = 1
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        family = TokenFamily.create_new_family(
            family_id=family_id,
            user_id=user_id,
            expires_at=expires_at
        )
        
        assert family.family_id == family_id
        assert family.user_id == user_id
        assert family.expires_at == expires_at
        assert family.is_active()
        assert family.security_score == 1.0
        assert len(family.active_tokens) == 0
        assert len(family.usage_history) == 0
    
    def test_create_new_family_with_initial_token(self):
        """Test creating new family with initial token."""
        family_id = str(uuid4())
        user_id = 1
        initial_token = TokenId.generate()
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.1",
            user_agent="Test Agent"
        )
        
        family = TokenFamily.create_new_family(
            family_id=family_id,
            user_id=user_id,
            initial_token_id=initial_token,
            security_context=security_context
        )
        
        assert family.family_id == family_id
        assert family.user_id == user_id
        assert initial_token in family.active_tokens
        assert len(family.active_tokens) == 1
        assert len(family.usage_history) == 1
        assert family.usage_history[0].event_type == TokenUsageEvent.ISSUED


class TestTokenFamilyRepositorySupport:
    """Test token family repository support methods."""
    
    @pytest.fixture
    def family(self):
        """Create a test token family."""
        return TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
    
    def test_set_active_tokens(self, family):
        """Test setting active tokens for repository mapping."""
        tokens = [TokenId.generate(), TokenId.generate()]
        
        family.set_active_tokens(tokens)
        
        assert family.active_tokens == tokens
        assert family.active_tokens is not tokens  # Should be a copy
    
    def test_set_active_tokens_with_empty_list(self, family):
        """Test setting active tokens with empty list."""
        family.set_active_tokens([])
        
        assert family.active_tokens == []
    
    def test_set_active_tokens_with_none(self, family):
        """Test setting active tokens with None."""
        family.set_active_tokens(None)
        
        assert family.active_tokens == []
    
    def test_set_revoked_tokens(self, family):
        """Test setting revoked tokens for repository mapping."""
        tokens = [TokenId.generate(), TokenId.generate()]
        
        family.set_revoked_tokens(tokens)
        
        assert family.revoked_tokens == tokens
        assert family.revoked_tokens is not tokens  # Should be a copy
    
    def test_set_usage_history(self, family):
        """Test setting usage history for repository mapping."""
        records = [
            TokenUsageRecord(
                token_id=TokenId.generate(),
                event_type=TokenUsageEvent.ISSUED,
                timestamp=datetime.now(timezone.utc)
            ),
            TokenUsageRecord(
                token_id=TokenId.generate(),
                event_type=TokenUsageEvent.USED,
                timestamp=datetime.now(timezone.utc)
            )
        ]
        
        family.set_usage_history(records)
        
        assert family.usage_history == records
        assert family.usage_history is not records  # Should be a copy


class TestTokenFamilySecurityAnalytics:
    """Test token family security analytics methods."""
    
    @pytest.fixture
    def family(self):
        """Create a test token family."""
        return TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
    
    def test_get_security_metadata(self, family):
        """Test getting security metadata."""
        metadata = family.get_security_metadata()
        
        assert metadata["family_id"] == family.family_id
        assert metadata["user_id"] == family.user_id
        assert metadata["status"] == TokenFamilyStatus.ACTIVE.value
        assert metadata["security_score"] == 1.0
        assert metadata["active_tokens_count"] == 0
        assert metadata["revoked_tokens_count"] == 0
        assert metadata["usage_history_count"] == 0
        assert metadata["compromise_reason"] is None
    
    def test_get_security_metadata_with_data(self, family):
        """Test getting security metadata with data."""
        token_id = TokenId.generate()
        family.add_token(token_id)
        family.revoke_token(token_id)
        family.compromise_family("Test compromise")
        
        metadata = family.get_security_metadata()
        
        assert metadata["status"] == TokenFamilyStatus.COMPROMISED.value
        assert metadata["security_score"] == 0.0
        assert metadata["active_tokens_count"] == 0
        assert metadata["revoked_tokens_count"] == 1
        assert metadata["usage_history_count"] == 2
        assert metadata["compromise_reason"] == "Test compromise"
    
    def test_get_usage_pattern_analysis_empty(self, family):
        """Test usage pattern analysis with empty history."""
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["total_events"] == 0
        assert analysis["suspicious_activity"] is False
        assert analysis["risk_level"] == "low"
        assert analysis["warnings"] == []
    
    def test_get_usage_pattern_analysis_high_frequency(self, family):
        """Test usage pattern analysis with high frequency usage."""
        # Add many tokens to create high frequency usage
        for i in range(6):
            token_id = TokenId.generate()
            family.add_token(token_id)
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["total_events"] == 6
        assert analysis["suspicious_activity"] is True
        assert analysis["risk_level"] == "medium"
        assert "high_frequency_usage" in analysis["warnings"]
    
    def test_get_usage_pattern_analysis_reuse_detection(self, family):
        """Test usage pattern analysis with reuse detection."""
        token_id = TokenId.generate()
        security_context = SecurityContext.create_for_request(
            client_ip="192.168.1.1",
            user_agent="Test Agent"
        )
        
        family.add_token(token_id)
        family.revoke_token(token_id)
        family.use_token(token_id, security_context)  # This triggers reuse detection
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["suspicious_activity"] is True
        assert analysis["risk_level"] == "critical"
        assert "reuse_detected" in analysis["warnings"]
        assert "compromise_detected" in analysis["warnings"]
    
    def test_get_usage_pattern_analysis_multiple_ips(self, family):
        """Test usage pattern analysis with multiple IPs."""
        # Create tokens with different IP addresses
        for i in range(4):
            token_id = TokenId.generate()
            security_context = SecurityContext.create_for_request(
                client_ip=f"192.168.1.{i+1}",
                user_agent="Test Agent"
            )
            family.add_token(token_id, security_context)
        
        analysis = family.get_usage_pattern_analysis()
        
        assert analysis["unique_ips_count"] == 4
        assert analysis["suspicious_activity"] is True
        assert analysis["risk_level"] == "high"
        assert "multiple_ips_detected" in analysis["warnings"]


class TestTokenFamilyEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_family_with_none_collections(self):
        """Test family creation with None collections."""
        family = TokenFamily(
            family_id=str(uuid4()),
            user_id=1,
            active_tokens=None,
            revoked_tokens=None,
            usage_history=None
        )
        
        assert family.active_tokens == []
        assert family.revoked_tokens == []
        assert family.usage_history == []
    
    def test_family_properties_return_copies(self):
        """Test that properties return copies, not references."""
        family = TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
        
        token_id = TokenId.generate()
        family.add_token(token_id)
        
        # Get property values
        active_tokens = family.active_tokens
        revoked_tokens = family.revoked_tokens
        usage_history = family.usage_history
        
        # Modify the returned lists
        active_tokens.append(TokenId.generate())
        revoked_tokens.append(TokenId.generate())
        usage_history.append(TokenUsageRecord(
            token_id=TokenId.generate(),
            event_type=TokenUsageEvent.USED,
            timestamp=datetime.now(timezone.utc)
        ))
        
        # Original family should be unchanged
        assert len(family.active_tokens) == 1
        assert len(family.revoked_tokens) == 0
        assert len(family.usage_history) == 1
    
    def test_family_immutable_status_enum_property(self):
        """Test that status_enum property returns correct value."""
        family = TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
        
        assert family.status_enum == TokenFamilyStatus.ACTIVE
        
        family.compromise_family("Test")
        assert family.status_enum == TokenFamilyStatus.COMPROMISED
    
    @patch('src.domain.entities.token_family.datetime')
    def test_family_uses_consistent_timestamps(self, mock_datetime):
        """Test that family uses consistent timestamps."""
        fixed_time = datetime.now(timezone.utc)
        mock_datetime.now.return_value = fixed_time
        
        family = TokenFamily(
            family_id=str(uuid4()),
            user_id=1
        )
        
        token_id = TokenId.generate()
        family.add_token(token_id)
        
        assert family.last_used_at == fixed_time
        assert family.usage_history[0].timestamp == fixed_time