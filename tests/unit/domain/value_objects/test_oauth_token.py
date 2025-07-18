"""Tests for the OAuthToken value object.

This module contains comprehensive tests for the OAuthToken value object,
ensuring it properly validates OAuth tokens and handles edge cases in production scenarios.
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any

import pytest
from src.domain.value_objects.oauth_token import OAuthToken


class TestOAuthToken:
    """Test cases for OAuthToken value object."""

    def test_valid_oauth_token_creation(self):
        """Test creating a valid OAuth token."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,  # 1 hour from now
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token = OAuthToken(token_data=token_data)
        
        # Assert
        assert oauth_token.access_token == "valid_access_token_123"
        assert oauth_token.expires_at == current_time + 3600
        assert oauth_token.token_type == "Bearer"
        assert oauth_token.id_token is None
        assert oauth_token.refresh_token is None

    def test_oauth_token_with_all_fields(self):
        """Test creating OAuth token with all optional fields."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "id_token": "valid_id_token_456",
            "refresh_token": "valid_refresh_token_789",
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token = OAuthToken(token_data=token_data)
        
        # Assert
        assert oauth_token.access_token == "valid_access_token_123"
        assert oauth_token.id_token == "valid_id_token_456"
        assert oauth_token.refresh_token == "valid_refresh_token_789"
        assert oauth_token.token_type == "Bearer"
        assert oauth_token.has_id_token() is True
        assert oauth_token.has_refresh_token() is True

    def test_oauth_token_empty_data(self):
        """Test that empty token data raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth token data cannot be empty"):
            OAuthToken(token_data={})

    def test_oauth_token_none_data(self):
        """Test that None token data raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth token data cannot be empty"):
            OAuthToken(token_data=None)  # type: ignore

    def test_oauth_token_invalid_data_type(self):
        """Test that non-dict token data raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth token data must be a dictionary"):
            OAuthToken(token_data="invalid")  # type: ignore

    def test_oauth_token_missing_access_token(self):
        """Test that missing access_token raises ValueError."""
        # Arrange
        current_time = time.time()
        token_data = {
            "expires_at": current_time + 3600,
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth token must contain 'access_token' field"):
            OAuthToken(token_data=token_data)

    def test_oauth_token_missing_expires_at(self):
        """Test that missing expires_at raises ValueError."""
        # Arrange
        token_data = {
            "access_token": "valid_access_token_123",
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth token must contain 'expires_at' field"):
            OAuthToken(token_data=token_data)

    def test_oauth_token_invalid_access_token(self):
        """Test that invalid access_token raises ValueError."""
        # Arrange
        current_time = time.time()
        invalid_access_tokens = [
            None,
            "",
            123,
            [],
        ]
        
        # Act & Assert
        for invalid_token in invalid_access_tokens:
            token_data = {
                "access_token": invalid_token,
                "expires_at": current_time + 3600,
            }
            with pytest.raises(ValueError, match="OAuth access token must be a non-empty string"):
                OAuthToken(token_data=token_data)

    def test_oauth_token_invalid_expires_at(self):
        """Test that invalid expires_at raises ValueError."""
        # Arrange
        invalid_expires_at = [
            "invalid",
            None,
            [],
            {},
        ]
        
        # Act & Assert
        for invalid_expiry in invalid_expires_at:
            token_data = {
                "access_token": "valid_access_token_123",
                "expires_at": invalid_expiry,
            }
            with pytest.raises(ValueError, match="OAuth token 'expires_at' must be a numeric timestamp"):
                OAuthToken(token_data=token_data)

    def test_oauth_token_expired(self):
        """Test that expired token raises ValueError."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time - 3600,  # 1 hour ago
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth token has expired"):
            OAuthToken(token_data=token_data)

    def test_oauth_token_default_token_type(self):
        """Test that default token type is 'Bearer'."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
        }
        
        # Act
        oauth_token = OAuthToken(token_data=token_data)
        
        # Assert
        assert oauth_token.token_type == "Bearer"

    def test_oauth_token_is_expired(self):
        """Test is_expired method."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act & Assert
        assert oauth_token.is_expired(current_time=current_time - 1) is False  # Not expired
        assert oauth_token.is_expired(current_time=current_time + 7200) is True  # Expired
        assert oauth_token.is_expired() is False  # Uses current time

    def test_oauth_token_time_until_expiry(self):
        """Test time_until_expiry method."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act & Assert
        assert oauth_token.time_until_expiry(current_time=current_time) == 3600
        assert oauth_token.time_until_expiry(current_time=current_time + 7200) == -3600  # Expired
        assert oauth_token.time_until_expiry() > 0  # Uses current time

    def test_oauth_token_has_id_token(self):
        """Test has_id_token method."""
        # Arrange
        current_time = time.time()
        token_data_with_id = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "id_token": "valid_id_token_456",
        }
        token_data_without_id = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
        }
        
        # Act
        oauth_token_with_id = OAuthToken(token_data=token_data_with_id)
        oauth_token_without_id = OAuthToken(token_data=token_data_without_id)
        
        # Assert
        assert oauth_token_with_id.has_id_token() is True
        assert oauth_token_without_id.has_id_token() is False

    def test_oauth_token_has_refresh_token(self):
        """Test has_refresh_token method."""
        # Arrange
        current_time = time.time()
        token_data_with_refresh = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "refresh_token": "valid_refresh_token_789",
        }
        token_data_without_refresh = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
        }
        
        # Act
        oauth_token_with_refresh = OAuthToken(token_data=token_data_with_refresh)
        oauth_token_without_refresh = OAuthToken(token_data=token_data_without_refresh)
        
        # Assert
        assert oauth_token_with_refresh.has_refresh_token() is True
        assert oauth_token_without_refresh.has_refresh_token() is False

    def test_oauth_token_to_dict(self):
        """Test to_dict method."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "id_token": "valid_id_token_456",
            "refresh_token": "valid_refresh_token_789",
            "token_type": "Bearer",
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act
        result = oauth_token.to_dict()
        
        # Assert
        assert result == token_data
        assert result is not token_data  # Should be a copy

    def test_oauth_token_expires_at_datetime(self):
        """Test expires_at_datetime property."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act
        expires_datetime = oauth_token.expires_at_datetime
        
        # Assert
        assert isinstance(expires_datetime, datetime)
        assert expires_datetime.tzinfo == timezone.utc
        # Use approximate comparison for floating-point precision
        assert abs(expires_datetime.timestamp() - (current_time + 3600)) < 0.1

    def test_oauth_token_mask_for_logging(self):
        """Test mask_for_logging method."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "very_long_access_token_123456789",
            "expires_at": current_time + 3600,
            "id_token": "very_long_id_token_456789012",
            "refresh_token": "very_long_refresh_token_789012345",
            "token_type": "Bearer",
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act
        masked = oauth_token.mask_for_logging()
        
        # Assert
        assert masked["access_token"] == "very_long_***"
        assert masked["id_token"] == "very_long_***"
        assert masked["refresh_token"] == "very_long_***"
        assert masked["token_type"] == "Bearer"
        assert masked["expires_at"] == current_time + 3600

    def test_oauth_token_string_representation(self):
        """Test string representation."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act & Assert
        assert str(oauth_token) == f"OAuthToken(type=Bearer, expires_at={current_time + 3600})"

    def test_oauth_token_repr_representation(self):
        """Test repr representation."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "very_long_access_token_123456789",
            "expires_at": current_time + 3600,
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act & Assert
        assert repr(oauth_token) == f"OAuthToken(access_token='very_long_***', expires_at={current_time + 3600})"

    def test_oauth_token_equality(self):
        """Test OAuth token equality."""
        # Arrange
        current_time = time.time()
        token_data1 = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        token_data2 = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        token_data3 = {
            "access_token": "different_access_token_456",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token1 = OAuthToken(token_data=token_data1)
        oauth_token2 = OAuthToken(token_data=token_data2)
        oauth_token3 = OAuthToken(token_data=token_data3)
        
        # Assert
        assert oauth_token1 == oauth_token2
        assert oauth_token1 != oauth_token3
        assert oauth_token1 != "invalid"  # Different type

    def test_oauth_token_hash(self):
        """Test OAuth token hash."""
        # Arrange
        current_time = time.time()
        token_data1 = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        token_data2 = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        token_data3 = {
            "access_token": "different_access_token_456",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token1 = OAuthToken(token_data=token_data1)
        oauth_token2 = OAuthToken(token_data=token_data2)
        oauth_token3 = OAuthToken(token_data=token_data3)
        
        # Assert
        assert hash(oauth_token1) == hash(oauth_token2)
        assert hash(oauth_token1) != hash(oauth_token3)

    def test_oauth_token_create_safe(self):
        """Test create_safe class method."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token = OAuthToken.create_safe(token_data=token_data)
        
        # Assert
        assert oauth_token.access_token == "valid_access_token_123"
        assert oauth_token.expires_at == current_time + 3600

    def test_oauth_token_create_safe_invalid(self):
        """Test create_safe class method with invalid data."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth token data cannot be empty"):
            OAuthToken.create_safe(token_data={})

    def test_oauth_token_production_scenario_high_volume(self):
        """Test OAuth token creation under high-volume scenario simulation."""
        # Act & Assert - Simulate high-volume processing
        current_time = time.time()
        tokens = []
        for i in range(50):  # Simulate 50 token creations
            token_data = {
                "access_token": f"valid_access_token_{i}",
                "expires_at": current_time + 3600 + i,
                "token_type": "Bearer",
            }
            oauth_token = OAuthToken(token_data=token_data)
            tokens.append(oauth_token)
            assert oauth_token.access_token == f"valid_access_token_{i}"
            assert oauth_token.expires_at == current_time + 3600 + i
            assert oauth_token.is_expired() is False
        
        # All tokens should be valid
        for token in tokens:
            assert isinstance(token, OAuthToken)
            assert token.access_token is not None
            assert token.expires_at > current_time

    def test_oauth_token_production_scenario_expiry_handling(self):
        """Test OAuth token expiry handling in production scenarios."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act & Assert
        # Token should not be expired now
        assert oauth_token.is_expired(current_time=current_time) is False
        assert oauth_token.time_until_expiry(current_time=current_time) == 3600
        
        # Token should be expired in the future
        assert oauth_token.is_expired(current_time=current_time + 7200) is True
        assert oauth_token.time_until_expiry(current_time=current_time + 7200) == -3600

    def test_oauth_token_security_logging_masking(self):
        """Test that token masking provides security for logging."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "very_sensitive_access_token_123456789",
            "expires_at": current_time + 3600,
            "id_token": "very_sensitive_id_token_456789012",
            "refresh_token": "very_sensitive_refresh_token_789012345",
            "token_type": "Bearer",
        }
        oauth_token = OAuthToken(token_data=token_data)
        
        # Act
        masked = oauth_token.mask_for_logging()
        
        # Assert
        # Ensure sensitive data is masked
        assert "very_sensitive_access_token_123456789" not in masked["access_token"]
        assert "very_sensitive_id_token_456789012" not in masked["id_token"]
        assert "very_sensitive_refresh_token_789012345" not in masked["refresh_token"]
        
        # Ensure non-sensitive data is preserved
        assert masked["token_type"] == "Bearer"
        assert masked["expires_at"] == current_time + 3600

    def test_oauth_token_edge_case_empty_strings(self):
        """Test OAuth token with empty string values."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "id_token": "",
            "refresh_token": "",
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token = OAuthToken(token_data=token_data)
        
        # Assert
        assert oauth_token.id_token == ""
        assert oauth_token.refresh_token == ""
        assert oauth_token.has_id_token() is False
        assert oauth_token.has_refresh_token() is False

    def test_oauth_token_edge_case_none_values(self):
        """Test OAuth token with None values for optional fields."""
        # Arrange
        current_time = time.time()
        token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "id_token": None,
            "refresh_token": None,
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token = OAuthToken(token_data=token_data)
        
        # Assert
        assert oauth_token.id_token is None
        assert oauth_token.refresh_token is None
        assert oauth_token.has_id_token() is False
        assert oauth_token.has_refresh_token() is False

    def test_oauth_token_immutability(self):
        """Test that OAuth token data is immutable."""
        # Arrange
        current_time = time.time()
        original_token_data = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        oauth_token = OAuthToken(token_data=original_token_data)
        
        # Act
        returned_dict = oauth_token.to_dict()
        
        # Assert
        assert returned_dict == original_token_data
        assert returned_dict is not original_token_data  # Should be a copy
        
        # Modifying the returned dict should not affect the original
        returned_dict["access_token"] = "modified_token"
        assert oauth_token.access_token == "valid_access_token_123"

    def test_oauth_token_hash_consistency(self):
        """Test that hash values are consistent for same tokens."""
        # Arrange
        current_time = time.time()
        token_data1 = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        token_data2 = {
            "access_token": "valid_access_token_123",
            "expires_at": current_time + 3600,
            "token_type": "Bearer",
        }
        
        # Act
        oauth_token1 = OAuthToken(token_data=token_data1)
        oauth_token2 = OAuthToken(token_data=token_data2)
        
        # Assert
        assert hash(oauth_token1) == hash(oauth_token2)
        
        # Hash should be consistent across multiple calls
        assert hash(oauth_token1) == hash(oauth_token1)
        assert hash(oauth_token2) == hash(oauth_token2) 