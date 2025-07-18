"""Tests for the OAuthUserInfo value object.

This module contains comprehensive tests for the OAuthUserInfo value object,
ensuring it properly validates OAuth user information and handles edge cases in production scenarios.
"""

from typing import Dict, Any

import pytest
from src.domain.value_objects.oauth_user_info import OAuthUserInfo
from src.domain.value_objects.email import Email


class TestOAuthUserInfo:
    """Test cases for OAuthUserInfo value object."""

    def test_valid_oauth_user_info_creation_with_sub(self):
        """Test creating a valid OAuth user info with 'sub' field."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "picture": "https://example.com/avatar.jpg",
            "locale": "en-US",
        }
        
        # Act
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Assert
        assert oauth_user_info.email.value == "user@example.com"
        assert oauth_user_info.provider_user_id == "123456789"
        assert oauth_user_info.name == "John Doe"
        assert oauth_user_info.given_name == "John"
        assert oauth_user_info.family_name == "Doe"
        assert oauth_user_info.picture == "https://example.com/avatar.jpg"
        assert oauth_user_info.locale == "en-US"

    def test_valid_oauth_user_info_creation_with_id(self):
        """Test creating a valid OAuth user info with 'id' field."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "id": "987654321",
            "name": "Jane Smith",
        }
        
        # Act
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Assert
        assert oauth_user_info.email.value == "user@example.com"
        assert oauth_user_info.provider_user_id == "987654321"
        assert oauth_user_info.name == "Jane Smith"
        assert oauth_user_info.given_name is None
        assert oauth_user_info.family_name is None
        assert oauth_user_info.picture is None
        assert oauth_user_info.locale is None

    def test_oauth_user_info_empty_data(self):
        """Test that empty user info raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth user info cannot be empty"):
            OAuthUserInfo(user_info={})

    def test_oauth_user_info_none_data(self):
        """Test that None user info raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth user info cannot be empty"):
            OAuthUserInfo(user_info=None)  # type: ignore

    def test_oauth_user_info_invalid_data_type(self):
        """Test that non-dict user info raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth user info must be a dictionary"):
            OAuthUserInfo(user_info="invalid")  # type: ignore

    def test_oauth_user_info_missing_email(self):
        """Test that missing email raises ValueError."""
        # Arrange
        user_info = {
            "sub": "123456789",
            "name": "John Doe",
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth user info must contain 'email' field"):
            OAuthUserInfo(user_info=user_info)

    def test_oauth_user_info_missing_user_id(self):
        """Test that missing user ID raises ValueError."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "name": "John Doe",
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth user info must contain 'sub' or 'id' field"):
            OAuthUserInfo(user_info=user_info)

    def test_oauth_user_info_invalid_email(self):
        """Test that invalid email raises ValueError."""
        # Arrange
        user_info = {
            "email": "invalid-email",
            "sub": "123456789",
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email in OAuth user info"):
            OAuthUserInfo(user_info=user_info)

    def test_oauth_user_info_get_display_name_with_name(self):
        """Test get_display_name when name is available."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
            "given_name": "John",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act
        display_name = oauth_user_info.get_display_name()
        
        # Assert
        assert display_name == "John Doe"

    def test_oauth_user_info_get_display_name_with_given_name(self):
        """Test get_display_name when only given_name is available."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "given_name": "John",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act
        display_name = oauth_user_info.get_display_name()
        
        # Assert
        assert display_name == "John"

    def test_oauth_user_info_get_display_name_with_email(self):
        """Test get_display_name when only email is available."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act
        display_name = oauth_user_info.get_display_name()
        
        # Assert
        assert display_name == "user@example.com"

    def test_oauth_user_info_to_dict(self):
        """Test to_dict method."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "picture": "https://example.com/avatar.jpg",
            "locale": "en-US",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act
        result = oauth_user_info.to_dict()
        
        # Assert
        assert result == user_info
        assert result is not user_info  # Should be a copy

    def test_oauth_user_info_mask_for_logging(self):
        """Test mask_for_logging method."""
        # Arrange
        user_info = {
            "email": "very_long_email@example.com",
            "sub": "very_long_user_id_123456789",
            "name": "Very Long User Name",
            "given_name": "Very Long Given Name",
            "family_name": "Very Long Family Name",
            "picture": "https://example.com/avatar.jpg",
            "locale": "en-US",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act
        masked = oauth_user_info.mask_for_logging()
        
        # Assert
        assert "very_long_email@example.com" not in masked["email"]
        assert "very_long_user_id_123456789" not in masked["provider_user_id"]
        assert "Very Long User Name" not in masked["name"]
        assert "Very Long Given Name" not in masked["given_name"]
        assert "Very Long Family Name" not in masked["family_name"]
        assert masked["has_picture"] is True
        assert masked["locale"] == "en-US"

    def test_oauth_user_info_string_representation(self):
        """Test string representation."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act & Assert
        assert "OAuthUserInfo" in str(oauth_user_info)
        assert "user@example.com" in str(oauth_user_info)
        assert "123456789" in str(oauth_user_info)

    def test_oauth_user_info_repr_representation(self):
        """Test repr representation."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act & Assert
        assert "OAuthUserInfo" in repr(oauth_user_info)
        assert "user@example.com" in repr(oauth_user_info)
        assert "123456789" in repr(oauth_user_info)

    def test_oauth_user_info_equality(self):
        """Test OAuth user info equality."""
        # Arrange
        user_info1 = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        user_info2 = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        user_info3 = {
            "email": "different@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        
        # Act
        oauth_user_info1 = OAuthUserInfo(user_info=user_info1)
        oauth_user_info2 = OAuthUserInfo(user_info=user_info2)
        oauth_user_info3 = OAuthUserInfo(user_info=user_info3)
        
        # Assert
        assert oauth_user_info1 == oauth_user_info2
        assert oauth_user_info1 != oauth_user_info3
        assert oauth_user_info1 != "invalid"  # Different type

    def test_oauth_user_info_hash(self):
        """Test OAuth user info hash."""
        # Arrange
        user_info1 = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        user_info2 = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        user_info3 = {
            "email": "different@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        
        # Act
        oauth_user_info1 = OAuthUserInfo(user_info=user_info1)
        oauth_user_info2 = OAuthUserInfo(user_info=user_info2)
        oauth_user_info3 = OAuthUserInfo(user_info=user_info3)
        
        # Assert
        assert hash(oauth_user_info1) == hash(oauth_user_info2)
        assert hash(oauth_user_info1) != hash(oauth_user_info3)

    def test_oauth_user_info_create_safe(self):
        """Test create_safe class method."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        
        # Act
        oauth_user_info = OAuthUserInfo.create_safe(user_info=user_info)
        
        # Assert
        assert oauth_user_info.email.value == "user@example.com"
        assert oauth_user_info.provider_user_id == "123456789"
        assert oauth_user_info.name == "John Doe"

    def test_oauth_user_info_create_safe_invalid(self):
        """Test create_safe class method with invalid data."""
        # Act & Assert
        with pytest.raises(ValueError, match="OAuth user info cannot be empty"):
            OAuthUserInfo.create_safe(user_info={})

    def test_oauth_user_info_production_scenario_high_volume(self):
        """Test OAuth user info creation under high-volume scenario simulation."""
        # Act & Assert - Simulate high-volume processing
        user_infos = []
        for i in range(50):  # Simulate 50 user info creations
            user_info = {
                "email": f"user{i}@example.com",
                "sub": f"user_id_{i}",
                "name": f"User {i}",
            }
            oauth_user_info = OAuthUserInfo(user_info=user_info)
            user_infos.append(oauth_user_info)
            assert oauth_user_info.email.value == f"user{i}@example.com"
            assert oauth_user_info.provider_user_id == f"user_id_{i}"
            assert oauth_user_info.name == f"User {i}"
        
        # All user infos should be valid
        for user_info in user_infos:
            assert isinstance(user_info, OAuthUserInfo)
            assert user_info.email is not None
            assert user_info.provider_user_id is not None

    def test_oauth_user_info_production_scenario_mixed_providers(self):
        """Test OAuth user info creation with mixed provider formats."""
        # Arrange
        user_info_configs = [
            # Google format
            {
                "user_info": {
                    "email": "user@example.com",
                    "sub": "google_user_id_123",
                    "name": "John Doe",
                    "given_name": "John",
                    "family_name": "Doe",
                    "picture": "https://google.com/avatar.jpg",
                    "locale": "en-US",
                },
                "expected_email": "user@example.com",
                "expected_id": "google_user_id_123",
            },
            # Microsoft format
            {
                "user_info": {
                    "email": "user@microsoft.com",
                    "id": "microsoft_user_id_456",
                    "name": "Jane Smith",
                },
                "expected_email": "user@microsoft.com",
                "expected_id": "microsoft_user_id_456",
            },
            # Facebook format
            {
                "user_info": {
                    "email": "user@facebook.com",
                    "id": "facebook_user_id_789",
                    "name": "Bob Johnson",
                    "picture": "https://facebook.com/avatar.jpg",
                },
                "expected_email": "user@facebook.com",
                "expected_id": "facebook_user_id_789",
            },
        ]
        
        # Act & Assert
        for config in user_info_configs:
            oauth_user_info = OAuthUserInfo(user_info=config["user_info"])
            assert oauth_user_info.email.value == config["expected_email"]
            assert oauth_user_info.provider_user_id == config["expected_id"]

    def test_oauth_user_info_security_logging_masking(self):
        """Test that user info masking provides security for logging."""
        # Arrange
        user_info = {
            "email": "very_sensitive_email@example.com",
            "sub": "very_sensitive_user_id_123456789",
            "name": "Very Sensitive User Name",
            "given_name": "Very Sensitive Given Name",
            "family_name": "Very Sensitive Family Name",
            "picture": "https://example.com/avatar.jpg",
            "locale": "en-US",
        }
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Act
        masked = oauth_user_info.mask_for_logging()
        
        # Assert
        # Ensure sensitive data is masked
        assert "very_sensitive_email@example.com" not in masked["email"]
        assert "very_sensitive_user_id_123456789" not in masked["provider_user_id"]
        assert "Very Sensitive User Name" not in masked["name"]
        assert "Very Sensitive Given Name" not in masked["given_name"]
        assert "Very Sensitive Family Name" not in masked["family_name"]
        
        # Ensure non-sensitive data is preserved
        assert masked["has_picture"] is True
        assert masked["locale"] == "en-US"

    def test_oauth_user_info_edge_case_empty_strings(self):
        """Test OAuth user info with empty string values."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "",
            "given_name": "",
            "family_name": "",
            "picture": "",
            "locale": "",
        }
        
        # Act
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Assert
        assert oauth_user_info.name == ""
        assert oauth_user_info.given_name == ""
        assert oauth_user_info.family_name == ""
        assert oauth_user_info.picture == ""
        assert oauth_user_info.locale == ""

    def test_oauth_user_info_edge_case_none_values(self):
        """Test OAuth user info with None values for optional fields."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": None,
            "given_name": None,
            "family_name": None,
            "picture": None,
            "locale": None,
        }
        
        # Act
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Assert
        assert oauth_user_info.name is None
        assert oauth_user_info.given_name is None
        assert oauth_user_info.family_name is None
        assert oauth_user_info.picture is None
        assert oauth_user_info.locale is None

    def test_oauth_user_info_immutability(self):
        """Test that OAuth user info data is immutable."""
        # Arrange
        original_user_info = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        oauth_user_info = OAuthUserInfo(user_info=original_user_info)
        
        # Act
        returned_dict = oauth_user_info.to_dict()
        
        # Assert
        assert returned_dict == original_user_info
        assert returned_dict is not original_user_info  # Should be a copy
        
        # Modifying the returned dict should not affect the original
        returned_dict["name"] = "Modified Name"
        assert oauth_user_info.name == "John Doe"

    def test_oauth_user_info_hash_consistency(self):
        """Test that hash values are consistent for same user infos."""
        # Arrange
        user_info1 = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        user_info2 = {
            "email": "user@example.com",
            "sub": "123456789",
            "name": "John Doe",
        }
        
        # Act
        oauth_user_info1 = OAuthUserInfo(user_info=user_info1)
        oauth_user_info2 = OAuthUserInfo(user_info=user_info2)
        
        # Assert
        assert hash(oauth_user_info1) == hash(oauth_user_info2)
        
        # Hash should be consistent across multiple calls
        assert hash(oauth_user_info1) == hash(oauth_user_info1)
        assert hash(oauth_user_info2) == hash(oauth_user_info2)

    def test_oauth_user_info_email_normalization(self):
        """Test that email is properly normalized."""
        # Arrange
        user_info = {
            "email": "USER@EXAMPLE.COM",  # Uppercase email
            "sub": "123456789",
        }
        
        # Act
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Assert
        assert oauth_user_info.email.value == "user@example.com"  # Should be lowercase

    def test_oauth_user_info_provider_user_id_conversion(self):
        """Test that provider user ID is converted to string."""
        # Arrange
        user_info = {
            "email": "user@example.com",
            "sub": 123456789,  # Integer ID
        }
        
        # Act
        oauth_user_info = OAuthUserInfo(user_info=user_info)
        
        # Assert
        assert oauth_user_info.provider_user_id == "123456789"  # Should be string
        assert isinstance(oauth_user_info.provider_user_id, str) 