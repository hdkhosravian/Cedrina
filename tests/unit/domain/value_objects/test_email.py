"""Tests for the Email value object.

This module contains comprehensive tests for the Email value object,
ensuring it properly validates email addresses according to business rules
and handles edge cases in production scenarios.
"""

import pytest
from src.domain.value_objects.email import Email


class TestEmail:
    """Test cases for Email value object."""

    def test_valid_email_creation(self):
        """Test creating a valid email address."""
        # Arrange
        valid_email = "user@example.com"
        
        # Act
        email = Email(value=valid_email)
        
        # Assert
        assert email.value == "user@example.com"  # Normalized to lowercase
        assert email.domain == "example.com"
        assert email.local_part == "user"

    def test_email_immutability(self):
        """Test that email is immutable."""
        # Arrange
        email = Email(value="user@example.com")
        
        # Act & Assert
        with pytest.raises(AttributeError):
            email.value = "new@example.com"  # type: ignore

    def test_email_normalization(self):
        """Test that email is normalized to lowercase."""
        # Arrange
        mixed_case_email = "User@Example.COM"
        
        # Act
        email = Email(value=mixed_case_email)
        
        # Assert
        assert email.value == "user@example.com"

    def test_email_whitespace_removal(self):
        """Test that whitespace is removed from email."""
        # Arrange
        email_with_spaces = "  user@example.com  "
        
        # Act
        email = Email(value=email_with_spaces)
        
        # Assert
        assert email.value == "user@example.com"

    def test_email_too_short(self):
        """Test email that is too short."""
        # Arrange
        short_email = "a@b"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Email length must be between 5 and 254 characters"):
            Email(value=short_email)

    def test_email_too_long(self):
        """Test email that is too long."""
        # Arrange
        long_local = "a" * 250
        long_email = f"{long_local}@example.com"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Email length must be between 5 and 254 characters"):
            Email(value=long_email)

    def test_email_invalid_format_no_at_symbol(self):
        """Test email without @ symbol."""
        # Arrange
        invalid_email = "userexample.com"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email format"):
            Email(value=invalid_email)

    def test_email_invalid_format_no_domain(self):
        """Test email with no domain."""
        # Arrange
        invalid_email = "user@"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email format"):
            Email(value=invalid_email)

    def test_email_invalid_format_no_local_part(self):
        """Test email with no local part."""
        # Arrange
        invalid_email = "@example.com"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email format"):
            Email(value=invalid_email)

    def test_email_invalid_format_invalid_characters(self):
        """Test email with invalid characters."""
        # Arrange
        invalid_email = "user name@example.com"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email format"):
            Email(value=invalid_email)

    def test_email_invalid_format_invalid_domain(self):
        """Test email with invalid domain format."""
        # Arrange
        invalid_email = "user@example"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email format"):
            Email(value=invalid_email)

    def test_email_disposable_domain_blocked(self):
        """Test that disposable email domains are blocked."""
        # Arrange
        disposable_email = "user@10minutemail.com"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Disposable email providers are not allowed"):
            Email(value=disposable_email)

    def test_email_multiple_disposable_domains_blocked(self):
        """Test that multiple disposable domains are blocked."""
        # Arrange
        disposable_domains = [
            "user@tempmail.org",
            "user@guerrillamail.com",
            "user@mailinator.com",
            "user@yopmail.com",
            "user@throwaway.email",
            "user@temp-mail.org",
            "user@getnada.com",
            "user@fakeinbox.com",
            "user@maildrop.cc",
            "user@trashmail.com",
            "user@sharklasers.com",
        ]
        
        # Act & Assert
        for email in disposable_domains:
            with pytest.raises(ValueError, match="Disposable email providers are not allowed"):
                Email(value=email)

    def test_email_non_string_value(self):
        """Test that non-string values are rejected."""
        # Arrange
        non_string_values = [123, None, [], {}, 1.5]
        
        # Act & Assert
        for value in non_string_values:
            with pytest.raises(TypeError, match="Email value must be a string"):
                Email(value=value)  # type: ignore

    def test_email_domain_property(self):
        """Test the domain property."""
        # Arrange
        email = Email(value="user@example.com")
        
        # Act & Assert
        assert email.domain == "example.com"

    def test_email_local_part_property(self):
        """Test the local_part property."""
        # Arrange
        email = Email(value="user@example.com")
        
        # Act & Assert
        assert email.local_part == "user"

    def test_email_mask_for_logging(self):
        """Test email masking for logging."""
        # Arrange
        email = Email(value="user@example.com")
        
        # Act
        masked = email.mask_for_logging()
        
        # Assert
        assert masked == "us**@e*********m"

    def test_email_mask_for_logging_short_local(self):
        """Test email masking with short local part."""
        # Arrange
        email = Email(value="a@example.com")
        
        # Act
        masked = email.mask_for_logging()
        
        # Assert
        assert masked == "a@e*********m"

    def test_email_mask_for_logging_short_domain(self):
        """Test email masking with short domain."""
        # Arrange
        email = Email(value="user@ab.com")
        
        # Act
        masked = email.mask_for_logging()
        
        # Assert
        assert masked == "us**@a****m"

    def test_email_is_common_provider_true(self):
        """Test common provider detection for known providers."""
        # Arrange
        common_providers = [
            "user@gmail.com",
            "user@yahoo.com",
            "user@hotmail.com",
            "user@outlook.com",
            "user@icloud.com",
        ]
        
        # Act & Assert
        for email_str in common_providers:
            email = Email(value=email_str)
            assert email.is_common_provider() is True

    def test_email_is_common_provider_false(self):
        """Test common provider detection for non-common providers."""
        # Arrange
        non_common_providers = [
            "user@example.com",
            "user@company.org",
            "user@custom-domain.net",
        ]
        
        # Act & Assert
        for email_str in non_common_providers:
            email = Email(value=email_str)
            assert email.is_common_provider() is False

    def test_email_equality(self):
        """Test email equality based on value."""
        # Arrange
        email1 = Email(value="user@example.com")
        email2 = Email(value="user@example.com")
        email3 = Email(value="different@example.com")
        
        # Act & Assert
        assert email1 == email2
        assert email1 != email3
        assert email1 != "user@example.com"  # Different type

    def test_email_hash(self):
        """Test email hash based on value."""
        # Arrange
        email1 = Email(value="user@example.com")
        email2 = Email(value="user@example.com")
        email3 = Email(value="different@example.com")
        
        # Act & Assert
        assert hash(email1) == hash(email2)
        assert hash(email1) != hash(email3)

    def test_email_string_representation(self):
        """Test email string representation."""
        # Arrange
        email = Email(value="user@example.com")
        
        # Act & Assert
        assert str(email) == "user@example.com"

    def test_email_minimum_valid_length(self):
        """Test email with minimum valid length."""
        # Arrange
        min_length_email = "a@b.co"
        
        # Act
        email = Email(value=min_length_email)
        
        # Assert
        assert email.value == "a@b.co"

    def test_email_maximum_valid_length(self):
        """Test email with maximum valid length."""
        # Arrange
        # Create email with exactly 254 characters
        # RFC 5321: local part max 64 chars, domain max 253 chars, total max 254
        local_part = "a" * 64
        domain = "b" * 185 + ".com"  # 185 + 4 = 189 chars for domain
        max_length_email = f"{local_part}@{domain}"
        
        # Act
        email = Email(value=max_length_email)
        
        # Assert
        assert len(email.value) == 254

    def test_email_complex_local_part(self):
        """Test email with complex local part (dots, plus, etc.)."""
        # Arrange
        complex_emails = [
            "user.name@example.com",
            "user+tag@example.com",
            "user-name@example.com",
            "user_name@example.com",
            "user123@example.com",
        ]
        
        # Act & Assert
        for email_str in complex_emails:
            email = Email(value=email_str)
            assert email.value == email_str.lower()

    def test_email_complex_domain(self):
        """Test email with complex domain."""
        # Arrange
        complex_domains = [
            "user@sub.example.com",
            "user@example.co.uk",
            "user@example-domain.com",
        ]
        
        # Act & Assert
        for email_str in complex_domains:
            email = Email(value=email_str)
            assert email.value == email_str.lower()

    def test_email_edge_case_special_characters(self):
        """Test email with special characters in local part."""
        # Arrange
        special_char_emails = [
            "user%test@example.com",
            "user.test@example.com",
            "user-test@example.com",
        ]
        
        # Act & Assert
        for email_str in special_char_emails:
            email = Email(value=email_str)
            assert email.value == email_str.lower()

    def test_email_case_insensitive_equality(self):
        """Test that email equality is case-insensitive after normalization."""
        # Arrange
        email1 = Email(value="User@Example.COM")
        email2 = Email(value="user@example.com")
        
        # Act & Assert
        assert email1 == email2
        assert hash(email1) == hash(email2)

    def test_email_whitespace_normalization(self):
        """Test that whitespace is properly handled."""
        # Arrange
        email_with_whitespace = "  user@example.com  "
        
        # Act
        email = Email(value=email_with_whitespace)
        
        # Assert
        assert email.value == "user@example.com"

    def test_email_production_scenario_high_volume(self):
        """Test email validation under high-volume scenario simulation."""
        # Arrange
        valid_emails = [
            "user1@example.com",
            "user2@company.org",
            "admin@test.net",
            "support@service.co.uk",
        ]
        
        # Act & Assert - Simulate high-volume processing
        for i in range(100):  # Simulate 100 email validations
            for email_str in valid_emails:
                email = Email(value=email_str)
                assert email.value == email_str.lower()
                assert email.domain == email_str.split("@")[1]
                assert email.local_part == email_str.split("@")[0]

    def test_email_production_scenario_malformed_inputs(self):
        """Test email validation with various malformed inputs."""
        # Arrange
        malformed_inputs = [
            "user",  # No @
            "@example.com",  # No local part
            "user@",  # No domain
            "user@example",  # No TLD
            "user name@example.com",  # Space in local part
            "user@example com",  # Space in domain
            "user@@example.com",  # Double @
        ]
        
        # Act & Assert
        for malformed_input in malformed_inputs:
            with pytest.raises((ValueError, TypeError)):
                Email(value=malformed_input)

    def test_email_security_logging_masking(self):
        """Test that email masking provides security for logging."""
        # Arrange
        test_emails = [
            ("user@example.com", "us**@e*********m"),
            ("admin@company.org", "ad***@c*********g"),
            ("test@domain.net", "te**@d********t"),
        ]
        
        # Act & Assert
        for email_str, expected_mask in test_emails:
            email = Email(value=email_str)
            masked = email.mask_for_logging()
            assert masked == expected_mask
            # Ensure original email is not exposed in masked version
            assert email_str not in masked 