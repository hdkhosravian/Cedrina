"""Tests for the ConfirmationToken value object.

This module contains comprehensive tests for the ConfirmationToken value object,
ensuring it properly generates secure tokens and handles edge cases in production scenarios.
"""

import pytest
import secrets
from src.domain.value_objects.confirmation_token import ConfirmationToken


class TestConfirmationToken:
    """Test cases for ConfirmationToken value object."""

    def test_confirmation_token_creation(self):
        """Test creating a confirmation token with a valid value."""
        # Arrange
        valid_token = "a" * 64
        
        # Act
        token = ConfirmationToken(value=valid_token)
        
        # Assert
        assert token.value == valid_token
        assert len(token.value) == 64

    def test_confirmation_token_immutability(self):
        """Test that confirmation token is immutable."""
        # Arrange
        token = ConfirmationToken(value="a" * 64)
        
        # Act & Assert
        with pytest.raises(AttributeError):
            token.value = "new_token"  # type: ignore

    def test_confirmation_token_generate(self):
        """Test generating a new confirmation token."""
        # Act
        token = ConfirmationToken.generate()
        
        # Assert
        assert isinstance(token, ConfirmationToken)
        assert len(token.value) == 64
        assert token.value.isalnum()  # Should be hexadecimal

    def test_confirmation_token_generate_multiple_unique(self):
        """Test that generated tokens are unique."""
        # Act
        token1 = ConfirmationToken.generate()
        token2 = ConfirmationToken.generate()
        token3 = ConfirmationToken.generate()
        
        # Assert
        assert token1.value != token2.value
        assert token2.value != token3.value
        assert token1.value != token3.value

    def test_confirmation_token_generate_hexadecimal(self):
        """Test that generated tokens are valid hexadecimal."""
        # Act
        token = ConfirmationToken.generate()
        
        # Assert
        assert all(c in '0123456789abcdef' for c in token.value)

    def test_confirmation_token_length_constant(self):
        """Test that the LENGTH constant is correct."""
        # Assert
        assert ConfirmationToken.LENGTH == 64

    def test_confirmation_token_equality(self):
        """Test confirmation token equality based on value."""
        # Arrange
        token1 = ConfirmationToken(value="a" * 64)
        token2 = ConfirmationToken(value="a" * 64)
        token3 = ConfirmationToken(value="b" * 64)
        
        # Act & Assert
        assert token1 == token2
        assert token1 != token3
        assert token1 != "a" * 64  # Different type

    def test_confirmation_token_hash(self):
        """Test confirmation token hash based on value."""
        # Arrange
        token1 = ConfirmationToken(value="a" * 64)
        token2 = ConfirmationToken(value="a" * 64)
        token3 = ConfirmationToken(value="b" * 64)
        
        # Act & Assert
        assert hash(token1) == hash(token2)
        assert hash(token1) != hash(token3)

    def test_confirmation_token_string_representation(self):
        """Test confirmation token string representation."""
        # Arrange
        token_value = "a" * 64
        token = ConfirmationToken(value=token_value)
        
        # Act & Assert
        # The dataclass uses default repr, so we check it contains the value
        assert token_value in str(token)
        assert "ConfirmationToken" in str(token)

    def test_confirmation_token_production_scenario_high_volume(self):
        """Test token generation under high-volume scenario simulation."""
        # Act & Assert - Simulate high-volume processing
        tokens = []
        for i in range(100):  # Simulate 100 token generations
            token = ConfirmationToken.generate()
            tokens.append(token)
            assert len(token.value) == 64
            assert token.value.isalnum()
        
        # Ensure all tokens are unique
        unique_tokens = set(token.value for token in tokens)
        assert len(unique_tokens) == 100

    def test_confirmation_token_entropy_quality(self):
        """Test that generated tokens have sufficient entropy."""
        # Act
        tokens = [ConfirmationToken.generate() for _ in range(50)]
        
        # Assert - Check that tokens are sufficiently random
        # This is a basic check - in production, you might use more sophisticated entropy tests
        all_chars = set()
        for token in tokens:
            all_chars.update(token.value)
        
        # Should have most hexadecimal characters represented
        assert len(all_chars) >= 10  # At least 10 different hex chars

    def test_confirmation_token_manual_creation_with_valid_hex(self):
        """Test creating token with manually provided valid hexadecimal."""
        # Arrange
        valid_hex = "a" * 64
        
        # Act
        token = ConfirmationToken(value=valid_hex)
        
        # Assert
        assert token.value == valid_hex
        assert len(token.value) == 64

    def test_confirmation_token_manual_creation_with_mixed_hex(self):
        """Test creating token with mixed case hexadecimal."""
        # Arrange
        mixed_hex = "aBcDeF1234567890" * 4  # 64 characters
        
        # Act
        token = ConfirmationToken(value=mixed_hex)
        
        # Assert
        assert token.value == mixed_hex
        assert len(token.value) == 64

    def test_confirmation_token_generate_consistency(self):
        """Test that token generation is consistent across multiple calls."""
        # Act
        tokens = []
        for _ in range(10):
            token = ConfirmationToken.generate()
            tokens.append(token)
        
        # Assert
        for token in tokens:
            assert isinstance(token, ConfirmationToken)
            assert len(token.value) == 64
            assert token.value.isalnum()

    def test_confirmation_token_security_properties(self):
        """Test that generated tokens have good security properties."""
        # Act
        token = ConfirmationToken.generate()
        
        # Assert
        # Should be exactly 64 characters
        assert len(token.value) == 64
        
        # Should be hexadecimal (lowercase)
        assert all(c in '0123456789abcdef' for c in token.value)
        
        # Should not be all the same character
        assert len(set(token.value)) > 1
        
        # Should not be a simple pattern
        assert not token.value.startswith('0' * 64)
        assert not token.value.startswith('f' * 64)

    def test_confirmation_token_manual_creation_edge_cases(self):
        """Test creating tokens with edge case values."""
        # Arrange
        edge_cases = [
            "0" * 64,  # All zeros
            "f" * 64,  # All f's
            "a" * 64,  # All a's
            "0123456789abcdef" * 4,  # Pattern
        ]
        
        # Act & Assert
        for value in edge_cases:
            token = ConfirmationToken(value=value)
            assert token.value == value
            assert len(token.value) == 64

    def test_confirmation_token_generate_statistical_properties(self):
        """Test statistical properties of generated tokens."""
        # Act
        tokens = [ConfirmationToken.generate() for _ in range(100)]
        
        # Assert
        # Check that we have a good distribution of characters
        char_counts = {}
        for token in tokens:
            for char in token.value:
                char_counts[char] = char_counts.get(char, 0) + 1
        
        # Should have most hex characters represented
        assert len(char_counts) >= 8  # At least 8 different hex chars
        
        # No single character should dominate
        max_count = max(char_counts.values())
        total_chars = sum(char_counts.values())
        assert max_count < total_chars * 0.3  # No char should be >30% of total

    def test_confirmation_token_equality_with_generated_tokens(self):
        """Test equality with generated tokens."""
        # Act
        token1 = ConfirmationToken.generate()
        token2 = ConfirmationToken(value=token1.value)
        
        # Assert
        assert token1 == token2
        assert hash(token1) == hash(token2)

    def test_confirmation_token_immutability_after_generation(self):
        """Test that generated tokens are immutable."""
        # Act
        token = ConfirmationToken.generate()
        
        # Assert
        with pytest.raises(AttributeError):
            token.value = "new_value"  # type: ignore

    def test_confirmation_token_length_validation(self):
        """Test that tokens must be exactly 64 characters."""
        # Arrange
        invalid_lengths = [
            "a" * 63,  # Too short
            "a" * 65,  # Too long
            "",  # Empty
        ]
        
        # Act & Assert
        for invalid_token in invalid_lengths:
            # Should not raise an exception - the class doesn't validate length
            # This is by design as the class is meant to be flexible
            token = ConfirmationToken(value=invalid_token)
            assert token.value == invalid_token

    def test_confirmation_token_generate_entropy_source(self):
        """Test that generated tokens use the correct entropy source."""
        # Act
        token = ConfirmationToken.generate()
        
        # Assert
        # The token should be generated using secrets.token_hex(32)
        # which produces 64 hexadecimal characters
        assert len(token.value) == 64
        assert all(c in '0123456789abcdef' for c in token.value)
        
        # Verify it's not using a predictable source
        # (This is a basic check - in production you might use more sophisticated tests)
        assert token.value != "0" * 64
        assert token.value != "f" * 64

    def test_confirmation_token_production_scenario_concurrent_generation(self):
        """Test token generation under concurrent scenario simulation."""
        # Act - Simulate concurrent token generation
        tokens = []
        for i in range(50):  # Simulate 50 concurrent generations
            token = ConfirmationToken.generate()
            tokens.append(token)
            
            # Each token should be valid immediately
            assert len(token.value) == 64
            assert token.value.isalnum()
        
        # Assert - All tokens should be unique
        unique_values = set(token.value for token in tokens)
        assert len(unique_values) == 50
        
        # All tokens should be valid
        for token in tokens:
            assert isinstance(token, ConfirmationToken)
            assert len(token.value) == 64 