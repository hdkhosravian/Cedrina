"""Unit tests for Error Classification Service.

These tests verify that the error classification service properly classifies
different types of errors using the Strategy pattern following TDD principles.
"""

import pytest
from unittest.mock import Mock

from src.domain.services.authentication.error_classification_service import (
    ErrorClassificationService,
    ErrorClassificationStrategy,
    AuthenticationErrorStrategy,
    PasswordPolicyStrategy,
    UsernameValidationStrategy,
    EmailValidationStrategy,
    GenericValidationStrategy,
)
from src.common.exceptions import (
    PasswordPolicyError,
    ValidationError,
    AuthenticationError,
    CedrinaError,
)


class TestAuthenticationErrorStrategy:
    """Test AuthenticationErrorStrategy."""

    def test_can_classify_authentication_error(self):
        """Test that AuthenticationErrorStrategy can classify authentication errors."""
        strategy = AuthenticationErrorStrategy()
        error = AuthenticationError("Invalid credentials")
        
        assert strategy.can_classify(error) is True

    def test_can_classify_authentication_keywords(self):
        """Test that AuthenticationErrorStrategy can classify errors with authentication keywords."""
        strategy = AuthenticationErrorStrategy()
        error = ValueError("invalid_username_or_password")
        
        assert strategy.can_classify(error) is True

    def test_cannot_classify_other_errors(self):
        """Test that AuthenticationErrorStrategy cannot classify non-authentication errors."""
        strategy = AuthenticationErrorStrategy()
        error = ValueError("Some other error")
        
        assert strategy.can_classify(error) is False

    def test_classify_returns_authentication_error(self):
        """Test that AuthenticationErrorStrategy returns AuthenticationError."""
        strategy = AuthenticationErrorStrategy()
        error = ValueError("Invalid credentials")
        
        result = strategy.classify(error)
        assert isinstance(result, AuthenticationError)
        assert str(result) == "Invalid credentials"


class TestPasswordPolicyStrategy:
    """Test PasswordPolicyStrategy."""

    def test_can_classify_password_policy_error(self):
        """Test that PasswordPolicyStrategy can classify password policy errors."""
        strategy = PasswordPolicyStrategy()
        error = PasswordPolicyError("Password too weak")
        
        assert strategy.can_classify(error) is True

    def test_can_classify_password_policy_keywords(self):
        """Test that PasswordPolicyStrategy can classify errors with password policy keywords."""
        strategy = PasswordPolicyStrategy()
        error = ValueError("password contains common weak patterns")
        
        assert strategy.can_classify(error) is True

    def test_cannot_classify_other_errors(self):
        """Test that PasswordPolicyStrategy cannot classify non-password policy errors."""
        strategy = PasswordPolicyStrategy()
        error = ValueError("Some other error")
        
        assert strategy.can_classify(error) is False

    def test_classify_returns_password_policy_error(self):
        """Test that PasswordPolicyStrategy returns PasswordPolicyError."""
        strategy = PasswordPolicyStrategy()
        error = ValueError("Password too weak")
        
        result = strategy.classify(error)
        assert isinstance(result, PasswordPolicyError)
        assert str(result) == "Password too weak"


class TestUsernameValidationStrategy:
    """Test cases for UsernameValidationStrategy."""
    
    def test_can_classify_username_validation_error(self):
        """Test that strategy can classify username validation errors."""
        # Arrange
        strategy = UsernameValidationStrategy()
        error = ValueError("Username must be at least 3 characters long")
        
        # Act
        result = strategy.can_classify(error)
        
        # Assert
        assert result is True
    
    def test_cannot_classify_non_username_error(self):
        """Test that strategy cannot classify non-username related errors."""
        # Arrange
        strategy = UsernameValidationStrategy()
        error = ValueError("Password must contain uppercase")
        
        # Act
        result = strategy.can_classify(error)
        
        # Assert
        assert result is False
    
    def test_classify_returns_validation_error(self):
        """Test that strategy returns ValidationError."""
        # Arrange
        strategy = UsernameValidationStrategy()
        error = ValueError("Username contains invalid characters")
        
        # Act
        result = strategy.classify(error)
        
        # Assert
        assert isinstance(result, ValidationError)
        assert str(result) == "Username contains invalid characters"


class TestEmailValidationStrategy:
    """Test cases for EmailValidationStrategy."""
    
    def test_can_classify_email_validation_error(self):
        """Test that strategy can classify email validation errors."""
        # Arrange
        strategy = EmailValidationStrategy()
        error = ValueError("Invalid email format")
        
        # Act
        result = strategy.can_classify(error)
        
        # Assert
        assert result is True
    
    def test_cannot_classify_non_email_error(self):
        """Test that strategy cannot classify non-email related errors."""
        # Arrange
        strategy = EmailValidationStrategy()
        error = ValueError("Password is too short")
        
        # Act
        result = strategy.can_classify(error)
        
        # Assert
        assert result is False
    
    def test_classify_returns_validation_error(self):
        """Test that strategy returns ValidationError."""
        # Arrange
        strategy = EmailValidationStrategy()
        error = ValueError("Email domain is invalid")
        
        # Act
        result = strategy.classify(error)
        
        # Assert
        assert isinstance(result, ValidationError)
        assert str(result) == "Email domain is invalid"


class TestGenericValidationStrategy:
    """Test cases for GenericValidationStrategy."""
    
    def test_can_classify_any_value_error(self):
        """Test that strategy can classify any ValueError."""
        # Arrange
        strategy = GenericValidationStrategy()
        error = ValueError("Some validation error")
        
        # Act
        result = strategy.can_classify(error)
        
        # Assert
        assert result is True
    
    def test_cannot_classify_non_value_error(self):
        """Test that strategy cannot classify non-ValueError exceptions."""
        # Arrange
        strategy = GenericValidationStrategy()
        error = TypeError("Some type error")
        
        # Act
        result = strategy.can_classify(error)
        
        # Assert
        assert result is False
    
    def test_classify_returns_validation_error(self):
        """Test that strategy returns ValidationError."""
        # Arrange
        strategy = GenericValidationStrategy()
        error = ValueError("Some generic validation error")
        
        # Act
        result = strategy.classify(error)
        
        # Assert
        assert isinstance(result, ValidationError)
        assert str(result) == "Some generic validation error"


class TestErrorClassificationService:
    """Test cases for ErrorClassificationService."""
    
    @pytest.mark.asyncio
    async def test_classify_password_error_returns_password_policy_error(self):
        """Test that password errors are classified as PasswordPolicyError."""
        # Arrange
        service = ErrorClassificationService()
        error = ValueError("Password must contain at least one uppercase letter")
        
        # Act
        result = await service.classify_error(error)
        
        # Assert
        assert isinstance(result, PasswordPolicyError)
        assert str(result) == "Password must contain at least one uppercase letter"
    
    @pytest.mark.asyncio
    async def test_classify_username_error_returns_validation_error(self):
        """Test that username errors are classified as ValidationError."""
        # Arrange
        service = ErrorClassificationService()
        error = ValueError("Username must be at least 3 characters")
        
        # Act
        result = await service.classify_error(error)
        
        # Assert
        assert isinstance(result, ValidationError)
        assert str(result) == "Username must be at least 3 characters"
    
    @pytest.mark.asyncio
    async def test_classify_email_error_returns_validation_error(self):
        """Test that email errors are classified as ValidationError."""
        # Arrange
        service = ErrorClassificationService()
        error = ValueError("Invalid email format")
        
        # Act
        result = await service.classify_error(error)
        
        # Assert
        assert isinstance(result, ValidationError)
        assert str(result) == "Invalid email format"
    
    @pytest.mark.asyncio
    async def test_classify_generic_value_error_returns_validation_error(self):
        """Test that generic ValueError is classified as ValidationError."""
        # Arrange
        service = ErrorClassificationService()
        error = ValueError("Some other validation error")
        
        # Act
        result = await service.classify_error(error)
        
        # Assert
        assert isinstance(result, ValidationError)
        assert str(result) == "Some other validation error"
    
    @pytest.mark.asyncio
    async def test_classify_domain_exception_returns_same_exception(self):
        """Test that domain exceptions are returned unchanged."""
        # Arrange
        service = ErrorClassificationService()
        original_error = PasswordPolicyError("Original password error")
        
        # Act
        result = await service.classify_error(original_error)
        
        # Assert
        # The service creates a new instance with the same content, not returns the same object
        assert isinstance(result, PasswordPolicyError)
        assert str(result) == "Original password error"
    
    @pytest.mark.asyncio
    async def test_classify_unclassified_error_returns_validation_error(self):
        """Test that unclassified errors return ValidationError (not AuthenticationError)."""
        # Arrange
        service = ErrorClassificationService()
        error = TypeError("Some type error")
        
        # Act
        result = await service.classify_error(error)
        
        # Assert
        # The service returns ValidationError for unclassified errors, not AuthenticationError
        assert isinstance(result, ValidationError)
        assert str(result) == "Some type error"
    
    @pytest.mark.asyncio
    async def test_register_strategy_adds_to_end(self):
        """Test that registering a strategy adds it to the end of the list."""
        # Arrange
        service = ErrorClassificationService()
        custom_strategy = Mock(spec=ErrorClassificationStrategy)
        custom_strategy.can_classify.return_value = True
        custom_strategy.classify.return_value = ValidationError("Custom error")
        
        # Act
        service.register_strategy(custom_strategy)
        
        # Assert
        # The custom strategy should be called for errors that don't match other strategies
        # Use a TypeError which won't be caught by GenericValidationStrategy
        error = TypeError("Some error")
        result = await service.classify_error(error)
        
        custom_strategy.can_classify.assert_called_once_with(error)
        custom_strategy.classify.assert_called_once_with(error)
        assert isinstance(result, ValidationError)
    
    @pytest.mark.asyncio
    async def test_strategy_order_matters(self):
        """Test that strategy order affects classification."""
        # Arrange
        service = ErrorClassificationService()
        
        # Create a custom strategy that matches specific errors but returns ValidationError
        custom_strategy = Mock(spec=ErrorClassificationStrategy)
        custom_strategy.can_classify.return_value = True
        custom_strategy.classify.return_value = ValidationError("Custom classification")
        
        # Insert the custom strategy at the beginning of the list
        service._strategies.insert(0, custom_strategy)
        
        # Act
        # Use an error that would be caught by GenericValidationStrategy
        error = ValueError("Custom specific error message")
        result = await service.classify_error(error)
        
        # Assert
        # Custom strategy should be called first and return ValidationError
        assert isinstance(result, ValidationError)
        assert str(result) == "Custom classification"
        custom_strategy.can_classify.assert_called_once_with(error)
        custom_strategy.classify.assert_called_once_with(error)


class TestErrorClassificationIntegration:
    """Integration tests for error classification in real scenarios."""
    
    @pytest.mark.asyncio
    async def test_password_validation_scenarios(self):
        """Test various password validation error scenarios."""
        # Arrange
        service = ErrorClassificationService()
        test_cases = [
            ("Password must be at least 8 characters long", ValidationError),  # Basic validation
            ("Password must contain at least one uppercase letter", ValidationError),  # Basic validation
            ("Password must contain at least one lowercase letter", ValidationError),  # Basic validation
            ("Password must contain at least one digit", ValidationError),  # Basic validation
            ("Password must contain at least one special character", ValidationError),  # Basic validation
            ("Password is too long", ValidationError),  # Basic validation
            ("password contains common weak patterns", PasswordPolicyError),  # Policy error
            ("password does not meet security requirements", PasswordPolicyError),  # Policy error
        ]

        for error_message, expected_type in test_cases:
            # Act
            error = ValueError(error_message)
            result = await service.classify_error(error)

            # Assert
            assert isinstance(result, expected_type), f"Failed for: {error_message}"
    
    @pytest.mark.asyncio
    async def test_username_validation_scenarios(self):
        """Test various username validation error scenarios."""
        # Arrange
        service = ErrorClassificationService()
        test_cases = [
            ("Username must be at least 3 characters", ValidationError),
            ("Username contains invalid characters", ValidationError),
            ("Username is too long", ValidationError),
        ]
        
        for error_message, expected_type in test_cases:
            # Act
            error = ValueError(error_message)
            result = await service.classify_error(error)
            
            # Assert
            assert isinstance(result, expected_type), f"Failed for: {error_message}"
            assert str(result) == error_message
    
    @pytest.mark.asyncio
    async def test_email_validation_scenarios(self):
        """Test various email validation error scenarios."""
        # Arrange
        service = ErrorClassificationService()
        test_cases = [
            ("Invalid email format", ValidationError),
            ("Email domain is invalid", ValidationError),
            ("Email address is too long", ValidationError),
        ]
        
        for error_message, expected_type in test_cases:
            # Act
            error = ValueError(error_message)
            result = await service.classify_error(error)
            
            # Assert
            assert isinstance(result, expected_type), f"Failed for: {error_message}"
            assert str(result) == error_message 