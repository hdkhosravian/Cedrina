"""Error Classification Domain Service.

This service handles the classification of domain errors following Domain-Driven Design
principles. It uses the Strategy pattern to classify different types of errors and
convert them to appropriate domain exceptions.

Key DDD Principles Applied:
- Single Responsibility: Only handles error classification
- Strategy Pattern: Different classification strategies for different error types
- Domain Language: Uses ubiquitous language for error types
- Dependency Inversion: Depends on abstractions, not concretions
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Type
import structlog

from src.core.exceptions import (
    AuthenticationError,
    PasswordPolicyError,
    ValidationError,
    CedrinaError
)

logger = structlog.get_logger(__name__)


class ErrorClassificationStrategy(ABC):
    """Abstract base class for error classification strategies."""
    
    @abstractmethod
    def can_classify(self, error: Exception) -> bool:
        """Check if this strategy can classify the given error."""
        pass
    
    @abstractmethod
    def classify(self, error: Exception) -> CedrinaError:
        """Classify the error into an appropriate domain exception."""
        pass


class AuthenticationErrorStrategy(ErrorClassificationStrategy):
    """Strategy for classifying authentication errors."""
    
    AUTHENTICATION_KEYWORDS = [
        "invalid_username_or_password", "invalid credentials", "authentication failed",
        "user not found", "account inactive", "email confirmation required",
        "invalid_credentials", "authentication_system_error"
    ]
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is an authentication error."""
        if isinstance(error, AuthenticationError):
            return True
        
        if not isinstance(error, ValueError):
            return False
        
        error_message = str(error).lower()
        return any(keyword in error_message for keyword in self.AUTHENTICATION_KEYWORDS)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as AuthenticationError."""
        return AuthenticationError(str(error))


class PasswordPolicyStrategy(ErrorClassificationStrategy):
    """Strategy for classifying password policy errors (registration/password change)."""
    
    PASSWORD_POLICY_KEYWORDS = [
        "password contains common weak patterns", "password does not meet security requirements",
        "password must contain", "password length", "password complexity",
        "uppercase", "lowercase", "digit", "special character", "minimum length"
    ]
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is a password policy error."""
        if isinstance(error, PasswordPolicyError):
            return True
        
        if not isinstance(error, ValueError):
            return False
        
        error_message = str(error).lower()
        # Only classify as password policy if it's specifically about password requirements
        return any(keyword in error_message for keyword in self.PASSWORD_POLICY_KEYWORDS)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as PasswordPolicyError."""
        return PasswordPolicyError(str(error))


class UsernameValidationStrategy(ErrorClassificationStrategy):
    """Strategy for classifying username validation errors."""
    
    USERNAME_KEYWORDS = [
        "username", "length", "characters", "invalid", "format"
    ]
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is a username validation error."""
        if not isinstance(error, ValueError):
            return False
        
        error_message = str(error).lower()
        return any(keyword in error_message for keyword in self.USERNAME_KEYWORDS)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as ValidationError."""
        return ValidationError(str(error))


class EmailValidationStrategy(ErrorClassificationStrategy):
    """Strategy for classifying email validation errors."""
    
    EMAIL_KEYWORDS = [
        "email", "format", "invalid", "domain", "address"
    ]
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is an email validation error."""
        if not isinstance(error, ValueError):
            return False
        
        error_message = str(error).lower()
        return any(keyword in error_message for keyword in self.EMAIL_KEYWORDS)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as ValidationError."""
        return ValidationError(str(error))


class GenericValidationStrategy(ErrorClassificationStrategy):
    """Strategy for classifying generic validation errors."""
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is a generic validation error."""
        return isinstance(error, ValueError)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as ValidationError."""
        return ValidationError(str(error))


class ErrorClassificationService:
    """Domain service for classifying errors using Strategy pattern.
    
    This service follows the Strategy pattern to classify different types of errors
    and convert them to appropriate domain exceptions. It maintains a registry of
    classification strategies and applies them in order of specificity.
    """
    
    def __init__(self):
        """Initialize with classification strategies."""
        self._strategies: List[ErrorClassificationStrategy] = [
            AuthenticationErrorStrategy(),  # Highest priority - check authentication first
            PasswordPolicyStrategy(),       # Check password policy errors
            UsernameValidationStrategy(),
            EmailValidationStrategy(),
            GenericValidationStrategy(),
        ]
    
    def classify_error(self, error: Exception) -> CedrinaError:
        """Classify an error using the appropriate strategy.
        
        Args:
            error: The exception to classify
            
        Returns:
            CedrinaError: Appropriate domain exception
            
        Raises:
            AuthenticationError: If no strategy can classify the error
        """
        # If it's already a domain exception, return it
        if isinstance(error, CedrinaError):
            return error
        
        # Try to find a strategy that can classify this error
        for strategy in self._strategies:
            if strategy.can_classify(error):
                classified_error = strategy.classify(error)
                logger.debug(
                    "Error classified",
                    original_error_type=type(error).__name__,
                    classified_error_type=type(classified_error).__name__,
                    strategy_type=type(strategy).__name__
                )
                return classified_error
        
        # If no strategy can classify it, log and return generic error
        logger.warning(
            "Unclassified error",
            error_type=type(error).__name__,
            error_message=str(error)
        )
        return AuthenticationError(str(error))
    
    def register_strategy(self, strategy: ErrorClassificationStrategy) -> None:
        """Register a new classification strategy.
        
        Args:
            strategy: The strategy to register
        """
        self._strategies.insert(0, strategy)  # Insert at beginning for priority
        logger.debug(
            "Error classification strategy registered",
            strategy_type=type(strategy).__name__
        ) 