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

from src.common.exceptions import (
    AuthenticationError,
    PasswordPolicyError,
    ValidationError,
    CedrinaError,
    DuplicateUserError,
    InvalidOldPasswordError,
    PasswordReuseError,
    RateLimitExceededError,  # <-- Add import
)

from .base_authentication_service import BaseAuthenticationService, ServiceContext

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


class DuplicateUserStrategy(ErrorClassificationStrategy):
    """Strategy for classifying duplicate user errors."""
    
    DUPLICATE_USER_KEYWORDS = [
        "already exists", "already registered", "duplicate", "username already", 
        "email already", "user already exists", "already in use"
    ]
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is a duplicate user error."""
        if isinstance(error, DuplicateUserError):
            return True
        
        if not isinstance(error, ValueError):
            return False
        
        error_message = str(error).lower()
        return any(keyword in error_message for keyword in self.DUPLICATE_USER_KEYWORDS)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as DuplicateUserError."""
        return DuplicateUserError(str(error))


class InvalidOldPasswordStrategy(ErrorClassificationStrategy):
    """Strategy for classifying invalid old password errors."""
    
    INVALID_OLD_PASSWORD_KEYWORDS = [
        "old password", "current password", "incorrect password", "wrong password",
        "invalid old password", "password verification failed"
    ]
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is an invalid old password error."""
        if isinstance(error, InvalidOldPasswordError):
            return True
        
        if not isinstance(error, ValueError):
            return False
        
        error_message = str(error).lower()
        return any(keyword in error_message for keyword in self.INVALID_OLD_PASSWORD_KEYWORDS)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as InvalidOldPasswordError."""
        return InvalidOldPasswordError(str(error))


class PasswordReuseStrategy(ErrorClassificationStrategy):
    """Strategy for classifying password reuse errors."""
    
    PASSWORD_REUSE_KEYWORDS = [
        "password reuse", "same password", "reuse password", "password already used",
        "cannot reuse", "password must be different"
    ]
    
    def can_classify(self, error: Exception) -> bool:
        """Check if this is a password reuse error."""
        if isinstance(error, PasswordReuseError):
            return True
        
        if not isinstance(error, ValueError):
            return False
        
        error_message = str(error).lower()
        return any(keyword in error_message for keyword in self.PASSWORD_REUSE_KEYWORDS)
    
    def classify(self, error: Exception) -> CedrinaError:
        """Classify as PasswordReuseError."""
        return PasswordReuseError(str(error))


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


class RateLimitExceededStrategy(ErrorClassificationStrategy):
    """Strategy for classifying rate limit exceeded errors."""
    def can_classify(self, error: Exception) -> bool:
        return isinstance(error, RateLimitExceededError)
    def classify(self, error: Exception) -> CedrinaError:
        return RateLimitExceededError(str(error))


class ErrorClassificationService(BaseAuthenticationService):
    """Domain service for classifying errors using Strategy pattern.
    
    This service follows the Strategy pattern to classify different types of errors
    and convert them to appropriate domain exceptions. It maintains a registry of
    classification strategies and applies them in order of specificity.
    """
    
    def __init__(self, event_publisher=None):
        """Initialize with classification strategies."""
        super().__init__(event_publisher)
        
        self._strategies: List[ErrorClassificationStrategy] = [
            RateLimitExceededStrategy(),   # Highest priority for rate limit errors
            DuplicateUserStrategy(),      # Highest priority - check duplicate user first
            InvalidOldPasswordStrategy(), # Check invalid old password errors
            PasswordReuseStrategy(),      # Check password reuse errors
            AuthenticationErrorStrategy(), # Check authentication errors
            PasswordPolicyStrategy(),     # Check password policy errors
            UsernameValidationStrategy(),
            EmailValidationStrategy(),
            GenericValidationStrategy(),
        ]
    
    async def classify_error(
        self, 
        error: Exception, 
        language: str = "en",
        correlation_id: str = ""
    ) -> CedrinaError:
        """Classify an error using the appropriate strategy.
        
        Args:
            error: The exception to classify
            language: Language code for error messages
            correlation_id: Request correlation ID for tracking
            
        Returns:
            CedrinaError: Appropriate domain exception
            
        Raises:
            ValueError: If error is None
        """
        context = ServiceContext(
            correlation_id=correlation_id,
            language=language,
            operation="error_classification"
        )
        
        async with self._operation_context(context) as ctx:
            # Validate input
            if error is None:
                raise ValueError("Error cannot be None")
            
            # Find appropriate strategy
            for strategy in self._strategies:
                if strategy.can_classify(error):
                    classified_error = strategy.classify(error)
                    
                    logger.debug(
                        "Error classified successfully",
                        original_error_type=type(error).__name__,
                        classified_error_type=type(classified_error).__name__,
                        correlation_id=ctx.correlation_id
                    )
                    
                    return classified_error
            
            # If no strategy matches, return generic validation error
            logger.warning(
                "No classification strategy found for error",
                error_type=type(error).__name__,
                error_message=str(error),
                correlation_id=ctx.correlation_id
            )
            
            return ValidationError(str(error))
    
    def register_strategy(self, strategy: ErrorClassificationStrategy) -> None:
        """Register a new classification strategy.
        
        Args:
            strategy: Error classification strategy to register
        """
        if strategy not in self._strategies:
            self._strategies.append(strategy)
            logger.info(
                "New error classification strategy registered",
                strategy_type=type(strategy).__name__
            )
    
    async def _validate_operation_prerequisites(self, context: ServiceContext) -> None:
        """Validate operation prerequisites for error classification.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        # Error classification service has no specific prerequisites
        # All operations are valid as long as the service is initialized
        pass 