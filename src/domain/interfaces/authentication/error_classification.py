"""Error Classification Interface.

This module defines the interface for error classification services following
Domain-Driven Design principles and dependency inversion.

Key DDD Principles Applied:
- Single Responsibility: Handles only error classification logic
- Ubiquitous Language: Method names reflect error classification concepts
- Dependency Inversion: Abstracts error classification strategies
- Fail-Safe Security: Implements secure error handling and logging
"""

from abc import ABC, abstractmethod

from src.common.exceptions import CedrinaError


class IErrorClassificationService(ABC):
    """Interface for error classification services.
    
    This interface defines the contract for services that classify errors
    and convert them to appropriate domain exceptions. It provides a
    centralized mechanism for error handling and security monitoring.
    
    DDD Principles:
    - Single Responsibility: Handles only error classification operations
    - Ubiquitous Language: Method names reflect error classification concepts
    - Domain Events: Publishes error classification events for monitoring
    - Fail-Safe Security: Implements secure error handling and logging
    """
    
    @abstractmethod
    def classify_error(self, error: Exception) -> CedrinaError:
        """Classify an error using the appropriate strategy.
        
        This method analyzes the provided exception and converts it to
        an appropriate domain exception that aligns with the ubiquitous
        language and business requirements.
        
        Args:
            error: The exception to classify
            
        Returns:
            CedrinaError: Appropriate domain exception
            
        Raises:
            ClassificationError: If error classification fails
        """
        raise NotImplementedError 