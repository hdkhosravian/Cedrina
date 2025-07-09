"""Error Classification Interface.

This module defines the interface for error classification services following
Domain-Driven Design principles and dependency inversion.
"""

from abc import ABC, abstractmethod

from src.core.exceptions import CedrinaError


class IErrorClassificationService(ABC):
    """Interface for error classification services.
    
    This interface defines the contract for services that classify errors
    and convert them to appropriate domain exceptions.
    """
    
    @abstractmethod
    def classify_error(self, error: Exception) -> CedrinaError:
        """Classify an error using the appropriate strategy.
        
        Args:
            error: The exception to classify
            
        Returns:
            CedrinaError: Appropriate domain exception
        """
        raise NotImplementedError 