"""Base Infrastructure Service.

This module provides a base class for infrastructure services to eliminate
code duplication and ensure consistent patterns across all services.

Key Features:
- Common logging patterns with structured logging
- Standardized error handling and conversion
- Configuration loading utilities
- Service initialization patterns
- Security context handling
"""

import structlog
from abc import ABC
from typing import Optional, Any, Dict

from src.core.config.settings import settings
from src.common.exceptions import AuthenticationError
from src.domain.value_objects.security_context import SecurityContext
from src.common.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class BaseInfrastructureService(ABC):
    """
    Base class for infrastructure services providing common functionality.
    
    This base class eliminates code duplication across infrastructure services
    by providing common patterns for:
    - Structured logging with service context
    - Standardized error handling and conversion
    - Configuration loading and validation
    - Security context processing
    - Service initialization patterns
    
    All infrastructure services should inherit from this base class to ensure
    consistency and reduce duplication.
    """
    
    def __init__(self, service_name: str, **kwargs):
        """
        Initialize base infrastructure service.
        
        Args:
            service_name: Name of the service for logging context
            **kwargs: Additional initialization parameters
        """
        self._service_name = service_name
        self._logger = logger.bind(service=service_name)
        
        # Log service initialization
        log_kwargs = dict(kwargs)
        if "service_type" not in log_kwargs:
            log_kwargs["service_type"] = "infrastructure_service"
        self._logger.info(
            f"{service_name} initialized",
            **log_kwargs
        )
    
    def _log_operation(self, operation: str, **context) -> structlog.BoundLogger:
        """
        Create a bound logger for operation-specific logging.
        
        Args:
            operation: Name of the operation being logged
            **context: Additional context for the operation
            
        Returns:
            structlog.BoundLogger: Logger bound with operation context
        """
        return self._logger.bind(
            operation=operation,
            service=self._service_name,
            **context
        )
    
    def _handle_infrastructure_error(
        self,
        error: Exception,
        operation: str,
        user_id: Optional[int] = None,
        correlation_id: Optional[str] = None,
        language: str = "en"
    ) -> AuthenticationError:
        """
        Handle infrastructure errors and convert to domain exceptions.
        
        Args:
            error: Original exception
            operation: Name of the operation that failed
            user_id: Optional user ID for context
            correlation_id: Optional correlation ID for tracing
            language: Language for error messages
            
        Returns:
            AuthenticationError: Converted domain exception
        """
        operation_logger = self._log_operation(
            operation,
            user_id=user_id,
            correlation_id=correlation_id
        )
        
        operation_logger.error(
            "Infrastructure error occurred",
            error_type=type(error).__name__,
            error_message=str(error),
            user_id=user_id,
            correlation_id=correlation_id
        )
        
        # Convert to domain exception with translated message
        return AuthenticationError(
            get_translated_message(f"{operation}_infrastructure_error", language)
        )
    
    def _validate_security_context(
        self,
        security_context: SecurityContext,
        operation: str
    ) -> None:
        """
        Validate security context for operations.
        
        Args:
            security_context: Security context to validate
            operation: Name of the operation for logging
            
        Raises:
            ValueError: If security context is invalid
        """
        if not security_context:
            raise ValueError("Security context is required")
        
        operation_logger = self._log_operation(operation)
        operation_logger.debug(
            "Security context validated",
            client_ip=security_context.client_ip,
            user_agent=security_context.user_agent[:50] + "..." if security_context.user_agent else None,
            correlation_id=security_context.correlation_id
        )
    
    def _get_config_value(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with fallback.
        
        Args:
            key: Configuration key to retrieve
            default: Default value if key not found
            
        Returns:
            Any: Configuration value or default
        """
        return getattr(settings, key, default)
    
    def _mask_sensitive_data(self, data: str, visible_chars: int = 3) -> str:
        """
        Mask sensitive data for logging.
        
        Args:
            data: Data to mask
            visible_chars: Number of characters to keep visible
            
        Returns:
            str: Masked data safe for logging
        """
        if not data or len(data) <= visible_chars * 2:
            return "***"
        
        return data[:visible_chars] + "***" + data[-visible_chars:]
    
    def _log_success(
        self,
        operation: str,
        user_id: Optional[int] = None,
        correlation_id: Optional[str] = None,
        **context
    ) -> None:
        """
        Log successful operation completion.
        
        Args:
            operation: Name of the completed operation
            user_id: Optional user ID for context
            correlation_id: Optional correlation ID for tracing
            **context: Additional context for logging
        """
        operation_logger = self._log_operation(
            operation,
            user_id=user_id,
            correlation_id=correlation_id
        )
        
        operation_logger.info(
            f"{operation} completed successfully",
            user_id=user_id,
            correlation_id=correlation_id,
            **context
        )
    
    def _log_warning(
        self,
        operation: str,
        message: str,
        user_id: Optional[int] = None,
        correlation_id: Optional[str] = None,
        **context
    ) -> None:
        """
        Log warning message.
        
        Args:
            operation: Name of the operation
            message: Warning message
            user_id: Optional user ID for context
            correlation_id: Optional correlation ID for tracing
            **context: Additional context for logging
        """
        operation_logger = self._log_operation(
            operation,
            user_id=user_id,
            correlation_id=correlation_id
        )
        
        operation_logger.warning(
            message,
            user_id=user_id,
            correlation_id=correlation_id,
            **context
        ) 