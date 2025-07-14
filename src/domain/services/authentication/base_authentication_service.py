"""
Base Authentication Service.

This module provides shared functionality for all authentication domain services,
following advanced software engineering principles including TDD, DDD, SOLID,
Design Patterns, DRY, and Clean Code.

Key Features:
- Shared logging patterns with security context
- Standardized error handling and classification
- Common validation utilities
- Unified event publishing patterns
- Performance monitoring and metrics
- Security context management

Design Principles Applied:
- Single Responsibility: Each utility has one clear purpose
- Open/Closed: Extensible through inheritance and composition
- Liskov Substitution: All implementations are interchangeable
- Interface Segregation: Focused interfaces for specific needs
- Dependency Inversion: Depends on abstractions, not concretions
"""

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Type
from contextlib import asynccontextmanager

import structlog

from src.common.exceptions import (
    AuthenticationError,
    CedrinaError,
    ValidationError,
)
from src.common.events import IEventPublisher
from src.domain.value_objects.security_context import SecurityContext
from src.common.i18n import get_translated_message


@dataclass
class ServiceContext:
    """Context object for service operations with security metadata."""
    
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    language: str = "en"
    client_ip: str = ""
    user_agent: str = ""
    operation: str = ""
    security_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize security metadata if not provided."""
        if not self.security_metadata:
            self.security_metadata = {}


@dataclass
class ServiceMetrics:
    """Metrics tracking for service operations."""
    
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    average_response_time_ms: float = 0.0
    last_operation_time: Optional[datetime] = None
    
    def update_metrics(self, success: bool, response_time_ms: float) -> None:
        """Update service metrics."""
        self.total_operations += 1
        if success:
            self.successful_operations += 1
        else:
            self.failed_operations += 1
        
        # Update average response time
        if self.average_response_time_ms == 0.0:
            self.average_response_time_ms = response_time_ms
        else:
            self.average_response_time_ms = (
                (self.average_response_time_ms * (self.total_operations - 1) + response_time_ms) 
                / self.total_operations
            )
        
        self.last_operation_time = datetime.now(timezone.utc)


class BaseAuthenticationService(ABC):
    """Base class for all authentication domain services.
    
    This class provides shared functionality and consistent patterns
    for all authentication services, eliminating code duplication
    and ensuring maintainable, clean code.
    
    Shared Features:
    - Structured logging with security context
    - Standardized error handling and classification
    - Common validation utilities
    - Unified event publishing patterns
    - Performance monitoring and metrics
    - Security context management
    - Correlation ID handling
    """
    
    def __init__(self, event_publisher: Optional[IEventPublisher] = None):
        """Initialize base authentication service.
        
        Args:
            event_publisher: Publisher for domain events
        """
        self._event_publisher = event_publisher
        self._metrics = ServiceMetrics()
        self._logger = structlog.get_logger(self.__class__.__name__)
        
        self._logger.info(
            f"{self.__class__.__name__} initialized",
            service_type="domain_service",
            base_class="BaseAuthenticationService"
        )
    
    @asynccontextmanager
    async def _operation_context(self, context: ServiceContext):
        """Context manager for service operations with consistent logging and error handling.
        
        This context manager provides:
        - Operation timing and metrics
        - Structured logging with security context
        - Standardized error handling
        - Performance monitoring
        
        Args:
            context: Service context with operation metadata
            
        Yields:
            ServiceContext: Enhanced context with timing information
        """
        start_time = time.time()
        operation_logger = self._create_operation_logger(context)
        
        try:
            operation_logger.info(
                f"{context.operation} operation started",
                correlation_id=context.correlation_id,
                client_ip=self._mask_ip(context.client_ip),
                user_agent_length=len(context.user_agent) if context.user_agent else 0
            )
            
            yield context
            
            # Log successful completion
            response_time_ms = (time.time() - start_time) * 1000
            self._metrics.update_metrics(True, response_time_ms)
            
            operation_logger.info(
                f"{context.operation} operation completed successfully",
                correlation_id=context.correlation_id,
                response_time_ms=round(response_time_ms, 2)
            )
            
        except (AuthenticationError, ValidationError, CedrinaError) as e:
            # Log domain-specific errors
            response_time_ms = (time.time() - start_time) * 1000
            self._metrics.update_metrics(False, response_time_ms)
            
            operation_logger.warning(
                f"{context.operation} operation failed",
                correlation_id=context.correlation_id,
                error_type=type(e).__name__,
                error_message=str(e),
                response_time_ms=round(response_time_ms, 2)
            )
            raise
            
        except Exception as e:
            # Log unexpected errors
            response_time_ms = (time.time() - start_time) * 1000
            self._metrics.update_metrics(False, response_time_ms)
            
            operation_logger.error(
                f"{context.operation} operation failed with unexpected error",
                correlation_id=context.correlation_id,
                error_type=type(e).__name__,
                error_message=str(e),
                response_time_ms=round(response_time_ms, 2)
            )
            
            # Convert to domain error for consistent error handling
            raise AuthenticationError(
                get_translated_message("service_unavailable", context.language)
            ) from e
    
    def _create_operation_logger(self, context: ServiceContext) -> structlog.BoundLogger:
        """Create a bound logger with operation context.
        
        Args:
            context: Service context with operation metadata
            
        Returns:
            structlog.BoundLogger: Logger bound with operation context
        """
        return self._logger.bind(
            correlation_id=context.correlation_id,
            operation=context.operation,
            client_ip=self._mask_ip(context.client_ip),
            user_agent=self._mask_user_agent(context.user_agent),
            language=context.language
        )
    
    def _mask_ip(self, ip_address: str) -> str:
        """Mask IP address for security logging.
        
        Args:
            ip_address: IP address to mask
            
        Returns:
            str: Masked IP address
        """
        if not ip_address:
            return ""
        
        if len(ip_address) > 15:
            return ip_address[:15] + "***"
        return ip_address
    
    def _mask_user_agent(self, user_agent: str) -> str:
        """Mask user agent for security logging.
        
        Args:
            user_agent: User agent string to mask
            
        Returns:
            str: Masked user agent
        """
        if not user_agent:
            return ""
        
        if len(user_agent) > 50:
            return user_agent[:50] + "***"
        return user_agent
    
    def _create_security_context(
        self,
        client_ip: str,
        user_agent: str,
        correlation_id: str
    ) -> SecurityContext:
        """Create security context for operations.
        
        Args:
            client_ip: Client IP address
            user_agent: User agent string
            correlation_id: Request correlation ID
            
        Returns:
            SecurityContext: Security context object
        """
        return SecurityContext(
            client_ip=client_ip,
            user_agent=user_agent,
            request_timestamp=datetime.now(timezone.utc),
            correlation_id=correlation_id
        )
    
    async def _publish_domain_event(
        self,
        event: Any,
        context: ServiceContext,
        logger: structlog.BoundLogger
    ) -> None:
        """Publish domain event with consistent error handling.
        
        Args:
            event: Domain event to publish
            context: Service context
            logger: Bound logger for operation
        """
        if not self._event_publisher:
            logger.debug("No event publisher available, skipping event publication")
            return
        
        try:
            await self._event_publisher.publish(event)
            logger.debug(
                "Domain event published successfully",
                event_type=type(event).__name__,
                correlation_id=context.correlation_id
            )
        except Exception as e:
            logger.warning(
                "Failed to publish domain event",
                event_type=type(event).__name__,
                error=str(e),
                correlation_id=context.correlation_id
            )
            # Re-raise the exception for test scenarios
            raise
    
    def _validate_required_parameters(
        self,
        parameters: Dict[str, Any],
        context: ServiceContext
    ) -> None:
        """Validate required parameters with consistent error handling.
        
        Args:
            parameters: Dictionary of parameter names and values
            context: Service context
            
        Raises:
            ValueError: If any required parameter is missing or invalid
        """
        for param_name, param_value in parameters.items():
            if param_value is None:
                raise ValueError(f"{param_name} cannot be None")
            if isinstance(param_value, str) and not param_value.strip():
                raise ValueError(f"{param_name} cannot be empty")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get service metrics.
        
        Returns:
            Dict[str, Any]: Service metrics
        """
        return {
            "total_operations": self._metrics.total_operations,
            "successful_operations": self._metrics.successful_operations,
            "failed_operations": self._metrics.failed_operations,
            "success_rate": (
                self._metrics.successful_operations / self._metrics.total_operations
                if self._metrics.total_operations > 0 else 0.0
            ),
            "average_response_time_ms": round(self._metrics.average_response_time_ms, 2),
            "last_operation_time": self._metrics.last_operation_time.isoformat()
            if self._metrics.last_operation_time else None
        }
    
    @abstractmethod
    async def _validate_operation_prerequisites(
        self,
        context: ServiceContext
    ) -> None:
        """Validate operation prerequisites.
        
        This method should be implemented by subclasses to validate
        any prerequisites specific to the operation being performed.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        pass 