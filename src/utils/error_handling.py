"""Error handling utilities for the application.

This module provides standardized error handling utilities following clean code
principles and eliminating duplication across the codebase.
"""

import structlog
from typing import Any, Dict, Optional
from functools import wraps
import asyncio

logger = structlog.get_logger(__name__)


def log_error_with_context(
    error: Exception,
    operation: str,
    **context: Any
) -> None:
    """Log an error with standardized context and formatting.
    
    Args:
        error: The exception that occurred
        operation: Description of the operation that failed
        **context: Additional context to include in the log
    """
    logger.error(
        f"{operation} failed",
        error=str(error),
        error_type=type(error).__name__,
        **context
    )


def log_security_event(
    event_type: str,
    severity: str = "warning",
    **context: Any
) -> None:
    """Log a security-related event with standardized formatting.
    
    Args:
        event_type: Type of security event
        severity: Log severity level
        **context: Additional context to include in the log
    """
    log_method = getattr(logger, severity.lower())
    log_method(
        f"Security event: {event_type}",
        event_type=event_type,
        **context
    )


def handle_operation_error(
    operation: str,
    default_error_message: str,
    **context: Any
):
    """Decorator to standardize error handling for operations.
    
    Args:
        operation: Description of the operation
        default_error_message: Default error message if exception doesn't have one
        **context: Additional context to include in error logs
        
    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                log_error_with_context(e, operation, **context)
                # Re-raise with standardized message if needed
                if not hasattr(e, 'message') or not e.message:
                    e.message = default_error_message
                raise
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_error_with_context(e, operation, **context)
                # Re-raise with standardized message if needed
                if not hasattr(e, 'message') or not e.message:
                    e.message = default_error_message
                raise
                
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def create_error_context(
    user_id: Optional[int] = None,
    correlation_id: Optional[str] = None,
    operation: Optional[str] = None,
    **additional_context: Any
) -> Dict[str, Any]:
    """Create standardized error context for logging.
    
    Args:
        user_id: User ID if applicable
        correlation_id: Request correlation ID
        operation: Operation being performed
        **additional_context: Additional context fields
        
    Returns:
        Dict containing standardized error context
    """
    context = {}
    
    if user_id is not None:
        context["user_id"] = user_id
    
    if correlation_id is not None:
        context["correlation_id"] = correlation_id
        
    if operation is not None:
        context["operation"] = operation
        
    context.update(additional_context)
    return context 