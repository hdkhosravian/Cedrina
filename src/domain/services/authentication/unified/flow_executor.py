"""Authentication Flow Executor for Unified Authentication Service.

This module contains the authentication flow executor that centralizes
common authentication flow patterns to eliminate DRY violations and
ensure consistent behavior across different authentication methods.
"""

import structlog
from typing import Callable, Awaitable, Any

from src.common.exceptions import AuthenticationError
from src.common.i18n import get_translated_message
from .context import AuthenticationContext

logger = structlog.get_logger(__name__)


class AuthenticationFlowExecutor:
    """Executes authentication flows with consistent error handling and metrics.
    
    This class centralizes the common authentication flow pattern to eliminate
    DRY violations and ensure consistent behavior across different authentication
    methods.
    
    Responsibilities:
    - Execute authentication functions with error handling
    - Update authentication metrics
    - Provide consistent logging and security monitoring
    - Handle unexpected errors gracefully
    """
    
    def __init__(self, secure_logger, error_standardizer):
        """Initialize authentication flow executor.
        
        Args:
            secure_logger: Secure logging service
            error_standardizer: Error standardization service
        """
        self._secure_logger = secure_logger
        self._error_standardizer = error_standardizer
    
    async def execute(
        self,
        authentication_func: Callable[[], Awaitable[Any]],
        context: AuthenticationContext,
        request_start_time: float,
        oauth: bool = False
    ) -> Any:
        """Execute authentication flow with consistent error handling and metrics.
        
        Args:
            authentication_func: Function that performs the actual authentication
            context: Authentication context with security metadata
            request_start_time: When the request started for timing
            oauth: Whether this is an OAuth authentication
            
        Returns:
            Result from authentication_func
            
        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            # Execute the authentication function
            result = await authentication_func()
            return result
            
        except AuthenticationError:
            # Re-raise authentication errors
            raise
        except Exception as e:
            # Handle unexpected errors
            logger.error(
                "Unexpected authentication error",
                error=str(e),
                correlation_id=context.correlation_id,
                oauth=oauth
            )
            raise AuthenticationError(
                get_translated_message("authentication_error", context.language)
            ) 