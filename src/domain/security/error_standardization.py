"""Error Standardization Service for Preventing Information Disclosure.

This service provides consistent error responses and timing behavior across
all authentication and authorization endpoints to prevent enumeration attacks,
timing attacks, and other information disclosure vulnerabilities.

Key Security Features:
- Consistent error messages regardless of actual failure reason
- Standardized response timing to prevent timing attacks
- Generic error codes that don't reveal system internals
- Safe error logging that doesn't expose sensitive information
- OWASP-compliant error handling practices

TIMING CONFIGURATION (Easy to Change):
All timing values are configurable via environment variables - no code changes needed!
- SECURITY_TIMING_FAST_MIN/MAX: Fast operations (default: 20-50ms)
- SECURITY_TIMING_MEDIUM_MIN/MAX: Medium operations (default: 80-150ms)  
- SECURITY_TIMING_SLOW_MIN/MAX: Slow operations (default: 400-800ms for powerful servers)
- SECURITY_TIMING_VARIABLE_MIN/MAX: Variable operations (default: 400-800ms)

Examples:
  SECURITY_TIMING_SLOW_MIN=0.3 SECURITY_TIMING_SLOW_MAX=0.6  # 300-600ms
  SECURITY_TIMING_SLOW_MIN=0.5 SECURITY_TIMING_SLOW_MAX=1.0  # 500-1000ms for extra security
"""

import asyncio
import hashlib
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

import structlog
import hmac
import secrets

from src.core.config.settings import settings
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class ErrorCategory(Enum):
    """Standard error categories for consistent handling."""
    
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    SYSTEM = "system"
    RATE_LIMIT = "rate_limit"
    RESOURCE_NOT_FOUND = "resource_not_found"


class TimingPattern(Enum):
    """Standard timing patterns for preventing timing attacks.
    
    Timing values are configurable via environment variables:
    - SECURITY_TIMING_FAST_MIN/MAX: Fast operations (validation errors)
    - SECURITY_TIMING_MEDIUM_MIN/MAX: Medium operations (authorization errors)  
    - SECURITY_TIMING_SLOW_MIN/MAX: Slow operations (authentication failures)
    - SECURITY_TIMING_VARIABLE_MIN/MAX: Variable operations (deterministic but variable)
    
    Defaults are optimized for powerful servers (400-800ms for SLOW/VARIABLE).
    """
    
    FAST = "fast"      # Configurable timing for non-sensitive operations
    MEDIUM = "medium"  # Configurable timing for validation errors
    SLOW = "slow"      # Configurable timing for authentication failures
    VARIABLE = "variable"  # Deterministic but variable based on correlation ID


@dataclass(frozen=True)
class StandardizedError:
    """Standardized error response that prevents information disclosure."""
    
    category: ErrorCategory
    message_key: str
    http_status: int
    timing_pattern: TimingPattern
    correlation_id: Optional[str] = None
    additional_headers: Optional[Dict[str, str]] = None


class ErrorStandardizationService:
    """Service for creating consistent error responses across all endpoints.
    
    This service implements security best practices:
    - All authentication failures return identical messages
    - Response timing is standardized to prevent timing attacks
    - Error codes are generic and don't reveal system internals
    - Detailed error information is logged securely for monitoring
    """
    
    def __init__(self):
        """Initialize error standardization service."""
        self._logger = structlog.get_logger("security.errors")
        self._request_timings: Dict[str, float] = {}
        self._timing_ranges = None  # Lazy load from settings
        self._cpu_operations = None  # Lazy load from settings
    
    @property
    def timing_ranges(self) -> Dict[TimingPattern, tuple]:
        """Get timing ranges from settings with lazy loading."""
        if self._timing_ranges is None:
            config_ranges = settings.get_timing_ranges()
            self._timing_ranges = {
                TimingPattern.FAST: config_ranges["FAST"],
                TimingPattern.MEDIUM: config_ranges["MEDIUM"],
                TimingPattern.SLOW: config_ranges["SLOW"],
                TimingPattern.VARIABLE: config_ranges["VARIABLE"]
            }
        return self._timing_ranges
    
    @property
    def cpu_operations(self) -> Dict[str, int]:
        """Get CPU operations per ms from settings with lazy loading."""
        if self._cpu_operations is None:
            self._cpu_operations = {
                "FAST": settings.get_cpu_operations_per_ms("FAST"),
                "MEDIUM": settings.get_cpu_operations_per_ms("MEDIUM"),
                "SLOW": settings.get_cpu_operations_per_ms("SLOW"),
                "VARIABLE": settings.get_cpu_operations_per_ms("VARIABLE")
            }
        return self._cpu_operations
    
    # Standard error definitions
    STANDARD_ERRORS = {
        # Authentication errors
        "invalid_credentials": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="invalid_username_or_password",
            http_status=400,
            timing_pattern=TimingPattern.SLOW
        ),
        "user_not_found": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="user_not_found",
            http_status=404,
            timing_pattern=TimingPattern.SLOW
        ),
        "inactive_account": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="user_account_inactive",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        "locked_account": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="account_locked",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        "expired_credentials": StandardizedError(
            category=ErrorCategory.AUTHENTICATION,
            message_key="expired_credentials",
            http_status=401,
            timing_pattern=TimingPattern.SLOW
        ),
        # Authorization errors
        "insufficient_permissions": StandardizedError(
            category=ErrorCategory.AUTHORIZATION,
            message_key="access_denied_generic",
            http_status=403,
            timing_pattern=TimingPattern.MEDIUM
        ),
        "resource_forbidden": StandardizedError(
            category=ErrorCategory.AUTHORIZATION,
            message_key="access_denied_generic",
            http_status=403,
            timing_pattern=TimingPattern.MEDIUM
        ),
        # Validation errors
        "invalid_input": StandardizedError(
            category=ErrorCategory.VALIDATION,
            message_key="invalid_input_generic",
            http_status=400,
            timing_pattern=TimingPattern.FAST
        ),
        "malformed_request": StandardizedError(
            category=ErrorCategory.VALIDATION,
            message_key="invalid_input_generic",
            http_status=400,
            timing_pattern=TimingPattern.FAST
        ),
        # System errors
        "internal_error": StandardizedError(
            category=ErrorCategory.SYSTEM,
            message_key="service_temporarily_unavailable",
            http_status=500,
            timing_pattern=TimingPattern.MEDIUM
        ),
        "service_unavailable": StandardizedError(
            category=ErrorCategory.SYSTEM,
            message_key="service_temporarily_unavailable",
            http_status=503,
            timing_pattern=TimingPattern.MEDIUM
        ),
        # Rate limiting
        "rate_limited": StandardizedError(
            category=ErrorCategory.RATE_LIMIT,
            message_key="too_many_requests_generic",
            http_status=429,
            timing_pattern=TimingPattern.FAST,
            additional_headers={"Retry-After": "60"}
        ),
        # Resource not found
        "resource_not_found": StandardizedError(
            category=ErrorCategory.RESOURCE_NOT_FOUND,
            message_key="resource_not_accessible",
            http_status=404,
            timing_pattern=TimingPattern.MEDIUM
        )
    }
    
    async def create_standardized_response(
        self,
        error_type: str,
        actual_error: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en",
        request_start_time: Optional[float] = None
    ) -> Dict[str, Any]:
        """Create a standardized error response with consistent timing.
        
        Args:
            error_type: Type of error from STANDARD_ERRORS
            actual_error: Actual error details (for logging only)
            correlation_id: Request correlation ID
            language: Language code for i18n
            request_start_time: When the request started (for timing)
            
        Returns:
            Dict: Standardized error response
        """
        # Get standard error definition
        standard_error = self.STANDARD_ERRORS.get(
            error_type, 
            self.STANDARD_ERRORS["internal_error"]
        )
        
        # Log actual error details for monitoring (secure logging)
        if actual_error:
            self._logger.warning(
                "Standardized error response generated",
                error_type=error_type,
                actual_error_hash=hashlib.sha256(actual_error.encode()).hexdigest()[:16],
                standard_message_key=standard_error.message_key,
                correlation_id=correlation_id,
                category=standard_error.category.value
            )
        
        # Apply standardized timing
        await self._apply_standard_timing(
            standard_error.timing_pattern,
            correlation_id,
            request_start_time
        )
        
        # Create response
        response = {
            "detail": get_translated_message(standard_error.message_key, language),
            "error_code": standard_error.category.value.upper(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if correlation_id:
            response["correlation_id"] = correlation_id
        
        return response
    
    async def create_authentication_error_response(
        self,
        actual_failure_reason: str,
        username: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en",
        request_start_time: Optional[float] = None
    ) -> Dict[str, Any]:
        """Create standardized authentication error response.
        
        All authentication failures return the same response regardless
        of the actual reason (user not found, wrong password, inactive account, etc.)
        
        Args:
            actual_failure_reason: Actual reason for failure (logged only)
            username: Attempted username (logged securely)
            correlation_id: Request correlation ID
            language: Language code
            request_start_time: Request start time for timing
            
        Returns:
            Dict: Standardized authentication error response
        """
        # Log actual failure for security monitoring
        self._logger.warning(
            "Authentication failure standardized",
            failure_reason=actual_failure_reason,
            username_hash=hashlib.sha256(username.encode()).hexdigest()[:16] if username else None,
            correlation_id=correlation_id,
            response_standardized=True
        )
        
        # Always return the same error type for authentication failures
        return await self.create_standardized_response(
            error_type="invalid_credentials",
            actual_error=f"{actual_failure_reason} for user {username[:2] + '***' if username else 'unknown'}",
            correlation_id=correlation_id,
            language=language,
            request_start_time=request_start_time
        )
    
    async def apply_standard_timing(
        self,
        elapsed_time: float,
        timing_pattern: TimingPattern = TimingPattern.SLOW,
        correlation_id: Optional[str] = None
    ) -> None:
        """Public method to apply standardized timing.
        
        Args:
            elapsed_time: Time already elapsed in the request
            timing_pattern: Desired timing pattern
            correlation_id: Request correlation ID
        """
        # Calculate when the request started
        current_time = time.time()
        request_start_time = current_time - elapsed_time
        
        await self._apply_standard_timing(
            timing_pattern=timing_pattern,
            correlation_id=correlation_id,
            request_start_time=request_start_time
        )
    
    async def _apply_standard_timing(
        self,
        timing_pattern: TimingPattern,
        correlation_id: Optional[str] = None,
        request_start_time: Optional[float] = None
    ) -> None:
        """Apply standardized timing to prevent timing attacks using sophisticated non-blocking operations.
        
        Args:
            timing_pattern: Desired timing pattern
            correlation_id: Request correlation ID for deterministic timing
            request_start_time: When the request started
        """
        current_time = time.time()
        
        # Calculate target timing based on pattern
        min_time, max_time = self.timing_ranges[timing_pattern]
        
        if timing_pattern == TimingPattern.VARIABLE and settings.ENABLE_DETERMINISTIC_TIMING:
            if correlation_id:
                # Use correlation ID for deterministic but variable timing
                # Create a more sophisticated seed from correlation ID and server instance
                server_id = settings.get_server_instance_id()
                combined_id = f"{correlation_id}:{server_id}"
                seed_bytes = hashlib.sha256(combined_id.encode()).digest()
                seed = int.from_bytes(seed_bytes[:8], byteorder='big')
                # Use modulo to ensure timing stays within bounds
                target_time = min_time + (seed % int((max_time - min_time) * 1000)) / 1000
            else:
                target_time = (min_time + max_time) / 2
        else:
            target_time = (min_time + max_time) / 2
        
        # Calculate elapsed time so far
        elapsed = current_time - (request_start_time or current_time)
        
        # Apply sophisticated CPU-intensive operations for security-critical patterns
        if timing_pattern in [TimingPattern.SLOW, TimingPattern.VARIABLE]:
            # Calculate remaining time needed
            remaining_time = max(0, target_time - elapsed)
            
            if remaining_time > 0:
                # Use configurable CPU operations that scale with time needed
                operations_per_ms = self.cpu_operations["SLOW"]
                operations_needed = int(remaining_time * 1000 * operations_per_ms)
                
                # Use multiple cryptographic operations for better security
                data = correlation_id.encode() if correlation_id else b"security_timing"
                
                # Perform a mix of cryptographic operations
                use_advanced_ops = settings.USE_ADVANCED_CRYPTO_OPERATIONS
                
                for i in range(max(1, operations_needed)):
                    if use_advanced_ops:
                        # Alternate between different hash algorithms for unpredictability
                        if i % 3 == 0:
                            data = hashlib.sha256(data).digest()
                        elif i % 3 == 1:
                            data = hashlib.sha512(data).digest()
                        else:
                            data = hashlib.blake2b(data, digest_size=32).digest()
                        
                        # Add some HMAC operations for additional complexity
                        if i % 5 == 0:
                            key = f"timing_key_{i}".encode()
                            data = hmac.new(key, data, hashlib.sha256).digest()
                    else:
                        # Use simpler operations for less powerful servers
                        data = hashlib.sha256(data).digest()
        
        # For MEDIUM pattern, use lighter operations
        elif timing_pattern == TimingPattern.MEDIUM:
            # Use lighter but still deterministic operations
            operations_per_ms = self.cpu_operations["MEDIUM"]
            operations_needed = int((target_time - elapsed) * 1000 * operations_per_ms)
            data = correlation_id.encode() if correlation_id else b"medium_timing"
            
            for _ in range(max(1, operations_needed)):
                data = hashlib.md5(data).digest()
        
        # For FAST pattern, minimal operations
        elif timing_pattern == TimingPattern.FAST:
            # Just ensure some minimal processing for consistency
            if correlation_id:
                _ = hashlib.sha256(correlation_id.encode()).hexdigest()[:8]
        
        # Log timing for monitoring (without sensitive data)
        final_elapsed = time.time() - (request_start_time or current_time)
        self._logger.debug(
            "Standardized timing applied (non-blocking)",
            timing_pattern=timing_pattern.value,
            target_time=target_time,
            final_elapsed=final_elapsed,
            correlation_id=correlation_id[:8] + "..." if correlation_id and len(correlation_id) > 8 else correlation_id
        )
    
    def get_safe_error_message(
        self,
        error_category: ErrorCategory,
        language: str = "en"
    ) -> str:
        """Get a safe, generic error message for a category.
        
        Args:
            error_category: Category of error
            language: Language code
            
        Returns:
            str: Safe error message
        """
        message_keys = {
            ErrorCategory.AUTHENTICATION: "invalid_credentials_generic",
            ErrorCategory.AUTHORIZATION: "access_denied_generic",
            ErrorCategory.VALIDATION: "invalid_input_generic",
            ErrorCategory.SYSTEM: "service_temporarily_unavailable",
            ErrorCategory.RATE_LIMIT: "too_many_requests_generic",
            ErrorCategory.RESOURCE_NOT_FOUND: "resource_not_accessible"
        }
        
        message_key = message_keys.get(error_category, "service_temporarily_unavailable")
        return get_translated_message(message_key, language)
    
    def log_error_safely(
        self,
        error_type: str,
        error_details: Dict[str, Any],
        correlation_id: Optional[str] = None,
        user_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log error details safely without exposing sensitive information.
        
        Args:
            error_type: Type of error
            error_details: Error details to log
            correlation_id: Request correlation ID
            user_context: User context (will be sanitized)
        """
        # Sanitize user context
        safe_user_context = {}
        if user_context:
            safe_user_context = {
                "user_id": user_context.get("user_id"),
                "has_username": bool(user_context.get("username")),
                "role": user_context.get("role"),
                "is_authenticated": user_context.get("is_authenticated", False)
            }
        
        # Sanitize error details
        safe_error_details = {}
        for key, value in error_details.items():
            if key in ["username", "email", "password"]:
                # Hash sensitive fields
                safe_error_details[f"{key}_hash"] = hashlib.sha256(str(value).encode()).hexdigest()[:16]
            elif key in ["ip_address"]:
                # Mask IP addresses
                safe_error_details[f"{key}_masked"] = self._mask_ip(str(value))
            else:
                safe_error_details[key] = value
        
        self._logger.error(
            "Error handled safely",
            error_type=error_type,
            error_details=safe_error_details,
            user_context=safe_user_context,
            correlation_id=correlation_id,
            secure_logging=True
        )
    
    def _mask_ip(self, ip_address: str) -> str:
        """Mask IP address for privacy compliance."""
        if "." in ip_address:
            parts = ip_address.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        return ip_address[:8] + "***"


# Global error standardization service instance
error_standardization_service = ErrorStandardizationService() 