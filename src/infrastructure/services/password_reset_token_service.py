"""Infrastructure implementation of Password Reset Token Service.

This service provides concrete implementation for password reset token operations,
using value objects and following clean architecture principles with enhanced security.
"""

import secrets
from datetime import datetime, timezone
from typing import Optional

from src.common.exceptions import RateLimitExceededError
from src.domain.entities.user import User
from src.domain.interfaces import IPasswordResetTokenService, IRateLimitingService
from src.domain.value_objects.reset_token import ResetToken
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.services.base_service import BaseInfrastructureService


class PasswordResetTokenService(IPasswordResetTokenService, BaseInfrastructureService):
    """Infrastructure implementation of password reset token service with enhanced security.
    
    This service handles token generation, validation, and lifecycle management
    using domain value objects and following clean code principles.
    
    Enhanced Security Features:
    - Rate limiting per email address to prevent abuse
    - Cryptographically secure token generation with unpredictable format
    - Value object-based domain modeling
    - Comprehensive error handling and logging
    - Timing attack protection
    - One-time use enforcement
    - Security metrics and monitoring
    """
    
    def __init__(
        self, 
        token_expiry_minutes: int = 5,
        rate_limiting_service: Optional[IRateLimitingService] = None
    ):
        """Initialize the token service with rate limiting.
        
        Args:
            token_expiry_minutes: Token expiration time in minutes
            rate_limiting_service: Rate limiting service for abuse prevention
        """
        super().__init__(
            service_name="PasswordResetTokenService",
            token_expiry_minutes=token_expiry_minutes,
            rate_limiting_enabled=rate_limiting_service is not None
        )
        
        self._token_expiry_minutes = token_expiry_minutes
        self._rate_limiting_service = rate_limiting_service
    
    async def generate_token(self, user: User) -> ResetToken:
        """Generate a new password reset token for the user with rate limiting.
        
        This method implements enhanced security by:
        - Checking rate limits per email address
        - Generating unpredictable tokens with mixed character sets
        - Providing comprehensive security logging
        - Following single responsibility principle
        
        Args:
            user: User entity to generate token for
            
        Returns:
            ResetToken: New secure token value object
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded for this email
        """
        operation = "generate_token"
        
        try:
            # Check rate limiting if service is available
            if self._rate_limiting_service:
                await self._check_rate_limit(user)
            
            # Log token generation (with user ID only for security)
            self._log_operation(operation).info(
                "Generating enhanced password reset token",
                user_id=user.id,
                username=user.username,
                rate_limiting_enabled=self._rate_limiting_service is not None
            )
            
            # Check if user already has an active token
            if self._has_active_token(user):
                self._log_warning(
                    operation=operation,
                    message="Replacing existing token for user",
                    user_id=user.id,
                    previous_token_prefix=user.password_reset_token[:8] if user.password_reset_token else None
                )
            
            # Generate new token using enhanced value object
            token = ResetToken.generate(expiry_minutes=self._token_expiry_minutes)
            
            # Get security metrics for monitoring
            security_metrics = token.get_security_metrics()
            
            # Update user entity with token data
            user.password_reset_token = token.value
            user.password_reset_token_expires_at = token.expires_at
            
            # Record rate limiting attempt if service is available
            if self._rate_limiting_service:
                await self._rate_limiting_service.record_attempt(user.id)
            
            self._log_success(
                operation=operation,
                user_id=user.id,
                token_prefix=token.value[:8],
                expires_at=token.expires_at.isoformat(),
                security_metrics=security_metrics,
                rate_limiting_applied=True
            )
            
            return token
            
        except RateLimitExceededError:
            # Re-raise rate limit errors
            raise
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )
    
    async def _check_rate_limit(self, user: User) -> None:
        """Check rate limit for user before generating token.
        
        Args:
            user: User entity to check rate limit for
            
        Raises:
            RateLimitExceededError: If rate limit is exceeded
        """
        if not self._rate_limiting_service:
            return
        
        try:
            is_limited = await self._rate_limiting_service.is_user_rate_limited(user.id)
            
            if is_limited:
                reset_time = await self._rate_limiting_service.get_time_until_reset(user.id)
                
                self._log_warning(
                    operation="check_rate_limit",
                    message="Rate limit exceeded for password reset token generation",
                    user_id=user.id,
                    reset_time=reset_time.isoformat() if reset_time else None
                )
                
                raise RateLimitExceededError(
                    f"Too many password reset attempts. Please try again later."
                )
                
        except RateLimitExceededError:
            # Re-raise rate limit errors
            raise
        except Exception as e:
            self._log_warning(
                operation="check_rate_limit",
                message="Error checking rate limit for token generation",
                user_id=user.id,
                error=str(e)
            )
            # Fail open for availability - don't block users due to rate limit errors
            return
    
    def validate_token(self, user: User, token: str) -> bool:
        """Validate a password reset token for the user.
        
        Args:
            user: User entity to validate token for
            token: Token string to validate
            
        Returns:
            bool: True if token is valid and not expired
        """
        operation = "validate_token"
        
        try:
            # Create token value object from stored data
            stored_token = self._create_token_from_user(user)
            if not stored_token:
                self._log_warning(
                    operation=operation,
                    message="Token validation failed - no active token",
                    user_id=user.id
                )
                return False
            
            # Check expiration first
            if stored_token.is_expired():
                self._log_warning(
                    operation=operation,
                    message="Token validation failed - token expired",
                    user_id=user.id,
                    stored_token_prefix=stored_token.value[:8],
                    expires_at=stored_token.expires_at.isoformat()
                )
                return False
            
            # Use constant-time comparison to prevent timing attacks
            is_valid = secrets.compare_digest(stored_token.value, token)
            
            # Log validation result (with token prefix only)
            self._log_success(
                operation=operation,
                user_id=user.id,
                is_valid=is_valid,
                stored_token_prefix=stored_token.value[:8],
                provided_token_prefix=token[:8] if token else None,
                security_metrics=stored_token.get_security_metrics() if is_valid else None
            )
            
            return is_valid
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )
    
    def is_token_valid(self, user: User, token: str) -> bool:
        """Alias for validate_token for backward compatibility."""
        return self.validate_token(user, token)
    
    def invalidate_token(self, user: User, reason: str = "manual_invalidation") -> None:
        """Invalidate the user's password reset token.
        
        Args:
            user: User entity to invalidate token for
            reason: Reason for invalidation (for logging)
        """
        operation = "invalidate_token"
        
        try:
            if self._has_active_token(user):
                self._log_success(
                    operation=operation,
                    user_id=user.id,
                    reason=reason,
                    token_prefix=user.password_reset_token[:8] if user.password_reset_token else None
                )
                
                user.password_reset_token = None
                user.password_reset_token_expires_at = None
                
            else:
                self._log_warning(
                    operation=operation,
                    message="Token invalidation skipped - no active token",
                    user_id=user.id,
                    reason=reason
                )
                
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id,
                reason=reason
            )
    
    def is_token_expired(self, user: User) -> bool:
        """Check if the user's token is expired.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if token is expired or doesn't exist
        """
        operation = "is_token_expired"
        
        try:
            stored_token = self._create_token_from_user(user)
            if not stored_token:
                return True
            
            is_expired = stored_token.is_expired()
            
            if is_expired:
                self._log_success(
                    operation=operation,
                    user_id=user.id,
                    token_prefix=stored_token.value[:8],
                    expires_at=stored_token.expires_at.isoformat()
                )
            
            return is_expired
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )
    
    def get_token_expiry(self, user: User) -> Optional[datetime]:
        """Get the expiry time of the user's token.
        
        Args:
            user: User entity to check
            
        Returns:
            Optional[datetime]: Token expiry time if exists and valid
        """
        operation = "get_token_expiry"
        
        try:
            stored_token = self._create_token_from_user(user)
            if not stored_token:
                return None
            
            return stored_token.expires_at
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )
    
    def get_time_remaining(self, user: User) -> Optional[int]:
        """Get remaining time until token expires in seconds.
        
        Args:
            user: User entity to check
            
        Returns:
            Optional[int]: Remaining seconds if token exists and valid, None otherwise
        """
        operation = "get_time_remaining"
        
        try:
            stored_token = self._create_token_from_user(user)
            if not stored_token:
                return None
            
            remaining_time = stored_token.time_remaining()
            return int(remaining_time.total_seconds()) if remaining_time.total_seconds() > 0 else None
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )
    
    def get_token_security_metrics(self, user: User) -> Optional[dict]:
        """Get security metrics for the user's token.
        
        Args:
            user: User entity to check
            
        Returns:
            Optional[dict]: Security metrics if token exists and valid
        """
        operation = "get_token_security_metrics"
        
        try:
            stored_token = self._create_token_from_user(user)
            if not stored_token:
                return None
            
            return stored_token.get_security_metrics()
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )
    
    def _has_active_token(self, user: User) -> bool:
        """Check if user has an active token.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if user has both token and expiry set
        """
        return (
            user.password_reset_token is not None
            and user.password_reset_token_expires_at is not None
        )

    def _create_token_from_user(self, user: User) -> Optional[ResetToken]:
        """Create ResetToken from user's stored token data.
        
        Args:
            user: User entity with stored token data
            
        Returns:
            ResetToken if user has valid token data, None otherwise
        """
        if not self._has_active_token(user):
            return None
        
        try:
            return ResetToken.from_existing(
                user.password_reset_token,
                user.password_reset_token_expires_at
            )
        except ValueError:
            # Invalid token data - clear it
            self.invalidate_token(user, reason="invalid_token_data")
            return None