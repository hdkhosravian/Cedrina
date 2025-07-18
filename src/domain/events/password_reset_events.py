"""Password Reset Domain Events.

These events represent significant business occurrences in the password reset domain
that other parts of the system may need to react to (logging, monitoring, notifications).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from pydantic import EmailStr

from .base_events import (
    BaseDomainEvent, 
    EmailEventMixin, 
    UserEventMixin,
    StringValidationMixin,
    TimestampValidationMixin
)


@dataclass(frozen=True)
class PasswordResetRequestedEvent(BaseDomainEvent, EmailEventMixin, UserEventMixin, TimestampValidationMixin, StringValidationMixin):
    """Event emitted when a password reset is requested.
    
    This event is useful for:
    - Audit logging
    - Security monitoring
    - Rate limiting analytics
    - Email delivery tracking
    
    Attributes:
        user_id: ID of the user associated with the event
        email: Email address the reset was requested for
        token_expires_at: When the reset token expires
        language: Language used for the request
        user_agent: Optional user agent string
        ip_address: Optional IP address of requester
    """
    
    user_id: int
    email: EmailStr
    token_expires_at: datetime
    language: str = "en"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event-specific data."""
        self._validate_user_id(self.user_id)
        self._validate_email(self.email)
        self._validate_future_timestamp(self.token_expires_at, "Token expiration")
        self._validate_required_string(self.language, "Language")
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: EmailStr,
        token_expires_at: datetime,
        language: str = "en",
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[dict] = None
    ) -> "PasswordResetRequestedEvent":
        """Create a new password reset requested event."""
        return cls(
            user_id=user_id,
            email=email,
            token_expires_at=token_expires_at,
            language=language,
            user_agent=user_agent,
            ip_address=ip_address,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class PasswordResetCompletedEvent(BaseDomainEvent, EmailEventMixin, UserEventMixin, StringValidationMixin):
    """Event emitted when a password reset is successfully completed.
    
    This event is useful for:
    - Audit logging
    - Security notifications
    - Analytics
    - Triggering additional security measures
    
    Attributes:
        user_id: ID of the user associated with the event
        email: Email address of the user
        reset_method: Method used for reset (e.g., "token")
        user_agent: Optional user agent string
        ip_address: Optional IP address of requester
    """
    
    user_id: int
    email: EmailStr
    reset_method: str = "token"
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event-specific data."""
        self._validate_user_id(self.user_id)
        self._validate_email(self.email)
        self._validate_required_string(self.reset_method, "Reset method")
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: EmailStr,
        reset_method: str = "token",
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[dict] = None
    ) -> "PasswordResetCompletedEvent":
        """Create a new password reset completed event."""
        return cls(
            user_id=user_id,
            email=email,
            reset_method=reset_method,
            user_agent=user_agent,
            ip_address=ip_address,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class PasswordResetFailedEvent(BaseDomainEvent, EmailEventMixin, UserEventMixin, StringValidationMixin):
    """Event emitted when a password reset attempt fails.
    
    This event is useful for:
    - Security monitoring
    - Fraud detection
    - Rate limiting adjustments
    - Alert generation
    
    Attributes:
        user_id: ID of the user associated with the event
        email: Email address of the attempted reset
        failure_reason: Reason for failure
        token_used: Masked token that was used (if any)
        user_agent: Optional user agent string
        ip_address: Optional IP address of requester
    """
    
    user_id: int
    email: EmailStr
    failure_reason: str
    token_used: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event-specific data."""
        self._validate_user_id(self.user_id)
        self._validate_email(self.email)
        self._validate_required_string(self.failure_reason, "Failure reason")
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: EmailStr,
        failure_reason: str,
        token_used: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[dict] = None
    ) -> "PasswordResetFailedEvent":
        """Create a new password reset failed event."""
        return cls(
            user_id=user_id,
            email=email,
            failure_reason=failure_reason,
            token_used=token_used,
            user_agent=user_agent,
            ip_address=ip_address,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class PasswordResetTokenExpiredEvent(BaseDomainEvent, EmailEventMixin, UserEventMixin, TimestampValidationMixin):
    """Event emitted when a password reset token expires.
    
    This event is useful for:
    - Cleanup operations
    - Analytics on token usage patterns
    - Security monitoring
    
    Attributes:
        user_id: ID of the user associated with the event
        email: Email address associated with expired token
        token_created_at: When the token was originally created
        expired_at: When the token expired
    """
    
    user_id: int
    email: EmailStr
    token_created_at: datetime
    expired_at: datetime
    
    def _validate_event_data(self) -> None:
        """Validate event-specific data."""
        self._validate_user_id(self.user_id)
        self._validate_email(self.email)
        self._validate_timestamp_order(self.token_created_at, self.expired_at, "Token creation time", "Expired time")
        self._validate_past_timestamp(self.expired_at, "Expired time")
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: EmailStr,
        token_created_at: datetime,
        expired_at: datetime,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[dict] = None
    ) -> "PasswordResetTokenExpiredEvent":
        """Create a new password reset token expired event."""
        return cls(
            user_id=user_id,
            email=email,
            token_created_at=token_created_at,
            expired_at=expired_at,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        ) 