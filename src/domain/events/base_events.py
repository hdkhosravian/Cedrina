"""
Base Domain Events and Common Patterns.

This module provides the foundation for all domain events, extracting
common patterns to eliminate duplication and ensure consistency.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from dataclasses import dataclass, field, KW_ONLY, fields
from abc import ABC, abstractmethod, ABCMeta


def _make_hashable(obj):
    """
    Recursively convert obj to a hashable type.
    - dicts become sorted tuples of (key, value)
    - lists/tuples become tuples
    - sets become frozensets
    - all other types are returned as-is
    """
    if isinstance(obj, dict):
        return tuple(sorted((k, _make_hashable(v)) for k, v in obj.items()))
    if isinstance(obj, (list, tuple)):
        return tuple(_make_hashable(i) for i in obj)
    if isinstance(obj, set):
        return frozenset(_make_hashable(i) for i in obj)
    return obj


class HashableEventMixin:
    """
    Mixin to provide a robust, recursive, production-grade __hash__ for event dataclasses.
    """
    def __hash__(self):
        """
        Make events hashable by converting all fields to a tuple.
        For the metadata dict, and any nested dict/list/set, recursively convert to hashable types.
        This ensures that events with the same data produce the same hash.
        """
        from dataclasses import fields
        values = tuple(_make_hashable(getattr(self, f.name)) for f in fields(self))
        return hash(values)


class EventMeta(ABCMeta):
    """
    Metaclass to enforce the custom __hash__ from HashableEventMixin for all subclasses.
    """
    def __new__(mcs, name, bases, namespace, **kwargs):
        namespace['__hash__'] = HashableEventMixin.__hash__
        return super().__new__(mcs, name, bases, namespace, **kwargs)

@dataclass(eq=True, frozen=True)
class BaseDomainEvent(ABC, metaclass=EventMeta):
    """
    Base class for all domain events with common patterns.

    This class extracts the common patterns found across all domain events:
    - correlation_id for tracing
    - timestamp for audit trails
    - metadata for extensibility
    - validation through __post_init__

    Attributes:
        correlation_id: Optional correlation ID for distributed tracing
        timestamp: When the event occurred (UTC)
        metadata: Additional context data for extensibility
    """
    _: KW_ONLY
    correlation_id: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """
        Validate common event data and ensure timezone awareness.
        """
        # Ensure timestamp is timezone-aware
        if not self.timestamp.tzinfo:
            object.__setattr__(self, 'timestamp', self.timestamp.replace(tzinfo=timezone.utc))
        # Validate correlation_id if provided
        if self.correlation_id is not None and self.correlation_id.strip() == "":
            raise ValueError("Correlation ID cannot be empty")
        # Call subclass validation
        self._validate_event_data()

    @abstractmethod
    def _validate_event_data(self) -> None:
        """
        Validate event-specific data. Override in subclasses.
        """
        pass

    @classmethod
    def create(cls, **kwargs) -> "BaseDomainEvent":
        """
        Factory method for creating domain events with validation.
        """
        return cls(**kwargs)


class UserEventMixin:
    """
    Mixin for events that involve a user.
    Provides common validation for user_id field.
    """
    def _validate_user_id(self, user_id: int) -> None:
        """Validate user ID is positive."""
        if user_id <= 0:
            raise ValueError("User ID must be positive")


class TokenEventMixin:
    """
    Mixin for events that involve tokens.
    Provides common validation for token-related fields.
    """
    def _validate_token_id(self, token_id: str) -> None:
        """Validate token ID is not empty."""
        if not token_id or not token_id.strip():
            raise ValueError("Token ID is required and cannot be empty")
    def _validate_family_id(self, family_id: str) -> None:
        """Validate family ID is not empty."""
        if not family_id or not family_id.strip():
            raise ValueError("Family ID is required and cannot be empty")


class SecurityEventMixin:
    """
    Mixin for security-related events.
    Provides common validation for security event fields.
    """
    def _validate_reason(self, reason: str) -> None:
        """Validate reason is not empty."""
        if not reason or not reason.strip():
            raise ValueError("Reason is required and cannot be empty")
    def _validate_provider(self, provider: str) -> None:
        """Validate provider is not empty."""
        if not provider or not provider.strip():
            raise ValueError("Provider is required and cannot be empty")
    def _validate_error_code(self, error_code: str) -> None:
        """Validate error code is not empty."""
        if not error_code or not error_code.strip():
            raise ValueError("Error code is required and cannot be empty")
    def _validate_error_description(self, error_description: str) -> None:
        """Validate error description is not empty."""
        if not error_description or not error_description.strip():
            raise ValueError("Error description is required and cannot be empty")


class EmailEventMixin:
    """
    Mixin for events that involve email addresses.
    Provides common validation for email fields.
    """
    def _validate_email(self, email: str) -> None:
        """Validate email is not empty."""
        if not email or not email.strip():
            raise ValueError("Email is required and cannot be empty")


class StringValidationMixin:
    """
    Mixin for events that need string validation.
    Provides common validation for string fields.
    """
    def _validate_required_string(self, value: str, field_name: str) -> None:
        """Validate that a required string field is not empty."""
        if not value or not value.strip():
            raise ValueError(f"{field_name} is required and cannot be empty")
    def _validate_optional_string(self, value: Optional[str], field_name: str) -> None:
        """Validate that an optional string field is not empty if provided."""
        if value is not None and not value.strip():
            raise ValueError(f"{field_name} cannot be empty if provided")


class TimestampValidationMixin:
    """
    Mixin for events that need timestamp validation.
    Provides common validation for timestamp fields.
    """
    def _validate_future_timestamp(self, timestamp: datetime, field_name: str) -> None:
        """Validate that a timestamp is in the future."""
        if timestamp <= self.timestamp:
            raise ValueError(f"{field_name} must be in the future")
    def _validate_past_timestamp(self, timestamp: datetime, field_name: str) -> None:
        """Validate that a timestamp is in the past."""
        if timestamp > self.timestamp:
            raise ValueError(f"{field_name} cannot be in the future")
    def _validate_timestamp_order(self, earlier: datetime, later: datetime, earlier_name: str, later_name: str) -> None:
        """Validate that two timestamps are in correct order."""
        if earlier >= later:
            raise ValueError(f"{earlier_name} must be before {later_name}")


class SessionEventMixin:
    """
    Mixin for events that involve sessions.
    Provides common validation for session-related fields.
    """
    def _validate_session_id(self, session_id: str) -> None:
        """Validate session ID is not empty."""
        if not session_id or not session_id.strip():
            raise ValueError("Session ID is required and cannot be empty")
    def _validate_event_type(self, event_type: str) -> None:
        """Validate event type is not empty."""
        if not event_type or not event_type.strip():
            raise ValueError("Event type is required and cannot be empty") 