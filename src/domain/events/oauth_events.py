"""
OAuth Domain Events.

This module defines domain events specific to OAuth authentication,
following Domain-Driven Design principles with clear ubiquitous language.

Domain Events:
- OAuthAuthenticationSuccessEvent: Successful OAuth authentication
- OAuthAuthenticationFailedEvent: Failed OAuth authentication
- OAuthProfileCreatedEvent: OAuth profile created
- OAuthProfileUpdatedEvent: OAuth profile updated

Event Properties:
- Immutable data structures
- Clear ubiquitous language
- Correlation IDs for tracing
- Timestamps for audit trails
- Security context for forensic analysis
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

from .base_events import (
    BaseDomainEvent, 
    UserEventMixin, 
    SecurityEventMixin, 
    EmailEventMixin,
    StringValidationMixin
)


@dataclass(frozen=True)
class OAuthAuthenticationSuccessEvent(BaseDomainEvent, UserEventMixin, SecurityEventMixin, EmailEventMixin):
    """Domain event published when OAuth authentication succeeds."""
    
    provider: str
    user_id: int
    email: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_provider(self.provider)
        
        if self.email is not None:
            self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        provider: str,
        user_id: int,
        email: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "OAuthAuthenticationSuccessEvent":
        """Create a new OAuth authentication success event."""
        return cls(
            provider=provider,
            user_id=user_id,
            email=email,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class OAuthAuthenticationFailedEvent(BaseDomainEvent, SecurityEventMixin, UserEventMixin):
    """Domain event published when OAuth authentication fails."""
    
    provider: str
    error_code: str
    error_description: str
    user_id: Optional[int] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_provider(self.provider)
        self._validate_error_code(self.error_code)
        self._validate_error_description(self.error_description)
        
        if self.user_id is not None:
            self._validate_user_id(self.user_id)
    
    @classmethod
    def create(
        cls,
        provider: str,
        error_code: str,
        error_description: str,
        user_id: Optional[int] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "OAuthAuthenticationFailedEvent":
        """Create a new OAuth authentication failed event."""
        return cls(
            provider=provider,
            error_code=error_code,
            error_description=error_description,
            user_id=user_id,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class OAuthProfileCreatedEvent(BaseDomainEvent, UserEventMixin, SecurityEventMixin, StringValidationMixin, EmailEventMixin):
    """Domain event published when an OAuth profile is created."""
    
    user_id: int
    provider: str
    provider_user_id: str
    email: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_provider(self.provider)
        self._validate_required_string(self.provider_user_id, "Provider user ID")
        
        if self.email is not None:
            self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        provider: str,
        provider_user_id: str,
        email: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "OAuthProfileCreatedEvent":
        """Create a new OAuth profile created event."""
        return cls(
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            email=email,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class OAuthProfileUpdatedEvent(BaseDomainEvent, UserEventMixin, SecurityEventMixin, StringValidationMixin, EmailEventMixin):
    """Domain event published when an OAuth profile is updated."""
    
    user_id: int
    provider: str
    provider_user_id: str
    email: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_provider(self.provider)
        self._validate_required_string(self.provider_user_id, "Provider user ID")
        
        if self.email is not None:
            self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        provider: str,
        provider_user_id: str,
        email: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "OAuthProfileUpdatedEvent":
        """Create a new OAuth profile updated event."""
        return cls(
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            email=email,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class OAuthProfileLinkedEvent(BaseDomainEvent, UserEventMixin, SecurityEventMixin, StringValidationMixin, EmailEventMixin):
    """Domain event published when an OAuth profile is linked to a user."""
    
    user_id: int
    provider: str
    provider_user_id: str
    email: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_provider(self.provider)
        self._validate_required_string(self.provider_user_id, "Provider user ID")
        
        if self.email is not None:
            self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        provider: str,
        provider_user_id: str,
        email: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "OAuthProfileLinkedEvent":
        """Create a new OAuth profile linked event."""
        return cls(
            user_id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            email=email,
            correlation_id=correlation_id,
            timestamp=timestamp or datetime.now(timezone.utc),
            metadata=metadata or {}
        ) 