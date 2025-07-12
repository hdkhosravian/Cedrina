"""
Domain Events for Authentication and Token Family Operations.

This module defines domain events that represent significant business occurrences
in the authentication domain, following Domain-Driven Design principles.

Domain Events:
- TokenFamilyCreatedEvent: New token family established
- TokenAddedEvent: Token added to family
- TokenUsedEvent: Token usage recorded
- TokenRevokedEvent: Token revoked from family
- TokenReuseDetectedEvent: Security violation detected
- TokenFamilyCompromisedEvent: Family-wide security breach
- TokenRefreshedEvent: Token refresh completed
- SecurityIncidentEvent: General security events
- EmailConfirmedEvent: Email confirmation completed

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
from enum import Enum

from .base_events import (
    BaseDomainEvent, 
    UserEventMixin, 
    TokenEventMixin, 
    SecurityEventMixin, 
    EmailEventMixin,
    StringValidationMixin,
    SessionEventMixin
)


class SecurityThreatLevel(Enum):
    """Enumeration of security threat levels for risk assessment."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class EmailConfirmedEvent(BaseDomainEvent, EmailEventMixin, UserEventMixin):
    """Domain event published when an email is confirmed."""
    
    user_id: int
    email: str
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: str,
        correlation_id: Optional[str] = None
    ) -> "EmailConfirmedEvent":
        """Create a new email confirmed event."""
        return cls(
            user_id=user_id,
            email=email,
            correlation_id=correlation_id
        )


@dataclass(frozen=True)
class AuthenticationFailedEvent(BaseDomainEvent, SecurityEventMixin):
    """Domain event published when authentication fails."""
    reason: str
    user_id: Optional[int] = None
    email: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_reason(self.reason)
        
        if self.user_id is not None:
            self._validate_user_id(self.user_id)
        
        if self.email is not None:
            self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        reason: str,
        user_id: Optional[int] = None,
        email: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "AuthenticationFailedEvent":
        """Create a new authentication failed event."""
        return cls(
            reason=reason,
            user_id=user_id,
            email=email,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class TokenFamilyCreatedEvent(BaseDomainEvent, UserEventMixin, TokenEventMixin):
    """Domain event published when a new token family is created."""
    
    family_id: str
    user_id: int
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_family_id(self.family_id)
    
    @classmethod
    def create(
        cls,
        family_id: str,
        user_id: int,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "TokenFamilyCreatedEvent":
        """Create a new token family created event."""
        return cls(
            family_id=family_id,
            user_id=user_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class TokenAddedEvent(BaseDomainEvent, UserEventMixin, TokenEventMixin):
    """Domain event published when a token is added to a family."""
    
    family_id: str
    token_id: str
    user_id: int
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_family_id(self.family_id)
        self._validate_token_id(self.token_id)
    
    @classmethod
    def create(
        cls,
        family_id: str,
        token_id: str,
        user_id: int,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "TokenAddedEvent":
        """Create a new token added event."""
        return cls(
            family_id=family_id,
            token_id=token_id,
            user_id=user_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class TokenUsedEvent(BaseDomainEvent, UserEventMixin, TokenEventMixin):
    """Domain event published when a token is used."""
    
    family_id: str
    token_id: str
    user_id: int
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_family_id(self.family_id)
        self._validate_token_id(self.token_id)
    
    @classmethod
    def create(
        cls,
        family_id: str,
        token_id: str,
        user_id: int,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "TokenUsedEvent":
        """Create a new token used event."""
        return cls(
            family_id=family_id,
            token_id=token_id,
            user_id=user_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class TokenRevokedEvent(BaseDomainEvent, UserEventMixin, TokenEventMixin):
    """Domain event published when a token is revoked."""
    
    family_id: str
    token_id: str
    user_id: int
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_family_id(self.family_id)
        self._validate_token_id(self.token_id)
    
    @classmethod
    def create(
        cls,
        family_id: str,
        token_id: str,
        user_id: int,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "TokenRevokedEvent":
        """Create a new token revoked event."""
        return cls(
            family_id=family_id,
            token_id=token_id,
            user_id=user_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class TokenReuseDetectedEvent(BaseDomainEvent, UserEventMixin, TokenEventMixin, SecurityEventMixin):
    """Domain event published when token reuse is detected."""
    
    family_id: str
    token_id: str
    user_id: int
    reason: str
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_family_id(self.family_id)
        self._validate_token_id(self.token_id)
        self._validate_reason(self.reason)
    
    @classmethod
    def create(
        cls,
        family_id: str,
        token_id: str,
        user_id: int,
        reason: str,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "TokenReuseDetectedEvent":
        """Create a new token reuse detected event."""
        return cls(
            family_id=family_id,
            token_id=token_id,
            user_id=user_id,
            reason=reason,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class TokenFamilyCompromisedEvent(BaseDomainEvent, UserEventMixin, TokenEventMixin, SecurityEventMixin):
    """Domain event published when a token family is compromised."""
    
    family_id: str
    user_id: int
    reason: str
    detected_token: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_family_id(self.family_id)
        self._validate_reason(self.reason)
        
        if self.detected_token is not None:
            self._validate_token_id(self.detected_token)
    
    @classmethod
    def create(
        cls,
        family_id: str,
        user_id: int,
        reason: str,
        detected_token: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "TokenFamilyCompromisedEvent":
        """Create a new token family compromised event."""
        return cls(
            family_id=family_id,
            user_id=user_id,
            reason=reason,
            detected_token=detected_token,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class TokenRefreshedEvent(BaseDomainEvent, UserEventMixin, TokenEventMixin):
    """Domain event published when tokens are refreshed."""
    
    family_id: str
    old_token_id: str
    new_token_id: str
    user_id: int
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_family_id(self.family_id)
        self._validate_token_id(self.old_token_id)
        self._validate_token_id(self.new_token_id)
        
        if self.old_token_id == self.new_token_id:
            raise ValueError("Old and new token IDs must be different")
    
    @classmethod
    def create(
        cls,
        family_id: str,
        old_token_id: str,
        new_token_id: str,
        user_id: int,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "TokenRefreshedEvent":
        """Create a new token refreshed event."""
        return cls(
            family_id=family_id,
            old_token_id=old_token_id,
            new_token_id=new_token_id,
            user_id=user_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class SecurityIncidentEvent(BaseDomainEvent, SecurityEventMixin):
    """Domain event published for general security incidents."""
    
    incident_type: str
    threat_level: SecurityThreatLevel
    description: str
    user_id: Optional[int] = None
    family_id: Optional[str] = None
    token_id: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_required_string(self.incident_type, "Incident type")
        self._validate_required_string(self.description, "Description")
        
        if self.user_id is not None:
            self._validate_user_id(self.user_id)
        
        if self.family_id is not None:
            self._validate_family_id(self.family_id)
        
        if self.token_id is not None:
            self._validate_token_id(self.token_id)
    
    @classmethod
    def create(
        cls,
        incident_type: str,
        threat_level: SecurityThreatLevel,
        description: str,
        user_id: Optional[int] = None,
        family_id: Optional[str] = None,
        token_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "SecurityIncidentEvent":
        """Create a new security incident event."""
        return cls(
            incident_type=incident_type,
            threat_level=threat_level,
            description=description,
            user_id=user_id,
            family_id=family_id,
            token_id=token_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class UserAuthenticationEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published for user authentication events."""
    
    event_type: str  # "login", "logout", "failed_login", "password_changed", etc.
    user_id: int
    success: bool
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_required_string(self.event_type, "Event type")
    
    @classmethod
    def create(
        cls,
        event_type: str,
        user_id: int,
        success: bool,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "UserAuthenticationEvent":
        """Create a new user authentication event."""
        return cls(
            event_type=event_type,
            user_id=user_id,
            success=success,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class SessionEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published for session-related events."""
    
    event_type: str  # "created", "revoked", "expired", "refreshed"
    session_id: str
    user_id: int
    family_id: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_event_type(self.event_type)
        self._validate_session_id(self.session_id)
        
        if self.family_id is not None:
            self._validate_family_id(self.family_id)
    
    @classmethod
    def create(
        cls,
        event_type: str,
        session_id: str,
        user_id: int,
        family_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "SessionEvent":
        """Create a new session event."""
        return cls(
            event_type=event_type,
            session_id=session_id,
            user_id=user_id,
            family_id=family_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class UserLoggedInEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when a user logs in successfully."""
    user_id: int
    email: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        
        if self.email is not None:
            self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "UserLoggedInEvent":
        return cls(
            user_id=user_id,
            email=email,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class UserRegisteredEvent(BaseDomainEvent, UserEventMixin, EmailEventMixin):
    """Domain event published when a user registers successfully."""
    user_id: int
    email: str
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_email(self.email)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        email: str,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "UserRegisteredEvent":
        return cls(
            user_id=user_id,
            email=email,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class UserLoggedOutEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when a user logs out successfully."""
    user_id: int
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "UserLoggedOutEvent":
        return cls(
            user_id=user_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class PasswordChangedEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when a user changes their password."""
    user_id: int
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
    
    @classmethod
    def create(
        cls,
        user_id: int,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "PasswordChangedEvent":
        return cls(
            user_id=user_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class SessionCreatedEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when a session is created."""
    session_id: str
    user_id: int
    family_id: Optional[str] = None
    
    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_session_id(self.session_id)
        
        if self.family_id is not None:
            self._validate_family_id(self.family_id)
    
    @classmethod
    def create(
        cls,
        session_id: str,
        user_id: int,
        family_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "SessionCreatedEvent":
        return cls(
            session_id=session_id,
            user_id=user_id,
            family_id=family_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class SessionRevokedEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when a session is revoked."""
    session_id: str
    user_id: int
    family_id: Optional[str] = None
    reason: Optional[str] = None

    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_session_id(self.session_id)
        
        if self.family_id is not None:
            self._validate_family_id(self.family_id)

    @classmethod
    def create(
        cls,
        session_id: str,
        user_id: int,
        family_id: Optional[str] = None,
        reason: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "SessionRevokedEvent":
        return cls(
            session_id=session_id,
            user_id=user_id,
            family_id=family_id,
            reason=reason,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class SessionExpiredEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when a session expires."""
    session_id: str
    user_id: int
    family_id: Optional[str] = None

    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_session_id(self.session_id)
        
        if self.family_id is not None:
            self._validate_family_id(self.family_id)

    @classmethod
    def create(
        cls,
        session_id: str,
        user_id: int,
        family_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "SessionExpiredEvent":
        return cls(
            session_id=session_id,
            user_id=user_id,
            family_id=family_id,
            correlation_id=correlation_id,
            metadata=metadata or {}
        )


@dataclass(frozen=True)
class SessionActivityUpdatedEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when session activity is updated."""
    session_id: str
    user_id: int
    family_id: Optional[str] = None
    activity_type: Optional[str] = None

    def _validate_event_data(self) -> None:
        """Validate event data."""
        self._validate_user_id(self.user_id)
        self._validate_session_id(self.session_id)
        
        if self.family_id is not None:
            self._validate_family_id(self.family_id)

    @classmethod
    def create(
        cls,
        session_id: str,
        user_id: int,
        family_id: Optional[str] = None,
        activity_type: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "SessionActivityUpdatedEvent":
        return cls(
            session_id=session_id,
            user_id=user_id,
            family_id=family_id,
            activity_type=activity_type,
            correlation_id=correlation_id,
            metadata=metadata or {}
        ) 