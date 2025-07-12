"""Domain Events for the authentication domain.

Domain events represent significant occurrences in the business domain
that other parts of the system may need to react to.
"""

from .base_events import BaseDomainEvent
from .password_reset_events import (
    PasswordResetRequestedEvent,
    PasswordResetCompletedEvent,
    PasswordResetFailedEvent,
    PasswordResetTokenExpiredEvent,
)
from .authentication_events import (
    EmailConfirmedEvent,
    AuthenticationFailedEvent,
    TokenFamilyCreatedEvent,
    TokenAddedEvent,
    TokenUsedEvent,
    TokenRevokedEvent,
    TokenReuseDetectedEvent,
    TokenFamilyCompromisedEvent,
    TokenRefreshedEvent,
    SecurityIncidentEvent,
    UserAuthenticationEvent,
    SessionEvent,
    UserLoggedInEvent,
    UserRegisteredEvent,
    UserLoggedOutEvent,
    PasswordChangedEvent,
    SessionCreatedEvent,
    SessionRevokedEvent,
    SessionExpiredEvent,
    SessionActivityUpdatedEvent,
)
from .oauth_events import (
    OAuthAuthenticationSuccessEvent,
    OAuthAuthenticationFailedEvent,
    OAuthProfileCreatedEvent,
    OAuthProfileUpdatedEvent,
    OAuthProfileLinkedEvent,
)

__all__ = [
    # Base classes
    "BaseDomainEvent",
    
    # Password reset events
    "PasswordResetRequestedEvent",
    "PasswordResetCompletedEvent", 
    "PasswordResetFailedEvent",
    "PasswordResetTokenExpiredEvent",
    
    # Authentication events
    "EmailConfirmedEvent",
    "AuthenticationFailedEvent",
    "TokenFamilyCreatedEvent",
    "TokenAddedEvent",
    "TokenUsedEvent",
    "TokenRevokedEvent",
    "TokenReuseDetectedEvent",
    "TokenFamilyCompromisedEvent",
    "TokenRefreshedEvent",
    "SecurityIncidentEvent",
    "UserAuthenticationEvent",
    "SessionEvent",
    "UserLoggedInEvent",
    "UserRegisteredEvent",
    "UserLoggedOutEvent",
    "PasswordChangedEvent",
    "SessionCreatedEvent",
    "SessionRevokedEvent",
    "SessionExpiredEvent",
    "SessionActivityUpdatedEvent",
    
    # OAuth events
    "OAuthAuthenticationSuccessEvent",
    "OAuthAuthenticationFailedEvent",
    "OAuthProfileCreatedEvent",
    "OAuthProfileUpdatedEvent",
    "OAuthProfileLinkedEvent",
]
