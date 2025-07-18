"""
Domain entities module.

This module contains all domain entities following Domain-Driven Design principles.
Entities represent the core business concepts and contain rich business logic.

Key Entities:
- User: Core user entity with authentication and profile management
- TokenFamily: Token family entity for advanced security patterns
- OAuthProfile: OAuth integration entity for external authentication

The entities are designed with:
- Rich business logic and behavior
- Clear ubiquitous language
- Immutable value objects
- Domain events for side effects
- Repository interfaces for persistence
"""

from .role import Role
from .user import User
from .token_family import TokenFamily
from .oauth_profile import OAuthProfile
from .session import Session

# Import value objects consistently
from ..value_objects.token_family_status import TokenFamilyStatus
from ..value_objects.token_usage_event import TokenUsageEvent
from ..value_objects.token_usage_record import TokenUsageRecord

__all__ = [
    "Role",
    "User",
    "TokenFamily",
    "OAuthProfile",
    "Session",
    "TokenFamilyStatus",
    "TokenUsageEvent", 
    "TokenUsageRecord",
]
