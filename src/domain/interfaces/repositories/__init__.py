"""
Repository Interfaces Package.

This package contains abstract interfaces for repository pattern implementations
following domain-driven design principles. These interfaces define contracts
for data persistence operations while keeping the domain layer independent
of infrastructure concerns.
"""

# Repository interfaces following DDD principles
from .user_repository import IUserRepository
from .oauth_profile_repository import IOAuthProfileRepository
from .token_family_repository import ITokenFamilyRepository

__all__ = [
    "IUserRepository",
    "IOAuthProfileRepository", 
    "ITokenFamilyRepository",
] 