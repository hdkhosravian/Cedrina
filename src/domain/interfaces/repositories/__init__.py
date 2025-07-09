"""
Repository Interfaces Package.

This package contains abstract interfaces for repository pattern implementations
following domain-driven design principles. These interfaces define contracts
for data persistence operations while keeping the domain layer independent
of infrastructure concerns.
"""

# Import from the correct repositories.py file in parent directory
from .token_family_repository import ITokenFamilyRepository

__all__ = [
    "ITokenFamilyRepository",
] 