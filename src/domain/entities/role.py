"""Role enumeration for user authorization.

This module defines the Role enumeration that represents the possible roles
a user can have within the system, following Domain-Driven Design principles.
"""

from enum import Enum


class Role(str, Enum):
    """Represents the role of a user within the system (RBAC).

    This value object defines the possible roles a user can have, ensuring that
    role assignments are type-safe and constrained to a predefined set.

    Attributes:
        ADMIN: Confers administrative privileges for system management.
        USER: Represents a standard user with regular access rights.
    """

    ADMIN = "admin"
    USER = "user" 