"""
Token Family Status Value Object.

This value object represents the security status of a token family,
following Domain-Driven Design principles with immutable state and
rich business logic.

Domain Concepts:
- Token Family Status: The security state of a token family
- Status Transitions: Valid state changes based on security events
- Status Validation: Business rules for status consistency

Business Rules:
- Status transitions follow security lifecycle
- Compromised status is irreversible
- Expired status is terminal
- Active status allows normal operations
"""

from enum import Enum
from typing import Set


class TokenFamilyStatus(Enum):
    """
    Status of a token family reflecting its security state.
    
    Status Flow:
    ACTIVE -> COMPROMISED (on security violation)
    ACTIVE -> REVOKED (on manual revocation)
    ACTIVE -> EXPIRED (on time expiration)
    REVOKED -> COMPROMISED (on reuse detection)
    EXPIRED -> COMPROMISED (on reuse detection)
    """
    ACTIVE = "active"
    COMPROMISED = "compromised"
    REVOKED = "revoked"
    EXPIRED = "expired"
    
    @classmethod
    def get_terminal_statuses(cls) -> Set["TokenFamilyStatus"]:
        """Get statuses that cannot transition to other states."""
        return {cls.COMPROMISED, cls.EXPIRED}
    
    @classmethod
    def get_operational_statuses(cls) -> Set["TokenFamilyStatus"]:
        """Get statuses that allow normal token operations."""
        return {cls.ACTIVE}
    
    @classmethod
    def can_transition_to(cls, from_status: "TokenFamilyStatus", to_status: "TokenFamilyStatus") -> bool:
        """
        Check if status transition is valid.
        
        Business Rules:
        - COMPROMISED is terminal (no transitions out)
        - EXPIRED is terminal (no transitions out)
        - REVOKED can only transition to COMPROMISED
        - ACTIVE can transition to any other status
        """
        if from_status in cls.get_terminal_statuses():
            return False
        
        if to_status == cls.COMPROMISED:
            # Can always transition to compromised (security violation)
            return True
        
        if from_status == cls.REVOKED:
            # Revoked can only transition to compromised
            return to_status == cls.COMPROMISED
        
        if from_status == cls.ACTIVE:
            # Active can transition to any status
            return True
        
        return False
    
    def is_terminal(self) -> bool:
        """Check if this status is terminal (no further transitions)."""
        return self in self.get_terminal_statuses()
    
    def is_operational(self) -> bool:
        """Check if this status allows normal token operations."""
        return self in self.get_operational_statuses()
    
    def allows_token_operations(self) -> bool:
        """Check if this status allows token operations."""
        return self == self.ACTIVE
    
    def requires_security_response(self) -> bool:
        """Check if this status requires immediate security response."""
        return self in {self.COMPROMISED, self.REVOKED} 