"""
Token Usage Event Value Object.

This value object represents different types of token usage events
for security analysis and audit trails, following Domain-Driven Design
principles with immutable state and rich business logic.

Domain Concepts:
- Token Usage Event: A specific type of token interaction
- Security Analysis: Event categorization for threat detection
- Audit Trail: Comprehensive logging of all token interactions

Business Rules:
- Events are immutable and timestamped
- Events support security analysis and forensic investigation
- Events maintain correlation for request tracing
"""

from enum import Enum
from typing import Set


class TokenUsageEvent(Enum):
    """
    Types of token usage events for security analysis.
    
    Event Categories:
    - Normal Operations: ISSUED, USED, REFRESHED
    - Security Events: REVOKED, REUSE_DETECTED
    - Lifecycle Events: EXPIRED, COMPROMISED
    """
    ISSUED = "issued"
    USED = "used"
    REFRESHED = "refreshed"
    REVOKED = "revoked"
    REUSE_DETECTED = "reuse_detected"
    EXPIRED = "expired"
    COMPROMISED = "compromised"
    
    @classmethod
    def get_normal_operations(cls) -> Set["TokenUsageEvent"]:
        """Get events that represent normal token operations."""
        return {cls.ISSUED, cls.USED, cls.REFRESHED}
    
    @classmethod
    def get_security_violations(cls) -> Set["TokenUsageEvent"]:
        """Get events that indicate security violations."""
        return {cls.REVOKED, cls.REUSE_DETECTED, cls.COMPROMISED}
    
    @classmethod
    def get_lifecycle_events(cls) -> Set["TokenUsageEvent"]:
        """Get events that represent token lifecycle changes."""
        return {cls.EXPIRED, cls.COMPROMISED}
    
    def is_normal_operation(self) -> bool:
        """Check if this event represents a normal operation."""
        return self in self.get_normal_operations()
    
    def is_security_violation(self) -> bool:
        """Check if this event indicates a security violation."""
        return self in self.get_security_violations()
    
    def is_lifecycle_event(self) -> bool:
        """Check if this event represents a lifecycle change."""
        return self in self.get_lifecycle_events()
    
    def requires_immediate_response(self) -> bool:
        """Check if this event requires immediate security response."""
        return self in {self.REUSE_DETECTED, self.COMPROMISED}
    
    def affects_security_score(self) -> bool:
        """Check if this event affects the family security score."""
        return self in {self.REUSE_DETECTED, self.COMPROMISED, self.REVOKED}
    
    def get_security_impact(self) -> float:
        """
        Get the security impact score for this event.
        
        Returns:
            float: Impact score from 0.0 (no impact) to 1.0 (critical impact)
        """
        impact_scores = {
            self.ISSUED: 0.0,      # No impact
            self.USED: 0.0,        # No impact
            self.REFRESHED: 0.0,   # No impact
            self.REVOKED: 0.3,     # Moderate impact
            self.EXPIRED: 0.5,     # Medium impact
            self.REUSE_DETECTED: 1.0,  # Critical impact
            self.COMPROMISED: 1.0,     # Critical impact
        }
        return impact_scores.get(self, 0.0) 