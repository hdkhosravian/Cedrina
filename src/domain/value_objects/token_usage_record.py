"""
Token Usage Record Value Object.

This value object represents an immutable record of token usage for
security analysis and audit trails, following Domain-Driven Design
principles with rich business logic and validation.

Domain Concepts:
- Token Usage Record: Immutable record of a token interaction
- Security Context: Environmental information for threat analysis
- Audit Trail: Comprehensive logging for forensic investigation
- Correlation: Request tracing for debugging and monitoring

Business Rules:
- Records are immutable once created
- All records must have token ID and timestamp
- Security context is optional but valuable for analysis
- Correlation ID enables request tracing
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_usage_event import TokenUsageEvent


@dataclass(frozen=True)
class TokenUsageRecord:
    """
    Immutable record of token usage for security analysis.
    
    This value object captures all relevant information about a token
    interaction for security analysis, audit trails, and forensic
    investigation.
    
    Security Features:
    - Immutable design prevents tampering
    - Comprehensive context capture
    - Correlation support for request tracing
    - Rich metadata for threat analysis
    """
    
    token_id: TokenId
    event_type: TokenUsageEvent
    timestamp: datetime
    security_context: Optional[SecurityContext] = None
    correlation_id: Optional[str] = None
    
    def __post_init__(self):
        """Validate token usage record."""
        if not self.token_id:
            raise ValueError("Token ID is required")
        if not self.timestamp:
            raise ValueError("Timestamp is required")
        if self.timestamp.tzinfo is None:
            raise ValueError("Timestamp must be timezone-aware")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for persistence.
        
        Returns:
            Dict[str, Any]: Dictionary representation for storage
        """
        return {
            "token_id": self.token_id.value,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "client_ip": self.security_context.client_ip if self.security_context else None,
            "user_agent": self.security_context.user_agent if self.security_context else None,
            "correlation_id": self.correlation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenUsageRecord":
        """
        Create from dictionary.
        
        Args:
            data: Dictionary containing record data
            
        Returns:
            TokenUsageRecord: New record instance
            
        Raises:
            ValueError: If required data is missing or invalid
        """
        if "token_id" not in data:
            raise ValueError("Token ID is required")
        if "event_type" not in data:
            raise ValueError("Event type is required")
        if "timestamp" not in data:
            raise ValueError("Timestamp is required")
        
        # Parse timestamp
        timestamp = datetime.fromisoformat(data["timestamp"])
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        
        # Create security context if available
        security_context = None
        if data.get("client_ip") and data.get("user_agent"):
            security_context = SecurityContext.create_for_request(
                client_ip=data["client_ip"],
                user_agent=data["user_agent"],
                correlation_id=data.get("correlation_id")
            )
        
        return cls(
            token_id=TokenId(data["token_id"]),
            event_type=TokenUsageEvent(data["event_type"]),
            timestamp=timestamp,
            security_context=security_context,
            correlation_id=data.get("correlation_id")
        )
    
    def is_security_violation(self) -> bool:
        """Check if this record represents a security violation."""
        return self.event_type.is_security_violation()
    
    def requires_immediate_response(self) -> bool:
        """Check if this record requires immediate security response."""
        return self.event_type.requires_immediate_response()
    
    def get_security_impact(self) -> float:
        """Get the security impact score for this record."""
        return self.event_type.get_security_impact()
    
    def get_client_ip(self) -> Optional[str]:
        """Get client IP from security context."""
        return self.security_context.client_ip if self.security_context else None
    
    def get_user_agent(self) -> Optional[str]:
        """Get user agent from security context."""
        return self.security_context.user_agent if self.security_context else None
    
    def is_recent(self, within_seconds: int = 300) -> bool:
        """
        Check if this record is recent.
        
        Args:
            within_seconds: Time window in seconds (default: 5 minutes)
            
        Returns:
            bool: True if record is within the time window
        """
        now = datetime.now(timezone.utc)
        time_diff = (now - self.timestamp).total_seconds()
        return time_diff <= within_seconds
    
    def get_age_seconds(self) -> float:
        """
        Get the age of this record in seconds.
        
        Returns:
            float: Age in seconds from current time
        """
        now = datetime.now(timezone.utc)
        return (now - self.timestamp).total_seconds() 