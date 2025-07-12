"""
Security Context Value Object.

This value object encapsulates security-relevant information for authentication
requests, following Domain-Driven Design principles for immutable value objects.

Security Context captures:
- Client identification (IP address, User-Agent)
- Request correlation and tracing information
- Temporal context for security analysis
- Geographic and network context

This value object provides type safety and validation for security-sensitive
operations while maintaining immutability and equality semantics.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
import re

from src.common.exceptions import ValidationError


@dataclass(frozen=True)
class SecurityContext:
    """
    Immutable value object representing security context for authentication requests.
    
    This value object encapsulates all security-relevant information needed for
    threat assessment, audit trails, and forensic analysis.
    
    **Security Properties:**
    - Client IP address for geolocation and reputation analysis
    - User-Agent for device fingerprinting and behavior analysis
    - Request timestamp for temporal correlation and replay detection
    - Correlation ID for distributed tracing and incident response
    
    **Value Object Characteristics:**
    - Immutable: All fields are read-only after creation
    - Equality: Two contexts are equal if all fields match
    - Validation: All inputs are validated at construction time
    - Self-documenting: Field names reflect security domain concepts
    """
    
    client_ip: str
    user_agent: str
    request_timestamp: datetime
    correlation_id: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate security context fields at construction time."""
        self._validate_client_ip()
        self._validate_user_agent()
        self._validate_request_timestamp()
        if self.correlation_id:
            self._validate_correlation_id()
    
    def _validate_client_ip(self) -> None:
        """Validate client IP address format."""
        if not self.client_ip:
            raise ValidationError("Client IP address is required")
        
        # Basic IP validation (IPv4 and IPv6)
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if not re.match(ip_pattern, self.client_ip):
            raise ValidationError(f"Invalid IP address format: {self.client_ip}")
    
    def _validate_user_agent(self) -> None:
        """Validate user agent string."""
        if not self.user_agent:
            raise ValidationError("User-Agent is required")
        
        if len(self.user_agent) > 1000:  # Reasonable limit
            raise ValidationError("User-Agent exceeds maximum length")
    
    def _validate_request_timestamp(self) -> None:
        """Validate request timestamp."""
        if not self.request_timestamp:
            raise ValidationError("Request timestamp is required")
        
        # Ensure timestamp is timezone-aware
        if self.request_timestamp.tzinfo is None:
            raise ValidationError("Request timestamp must be timezone-aware")
    
    def _validate_correlation_id(self) -> None:
        """Validate correlation ID format."""
        if self.correlation_id and len(self.correlation_id) > 100:
            raise ValidationError("Correlation ID exceeds maximum length")
    
    @classmethod
    def create_for_request(
        cls,
        client_ip: str,
        user_agent: str,
        correlation_id: Optional[str] = None
    ) -> "SecurityContext":
        """
        Factory method to create security context for current request.
        
        Args:
            client_ip: Client IP address
            user_agent: User-Agent header value
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            SecurityContext: Validated security context instance
        """
        return cls(
            client_ip=client_ip,
            user_agent=user_agent,
            request_timestamp=datetime.now(timezone.utc),
            correlation_id=correlation_id
        )
    
    def is_internal_network(self) -> bool:
        """Check if request originates from internal network."""
        return (
            self.client_ip.startswith("10.") or
            self.client_ip.startswith("192.168.") or
            self.client_ip.startswith("172.")
        )
    
    def get_masked_ip(self) -> str:
        """Get masked IP address for logging (privacy protection)."""
        parts = self.client_ip.split(".")
        if len(parts) == 4:  # IPv4
            return f"{parts[0]}.{parts[1]}.xxx.xxx"
        return "xxx.xxx.xxx.xxx"  # IPv6 or invalid format
    
    def get_masked_user_agent(self) -> str:
        """Get masked User-Agent for logging (privacy protection)."""
        if len(self.user_agent) <= 50:
            return self.user_agent
        return self.user_agent[:47] + "..."
    
    def to_audit_dict(self) -> dict:
        """Convert to dictionary suitable for audit logging."""
        return {
            "client_ip": self.get_masked_ip(),
            "user_agent": self.get_masked_user_agent(),
            "request_timestamp": self.request_timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "is_internal": self.is_internal_network()
        } 