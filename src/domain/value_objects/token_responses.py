"""
Token Response Value Objects.

This module contains value objects for token-related responses following
Domain-Driven Design principles with clear ubiquitous language and
immutable state.

Domain Concepts:
- Token Pair: Access and refresh token pair with metadata
- Security Assessment: Risk assessment results for security context
- Token Validation Result: Validation result with security metadata
- Security Incident: Security event with threat level and response

Business Rules:
- All responses must include security metadata for audit trail
- Token pairs must include family security information
- Security assessments must include confidence scores and indicators
- Validation results must include comprehensive security context
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum

from src.domain.value_objects.security_context import SecurityContext


class SecurityThreatLevel(Enum):
    """
    Enumeration of security threat levels for risk assessment.
    
    This value object represents the different levels of security threats
    that can be detected during token operations, following DDD principles
    with clear business semantics.
    
    Business Rules:
    - Threat levels are ordered from lowest to highest risk
    - Each level has specific response requirements
    - Critical threats require immediate family compromise
    - Low threats allow continued monitoring
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def requires_immediate_response(self) -> bool:
        """Check if threat level requires immediate security response."""
        return self in {SecurityThreatLevel.HIGH, SecurityThreatLevel.CRITICAL}
    
    def requires_family_compromise(self) -> bool:
        """Check if threat level requires family compromise."""
        return self == SecurityThreatLevel.CRITICAL


@dataclass(frozen=True)
class SecurityAssessment:
    """
    Value object representing security risk assessment results.
    
    This value object encapsulates the results of security threat assessment
    for token operations, following DDD principles with clear business
    semantics and immutable state.
    
    Business Rules:
    - Confidence score must be between 0.0 and 1.0
    - Threat level must be valid enum value
    - Indicators must provide actionable security information
    - Recommended action must be specific and actionable
    """
    threat_level: SecurityThreatLevel
    confidence_score: float
    indicators: List[str]
    recommended_action: str
    
    def __post_init__(self):
        """Validate assessment data after initialization."""
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ValueError("Confidence score must be between 0.0 and 1.0")
        
        if not self.indicators:
            raise ValueError("Security indicators are required")
        
        if not self.recommended_action:
            raise ValueError("Recommended action is required")


@dataclass(frozen=True)
class TokenPair:
    """
    Value object representing an access/refresh token pair.
    
    This value object encapsulates a complete token pair with security
    metadata, following DDD principles with clear business semantics
    and immutable state.
    
    Business Rules:
    - Both access and refresh tokens must be provided
    - Token type must be valid (default: bearer)
    - Expiration time must be positive
    - Family ID must be provided for security tracking
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes default
    family_id: str = ""
    
    def __post_init__(self):
        """Validate token pair data after initialization."""
        if not self.access_token:
            raise ValueError("Access token is required")
        
        if not self.refresh_token:
            raise ValueError("Refresh token is required")
        
        if self.expires_in <= 0:
            raise ValueError("Expiration time must be positive")
        
        if not self.family_id:
            raise ValueError("Family ID is required for security tracking")


@dataclass(frozen=True)
class TokenValidationResult:
    """
    Value object representing token validation results.
    
    This value object encapsulates the results of token validation
    including security assessment and user information, following DDD
    principles with clear business semantics and immutable state.
    
    Business Rules:
    - User ID must be positive
    - Security assessment must be provided
    - Token payload must be valid
    - Validation timestamp must be current
    """
    user_id: int
    token_payload: Dict[str, Any]
    security_assessment: SecurityAssessment
    validated_at: datetime
    family_id: Optional[str] = None
    
    def __post_init__(self):
        """Validate validation result data after initialization."""
        if self.user_id <= 0:
            raise ValueError("User ID must be positive")
        
        if not self.token_payload:
            raise ValueError("Token payload is required")
        
        if not self.validated_at:
            raise ValueError("Validation timestamp is required")


@dataclass(frozen=True)
class SecurityIncident:
    """
    Value object representing a security incident.
    
    This value object encapsulates security incident information
    for audit trail and response coordination, following DDD principles
    with clear business semantics and immutable state.
    
    Business Rules:
    - Incident type must be specified
    - Threat level must be valid
    - Description must provide actionable information
    - Timestamp must be current
    """
    incident_type: str
    threat_level: SecurityThreatLevel
    description: str
    user_id: Optional[int] = None
    correlation_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        """Validate incident data after initialization."""
        if not self.incident_type:
            raise ValueError("Incident type is required")
        
        if not self.description:
            raise ValueError("Incident description is required")
        
        if self.user_id is not None and self.user_id <= 0:
            raise ValueError("User ID must be positive if provided") 