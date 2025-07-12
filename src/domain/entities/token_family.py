"""
Token Family Domain Entity for Advanced Security Patterns.

This domain entity implements the token family security pattern following
Domain-Driven Design principles with rich business logic and clear ubiquitous language.

Domain Concepts:
- Token Family: A group of related tokens sharing security properties and lifecycle
- Token Reuse Detection: Real-time detection of previously revoked token usage  
- Family-wide Revocation: Immediate security containment when violations are detected
- Security Incident: Any event indicating potential compromise or attack

Business Rules:
- Each family has a unique identifier and belongs to a single user
- Reuse of any revoked token compromises the entire family
- Compromised families cannot issue new tokens
- Families expire based on the longest-lived member token
- Status transitions follow security lifecycle rules
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.token_usage_event import TokenUsageEvent
from src.domain.value_objects.token_usage_record import TokenUsageRecord


class TokenFamily:
    """
    Domain entity representing a family of related tokens for security tracking.
    
    This entity encapsulates core business logic related to token family security,
    following Domain-Driven Design principles with rich behavior and clear
    ubiquitous language.
    
    Security Features:
    - Reuse detection: Detects when revoked tokens are used
    - Family-wide revocation: Compromises entire family on detection
    - Status management: Enforces valid status transitions
    - Token lifecycle: Manages active and revoked token collections
    
    Business Rules:
    - Each family has a unique identifier and belongs to a single user
    - Reuse of any revoked token compromises the entire family
    - Compromised families cannot issue new tokens
    - Families expire based on the longest-lived member token
    - Status transitions follow security lifecycle rules
    """
    
    def __init__(
        self,
        family_id: str,
        user_id: int,
        status: TokenFamilyStatus = TokenFamilyStatus.ACTIVE,
        created_at: Optional[datetime] = None,
        last_used_at: Optional[datetime] = None,
        compromised_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        compromise_reason: Optional[str] = None,
        security_score: float = 1.0,
        active_tokens: Optional[List[TokenId]] = None,
        revoked_tokens: Optional[List[TokenId]] = None,
        usage_history: Optional[List[TokenUsageRecord]] = None
    ):
        """Initialize token family with validation."""
        if not family_id:
            raise ValueError("Family ID is required")
        if user_id <= 0:
            raise ValueError("User ID must be positive")
        if not (0.0 <= security_score <= 1.0):
            raise ValueError("Security score must be between 0.0 and 1.0")
        
        self._family_id = family_id
        self._user_id = user_id
        self._status = status
        self._created_at = created_at or datetime.now(timezone.utc)
        self._last_used_at = last_used_at
        self._compromised_at = compromised_at
        self._expires_at = expires_at
        self._compromise_reason = compromise_reason
        self._security_score = security_score
        
        # Initialize collections
        self._active_tokens: List[TokenId] = active_tokens or []
        self._revoked_tokens: List[TokenId] = revoked_tokens or []
        self._usage_history: List[TokenUsageRecord] = usage_history or []
    
    # === Identity and Core Properties ===
    
    @property
    def family_id(self) -> str:
        """Get family identifier."""
        return self._family_id
    
    @property
    def user_id(self) -> int:
        """Get user identifier."""
        return self._user_id
    
    @property
    def status(self) -> TokenFamilyStatus:
        """Get family status."""
        return self._status
    
    @property
    def created_at(self) -> datetime:
        """Get creation timestamp."""
        return self._created_at
    
    @property
    def last_used_at(self) -> Optional[datetime]:
        """Get last usage timestamp."""
        return self._last_used_at
    
    @property
    def compromised_at(self) -> Optional[datetime]:
        """Get compromise timestamp."""
        return self._compromised_at
    
    @property
    def expires_at(self) -> Optional[datetime]:
        """Get expiration timestamp."""
        return self._expires_at
    
    @property
    def compromise_reason(self) -> Optional[str]:
        """Get compromise reason."""
        return self._compromise_reason
    
    @property
    def security_score(self) -> float:
        """Get security score."""
        return self._security_score
    
    @property
    def active_tokens(self) -> List[TokenId]:
        """Get active tokens."""
        return self._active_tokens.copy()
    
    @property
    def revoked_tokens(self) -> List[TokenId]:
        """Get revoked tokens."""
        return self._revoked_tokens.copy()
    
    @property
    def usage_history(self) -> List[TokenUsageRecord]:
        """Get usage history."""
        return self._usage_history.copy()
    
    # === Business Logic Methods ===
    
    def add_token(
        self, 
        token_id: TokenId, 
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Add a new token to the family.
        
        Business Rules:
        - Cannot add tokens to compromised families
        - Cannot add tokens to revoked families
        - Cannot add duplicate tokens
        - Records usage event for audit trail
        
        Args:
            token_id: The token ID to add
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            
        Raises:
            ValueError: If family is compromised, revoked, or token already exists
        """
        if not self._status.allows_token_operations():
            raise ValueError(f"Cannot add tokens to {self._status.value} family")
        
        if token_id in self._active_tokens:
            raise ValueError(f"Token {token_id.mask_for_logging()} already exists in family")
        
        # Add to active tokens
        self._active_tokens.append(token_id)
        
        # Record usage event
        usage_record = TokenUsageRecord(
            token_id=token_id,
            event_type=TokenUsageEvent.ISSUED,
            timestamp=datetime.now(timezone.utc),
            security_context=security_context,
            correlation_id=correlation_id
        )
        self._usage_history.append(usage_record)
        
        # Update last used time
        self._last_used_at = datetime.now(timezone.utc)
    
    def use_token(
        self,
        token_id: TokenId,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Record token usage and detect reuse attacks.
        
        Business Rules:
        - Reuse of revoked tokens compromises the entire family
        - Unknown token usage compromises the entire family
        - Valid usage updates last used timestamp
        - Records usage event for audit trail
        
        Args:
            token_id: The token being used
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if usage is valid, False if reuse detected
        """
        current_time = datetime.now(timezone.utc)
        
        # Check if token was previously revoked (reuse attack)
        if token_id in self._revoked_tokens:
            self._detect_reuse_attack(token_id, security_context, correlation_id)
            return False
        
        # Check if token is in active list
        if token_id not in self._active_tokens:
            # Unknown token usage - potential attack
            self._detect_reuse_attack(
                token_id, security_context, correlation_id,
                reason="Unknown token used in family"
            )
            return False
        
        # Record legitimate usage
        usage_record = TokenUsageRecord(
            token_id=token_id,
            event_type=TokenUsageEvent.USED,
            timestamp=current_time,
            security_context=security_context,
            correlation_id=correlation_id
        )
        self._usage_history.append(usage_record)
        
        # Update last used time
        self._last_used_at = current_time
        
        return True
    
    def refresh_token(
        self,
        old_token_id: TokenId,
        new_token_id: TokenId,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Refresh a token by revoking the old one and adding a new one.
        
        Business Rules:
        - Cannot refresh tokens in compromised families
        - Cannot refresh tokens in revoked families
        - Old token must be valid before refresh
        - Records refresh event for audit trail
        
        Args:
            old_token_id: The token being refreshed
            new_token_id: The new token being issued
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if refresh is successful, False if family is compromised
        """
        if not self._status.allows_token_operations():
            return False
        
        # Validate old token usage first
        if not self.use_token(old_token_id, security_context, correlation_id):
            return False
        
        # Revoke old token
        self.revoke_token(old_token_id, security_context, correlation_id)
        
        # Add new token
        self.add_token(new_token_id, security_context, correlation_id)
        
        # Record refresh event
        usage_record = TokenUsageRecord(
            token_id=new_token_id,
            event_type=TokenUsageEvent.REFRESHED,
            timestamp=datetime.now(timezone.utc),
            security_context=security_context,
            correlation_id=correlation_id
        )
        self._usage_history.append(usage_record)
        
        return True
    
    def revoke_token(
        self,
        token_id: TokenId,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Revoke a token from the family.
        
        Business Rules:
        - Token must be active to be revoked
        - Revoked tokens are moved to revoked collection
        - Records revocation event for audit trail
        
        Args:
            token_id: The token to revoke
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            
        Raises:
            ValueError: If token is not active or already revoked
        """
        if token_id not in self._active_tokens:
            # If token is already revoked, just return without error
            if token_id in self._revoked_tokens:
                return
            raise ValueError(f"Token {token_id.mask_for_logging()} is not active")
        
        # Remove from active tokens
        self._active_tokens.remove(token_id)
        
        # Add to revoked tokens
        self._revoked_tokens.append(token_id)
        
        # Record revocation event
        usage_record = TokenUsageRecord(
            token_id=token_id,
            event_type=TokenUsageEvent.REVOKED,
            timestamp=datetime.now(timezone.utc),
            security_context=security_context,
            correlation_id=correlation_id
        )
        self._usage_history.append(usage_record)
    
    def compromise_family(
        self,
        reason: str,
        detected_token: Optional[TokenId] = None,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Compromise the entire token family.
        
        Business Rules:
        - Compromise is irreversible
        - All tokens are moved to revoked collection
        - Records compromise event for audit trail
        - Updates security score to 0.0
        
        Args:
            reason: Reason for compromise
            detected_token: Token that triggered compromise
            security_context: Security context for tracking
            correlation_id: Request correlation ID
        """
        if self._status.is_terminal():
            return  # Already compromised or expired
        
        # Update status
        self._status = TokenFamilyStatus.COMPROMISED
        self._compromised_at = datetime.now(timezone.utc)
        self._compromise_reason = reason
        self._security_score = 0.0
        
        # Move all active tokens to revoked
        for token_id in self._active_tokens:
            self._revoked_tokens.append(token_id)
        self._active_tokens.clear()
        
        # Record compromise event
        if detected_token:
            usage_record = TokenUsageRecord(
                token_id=detected_token,
                event_type=TokenUsageEvent.COMPROMISED,
                timestamp=datetime.now(timezone.utc),
                security_context=security_context,
                correlation_id=correlation_id
            )
            self._usage_history.append(usage_record)
    
    def _detect_reuse_attack(
        self,
        token_id: TokenId,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None,
        reason: str = "Revoked token reuse detected"
    ) -> None:
        """
        Handle token reuse attack detection.
        
        Args:
            token_id: The token that was reused
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            reason: Reason for reuse detection
        """
        # Record reuse detection event
        usage_record = TokenUsageRecord(
            token_id=token_id,
            event_type=TokenUsageEvent.REUSE_DETECTED,
            timestamp=datetime.now(timezone.utc),
            security_context=security_context,
            correlation_id=correlation_id
        )
        self._usage_history.append(usage_record)
        
        # Compromise the family
        self.compromise_family(reason, token_id, security_context, correlation_id)
    
    # === Status and Validation Methods ===
    
    def is_active(self) -> bool:
        """Check if family is active."""
        return self._status == TokenFamilyStatus.ACTIVE
    
    def is_compromised(self) -> bool:
        """Check if family is compromised."""
        return self._status == TokenFamilyStatus.COMPROMISED
    
    def is_revoked(self) -> bool:
        """Check if family is revoked."""
        return self._status == TokenFamilyStatus.REVOKED
    
    def is_expired(self) -> bool:
        """Check if family is expired."""
        return self._status == TokenFamilyStatus.EXPIRED
    
    def has_token(self, token_id: TokenId) -> bool:
        """Check if family contains a token."""
        return token_id in self._active_tokens or token_id in self._revoked_tokens
    
    def is_token_active(self, token_id: TokenId) -> bool:
        """Check if a token is active in the family."""
        return token_id in self._active_tokens
    
    def is_token_revoked(self, token_id: TokenId) -> bool:
        """Check if a token is revoked in the family."""
        return token_id in self._revoked_tokens
    
    def update_expiration(self) -> None:
        """Update family expiration status."""
        if self._expires_at and datetime.now(timezone.utc) >= self._expires_at:
            if self._status != TokenFamilyStatus.COMPROMISED:
                self._status = TokenFamilyStatus.EXPIRED
    
    # === Factory Methods ===
    
    @classmethod
    def create_new_family(
        cls,
        family_id: str,
        user_id: int,
        expires_at: Optional[datetime] = None,
        security_context: Optional[SecurityContext] = None,
        initial_token_id: Optional[TokenId] = None
    ) -> "TokenFamily":
        """
        Factory method to create a new token family.
        
        Args:
            family_id: Unique family identifier
            user_id: User identifier
            expires_at: Optional expiration time
            security_context: Security context for tracking
            initial_token_id: Optional initial token to add
            
        Returns:
            TokenFamily: New token family instance
        """
        family = cls(
            family_id=family_id,
            user_id=user_id,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            last_used_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            security_score=1.0
        )
        
        # Add initial token if provided
        if initial_token_id:
            family.add_token(
                token_id=initial_token_id,
                security_context=security_context,
                correlation_id=None
            )
        
        return family
    
    # === Repository Support Methods ===
    
    def set_active_tokens(self, tokens: List[TokenId]) -> None:
        """
        Set active tokens (used by repository for encrypted data mapping).
        
        This method is used by the repository layer to set decrypted token data
        when mapping from ORM model to domain entity.
        
        Args:
            tokens: List of active token IDs
        """
        self._active_tokens = tokens.copy() if tokens else []
    
    def set_revoked_tokens(self, tokens: List[TokenId]) -> None:
        """
        Set revoked tokens (used by repository for encrypted data mapping).
        
        This method is used by the repository layer to set decrypted token data
        when mapping from ORM model to domain entity.
        
        Args:
            tokens: List of revoked token IDs
        """
        self._revoked_tokens = tokens.copy() if tokens else []
    
    def set_usage_history(self, history: List[TokenUsageRecord]) -> None:
        """
        Set usage history (used by repository for encrypted data mapping).
        
        This method is used by the repository layer to set decrypted usage data
        when mapping from ORM model to domain entity.
        
        Args:
            history: List of usage history records
        """
        self._usage_history = history.copy() if history else []
    
    # === Analytics and Security Methods ===
    
    def get_security_metadata(self) -> Dict[str, Any]:
        """
        Get security metadata for monitoring and analysis.
        
        Returns:
            Dict[str, Any]: Security metadata including family info, status, and metrics
        """
        return {
            "family_id": self._family_id,
            "user_id": self._user_id,
            "status": self._status.value,
            "security_score": self._security_score,
            "active_tokens_count": len(self._active_tokens),
            "revoked_tokens_count": len(self._revoked_tokens),
            "usage_history_count": len(self._usage_history),
            "compromise_reason": self._compromise_reason,
            "created_at": self._created_at.isoformat() if self._created_at else None,
            "last_used_at": self._last_used_at.isoformat() if self._last_used_at else None,
            "compromised_at": self._compromised_at.isoformat() if self._compromised_at else None,
            "expires_at": self._expires_at.isoformat() if self._expires_at else None
        }
    
    def get_usage_pattern_analysis(self) -> Dict[str, Any]:
        """
        Analyze usage patterns for security monitoring.
        
        Returns:
            Dict[str, Any]: Usage pattern analysis with risk assessment
        """
        total_events = len(self._usage_history)
        
        if total_events == 0:
            return {
                "total_events": 0,
                "suspicious_activity": False,
                "risk_level": "low",
                "warnings": []
            }
        
        # Analyze IP diversity
        unique_ips = set()
        for record in self._usage_history:
            if record.get_client_ip():
                unique_ips.add(record.get_client_ip())
        
        # Check for suspicious patterns
        warnings = []
        suspicious_activity = False
        risk_level = "low"
        
        # High frequency usage (more than 5 events in short time)
        if total_events > 5:
            warnings.append("high_frequency_usage")
            suspicious_activity = True
            risk_level = "medium"
        
        # Multiple IPs (more than 3 unique IPs)
        if len(unique_ips) > 3:
            warnings.append("multiple_ips_detected")
            suspicious_activity = True
            risk_level = "high"
        
        # Reuse detection
        reuse_events = [
            record for record in self._usage_history
            if record.event_type == TokenUsageEvent.REUSE_DETECTED
        ]
        if reuse_events:
            warnings.append("reuse_detected")
            suspicious_activity = True
            risk_level = "critical"
        
        # Compromise events
        compromise_events = [
            record for record in self._usage_history
            if record.event_type == TokenUsageEvent.COMPROMISED
        ]
        if compromise_events:
            warnings.append("compromise_detected")
            suspicious_activity = True
            risk_level = "critical"
        
        return {
            "total_events": total_events,
            "unique_ips_count": len(unique_ips),
            "suspicious_activity": suspicious_activity,
            "risk_level": risk_level,
            "warnings": warnings
        } 