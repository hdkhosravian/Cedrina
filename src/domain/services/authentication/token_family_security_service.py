"""
Token Family Security Service for Advanced Reuse Detection.

This domain service implements the token family security pattern with advanced
reuse detection, family-wide revocation, and comprehensive security monitoring.

The service provides:
- Token family lifecycle management
- Real-time reuse attack detection
- Automatic family compromise and revocation
- Security analytics and forensic analysis
- Performance optimized security checks

Security Patterns Implemented:
- Token Family Pattern: Groups related tokens for collective security
- Reuse Detection: Detects and prevents token replay attacks
- Family-wide Revocation: Compromises entire family on violation
- Zero-trust Validation: Every token use is validated against family state
- Forensic Logging: Comprehensive audit trails for security analysis

Domain-Driven Design:
- Domain service encapsulating complex security business logic
- Rich domain entities with security-focused behavior
- Clear separation of security concerns from infrastructure
- Ubiquitous language for security concepts and patterns
"""

import asyncio
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

import structlog

from src.domain.entities.token_family import (
    TokenFamily, 
    TokenFamilyStatus, 
    TokenUsageEvent,
    TokenUsageRecord
)
from src.domain.value_objects.jwt_token import TokenId
from src.domain.interfaces.repositories.token_family_repository import ITokenFamilyRepository
from src.core.exceptions import AuthenticationError
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class TokenFamilySecurityResult:
    """Result of token family security operations."""
    
    is_valid: bool
    family: Optional[TokenFamily] = None
    security_violation: Optional[str] = None
    compromise_detected: bool = False
    family_compromised: bool = False
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize mutable fields."""
        if self.metadata is None:
            object.__setattr__(self, 'metadata', {})


class TokenFamilySecurityService:
    """
    Domain service for advanced token family security management.
    
    This service implements the token family security pattern to provide
    advanced protection against token reuse attacks and compromised sessions.
    
    Key Security Features:
    - Real-time reuse detection with immediate family compromise
    - Family-wide revocation on security violations
    - Comprehensive usage tracking and forensic analysis
    - Performance optimized security checks for high-throughput systems
    - Advanced threat pattern analysis and risk scoring
    
    Security Architecture:
    - Zero-trust token validation with family state verification
    - Atomic security operations for consistency
    - Fail-secure error handling with comprehensive logging
    - Defense in depth with multiple security layers
    - Proactive threat detection and response
    """
    
    def __init__(self, token_family_repository: ITokenFamilyRepository):
        """
        Initialize token family security service.
        
        Args:
            token_family_repository: Repository for token family persistence
        """
        self.repository = token_family_repository
        self._security_metrics = {
            "families_created": 0,
            "reuse_attacks_detected": 0,
            "families_compromised": 0,
            "security_checks_performed": 0,
        }
    
    async def create_token_family(
        self,
        user_id: int,
        initial_token_id: TokenId,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> TokenFamily:
        """
        Create a new token family with initial security setup.
        
        Args:
            user_id: User ID for the token family
            initial_token_id: First token to add to the family
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            expires_at: Optional family expiration time
            
        Returns:
            TokenFamily: The created token family
            
        Raises:
            ValueError: If parameters are invalid
        """
        if user_id <= 0:
            raise ValueError("User ID must be positive")
        
        if not initial_token_id:
            raise ValueError("Initial token ID is required")
        
        # Create new token family
        family = TokenFamily(
            user_id=user_id,
            expires_at=expires_at or datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        # Add initial token
        family.add_token(
            token_id=initial_token_id,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id
        )
        
        # Persist the family
        created_family = await self.repository.create_family(family)
        
        # Update metrics
        self._security_metrics["families_created"] += 1
        
        logger.info(
            "Token family created",
            family_id=created_family.family_id,
            user_id=user_id,
            initial_token=initial_token_id.mask_for_logging(),
            correlation_id=correlation_id,
            security_enhanced=True
        )
        
        return created_family
    
    async def validate_token_usage(
        self,
        token_id: TokenId,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> TokenFamilySecurityResult:
        """
        Validate token usage with comprehensive security checks.
        
        This method performs:
        1. Find the token family containing the token
        2. Check for token reuse (previously revoked)
        3. Validate family status and security state
        4. Record usage event with security context
        5. Detect and handle security violations
        
        Args:
            token_id: Token being used
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            TokenFamilySecurityResult: Validation result with security metadata
        """
        validation_start = time.time()
        self._security_metrics["security_checks_performed"] += 1
        
        logger.debug(
            "Token family validation initiated",
            token_id=token_id.mask_for_logging(),
            correlation_id=correlation_id,
            security_enhanced=True
        )
        
        try:
            # Step 1: Find token family
            family = await self.repository.get_family_by_token(token_id)
            
            if not family:
                # Token not in any family - create isolated validation result
                logger.warning(
                    "Token not found in any family",
                    token_id=token_id.mask_for_logging(),
                    correlation_id=correlation_id,
                    security_enhanced=True
                )
                return TokenFamilySecurityResult(
                    is_valid=False,
                    security_violation="Token not found in any family",
                    metadata={"validation_time_ms": (time.time() - validation_start) * 1000}
                )
            
            # Step 2: Check family status
            if family.is_compromised():
                logger.warning(
                    "Token usage attempted on compromised family",
                    family_id=family.family_id,
                    token_id=token_id.mask_for_logging(),
                    compromise_reason=family.compromise_reason,
                    correlation_id=correlation_id,
                    security_enhanced=True
                )
                return TokenFamilySecurityResult(
                    is_valid=False,
                    family=family,
                    security_violation="Family is compromised",
                    family_compromised=True,
                    metadata={
                        "validation_time_ms": (time.time() - validation_start) * 1000,
                        "compromise_reason": family.compromise_reason,
                        "compromised_at": family.compromised_at.isoformat() if family.compromised_at else None
                    }
                )
            
            if not family.is_active():
                logger.warning(
                    "Token usage attempted on inactive family",
                    family_id=family.family_id,
                    token_id=token_id.mask_for_logging(),
                    family_status=family.status.value,
                    correlation_id=correlation_id,
                    security_enhanced=True
                )
                return TokenFamilySecurityResult(
                    is_valid=False,
                    family=family,
                    security_violation=f"Family is {family.status.value}",
                    metadata={
                        "validation_time_ms": (time.time() - validation_start) * 1000,
                        "family_status": family.status.value
                    }
                )
            
            # Step 3: Validate token usage with reuse detection
            is_usage_valid = family.use_token(
                token_id=token_id,
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id
            )
            
            if not is_usage_valid:
                # Reuse attack detected - family is automatically compromised
                await self._handle_reuse_attack(family, token_id, correlation_id)
                
                return TokenFamilySecurityResult(
                    is_valid=False,
                    family=family,
                    security_violation="Token reuse attack detected",
                    compromise_detected=True,
                    family_compromised=True,
                    metadata={
                        "validation_time_ms": (time.time() - validation_start) * 1000,
                        "attack_type": "token_reuse",
                        "detected_token": token_id.mask_for_logging()
                    }
                )
            
            # Step 4: Update family in repository
            updated_family = await self.repository.update_family(family)
            
            # Step 5: Success result
            validation_time = (time.time() - validation_start) * 1000
            
            logger.debug(
                "Token usage validation successful",
                family_id=family.family_id,
                token_id=token_id.mask_for_logging(),
                validation_time_ms=validation_time,
                correlation_id=correlation_id,
                security_enhanced=True
            )
            
            return TokenFamilySecurityResult(
                is_valid=True,
                family=updated_family,
                metadata={
                    "validation_time_ms": validation_time,
                    "family_security_score": family.security_score,
                    "usage_pattern": family.get_usage_pattern_analysis()
                }
            )
            
        except Exception as e:
            logger.error(
                "Token family validation error",
                token_id=token_id.mask_for_logging(),
                error=str(e),
                error_type=type(e).__name__,
                correlation_id=correlation_id,
                security_enhanced=True
            )
            
            return TokenFamilySecurityResult(
                is_valid=False,
                security_violation=f"Validation error: {str(e)}",
                metadata={
                    "validation_time_ms": (time.time() - validation_start) * 1000,
                    "error_type": type(e).__name__
                }
            )
    
    async def refresh_token_with_family_security(
        self,
        old_token_id: TokenId,
        new_token_id: TokenId,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> TokenFamilySecurityResult:
        """
        Refresh a token with family security validation.
        
        This method:
        1. Validates the old token usage
        2. Checks for family compromise
        3. Performs atomic token refresh
        4. Updates family security state
        5. Records security events
        
        Args:
            old_token_id: Token being refreshed
            new_token_id: New token being issued
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            TokenFamilySecurityResult: Refresh result with security metadata
        """
        logger.info(
            "Token refresh with family security initiated",
            old_token=old_token_id.mask_for_logging(),
            new_token=new_token_id.mask_for_logging(),
            correlation_id=correlation_id,
            security_enhanced=True
        )
        
        # Step 1: Validate old token usage
        validation_result = await self.validate_token_usage(
            token_id=old_token_id,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id
        )
        
        if not validation_result.is_valid:
            logger.warning(
                "Token refresh failed - old token validation failed",
                old_token=old_token_id.mask_for_logging(),
                security_violation=validation_result.security_violation,
                correlation_id=correlation_id,
                security_enhanced=True
            )
            return validation_result
        
        family = validation_result.family
        if not family:
            return TokenFamilySecurityResult(
                is_valid=False,
                security_violation="Family not found for refresh"
            )
        
        # Step 2: Perform atomic token refresh
        refresh_successful = family.refresh_token(
            old_token_id=old_token_id,
            new_token_id=new_token_id,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id
        )
        
        if not refresh_successful:
            logger.error(
                "Token refresh failed in family",
                family_id=family.family_id,
                old_token=old_token_id.mask_for_logging(),
                family_status=family.status.value,
                correlation_id=correlation_id,
                security_enhanced=True
            )
            return TokenFamilySecurityResult(
                is_valid=False,
                family=family,
                security_violation="Family refresh failed - possible compromise"
            )
        
        # Step 3: Update family in repository
        updated_family = await self.repository.update_family(family)
        
        logger.info(
            "Token refresh with family security completed",
            family_id=family.family_id,
            old_token=old_token_id.mask_for_logging(),
            new_token=new_token_id.mask_for_logging(),
            correlation_id=correlation_id,
            security_enhanced=True
        )
        
        return TokenFamilySecurityResult(
            is_valid=True,
            family=updated_family,
            metadata={
                "refresh_successful": True,
                "family_security_score": family.security_score,
                "active_tokens": len(family.active_tokens),
                "revoked_tokens": len(family.revoked_tokens)
            }
        )
    
    async def compromise_family_on_violation(
        self,
        family_id: str,
        reason: str,
        detected_token: Optional[TokenId] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Compromise a token family due to security violation.
        
        Args:
            family_id: Family to compromise
            reason: Reason for compromise
            detected_token: Token that triggered the violation
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if family was compromised, False if not found
        """
        self._security_metrics["families_compromised"] += 1
        
        logger.critical(
            "Token family compromise initiated",
            family_id=family_id,
            reason=reason,
            detected_token=detected_token.mask_for_logging() if detected_token else None,
            correlation_id=correlation_id,
            security_enhanced=True
        )
        
        # Use repository for atomic compromise operation
        success = await self.repository.compromise_family(
            family_id=family_id,
            reason=reason,
            detected_token=detected_token
        )
        
        if success:
            logger.critical(
                "Token family compromised successfully",
                family_id=family_id,
                reason=reason,
                correlation_id=correlation_id,
                security_enhanced=True
            )
        else:
            logger.error(
                "Failed to compromise token family",
                family_id=family_id,
                reason=reason,
                correlation_id=correlation_id,
                security_enhanced=True
            )
        
        return success
    
    async def _handle_reuse_attack(
        self,
        family: TokenFamily,
        detected_token: TokenId,
        correlation_id: Optional[str] = None
    ) -> None:
        """Handle detection of token reuse attack."""
        self._security_metrics["reuse_attacks_detected"] += 1
        
        logger.critical(
            "Token reuse attack detected - compromising family",
            family_id=family.family_id,
            detected_token=detected_token.mask_for_logging(),
            correlation_id=correlation_id,
            security_enhanced=True
        )
        
        # The family entity has already been compromised by the use_token call
        # Now we need to persist the compromise
        await self.repository.update_family(family)
        
        # Additional security alerting could be implemented here
        # TODO: Implement security operations center (SOC) notifications
        # TODO: Implement user security alerts
        # TODO: Implement automated incident response
    
    async def get_family_security_status(self, token_id: TokenId) -> Optional[Dict[str, Any]]:
        """
        Get security status for a token's family.
        
        Args:
            token_id: Token to check
            
        Returns:
            Optional[Dict[str, Any]]: Security status if family found
        """
        family = await self.repository.get_family_by_token(token_id)
        
        if not family:
            return None
        
        return {
            "family_id": family.family_id,
            "status": family.status.value,
            "is_active": family.is_active(),
            "is_compromised": family.is_compromised(),
            "security_score": family.security_score,
            "compromise_reason": family.compromise_reason,
            "last_used_at": family.last_used_at.isoformat() if family.last_used_at else None,
            "usage_pattern": family.get_usage_pattern_analysis(),
            "security_metadata": family.get_security_metadata()
        }
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get service security metrics."""
        return {
            **self._security_metrics,
            "reuse_detection_rate": (
                self._security_metrics["reuse_attacks_detected"] / 
                max(self._security_metrics["security_checks_performed"], 1)
            ),
            "family_compromise_rate": (
                self._security_metrics["families_compromised"] / 
                max(self._security_metrics["families_created"], 1)
            )
        } 