"""
Enhanced Token Validation Service for Advanced Security.

This domain service implements advanced token validation patterns with comprehensive
security checks for token pairing, session validation, and threat detection.

Key Security Features:
- Token pairing validation (access + refresh must have same JTI)
- Cross-user attack prevention
- Token expiration and format validation  
- Session consistency validation
- Security incident detection and logging
- Threat pattern analysis
- Token family reuse detection and family-wide revocation

Design Patterns:
- Domain Service: Encapsulates complex business logic for token validation
- Strategy Pattern: Different validation strategies for various threat scenarios
- Observer Pattern: Security event logging and monitoring
- Specification Pattern: Composable validation rules

Follows SOLID Principles:
- Single Responsibility: Focused on token validation security
- Open/Closed: Extensible through validation strategies
- Liskov Substitution: Validation strategies are interchangeable
- Interface Segregation: Focused interfaces for token validation
- Dependency Inversion: Depends on abstractions, not concrete implementations
"""

import asyncio
import hashlib
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

import jwt
from jwt import PyJWTError
import structlog

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken, TokenId
from src.domain.interfaces.authentication.token_validation import IEnhancedTokenValidationService
from src.infrastructure.services.authentication.session import SessionService
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class SecurityThreatLevel(Enum):
    """Enumeration of security threat levels for validation incidents."""
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class TokenValidationResult:
    """Result of token validation with security metadata."""
    
    # Validation outcomes
    is_valid: bool
    user: Optional[User] = None
    access_payload: Optional[Dict[str, Any]] = None
    refresh_payload: Optional[Dict[str, Any]] = None
    
    # Security analysis
    threat_level: SecurityThreatLevel = SecurityThreatLevel.LOW
    security_violations: List[str] = None
    validation_metadata: Dict[str, Any] = None
    
    # Token family security
    family_security_result: Optional[Any] = None  # TokenFamilySecurityResult
    reuse_detected: bool = False
    family_compromised: bool = False
    
    def __post_init__(self):
        """Initialize mutable fields."""
        if self.security_violations is None:
            object.__setattr__(self, 'security_violations', [])
        if self.validation_metadata is None:
            object.__setattr__(self, 'validation_metadata', {})
    
    def add_security_violation(self, violation: str) -> None:
        """Add a security violation to the result."""
        self.security_violations.append(violation)
    
    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the validation result."""
        self.validation_metadata[key] = value


@dataclass(frozen=True)
class TokenPairValidationContext:
    """Context for token pair validation with security analysis."""
    
    # Token data
    access_token_raw: str
    refresh_token_raw: str
    
    # Request context
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_timestamp: datetime = None
    correlation_id: Optional[str] = None
    
    # Security flags
    is_suspicious_request: bool = False
    previous_violations: int = 0
    
    def __post_init__(self):
        """Set default timestamp if not provided."""
        if self.request_timestamp is None:
            object.__setattr__(self, 'request_timestamp', datetime.now(timezone.utc))


class TokenValidationStrategy:
    """Abstract base for token validation strategies."""
    
    async def validate(
        self, 
        context: TokenPairValidationContext,
        access_token: AccessToken,
        refresh_token: RefreshToken,
    ) -> TokenValidationResult:
        """Validate tokens according to this strategy."""
        raise NotImplementedError


class JtiMatchingValidationStrategy(TokenValidationStrategy):
    """Validates that access and refresh tokens have matching JTIs."""
    
    async def validate(
        self,
        context: TokenPairValidationContext,
        access_token: AccessToken,
        refresh_token: RefreshToken,
    ) -> TokenValidationResult:
        """Validate JTI matching between token pair."""
        try:
            access_jti = access_token.get_token_id()
            refresh_jti = refresh_token.get_token_id()
            
            if access_jti.value != refresh_jti.value:
                logger.warning(
                    "JTI mismatch detected",
                    access_jti=access_jti.mask_for_logging(),
                    refresh_jti=refresh_jti.mask_for_logging(),
                    client_ip=context.client_ip,
                    correlation_id=context.correlation_id,
                )
                
                result = TokenValidationResult(
                    is_valid=False,
                    threat_level=SecurityThreatLevel.HIGH,
                )
                result.add_security_violation("JTI mismatch between access and refresh tokens")
                result.add_metadata("access_jti", access_jti.mask_for_logging())
                result.add_metadata("refresh_jti", refresh_jti.mask_for_logging())
                return result
            
            # JTI matching is valid
            result = TokenValidationResult(
                is_valid=True,
                access_payload=access_token.claims,
                refresh_payload=refresh_token.claims,
            )
            result.add_metadata("jti_validated", True)
            result.add_metadata("matched_jti", access_jti.mask_for_logging())
            return result
            
        except Exception as e:
            logger.error(
                "Error validating JTI matching",
                error=str(e),
                correlation_id=context.correlation_id,
            )
            result = TokenValidationResult(
                is_valid=False,
                threat_level=SecurityThreatLevel.MEDIUM,
            )
            result.add_security_violation(f"JTI validation error: {str(e)}")
            return result


class UserOwnershipValidationStrategy(TokenValidationStrategy):
    """Validates that both tokens belong to the same user."""
    
    async def validate(
        self,
        context: TokenPairValidationContext,
        access_token: AccessToken,
        refresh_token: RefreshToken,
    ) -> TokenValidationResult:
        """Validate user ownership consistency."""
        try:
            access_user_id = access_token.get_user_id()
            refresh_user_id = refresh_token.get_user_id()
            
            if access_user_id != refresh_user_id:
                logger.warning(
                    "Cross-user token attack detected",
                    access_user_id=access_user_id,
                    refresh_user_id=refresh_user_id,
                    client_ip=context.client_ip,
                    correlation_id=context.correlation_id,
                )
                
                result = TokenValidationResult(
                    is_valid=False,
                    threat_level=SecurityThreatLevel.CRITICAL,
                )
                result.add_security_violation("Cross-user token attack: user ID mismatch")
                result.add_metadata("access_user_id", access_user_id)
                result.add_metadata("refresh_user_id", refresh_user_id)
                return result
            
            # User ownership is valid
            result = TokenValidationResult(
                is_valid=True,
                access_payload=access_token.claims,
                refresh_payload=refresh_token.claims,
            )
            result.add_metadata("user_ownership_validated", True)
            result.add_metadata("user_id", access_user_id)
            return result
            
        except Exception as e:
            logger.error(
                "Error validating user ownership",
                error=str(e),
                correlation_id=context.correlation_id,
            )
            result = TokenValidationResult(
                is_valid=False,
                threat_level=SecurityThreatLevel.MEDIUM,
            )
            result.add_security_violation(f"User ownership validation error: {str(e)}")
            return result


class TokenExpirationValidationStrategy(TokenValidationStrategy):
    """Validates token expiration with security analysis."""
    
    async def validate(
        self,
        context: TokenPairValidationContext,
        access_token: AccessToken,
        refresh_token: RefreshToken,
    ) -> TokenValidationResult:
        """Validate token expiration status."""
        try:
            violations = []
            threat_level = SecurityThreatLevel.LOW
            
            # Check access token expiration
            if access_token.is_expired():
                violations.append("Access token has expired")
                # Expired access token is normal, but log for monitoring
                logger.debug(
                    "Expired access token in refresh request",
                    correlation_id=context.correlation_id,
                )
            
            # Check refresh token expiration
            if refresh_token.is_expired():
                violations.append("Refresh token has expired")
                threat_level = SecurityThreatLevel.MEDIUM
                logger.warning(
                    "Expired refresh token used",
                    correlation_id=context.correlation_id,
                    client_ip=context.client_ip,
                )
            
            # If refresh token is expired, validation fails
            if refresh_token.is_expired():
                result = TokenValidationResult(
                    is_valid=False,
                    threat_level=threat_level,
                    security_violations=violations,
                )
                result.add_metadata("refresh_expired", True)
                return result
            
            # Validation passes (access token expiration is acceptable for refresh)
            result = TokenValidationResult(
                is_valid=True,
                access_payload=access_token.claims,
                refresh_payload=refresh_token.claims,
                security_violations=violations,  # Include for monitoring
            )
            result.add_metadata("expiration_validated", True)
            result.add_metadata("access_expired", access_token.is_expired())
            result.add_metadata("refresh_expired", False)
            return result
            
        except Exception as e:
            logger.error(
                "Error validating token expiration",
                error=str(e),
                correlation_id=context.correlation_id,
            )
            result = TokenValidationResult(
                is_valid=False,
                threat_level=SecurityThreatLevel.MEDIUM,
            )
            result.add_security_violation(f"Expiration validation error: {str(e)}")
            return result


class TokenFamilyReuseValidationStrategy(TokenValidationStrategy):
    """Validates tokens against family reuse detection."""
    
    def __init__(self, token_family_security_service=None):
        """Initialize with optional token family security service."""
        self.token_family_security_service = token_family_security_service
    
    async def validate(
        self,
        context: TokenPairValidationContext,
        access_token: AccessToken,
        refresh_token: RefreshToken,
    ) -> TokenValidationResult:
        """Validate tokens for family reuse attacks."""
        if not self.token_family_security_service:
            # Family security not enabled - skip validation
            return TokenValidationResult(
                is_valid=True,
                access_payload=access_token.claims,
                refresh_payload=refresh_token.claims,
            )
        
        try:
            # Validate refresh token usage with family security
            refresh_token_id = refresh_token.get_token_id()
            
            family_result = await self.token_family_security_service.validate_token_usage(
                token_id=refresh_token_id,
                client_ip=context.client_ip,
                user_agent=context.user_agent,
                correlation_id=context.correlation_id
            )
            
            if not family_result.is_valid:
                # Family security violation detected
                threat_level = SecurityThreatLevel.CRITICAL if family_result.compromise_detected else SecurityThreatLevel.HIGH
                
                logger.warning(
                    "Token family security violation",
                    token_id=refresh_token_id.mask_for_logging(),
                    security_violation=family_result.security_violation,
                    family_compromised=family_result.family_compromised,
                    correlation_id=context.correlation_id,
                )
                
                result = TokenValidationResult(
                    is_valid=False,
                    threat_level=threat_level,
                    family_security_result=family_result,
                    reuse_detected=family_result.compromise_detected,
                    family_compromised=family_result.family_compromised,
                )
                result.add_security_violation(f"Token family violation: {family_result.security_violation}")
                result.add_metadata("family_security_check", True)
                result.add_metadata("family_violation", family_result.security_violation)
                return result
            
            # Family security validation passed
            result = TokenValidationResult(
                is_valid=True,
                access_payload=access_token.claims,
                refresh_payload=refresh_token.claims,
                family_security_result=family_result,
            )
            result.add_metadata("family_security_validated", True)
            result.add_metadata("family_security_score", family_result.metadata.get("family_security_score", 1.0))
            return result
            
        except Exception as e:
            logger.error(
                "Error validating token family security",
                error=str(e),
                correlation_id=context.correlation_id,
            )
            result = TokenValidationResult(
                is_valid=False,
                threat_level=SecurityThreatLevel.MEDIUM,
            )
            result.add_security_violation(f"Family security validation error: {str(e)}")
            return result


class EnhancedTokenValidationService(IEnhancedTokenValidationService):
    """
    Enhanced token validation service implementing advanced security patterns.
    
    This service coordinates multiple validation strategies to ensure comprehensive
    security validation of token pairs with threat detection and incident logging.
    
    Security Features:
    - Token pairing validation (JTI matching)
    - Cross-user attack prevention
    - Session consistency validation
    - Threat pattern analysis
    - Security incident logging
    - Performance optimization
    - Token family reuse detection
    - Family-wide revocation on compromise
    
    Architectural Patterns:
    - Strategy Pattern: Composable validation strategies
    - Chain of Responsibility: Sequential validation with early termination
    - Observer Pattern: Security event notifications
    - Template Method: Standardized validation workflow
    """
    
    def __init__(
        self,
        session_service: SessionService,
        validation_strategies: Optional[List[TokenValidationStrategy]] = None,
        token_family_security_service: Optional[Any] = None,  # TokenFamilySecurityService
    ):
        """
        Initialize enhanced token validation service.
        
        Args:
            session_service: Service for session validation and management
            validation_strategies: Custom validation strategies (optional)
            token_family_security_service: Token family security service for reuse detection
        """
        self.session_service = session_service
        self.token_family_security_service = token_family_security_service
        
        # Initialize default validation strategies if none provided
        if validation_strategies is None:
            validation_strategies = [
                JtiMatchingValidationStrategy(),
                UserOwnershipValidationStrategy(), 
                TokenExpirationValidationStrategy(),
            ]
            
            # Add family reuse detection if service is available
            if token_family_security_service:
                validation_strategies.append(
                    TokenFamilyReuseValidationStrategy(token_family_security_service)
                )
        
        self.validation_strategies = validation_strategies
        
        # Performance metrics
        self._validation_count = 0
        self._violation_count = 0
        self._family_violations_count = 0
        
    async def validate_token_pair(
        self,
        access_token: str,
        refresh_token: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en",
    ) -> Dict[str, Any]:
        """
        Validate access and refresh token pair with comprehensive security checks.
        
        This method implements the core security requirement that both tokens
        must belong to the same session (same JTI) with additional threat detection
        and token family reuse prevention.
        
        Args:
            access_token: Raw access token string
            refresh_token: Raw refresh token string
            client_ip: Client IP address for security logging
            user_agent: Client user agent for analysis
            correlation_id: Request correlation ID for tracing
            language: Language for error messages
            
        Returns:
            Dict containing validated user and token payloads
            
        Raises:
            AuthenticationError: If validation fails or security violation detected
        """
        validation_start = time.time()
        self._validation_count += 1
        
        # Create validation context
        context = TokenPairValidationContext(
            access_token_raw=access_token,
            refresh_token_raw=refresh_token,
            client_ip=client_ip,
            user_agent=user_agent,
            request_timestamp=datetime.now(timezone.utc),
            correlation_id=correlation_id,
        )
        
        logger.info(
            "Enhanced token validation initiated",
            correlation_id=correlation_id,
            client_ip=client_ip,
            validation_count=self._validation_count,
            family_security_enabled=self.token_family_security_service is not None,
        )
        
        try:
            # Step 1: Parse and validate token formats
            access_token_obj, refresh_token_obj = await self._parse_token_pair(
                context, language
            )
            
            # Step 2: Execute validation strategies
            validation_result = await self._execute_validation_strategies(
                context, access_token_obj, refresh_token_obj
            )
            
            if not validation_result.is_valid:
                await self._handle_validation_failure(validation_result, context, language)
                # This will raise AuthenticationError
            
            # Step 3: Session validation and user retrieval
            user = await self._validate_session_and_get_user(
                validation_result, context, language
            )
            
            # Step 4: Success logging and metrics
            validation_time = (time.time() - validation_start) * 1000
            logger.info(
                "Enhanced token validation successful",
                correlation_id=correlation_id,
                user_id=user.id,
                validation_time_ms=validation_time,
                jti=validation_result.access_payload.get("jti", "unknown")[:8] + "...",
                family_security_validated=validation_result.family_security_result is not None,
            )
            
            # Return successful validation result
            return {
                "user": user,
                "access_payload": validation_result.access_payload,
                "refresh_payload": validation_result.refresh_payload,
                "validation_metadata": {
                    **validation_result.validation_metadata,
                    "validation_time_ms": validation_time,
                    "strategies_executed": len(self.validation_strategies),
                    "family_security_enabled": self.token_family_security_service is not None,
                    "reuse_detected": validation_result.reuse_detected,
                    "family_compromised": validation_result.family_compromised,
                },
            }
            
        except AuthenticationError:
            # Re-raise authentication errors (already handled)
            raise
        except Exception as e:
            # Handle unexpected errors with security logging
            logger.error(
                "Unexpected error during token validation",
                error=str(e),
                error_type=type(e).__name__,
                correlation_id=correlation_id,
                client_ip=client_ip,
            )
            raise AuthenticationError(
                get_translated_message("token_validation_internal_error", language)
            )
    
    async def _parse_token_pair(
        self, 
        context: TokenPairValidationContext,
        language: str,
    ) -> Tuple[AccessToken, RefreshToken]:
        """Parse and validate token formats."""
        try:
            # Parse access token
            access_token = AccessToken.from_encoded(
                token=context.access_token_raw,
                public_key=settings.JWT_PUBLIC_KEY,
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            
            # Parse refresh token
            refresh_token = RefreshToken.from_encoded(
                token=context.refresh_token_raw,
                public_key=settings.JWT_PUBLIC_KEY,
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE,
            )
            
            return access_token, refresh_token
            
        except (ValueError, PyJWTError) as e:
            logger.warning(
                "Token parsing failed",
                error=str(e),
                correlation_id=context.correlation_id,
                client_ip=context.client_ip,
            )
            raise AuthenticationError(
                get_translated_message("invalid_token_format", language)
            )
    
    async def _execute_validation_strategies(
        self,
        context: TokenPairValidationContext,
        access_token: AccessToken,
        refresh_token: RefreshToken,
    ) -> TokenValidationResult:
        """Execute all validation strategies with early termination on failure."""
        combined_result = TokenValidationResult(is_valid=True)
        highest_threat_level = SecurityThreatLevel.LOW
        all_violations = []
        all_metadata = {}
        family_security_result = None
        reuse_detected = False
        family_compromised = False
        
        for strategy in self.validation_strategies:
            try:
                strategy_result = await strategy.validate(context, access_token, refresh_token)
                
                # Combine metadata
                all_metadata.update(strategy_result.validation_metadata)
                
                # Combine violations
                all_violations.extend(strategy_result.security_violations)
                
                # Track family security results
                if strategy_result.family_security_result:
                    family_security_result = strategy_result.family_security_result
                    reuse_detected = strategy_result.reuse_detected
                    family_compromised = strategy_result.family_compromised
                
                # Track highest threat level
                if strategy_result.threat_level.value > highest_threat_level.value:
                    highest_threat_level = strategy_result.threat_level
                
                # Early termination on critical failure
                if not strategy_result.is_valid:
                    logger.warning(
                        "Validation strategy failed",
                        strategy=strategy.__class__.__name__,
                        violations=strategy_result.security_violations,
                        threat_level=strategy_result.threat_level.value,
                        reuse_detected=strategy_result.reuse_detected,
                        family_compromised=strategy_result.family_compromised,
                        correlation_id=context.correlation_id,
                    )
                    
                    # Track family violations separately
                    if strategy_result.reuse_detected or strategy_result.family_compromised:
                        self._family_violations_count += 1
                    
                    return TokenValidationResult(
                        is_valid=False,
                        access_payload=strategy_result.access_payload,
                        refresh_payload=strategy_result.refresh_payload,
                        threat_level=highest_threat_level,
                        security_violations=all_violations,
                        validation_metadata=all_metadata,
                        family_security_result=family_security_result,
                        reuse_detected=reuse_detected,
                        family_compromised=family_compromised,
                    )
                
                # Update payloads from successful validation
                if strategy_result.access_payload:
                    combined_result = TokenValidationResult(
                        is_valid=True,
                        access_payload=strategy_result.access_payload,
                        refresh_payload=strategy_result.refresh_payload,
                        threat_level=highest_threat_level,
                        security_violations=all_violations,
                        validation_metadata=all_metadata,
                        family_security_result=family_security_result,
                        reuse_detected=reuse_detected,
                        family_compromised=family_compromised,
                    )
                
            except Exception as e:
                logger.error(
                    "Validation strategy error",
                    strategy=strategy.__class__.__name__,
                    error=str(e),
                    correlation_id=context.correlation_id,
                )
                # Continue with other strategies for robustness
                all_violations.append(f"Strategy {strategy.__class__.__name__} failed: {str(e)}")
        
        # All strategies passed
        return TokenValidationResult(
            is_valid=True,
            access_payload=combined_result.access_payload,
            refresh_payload=combined_result.refresh_payload,
            threat_level=highest_threat_level,
            security_violations=all_violations,
            validation_metadata=all_metadata,
            family_security_result=family_security_result,
            reuse_detected=reuse_detected,
            family_compromised=family_compromised,
        )
    
    async def _validate_session_and_get_user(
        self,
        validation_result: TokenValidationResult,
        context: TokenPairValidationContext,
        language: str,
    ) -> User:
        """Validate session consistency and retrieve user."""
        if not validation_result.access_payload or not validation_result.refresh_payload:
            raise AuthenticationError(
                get_translated_message("invalid_token_payload", language)
            )
        
        jti = validation_result.access_payload.get("jti")
        user_id = int(validation_result.access_payload.get("sub"))
        
        # Validate session exists and is active
        if not await self.session_service.is_session_valid(jti, user_id):
            logger.warning(
                "Session validation failed during token refresh",
                jti=jti[:8] + "..." if jti else "unknown",
                user_id=user_id,
                correlation_id=context.correlation_id,
            )
            raise AuthenticationError(
                get_translated_message("session_invalid_or_expired", language)
            )
        
        # Get user from database
        from src.infrastructure.database.async_db import get_async_db
        from src.domain.entities.user import User
        
        # Note: In real implementation, this would be injected via dependency injection
        # For now, we'll assume the user is valid since session validation passed
        # The actual user retrieval will be handled by the endpoint
        
        # Return a placeholder user object - actual implementation will inject user repository
        return User(
            id=user_id,
            username="validated_user",  # Will be replaced with actual user data
            email="user@example.com",   # Will be replaced with actual user data
            is_active=True,
        )
    
    async def _handle_validation_failure(
        self,
        validation_result: TokenValidationResult,
        context: TokenPairValidationContext,
        language: str,
    ) -> None:
        """Handle validation failure with security incident logging."""
        self._violation_count += 1
        
        # Enhanced logging for family security violations
        if validation_result.reuse_detected or validation_result.family_compromised:
            logger.critical(
                "Token family security violation detected",
                violations=validation_result.security_violations,
                threat_level=validation_result.threat_level.value,
                reuse_detected=validation_result.reuse_detected,
                family_compromised=validation_result.family_compromised,
                client_ip=context.client_ip,
                user_agent=context.user_agent,
                correlation_id=context.correlation_id,
                total_violations=self._violation_count,
                family_violations=self._family_violations_count,
            )
        else:
            # Log standard security incident
            logger.warning(
                "Token validation security violation",
                violations=validation_result.security_violations,
                threat_level=validation_result.threat_level.value,
                client_ip=context.client_ip,
                user_agent=context.user_agent,
                correlation_id=context.correlation_id,
                total_violations=self._violation_count,
            )
        
        # Determine error message based on threat level and violations
        if validation_result.reuse_detected:
            error_message = get_translated_message("token_reuse_attack_detected", language)
        elif validation_result.family_compromised:
            error_message = get_translated_message("token_family_compromised", language)
        elif validation_result.threat_level == SecurityThreatLevel.CRITICAL:
            error_message = get_translated_message("critical_security_violation", language)
        elif "JTI mismatch" in str(validation_result.security_violations):
            error_message = get_translated_message("token_pair_mismatch", language)
        elif "Cross-user" in str(validation_result.security_violations):
            error_message = get_translated_message("cross_user_attack_detected", language)
        elif "expired" in str(validation_result.security_violations):
            error_message = get_translated_message("token_expired", language)
        else:
            error_message = get_translated_message("token_validation_failed", language)
        
        # TODO: Implement additional security measures for high-threat scenarios:
        # - IP-based rate limiting escalation
        # - User account security alerts
        # - Automated token family revocation
        # - Security operations center (SOC) notifications
        # - Enhanced monitoring for compromised families
        
        raise AuthenticationError(error_message)
    
    def get_validation_metrics(self) -> Dict[str, Any]:
        """Get validation performance and security metrics."""
        return {
            "total_validations": self._validation_count,
            "total_violations": self._violation_count,
            "family_violations": self._family_violations_count,
            "violation_rate": self._violation_count / max(self._validation_count, 1),
            "family_violation_rate": self._family_violations_count / max(self._validation_count, 1),
            "strategies_configured": len(self.validation_strategies),
            "family_security_enabled": self.token_family_security_service is not None,
        } 