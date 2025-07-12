"""
Token Family Management Domain Service.

This domain service implements token family lifecycle management following
Domain-Driven Design principles with clear separation of concerns.

Domain Concepts:
- Token Family Creation: Establishing new token families for security tracking
- Family Security Validation: Verifying family integrity and status
- Token Reuse Detection: Identifying and responding to security violations
- Family Compromise: Immediate security containment for violations

Business Rules:
- Each token family belongs to a single user
- Reuse of revoked tokens compromises entire family
- Compromised families cannot issue new tokens
- Family status transitions follow security lifecycle
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, List
import uuid
import structlog

from src.domain.entities.token_family import TokenFamily
from src.domain.entities.user import User
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.interfaces.repositories.token_family_repository import ITokenFamilyRepository
from src.common.events import IEventPublisher
from src.domain.events.authentication_events import (
    TokenFamilyCreatedEvent,
    TokenReuseDetectedEvent,
    TokenFamilyCompromisedEvent
)

from .base_authentication_service import BaseAuthenticationService, ServiceContext

logger = structlog.get_logger(__name__)


class TokenFamilyManagementService(BaseAuthenticationService):
    """
    Domain service for token family lifecycle management.
    
    This service implements comprehensive token family management following
    Domain-Driven Design principles with clear business logic and security
    patterns.
    
    Family Management Features:
    - Secure token family creation with initial tokens
    - Family security validation and status checking
    - Token reuse detection and family compromise
    - Family-wide security incident response
    - Comprehensive audit trail generation
    
    Business Rules:
    - Each family has unique identifier and belongs to single user
    - Reuse of revoked tokens compromises entire family
    - Compromised families cannot issue new tokens
    - Family status transitions follow security lifecycle
    - All operations require audit trail and correlation tracking
    """
    
    def __init__(
        self,
        token_family_repository: ITokenFamilyRepository,
        event_publisher: IEventPublisher
    ):
        """
        Initialize token family management service.
        
        Args:
            token_family_repository: Repository for token family persistence
            event_publisher: Publisher for domain security events
        """
        super().__init__(event_publisher)
        self._token_family_repository = token_family_repository
        
        logger.info(
            "TokenFamilyManagementService initialized",
            service_type="domain_service",
            responsibilities=[
                "family_creation",
                "security_validation",
                "reuse_detection",
                "family_compromise",
                "audit_trail"
            ]
        )
    
    async def create_token_family(
        self,
        user: User,
        initial_token_id: TokenId,
        security_context: SecurityContext,
        expires_at: Optional[datetime] = None,
        correlation_id: Optional[str] = None
    ) -> TokenFamily:
        """
        Create a new token family with initial security setup.
        
        This method implements secure token family creation following
        domain business rules and security patterns.
        
        Args:
            user: User entity for the token family
            initial_token_id: First token to add to the family
            security_context: Security context for tracking
            expires_at: Optional family expiration time
            correlation_id: Request correlation ID for tracking
            
        Returns:
            TokenFamily: The created token family
            
        Raises:
            ValueError: If parameters are invalid
            AuthenticationError: If user is not authorized
            
        Business Rules:
        - User must be active and authorized
        - Initial token ID must be provided
        - Family ID must be unique
        - Security context is required for audit trail
        - Family expiration must be in the future
        """
        context = ServiceContext(
            correlation_id=correlation_id or "",
            operation="token_family_creation"
        )
        
        async with self._operation_context(context) as ctx:
            if not user.is_active:
                raise ValueError("Cannot create token family for inactive user")
            
            if not initial_token_id:
                raise ValueError("Initial token ID is required")
            
            # Generate unique family ID
            family_id = str(uuid.uuid4())
            
            # Calculate expiration time
            family_expires_at = expires_at or (
                datetime.now(timezone.utc) + timedelta(days=30)
            )
            
            # Create token family with security metadata
            token_family = TokenFamily.create_new_family(
                family_id=family_id,
                user_id=user.id,
                expires_at=family_expires_at,
                security_context=security_context,
                initial_token_id=initial_token_id
            )
            
            # Persist token family
            created_family = await self._token_family_repository.create_token_family(token_family)
            
            # Publish domain event for security monitoring
            event = TokenFamilyCreatedEvent(
                family_id=family_id,
                user_id=user.id,
                correlation_id=ctx.correlation_id
            )
            
            await self._publish_domain_event(event, ctx, logger)
            
            logger.info(
                "Token family created successfully",
                family_id=family_id[:8] + "...",
                user_id=user.id,
                initial_token=initial_token_id.mask_for_logging(),
                correlation_id=ctx.correlation_id
            )
            
            return created_family
    
    async def validate_token_family_security(
        self,
        family_id: str,
        token_id: TokenId,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Validate token family security and integrity.
        
        This method implements comprehensive family security validation
        following domain business rules and security patterns.
        
        Args:
            family_id: Token family identifier
            token_id: Token identifier to validate
            correlation_id: Request correlation ID for tracking
            
        Returns:
            bool: True if family is secure, False otherwise
            
        Business Rules:
        - Family must exist and be active
        - Token must belong to the family
        - Family must not be compromised or revoked
        - Token must not be revoked
        """
        context = ServiceContext(
            correlation_id=correlation_id or "",
            operation="token_family_security_validation"
        )
        
        async with self._operation_context(context) as ctx:
            # Retrieve token family
            token_family = await self._token_family_repository.get_family_by_id(family_id)
            if not token_family:
                logger.warning(
                    "Token family not found",
                    family_id=family_id[:8] + "...",
                    correlation_id=ctx.correlation_id
                )
                return False
            
            # Check family status
            if not token_family.is_active():
                logger.warning(
                    "Token family is not active",
                    family_id=family_id[:8] + "...",
                    status=token_family.status.value,
                    correlation_id=ctx.correlation_id
                )
                return False
            
            # Check if token belongs to family
            if not token_family.has_token(token_id):
                logger.warning(
                    "Token does not belong to family",
                    family_id=family_id[:8] + "...",
                    token_id=token_id.mask_for_logging(),
                    correlation_id=ctx.correlation_id
                )
                return False
            
            # Check if token is active
            if not token_family.is_token_active(token_id):
                logger.warning(
                    "Token is not active in family",
                    family_id=family_id[:8] + "...",
                    token_id=token_id.mask_for_logging(),
                    correlation_id=ctx.correlation_id
                )
                return False
            
            logger.debug(
                "Token family security validation passed",
                family_id=family_id[:8] + "...",
                token_id=token_id.mask_for_logging(),
                correlation_id=ctx.correlation_id
            )
            
            return True
    
    async def detect_token_reuse(
        self,
        token_family: TokenFamily,
        token_id: TokenId,
        security_context: SecurityContext,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Detect token reuse and handle security incident.
        
        This method implements token reuse detection following
        domain business rules and security patterns.
        
        Args:
            token_family: Token family to check
            token_id: Token ID that may have been reused
            security_context: Security context for tracking
            correlation_id: Request correlation ID for tracking
            
        Returns:
            bool: True if reuse detected, False otherwise
        """
        context = ServiceContext(
            correlation_id=correlation_id or "",
            operation="token_reuse_detection"
        )
        
        async with self._operation_context(context) as ctx:
            # Check if token is already revoked
            if token_family.is_token_revoked(token_id):
                logger.warning(
                    "Token reuse detected",
                    family_id=token_family.family_id[:8] + "...",
                    token_id=token_id.mask_for_logging(),
                    correlation_id=ctx.correlation_id
                )
                
                # Handle token reuse incident
                await self._handle_token_reuse_incident(
                    token_family, token_id, security_context, ctx.correlation_id,
                    "revoked_token_reuse"
                )
                
                return True
            
            return False
    
    async def compromise_family(
        self,
        token_family: TokenFamily,
        reason: str,
        detected_token: Optional[TokenId] = None,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Compromise token family due to security violation.
        
        This method implements family compromise following
        domain business rules and security patterns.
        
        Args:
            token_family: Token family to compromise
            reason: Reason for compromise
            detected_token: Token that triggered compromise
            security_context: Security context for tracking
            correlation_id: Request correlation ID for tracking
        """
        context = ServiceContext(
            correlation_id=correlation_id or "",
            operation="family_compromise"
        )
        
        async with self._operation_context(context) as ctx:
            # Mark family as compromised
            token_family.mark_compromised(reason)
            
            # Update family in repository
            await self._token_family_repository.update_token_family(token_family)
            
            # Publish compromise event
            event = TokenFamilyCompromisedEvent(
                family_id=token_family.family_id,
                user_id=token_family.user_id,
                reason=reason,
                detected_token=detected_token.mask_for_logging() if detected_token else None,
                correlation_id=ctx.correlation_id
            )
            
            await self._publish_domain_event(event, ctx, logger)
            
            logger.critical(
                "Token family compromised",
                family_id=token_family.family_id[:8] + "...",
                user_id=token_family.user_id,
                reason=reason,
                detected_token=detected_token.mask_for_logging() if detected_token else None,
                correlation_id=ctx.correlation_id
            )
    
    async def get_user_families(
        self,
        user_id: int,
        status: Optional[TokenFamilyStatus] = None,
        limit: int = 100
    ) -> List[TokenFamily]:
        """
        Get token families for a user.
        
        Args:
            user_id: User ID to get families for
            status: Optional status filter
            limit: Maximum number of families to return
            
        Returns:
            List[TokenFamily]: List of token families
        """
        return await self._token_family_repository.get_families_by_user_id(
            user_id, status, limit
        )
    
    async def _handle_token_reuse_incident(
        self,
        token_family: TokenFamily,
        token_id: TokenId,
        security_context: SecurityContext,
        correlation_id: str,
        reason: str
    ) -> None:
        """Handle token reuse security incident.
        
        Args:
            token_family: Token family involved
            token_id: Token that was reused
            security_context: Security context
            correlation_id: Request correlation ID
            reason: Reason for reuse detection
        """
        # Publish reuse detection event
        event = TokenReuseDetectedEvent(
            family_id=token_family.family_id,
            user_id=token_family.user_id,
            token_id=token_id.mask_for_logging(),
            reason=reason,
            correlation_id=correlation_id
        )
        
        context = ServiceContext(correlation_id=correlation_id, operation="token_reuse_handling")
        await self._publish_domain_event(event, context, logger)
        
        # Compromise the family
        await self.compromise_family(
            token_family, f"token_reuse_{reason}", token_id, security_context, correlation_id
        )
    
    async def _validate_operation_prerequisites(self, context: ServiceContext) -> None:
        """Validate operation prerequisites for token family management.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        # Token family management service requires token family repository to be available
        if not self._token_family_repository:
            raise AuthenticationError(
                get_translated_message("service_unavailable", context.language)
            ) 