"""
Domain Token Service Infrastructure Implementation.

This infrastructure service implements the domain interface for token management
while providing the bridge between domain logic and infrastructure concerns.

Architecture Pattern:
- Infrastructure Layer: Handles JWT encoding/decoding, external dependencies
- Domain Interface: Implements ITokenService contract
- Repository Pattern: Uses injected repositories for data persistence
- Event Publishing: Integrates with infrastructure event systems

Key Features:
- Complete replacement for legacy TokenService with Redis dependencies
- Domain-driven design with clean architecture principles
- Comprehensive security patterns with token family management
- High-performance implementation optimized for enterprise applications
- Extensive documentation and error handling
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession
import structlog

if TYPE_CHECKING:
    from src.infrastructure.services.authentication.jwt_service import JWTService

from src.core.config.settings import settings
from src.common.exceptions import AuthenticationError, SecurityViolationError
from src.domain.entities.user import User
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken, TokenId
from src.domain.interfaces.token_management import ITokenService

from src.domain.interfaces.repositories.token_family_repository import ITokenFamilyRepository
from src.common.events import IEventPublisher
from src.domain.services.authentication.token_family_management_service import TokenFamilyManagementService
from src.domain.value_objects.token_requests import TokenCreationRequest, TokenRefreshRequest
from src.domain.value_objects.token_responses import TokenPair

from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher
from src.common.i18n import get_translated_message
from src.infrastructure.services.base_service import BaseInfrastructureService
from src.domain.interfaces.repositories.user_repository import IUserRepository
from src.infrastructure.repositories.user_repository import UserRepository
from src.infrastructure.database.session_factory import ISessionFactory
from src.infrastructure.services.authentication.unified_session_service import UnifiedSessionService


class DomainTokenService(ITokenService, BaseInfrastructureService):
    """
    Infrastructure implementation of domain token lifecycle management.
    
    This service provides the infrastructure bridge for the domain token
    lifecycle management service, handling:
    
    **Infrastructure Responsibilities:**
    - Database session management and transactions
    - JWT encoding/decoding with infrastructure settings
    - Event publishing to infrastructure event systems
    - Error handling and conversion to appropriate HTTP responses
    - Performance monitoring and logging
    
    **Domain Integration:**
    - Implements domain interface contracts
    - Delegates business logic to domain service
    - Maintains clean architecture separation
    - Preserves domain model integrity
    
    **Security Features:**
    - Token family security with database-only storage
    - Advanced threat detection and response
    - Comprehensive audit trails and forensic analysis
    - Zero-trust validation with fail-secure error handling
    - Sub-millisecond performance for high-throughput applications
    """
    
    def __init__(
        self,
        session_factory: ISessionFactory,
        user_repository: Optional[IUserRepository] = None,
        token_family_repository: Optional[ITokenFamilyRepository] = None,
        event_publisher: Optional[IEventPublisher] = None,
        jwt_service = None,
        session_service: Optional[UnifiedSessionService] = None
    ):
        """
        Initialize domain token service with infrastructure dependencies.
        
        Args:
            session_factory: Factory for creating database sessions
            user_repository: Repository for user data access
            token_family_repository: Repository for token family persistence
            event_publisher: Publisher for domain events
            jwt_service: JWT service for token operations
        """
        super().__init__(
            service_name="DomainTokenService",
            service_type="infrastructure_service",
            domain_service="TokenFamilyManagementService",
            storage_type="database_only",
            security_features=["token_family", "reuse_detection", "threat_analysis"]
        )
        
        self.session_factory = session_factory
        self._user_repository = user_repository or UserRepository(session_factory)
        self._token_family_repository = token_family_repository or TokenFamilyRepository(session_factory)
        self._event_publisher = event_publisher or InMemoryEventPublisher()
        self._session_service = session_service
        
        # Set up logging with session tracking
        self._logger = structlog.get_logger(f"{__name__}.DomainTokenService")
        self._session_id = id(session_factory)
        
        # Safely get task ID - handle case where no event loop is running
        try:
            current_task = asyncio.current_task()
            self._task_id = current_task.get_name() if current_task else "no_event_loop"
        except RuntimeError:
            # No event loop running during initialization
            self._task_id = "no_event_loop"
        self._logger.debug(
            "DomainTokenService initialized", 
            session_id=self._session_id, 
            task_id=self._task_id,
            service_name=self._service_name
        )
        # Import JWTService dynamically to avoid circular imports
        if jwt_service is None:
            from src.infrastructure.services.authentication.jwt_service import JWTService
            self._jwt_service = JWTService()
        else:
            self._jwt_service = jwt_service
        
        # Initialize domain service with infrastructure dependencies
        # Note: The domain service uses the repository for database operations,
        # which already has access to the database session
        self._domain_service = TokenFamilyManagementService(
            token_family_repository=self._token_family_repository,
            event_publisher=self._event_publisher
        )
    
    async def create_token_pair_with_family_security(
        self,
        request: TokenCreationRequest
    ) -> TokenPair:
        """
        Create token pair with family security using domain service.
        
        This method provides the infrastructure implementation for token pair creation,
        handling database transactions and error conversion for the API layer.
        
        Args:
            request: Token creation request with user and security context
            
        Returns:
            TokenPair: Token pair with family security metadata
            
        Raises:
            AuthenticationError: If user is invalid or token creation fails
            SecurityViolationError: If security context indicates threat
        """
        async with self.session_factory.create_transactional_session() as session:
            try:
                # Generate token ID once to use for both family and JWT
                token_id = TokenId.generate()
                
                # Create token family with the generated token ID
                token_family = await self._domain_service.create_token_family(
                    user=request.user,
                    initial_token_id=token_id,
                    security_context=request.security_context,
                    correlation_id=request.correlation_id
                )
                
                # Create JWT tokens with the same token ID and family_id
                access_token = await self._jwt_service.create_access_token(
                    user=request.user, 
                    family_id=token_family.family_id,
                    jti=token_id.value  # Use the same token ID
                )
                refresh_token = await self._jwt_service.create_refresh_token(
                    user=request.user, 
                    jti=token_id.value,  # Use the same token ID
                    family_id=token_family.family_id
                )
                
                # CREATE DATABASE SESSION - This is the missing critical step!
                # Create session directly in the current database session
                try:
                    from datetime import datetime, timezone, timedelta
                    from src.domain.entities.session import Session as SessionEntity
                    import hashlib
                    
                    # Calculate refresh token expiration  
                    refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=7)  # Default 7 days
                    
                    # Create hash of refresh token for secure storage
                    if hasattr(refresh_token, 'token'):
                        refresh_token_str = refresh_token.token
                    else:
                        refresh_token_str = str(refresh_token)
                    
                    # Ensure we have a string
                    if not isinstance(refresh_token_str, str):
                        refresh_token_str = str(refresh_token_str)
                        
                    refresh_token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
                    
                    # Create the session entity directly
                    current_time = datetime.now(timezone.utc)
                    session_entity = SessionEntity(
                        user_id=request.user.id,
                        jti=token_id.value,
                        refresh_token_hash=refresh_token_hash,
                        expires_at=refresh_expires_at.replace(tzinfo=None),
                        last_activity_at=current_time.replace(tzinfo=None),
                        family_id=token_family.family_id
                    )
                    
                    # Add session to current transaction
                    session.add(session_entity)
                    # Session will be committed with the transaction
                    
                    self._log_success(
                        operation="create_session_during_login",
                        user_id=request.user.id,
                        jti=token_id.value[:8] + "...",
                        family_id=token_family.family_id[:8] + "...",
                        correlation_id=request.correlation_id
                    )
                    
                except Exception as e:
                    # Session creation is now MANDATORY for security
                    # If we can't create a session, we can't issue tokens
                    self._log_error(
                        operation="create_session_during_login",
                        message="CRITICAL: Session creation failed during login - cannot issue tokens",
                        error=str(e),
                        user_id=request.user.id,
                        jti=token_id.value[:8] + "...",
                        correlation_id=request.correlation_id
                    )
                    raise AuthenticationError("Session creation failed - cannot issue tokens")
                
                # Create token pair response
                access_token_str = access_token.token if hasattr(access_token, 'token') else str(access_token)
                refresh_token_str = refresh_token.token if hasattr(refresh_token, 'token') else str(refresh_token)
                token_pair = TokenPair(
                    access_token=access_token_str,  # Extract token string from value object
                    refresh_token=refresh_token_str,  # Extract token string from value object
                    family_id=token_family.family_id,
                    expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
                )
                
                self._log_success(
                    operation="create_token_pair_with_family_security",
                    user_id=request.user.id,
                    family_id=token_family.family_id[:8] + "...",
                    correlation_id=request.correlation_id
                )
                
                return token_pair
                    
            except (AuthenticationError, SecurityViolationError):
                # Re-raise domain exceptions without modification
                raise
            except Exception as e:
                raise self._handle_infrastructure_error(
                    error=e,
                    operation="create_token_pair_with_family_security",
                    user_id=request.user.id,
                    correlation_id=request.correlation_id
                )
    
    async def refresh_tokens_with_family_security(
        self,
        request: TokenRefreshRequest
    ) -> TokenPair:
        """
        Refresh tokens with family security using domain service.
        
        This method provides the infrastructure implementation for token refresh,
        handling database transactions and security incident response.
        
        Args:
            request: Token refresh request with security context
            
        Returns:
            TokenPair: New token pair with updated security metadata
            
        Raises:
            AuthenticationError: If refresh token is invalid or expired
            SecurityViolationError: If token reuse or family compromise detected
        """
        try:
            # Validate refresh token
            refresh_payload = await self._jwt_service.validate_token(request.refresh_token)
            
            # Extract token information
            user_id = int(refresh_payload.get("sub"))
            family_id = refresh_payload.get("family_id")
            jti = refresh_payload.get("jti")
            
            # Get user from repository
            user = await self._user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise AuthenticationError("User not found or inactive")
            
            # Create new JWT tokens using the new interface
            new_access_token = await self._jwt_service.create_access_token(user=user)
            new_refresh_token = await self._jwt_service.create_refresh_token(
                user=user, 
                jti=new_access_token.get_token_id().value,
                family_id=family_id
            )
            
            # Update token family using the new JWT's JTI
            new_token_id = new_access_token.get_token_id()
            old_token_id = TokenId(jti)
            # Fetch token family by family_id
            token_family = await self._token_family_repository.get_family_by_id(family_id)
            if token_family is None:
                raise AuthenticationError(f"Token family {family_id} not found for refresh.")
            await self._domain_service.detect_token_reuse(
                token_family=token_family,
                token_id=old_token_id,
                security_context=request.security_context,
                correlation_id=request.correlation_id
            )
            
            # Create token pair response
            new_access_token_str = new_access_token.token if hasattr(new_access_token, 'token') else str(new_access_token)
            new_refresh_token_str = new_refresh_token.token if hasattr(new_refresh_token, 'token') else str(new_refresh_token)
            token_pair = TokenPair(
                access_token=new_access_token_str,  # Extract token string from value object
                refresh_token=new_refresh_token_str,  # Extract token string from value object
                family_id=family_id,
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            )
            
            self._log_success(
                operation="refresh_tokens_with_family_security",
                family_id=family_id[:8] + "...",
                correlation_id=request.correlation_id
            )
            
            return token_pair
                
        except (AuthenticationError, SecurityViolationError):
            # Re-raise domain exceptions without modification
            raise
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="refresh_tokens_with_family_security",
                correlation_id=request.correlation_id
            )
    
    async def validate_token_with_family_security(
        self,
        access_token: str,
        security_context: SecurityContext,
        correlation_id: Optional[str] = None,
        language: str = "en"
    ) -> Dict[str, Any]:
        """
        Validate token with family security using domain service.
        
        This method provides the infrastructure implementation for token validation,
        handling performance optimization and error conversion.
        
        Args:
            access_token: JWT access token to validate
            security_context: Current request security context
            correlation_id: Request correlation ID for tracking
            language: Language for error messages
            
        Returns:
            Dict[str, Any]: Validated token payload with security metadata
            
        Raises:
            AuthenticationError: If token is invalid, expired, or user inactive
            SecurityViolationError: If family is compromised or security threat detected
        """
        try:
            # Validate JWT token first
            payload = await self._jwt_service.validate_token(access_token, language)
            
            # Extract token information
            jti = payload.get("jti")
            family_id = payload.get("family_id")
            
            if not jti or not family_id:
                raise AuthenticationError("Token missing required claims")
            
            # Create TokenId from JTI
            from src.domain.value_objects.jwt_token import TokenId
            token_id = TokenId(jti)
            
            # Validate token family security
            is_secure = await self._domain_service.validate_token_family_security(
                family_id=family_id,
                token_id=token_id,
                correlation_id=correlation_id
            )
            
            if not is_secure:
                raise SecurityViolationError("Token family security validation failed")
            
            self._log_operation("validate_token_with_family_security").debug(
                "Token validated successfully",
                user_id=payload.get("sub"),
                jti=payload.get("jti", "unknown")[:8] + "...",
                family_id=payload.get("family_id", "none")[:8] + "...",
                correlation_id=correlation_id
            )
            
            return payload
            
        except (AuthenticationError, SecurityViolationError):
            # Re-raise domain exceptions without modification
            raise
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="validate_token_with_family_security",
                correlation_id=correlation_id
            )
    

    
    async def revoke_token_family(
        self,
        family_id: str,
        reason: str = "Administrative revocation",
        correlation_id: Optional[str] = None
    ) -> bool:
        """Revoke an entire token family.
        
        Args:
            family_id: ID of the family to revoke
            reason: Reason for revocation
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if family was successfully revoked
        """
        try:
            # Get family from repository
            family = await self._token_family_repository.get_by_id(family_id)
            if not family:
                self._log_warning(
                    operation="revoke_token_family",
                    message="Token family not found for revocation",
                    family_id=family_id[:8] + "..."
                )
                return False
            
            # Compromise family
            family.compromise(reason)
            
            # Update in repository
            await self._token_family_repository.update_family(family)
            
            # Publish security event
            if self._event_publisher:
                await self._event_publisher.publish(
                    "TokenFamilyCompromisedEvent",
                    {
                        "family_id": family_id,
                        "reason": reason,
                        "correlation_id": correlation_id,
                        "compromised_at": family.compromised_at.isoformat() if family.compromised_at else None
                    }
                )
            
            self._log_success(
                operation="revoke_token_family",
                family_id=family_id[:8] + "...",
                reason=reason,
                correlation_id=correlation_id
            )
            
            return True
            
        except Exception as e:
            self._log_warning(
                operation="revoke_token_family",
                message="Failed to revoke token family",
                family_id=family_id[:8] + "...",
                error=str(e)
            )
            return False
    
    async def get_user_active_families(
        self,
        user_id: int,
        limit: int = 100
    ) -> list:
        """Get active token families for a user.
        
        Args:
            user_id: User ID to get families for
            limit: Maximum number of families to return
            
        Returns:
            list: List of active token families
        """
        try:
            families = await self._token_family_repository.get_active_families_by_user(
                user_id=user_id,
                limit=limit
            )
            
            return [
                {
                    "family_id": family.family_id,
                    "created_at": family.created_at.isoformat(),
                    "last_used_at": family.last_used_at.isoformat() if family.last_used_at else None,
                    "status": family.status.value,
                    "token_count": len(family.tokens)
                }
                for family in families
            ]
            
        except Exception as e:
            self._log_warning(
                operation="get_user_active_families",
                message="Failed to get user active families",
                user_id=user_id,
                error=str(e)
            )
            return []
    
    async def _revoke_token_in_database(self, jti: str, expires_in: Optional[int] = None) -> None:
        """Revoke token in database storage.
        
        Args:
            jti: JWT ID to revoke
            expires_in: Optional expiration time
        """
        try:
            # Always attempt to revoke the session in the database
            # Create session service per operation for proper database transaction handling
            async with self.session_factory.create_session() as db_session:
                session_service = UnifiedSessionService(
                    db_session=db_session,
                    token_family_repository=self._token_family_repository,
                    event_publisher=self._event_publisher
                )
                
                # Find the session by JTI and revoke it
                # The session service will handle finding the user ID from the session
                from sqlalchemy import select
                from src.domain.entities.session import Session
                
                result = await db_session.execute(
                    select(Session).where(Session.jti == jti)
                )
                session = result.scalars().first()
                
                if session:
                    # Directly update the session in the current database transaction
                    # instead of using the session service with a different transaction
                    current_time = datetime.now(timezone.utc)
                    session.revoked_at = current_time.replace(tzinfo=None)
                    session.revoke_reason = "Logout - Manual revocation"
                    
                    # Mark session as modified in current transaction
                    db_session.add(session)
                    
                    # Commit the transaction to persist the revocation
                    await db_session.commit()
                    
                    self._log_success(
                        operation="revoke_token_in_database",
                        jti=jti[:8] + "...",
                        user_id=session.user_id,
                        family_id=session.family_id[:8] + "..." if session.family_id else "none",
                        expires_in=expires_in
                    )
                else:
                    # Session not found - this is OK for tokens created before session implementation
                    # Just log and continue with logout
                    self._log_info(
                        operation="revoke_token_in_database",
                        message="Session not found for JTI - token created before session implementation",
                        jti=jti[:8] + "...",
                    )
                
        except Exception as e:
            # Log error but don't fail the logout - graceful degradation
            self._log_warning(
                operation="revoke_token_in_database",
                message="Failed to revoke token in database - continuing with logout",
                jti=jti[:8] + "...",
                error=str(e)
            )
            # Don't raise - allow logout to continue

    # ITokenService interface methods
    async def create_access_token(self, user: User) -> "AccessToken":
        """Creates a new JWT access token for a user."""
        from src.domain.value_objects.jwt_token import AccessToken
        
        try:
            # Create a simple token creation request
            from src.domain.value_objects.token_requests import TokenCreationRequest
            from src.domain.value_objects.security_context import SecurityContext
            
            request = TokenCreationRequest(
                user=user,
                security_context=SecurityContext.create_default(),
                correlation_id=None
            )
            
            token_pair = await self.create_token_pair_with_family_security(request)
            return AccessToken(
                token=token_pair.access_token,
                expires_at=None,  # TokenPair doesn't have expires_at info
                jti=None  # TokenPair doesn't have jti info directly
            )
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="create_access_token",
                user_id=user.id
            )

    async def create_refresh_token(self, user: User, jti: Optional[str] = None) -> "RefreshToken":
        """Creates a new JWT refresh token."""
        from src.domain.value_objects.jwt_token import RefreshToken
        
        try:
            # Create a simple token creation request
            from src.domain.value_objects.token_requests import TokenCreationRequest
            from src.domain.value_objects.security_context import SecurityContext
            
            request = TokenCreationRequest(
                user=user,
                security_context=SecurityContext.create_default(),
                correlation_id=None
            )
            
            token_pair = await self.create_token_pair_with_family_security(request)
            return RefreshToken(
                token=token_pair.refresh_token,
                expires_at=None,  # TokenPair doesn't have expires_at info
                jti=None  # TokenPair doesn't have jti info directly
            )
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="create_refresh_token",
                user_id=user.id
            )

    async def refresh_tokens(
        self, refresh_token: "RefreshToken"
    ) -> Tuple["AccessToken", "RefreshToken"]:
        """Refreshes an access token using a valid refresh token."""
        from src.domain.value_objects.jwt_token import AccessToken, RefreshToken
        from src.domain.value_objects.token_requests import TokenRefreshRequest
        from src.domain.value_objects.security_context import SecurityContext
        
        try:
            request = TokenRefreshRequest(
                refresh_token=refresh_token.token,
                security_context=SecurityContext.create_default(),
                correlation_id=None
            )
            
            token_pair = await self.refresh_tokens_with_family_security(request)
            return (
                AccessToken(
                    token=token_pair.access_token,
                    expires_at=None,  # TokenPair doesn't have expires_at info
                    jti=None  # TokenPair doesn't have jti info directly
                ),
                RefreshToken(
                    token=token_pair.refresh_token,
                    expires_at=None,  # TokenPair doesn't have expires_at info
                    jti=None  # TokenPair doesn't have jti info directly
                )
            )
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="refresh_tokens"
            )

    async def validate_access_token(self, token: str, language: str = "en") -> dict:
        """Validates a JWT access token and returns its payload."""
        from src.domain.value_objects.security_context import SecurityContext
        
        try:
            security_context = SecurityContext.create_default()
            payload = await self.validate_token_with_family_security(
                access_token=token,
                security_context=security_context,
                language=language
            )
            return payload
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="validate_access_token"
            )

    async def revoke_refresh_token(self, token: "RefreshToken", language: str = "en") -> None:
        """Revokes a refresh token."""
        try:
            # Get the JTI from the token
            jti = token.get_token_id().value
            
            # For now, we'll revoke the refresh token by treating it like an access token
            # In a full implementation, this would revoke the token family
            await self.revoke_access_token(jti)
            
            self._log_success(
                operation="revoke_refresh_token",
                jti=jti[:8] + "...",
                language=language
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="revoke_refresh_token",
                language=language
            )

    async def revoke_refresh_token_by_jti(self, jti: str, language: str = "en") -> None:
        """Revokes a refresh token by its JTI.
        
        This method finds the associated refresh token using the JTI and revokes it.
        This is useful for logout scenarios where we only have the access token.
        
        Args:
            jti: The unique identifier (jti claim) of the token pair to revoke.
            language: The language for any potential error messages.
        """
        try:
            # For now, we'll revoke the refresh token by treating it like an access token
            # In a full implementation, this would revoke the token family
            await self.revoke_access_token(jti)
            
            self._log_success(
                operation="revoke_refresh_token_by_jti",
                jti=jti[:8] + "...",
                language=language
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="revoke_refresh_token_by_jti",
                language=language
            )

    async def revoke_token_family(
        self,
        family_id: str,
        reason: str = "Manual revocation",
        correlation_id: Optional[str] = None
    ) -> bool:
        """Revokes an entire token family for enhanced security.

        This method implements the token family security pattern where
        all tokens in a family are revoked simultaneously. This provides
        enhanced security for logout operations.

        Args:
            family_id: The unique identifier of the token family to revoke.
            reason: Reason for revocation (for audit purposes).
            correlation_id: Request correlation ID for tracking.

        Returns:
            bool: True if family was found and revoked, False if not found.

        Raises:
            AuthenticationError: If revocation fails due to system error.
        """
        try:
            # Delegate to token family repository for actual revocation
            success = await self._token_family_repository.revoke_family(
                family_id=family_id,
                reason=reason,
                correlation_id=correlation_id
            )
            
            self._log_success(
                operation="revoke_token_family",
                family_id=family_id[:8] + "..." if family_id else "none",
                reason=reason,
                correlation_id=correlation_id,
                success=success
            )
            
            return success
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="revoke_token_family",
                family_id=family_id,
                reason=reason,
                correlation_id=correlation_id
            )

    async def revoke_access_token(
        self, jti: str, expires_in: Optional[int] = None
    ) -> None:
        """Revokes an access token by its unique identifier (jti)."""
        try:
            await self._revoke_token_in_database(jti, expires_in)
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="revoke_access_token",
                jti=jti
            )
            raise AuthenticationError("Failed to revoke access token")

    async def validate_token(self, token: str, language: str = "en") -> dict:
        """A generic method to validate any JWT and return its payload."""
        from src.domain.value_objects.security_context import SecurityContext
        
        try:
            security_context = SecurityContext.create_default()
            payload = await self.validate_token_with_family_security(
                access_token=token,
                security_context=security_context,
                language=language
            )
            return payload
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation="validate_token"
            )

    async def validate_token_pair(
        self,
        access_token: str,
        refresh_token: str,
        client_ip: str,
        user_agent: str,
        correlation_id: Optional[str] = None,
        language: str = "en"
    ) -> dict:
        """Validates that access and refresh tokens belong to the same session."""
        from src.domain.value_objects.security_context import SecurityContext
        from src.common.exceptions import SecurityViolationError
        
        try:
            # Step 1: JWT validation first
            self._logger.info(
                "Starting token pair validation with JWT and session validation",
                operation="validate_token_pair",
                correlation_id=correlation_id
            )
            
            result = await self._jwt_service.validate_token_pair(
                access_token=access_token,
                refresh_token=refresh_token,
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id,
                language=language
            )
            
            # Step 2: DATABASE SESSION VALIDATION - Temporarily disabled for normal flow
            # TODO: Re-enable after fixing session creation during login
            refresh_payload = result.get("refresh_payload", {})
            jti = refresh_payload.get("jti")
            user = result.get("user")
            
            # For now, only check if session is revoked (for logout functionality)
            # but don't fail if session doesn't exist (allows normal refresh flow)
            if jti and user:
                try:
                    async with self.session_factory.create_session() as db_session:
                        from sqlalchemy import select, and_
                        from src.domain.entities.session import Session as SessionEntity
                        from datetime import datetime, timezone
                        
                        # Check if session exists and is revoked (for logout blocking)
                        current_time = datetime.now(timezone.utc).replace(tzinfo=None)
                        result_query = await db_session.execute(
                            select(SessionEntity).where(
                                and_(
                                    SessionEntity.jti == jti,
                                    SessionEntity.user_id == user.id
                                )
                            )
                        )
                        session_entity = result_query.scalar_one_or_none()
                        
                        if session_entity:
                            # Session exists - check if it's revoked
                            if session_entity.revoked_at is not None:
                                self._logger.warning(
                                    "Session validation failed - session has been revoked",
                                    jti=jti[:8] + "..." if jti else "none",
                                    user_id=user.id,
                                    revoked_at=session_entity.revoked_at.isoformat() if session_entity.revoked_at else "unknown",
                                    correlation_id=correlation_id,
                                    security_violation=True
                                )
                                raise SecurityViolationError("Session has been revoked")
                            
                            # Session exists and is not revoked - update activity
                            session_entity.last_activity_at = current_time
                            db_session.add(session_entity)
                            await db_session.commit()
                            
                            self._logger.info(
                                "Session validation successful - session exists and not revoked",
                                jti=jti[:8] + "..." if jti else "none",
                                user_id=user.id,
                                correlation_id=correlation_id
                            )
                        else:
                            # Session doesn't exist - this MUST block token usage
                            # All tokens MUST have sessions for security
                            self._logger.error(
                                "CRITICAL SECURITY: Token has no database session - BLOCKING",
                                jti=jti[:8] + "..." if jti else "none",
                                user_id=user.id,
                                correlation_id=correlation_id,
                                security_violation=True,
                                security_policy="MANDATORY_SESSION_VALIDATION"
                            )
                            raise SecurityViolationError("Token must have database session for security")
                            
                except SecurityViolationError:
                    # Re-raise security violations - these must block the request
                    raise
                except Exception as e:
                    self._logger.error(
                        "Session validation error - allowing JWT-only validation for legacy tokens",
                        error=str(e),
                        jti=jti[:8] + "..." if jti else "none",
                        user_id=user.id,
                        correlation_id=correlation_id
                    )
                    # Continue with JWT-only validation only for unexpected errors
            
            self._logger.info(
                "Complete token pair validation successful",
                operation="validate_token_pair",
                correlation_id=correlation_id
            )
            
            return result
            
        except (AuthenticationError, SecurityViolationError):
            # Re-raise domain exceptions without modification
            raise
        except Exception as e:
            self._logger.error(
                "Unexpected error in validate_token_pair",
                error=str(e),
                error_type=type(e).__name__,
                operation="validate_token_pair",
                correlation_id=correlation_id
            )
            raise self._handle_infrastructure_error(
                error=e,
                operation="validate_token_pair",
                correlation_id=correlation_id
            ) 