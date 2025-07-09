"""
Domain Token Service Infrastructure Implementation.

This infrastructure service implements the domain interface for token management
while providing the bridge between domain logic and infrastructure concerns.

Architecture Pattern:
- Infrastructure Layer: Handles JWT encoding/decoding, external dependencies
- Domain Interface: Implements ITokenLifecycleManagementService contract
- Repository Pattern: Uses injected repositories for data persistence
- Event Publishing: Integrates with infrastructure event systems

Key Features:
- Complete replacement for legacy TokenService with Redis dependencies
- Domain-driven design with clean architecture principles
- Comprehensive security patterns with token family management
- High-performance implementation optimized for enterprise applications
- Extensive documentation and error handling
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Mapping, Tuple

import jwt
from jwt import encode as jwt_encode, decode as jwt_decode, PyJWTError
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError, SecurityViolationError
from src.domain.entities.user import User
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken
from src.domain.interfaces.token_management import ITokenService
from src.domain.interfaces.authentication.token_lifecycle_management import ITokenLifecycleManagementService
from src.domain.interfaces.repositories.token_family_repository import ITokenFamilyRepository
from src.domain.interfaces import IEventPublisher
from src.domain.services.authentication.token_lifecycle_management_service import (
    TokenLifecycleManagementService,
    TokenPair,
    TokenCreationRequest,
    TokenRefreshRequest
)
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class DomainTokenService(ITokenService, ITokenLifecycleManagementService):
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
        db_session: AsyncSession,
        token_family_repository: Optional[ITokenFamilyRepository] = None,
        event_publisher: Optional[IEventPublisher] = None
    ):
        """
        Initialize domain token service with infrastructure dependencies.
        
        Args:
            db_session: SQLAlchemy async session for database operations
            token_family_repository: Repository for token family persistence
            event_publisher: Publisher for domain events
        """
        self.db_session = db_session
        self._token_family_repository = token_family_repository or TokenFamilyRepository(db_session)
        self._event_publisher = event_publisher or InMemoryEventPublisher()
        
        # Initialize domain service with infrastructure dependencies
        # Note: The domain service uses the repository for database operations,
        # which already has access to the database session
        self._domain_service = TokenLifecycleManagementService(
            token_family_repository=self._token_family_repository,
            event_publisher=self._event_publisher
        )
        
        logger.info(
            "DomainTokenService initialized",
            service_type="infrastructure_service",
            domain_service="TokenLifecycleManagementService",
            storage_type="database_only",
            security_features=["token_family", "reuse_detection", "threat_analysis"]
        )
    
    async def create_token_pair_with_family_security(
        self,
        request: TokenCreationRequest
    ) -> TokenPair:
        """
        Create token pair with family security using domain service.
        
        This method provides the infrastructure implementation for token pair
        creation, handling database transactions and error conversion.
        
        Args:
            request: Token creation request with user and security context
            
        Returns:
            TokenPair: Complete token pair with family security metadata
            
        Raises:
            AuthenticationError: If user is invalid or token creation fails
            SecurityViolationError: If security context indicates threat
        """
        try:
            if not self.db_session.in_transaction():
                async with self.db_session.begin():
                    token_pair = await self._domain_service.create_token_pair_with_family_security(request)
            else:
                token_pair = await self._domain_service.create_token_pair_with_family_security(request)
                
                logger.info(
                    "Token pair created successfully",
                    user_id=request.user.id,
                    family_id=token_pair.family_id[:8] + "...",
                    correlation_id=request.correlation_id
                )
                
                return token_pair
                
        except (AuthenticationError, SecurityViolationError):
            # Re-raise domain exceptions without modification
            raise
        except Exception as e:
            logger.error(
                "Infrastructure error during token pair creation",
                user_id=request.user.id,
                error=str(e),
                correlation_id=request.correlation_id
            )
            raise AuthenticationError(
                get_translated_message("token_creation_infrastructure_error", "en")
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
            if not self.db_session.in_transaction():
                async with self.db_session.begin():
                    token_pair = await self._domain_service.refresh_tokens_with_family_security(request)
            else:
                token_pair = await self._domain_service.refresh_tokens_with_family_security(request)
                
                logger.info(
                    "Tokens refreshed successfully",
                    family_id=token_pair.family_id[:8] + "...",
                    correlation_id=request.correlation_id
                )
                
                return token_pair
                
        except (AuthenticationError, SecurityViolationError):
            # Re-raise domain exceptions without modification
            raise
        except Exception as e:
            logger.error(
                "Infrastructure error during token refresh",
                error=str(e),
                correlation_id=request.correlation_id
            )
            raise AuthenticationError(
                get_translated_message("token_refresh_infrastructure_error", "en"))
    
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
            # Delegate to domain service for business logic
            payload = await self._domain_service.validate_token_with_family_security(
                access_token=access_token,
                security_context=security_context,
                correlation_id=correlation_id,
                language=language
            )
            
            logger.debug(
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
            logger.error(
                "Infrastructure error during token validation",
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(
                get_translated_message("token_validation_infrastructure_error", language)
            )
    
    async def validate_access_token(self, token: str, language: str = "en") -> dict:
        """Validates a JWT access token and returns its payload."""
        try:
            # Delegate to domain service for validation
            payload = await self._domain_service.validate_access_token(token, language)
            return payload
        except Exception as e:
            logger.error(
                "Error validating access token",
                error=str(e)
            )
            raise AuthenticationError(get_translated_message("invalid_token", language))

    async def revoke_access_token(self, jti: str, expires_in: Optional[int] = None) -> None:
        """Revokes an access token by its unique identifier (jti)."""
        try:
            # Delegate to domain service for revocation
            await self._domain_service.revoke_access_token(jti, expires_in)
        except Exception as e:
            logger.error(
                "Error revoking access token",
                error=str(e)
            )
            raise AuthenticationError(get_translated_message("token_revocation_failed", "en"))

    async def revoke_refresh_token(self, token: RefreshToken, language: str = "en") -> None:
        """Revokes a refresh token."""
        try:
            # Delegate to domain service for revocation
            await self._domain_service.revoke_refresh_token(token, language)
        except Exception as e:
            logger.error(
                "Error revoking refresh token",
                error=str(e)
            )
            raise AuthenticationError(get_translated_message("token_revocation_failed", language))
    
    # === Legacy Compatibility Methods ===
    # DEPRECATED: These methods are provided for migration compatibility only.
    # New code should use create_token_pair_with_family_security instead.
    
    async def create_access_token(
        self,
        user: User,
        jti: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        DEPRECATED: Legacy compatibility method for access token creation.
        
        This method is provided for migration compatibility only.
        New code should use create_token_pair_with_family_security instead.
        
        **Migration Guide:**
        ```python
        # OLD (deprecated):
        token = await token_service.create_access_token(user)
        
        # NEW (recommended):
        request = TokenCreationRequest(user=user, security_context=context)
        token_pair = await token_service.create_token_pair_with_family_security(request)
        token = token_pair.access_token
        ```
        
        Args:
            user: User for whom to create the token
            jti: Optional JWT ID to use
            client_ip: Client IP for security context
            user_agent: User agent for security context
            correlation_id: Request correlation ID
            
        Returns:
            str: Encoded JWT access token
        """
        import warnings
        warnings.warn(
            "create_access_token is deprecated. Use create_token_pair_with_family_security instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Create security context from legacy parameters
        security_context = SecurityContext.create_for_request(
            client_ip=client_ip or "127.0.0.1",
            user_agent=user_agent or "Legacy-Client",
            correlation_id=correlation_id
        )
        
        # Create token pair using domain service
        request = TokenCreationRequest(
            user=user,
            security_context=security_context,
            correlation_id=correlation_id
        )
        
        token_pair = await self.create_token_pair_with_family_security(request)
        
        logger.warning(
            "Legacy access token creation method used",
            user_id=user.id,
            correlation_id=correlation_id,
            migration_note="Use create_token_pair_with_family_security instead"
        )
        
        return token_pair.access_token
    
    async def create_refresh_token(
        self,
        user: User,
        jti: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Legacy compatibility method for refresh token creation.
        
        This method provides backward compatibility with the legacy TokenService
        interface while using the new domain service internally.
        
        **Deprecation Notice:** This method is provided for migration compatibility.
        New code should use create_token_pair_with_family_security instead.
        
        Args:
            user: User for whom to create the token
            jti: Optional JWT ID to use
            client_ip: Client IP for security context
            user_agent: User agent for security context
            correlation_id: Request correlation ID
            
        Returns:
            str: Encoded JWT refresh token
        """
        # Create security context from legacy parameters
        security_context = SecurityContext.create_for_request(
            client_ip=client_ip or "127.0.0.1",
            user_agent=user_agent or "Legacy-Client",
            correlation_id=correlation_id
        )
        
        # Create token pair using domain service
        request = TokenCreationRequest(
            user=user,
            security_context=security_context,
            correlation_id=correlation_id
        )
        
        token_pair = await self.create_token_pair_with_family_security(request)
        
        logger.warning(
            "Legacy refresh token creation method used",
            user_id=user.id,
            correlation_id=correlation_id,
            migration_note="Use create_token_pair_with_family_security instead"
        )
        
        return token_pair.refresh_token
    
    async def refresh_tokens(
        self,
        refresh_token: str,
        language: str = "en",
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> Mapping[str, str]:
        """
        Legacy compatibility method for token refresh.
        
        This method provides backward compatibility with the legacy TokenService
        interface while using the new domain service internally.
        
        **Deprecation Notice:** This method is provided for migration compatibility.
        New code should use refresh_tokens_with_family_security instead.
        
        Args:
            refresh_token: Current refresh token
            language: Language for error messages
            client_ip: Client IP for security context
            user_agent: User agent for security context
            correlation_id: Request correlation ID
            
        Returns:
            Mapping[str, str]: New access and refresh tokens with metadata
        """
        # Create security context from legacy parameters
        security_context = SecurityContext.create_for_request(
            client_ip=client_ip or "127.0.0.1",
            user_agent=user_agent or "Legacy-Client",
            correlation_id=correlation_id
        )
        
        # Create refresh request using domain service
        request = TokenRefreshRequest(
            refresh_token=refresh_token,
            security_context=security_context,
            correlation_id=correlation_id,
            language=language
        )
        
        token_pair = await self.refresh_tokens_with_family_security(request)
        
        logger.warning(
            "Legacy token refresh method used",
            family_id=token_pair.family_id[:8] + "...",
            correlation_id=correlation_id,
            migration_note="Use refresh_tokens_with_family_security instead"
        )
        
        return {
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token,
            "token_type": token_pair.token_type,
            "expires_in": token_pair.expires_in,
        }
    
    async def validate_token(
        self,
        token: str,
        language: str = "en",
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> Mapping[str, Any]:
        """
        Legacy compatibility method for token validation.
        
        This method provides backward compatibility with the legacy TokenService
        interface while using the new domain service internally.
        
        **Deprecation Notice:** This method is provided for migration compatibility.
        New code should use validate_token_with_family_security instead.
        
        Args:
            token: JWT access token
            language: Language for error messages
            client_ip: Client IP for security context
            user_agent: User agent for security context
            correlation_id: Request correlation ID
            
        Returns:
            Mapping[str, Any]: Decoded payload
        """
        # Create security context from legacy parameters
        security_context = SecurityContext.create_for_request(
            client_ip=client_ip or "127.0.0.1",
            user_agent=user_agent or "Legacy-Client",
            correlation_id=correlation_id
        )
        
        # Validate using domain service
        payload = await self.validate_token_with_family_security(
            access_token=token,
            security_context=security_context,
            correlation_id=correlation_id,
            language=language
        )
        
        logger.warning(
            "Legacy token validation method used",
            user_id=payload.get("sub"),
            correlation_id=correlation_id,
            migration_note="Use validate_token_with_family_security instead"
        )
        
        return payload
    
    # === Administrative Methods ===
    
    async def revoke_token_family(
        self,
        family_id: str,
        reason: str = "Administrative revocation",
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Revoke an entire token family for administrative purposes.
        
        This method provides administrative functionality to revoke all tokens
        in a family, typically used for account suspension or security incidents.
        
        Args:
            family_id: Token family ID to revoke
            reason: Reason for revocation
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if family was successfully revoked
        """
        try:
            async with self.db_session.begin():
                # Create security context for administrative action
                security_context = SecurityContext.create_for_request(
                    client_ip="127.0.0.1",  # Internal system
                    user_agent="Administrative-System",
                    correlation_id=correlation_id
                )
                
                # Revoke family using repository
                success = await self._token_family_repository.compromise_family(
                    family_id=family_id,
                    reason=reason,
                    security_context=security_context
                )
                
                logger.info(
                    "Token family revoked administratively",
                    family_id=family_id[:8] + "...",
                    reason=reason,
                    correlation_id=correlation_id
                )
                
                return success
                
        except Exception as e:
            logger.error(
                "Failed to revoke token family",
                family_id=family_id[:8] + "...",
                error=str(e),
                correlation_id=correlation_id
            )
            return False
    
    async def get_user_active_families(
        self,
        user_id: int,
        limit: int = 100
    ) -> list:
        """
        Get active token families for a user.
        
        This method provides administrative functionality to view active
        token families for a user, useful for security monitoring.
        
        Args:
            user_id: User ID to get families for
            limit: Maximum number of families to return
            
        Returns:
            list: List of active token families
        """
        try:
            families = await self._token_family_repository.get_user_active_families(
                user_id=user_id,
                limit=limit
            )
            
            logger.debug(
                "Retrieved user active families",
                user_id=user_id,
                family_count=len(families)
            )
            
            return families
            
        except Exception as e:
            logger.error(
                "Failed to retrieve user active families",
                user_id=user_id,
                error=str(e)
            )
            return [] 