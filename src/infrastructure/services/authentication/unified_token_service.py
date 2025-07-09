"""
Unified Token Service with Token Family Security.

This service replaces the existing TokenService and integrates token family security
patterns while eliminating Redis dependency. All token operations are now performed
using PostgreSQL for consistency, ACID transactions, and advanced security features.

Key Features:
- Token family security patterns for reuse detection
- Database-only approach (no Redis dependency)
- ACID transactions for all token operations
- Advanced security monitoring and compromise detection
- Encrypted token storage in database
- High-performance queries optimized for sub-millisecond response times
- Comprehensive audit trails and forensic analysis

Architecture:
- Clean architecture principles
- Domain-driven design with rich domain entities
- Repository pattern for data persistence
- Command-query responsibility segregation (CQRS)
- Event-driven security responses

Security Benefits:
- Real-time token reuse detection
- Family-wide revocation on security violations
- Zero-trust token validation
- Comprehensive security metrics and monitoring
- Performance-optimized for high-throughput applications
"""

import asyncio
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Mapping

import jwt
from jwt import encode as jwt_encode, decode as jwt_decode, PyJWTError
from sqlalchemy.ext.asyncio import AsyncSession
from structlog import get_logger

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError
from src.domain.entities.user import User
from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus
from src.domain.value_objects.jwt_token import TokenId
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.domain.services.authentication.token_family_security_service import TokenFamilySecurityService
from src.infrastructure.services.authentication.unified_session_service import UnifiedSessionService
from src.utils.i18n import get_translated_message

logger = get_logger(__name__)


class UnifiedTokenService:
    """
    Unified token service with token family security and database-only storage.
    
    This service replaces the existing Redis-based token management with a unified
    database approach that provides stronger security guarantees through token
    family patterns and ACID transactions.
    
    Key Features:
    - Token family security for reuse detection and family-wide revocation
    - Database-only storage with encrypted token data
    - ACID transactions for consistent token operations
    - Real-time security monitoring and compromise detection
    - High-performance queries optimized for sub-millisecond response times
    - Comprehensive audit trails for forensic analysis
    
    Security Benefits:
    - Detects and prevents token replay attacks
    - Immediate containment when compromise is detected
    - Zero-trust validation for all token operations
    - Performance metrics for security monitoring
    - Advanced threat pattern analysis
    """
    
    def __init__(
        self,
        db_session: AsyncSession,
        token_family_repository: Optional[TokenFamilyRepository] = None,
        token_family_security_service: Optional[TokenFamilySecurityService] = None,
        session_service: Optional[UnifiedSessionService] = None
    ):
        """
        Initialize the unified token service.
        
        Args:
            db_session: SQLAlchemy async session for database operations
            token_family_repository: Repository for token family persistence
            token_family_security_service: Service for token family security operations
            session_service: Service for session management (legacy compatibility)
        """
        self.db_session = db_session
        self.token_family_repository = token_family_repository or TokenFamilyRepository(db_session)
        self.token_family_security_service = token_family_security_service or TokenFamilySecurityService(
            self.token_family_repository
        )
        # Keep session service for backwards compatibility during migration
        self.session_service = session_service
    
    async def create_access_token(
        self,
        user: User,
        jti: Optional[str] = None,
        family_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Create a JWT access token with token family integration.
        
        Args:
            user: User for whom to create the token
            jti: Optional JWT ID to use (generates if None)
            family_id: Optional family ID for token family association
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            str: Encoded JWT access token
            
        Raises:
            ValueError: If user is invalid
            AuthenticationError: If token creation fails
        """
        try:
            # Generate secure JTI if not provided
            if jti is None:
                jti = TokenId.generate().value
            else:
                # Validate provided JTI format
                TokenId(jti)
            
            # Create token payload
            payload = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
                "iat": datetime.now(timezone.utc),
                "jti": jti,
            }
            
            # Add family ID to payload if provided
            if family_id:
                payload["family_id"] = family_id
            
            # Sign token
            token = jwt_encode(
                payload,
                settings.JWT_PRIVATE_KEY.get_secret_value(),
                algorithm="RS256"
            )
            
            logger.debug(
                "Access token created",
                user_id=user.id,
                jti=jti[:8] + "...",
                family_id=family_id[:8] + "..." if family_id else None,
                correlation_id=correlation_id
            )
            
            return token
            
        except Exception as e:
            logger.error(
                "Failed to create access token",
                user_id=user.id,
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(get_translated_message("token_creation_failed", "en"))
    
    async def create_refresh_token(
        self,
        user: User,
        jti: Optional[str] = None,
        family_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Create a JWT refresh token with token family integration.
        
        Args:
            user: User for whom to create the token
            jti: Optional JWT ID to use (generates if None)
            family_id: Optional family ID for token family association
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            str: Encoded JWT refresh token
            
        Raises:
            ValueError: If user is invalid
            AuthenticationError: If token creation fails
        """
        try:
            # Generate secure JTI if not provided
            if jti is None:
                jti = TokenId.generate().value
            else:
                # Validate provided JTI format
                TokenId(jti)
            
            # Create token payload
            payload = {
                "sub": str(user.id),
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
                "exp": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
                "iat": datetime.now(timezone.utc),
                "jti": jti,
            }
            
            # Add family ID to payload if provided
            if family_id:
                payload["family_id"] = family_id
            
            # Sign token
            refresh_token = jwt_encode(
                payload,
                settings.JWT_PRIVATE_KEY.get_secret_value(),
                algorithm="RS256"
            )
            
            logger.debug(
                "Refresh token created",
                user_id=user.id,
                jti=jti[:8] + "...",
                family_id=family_id[:8] + "..." if family_id else None,
                correlation_id=correlation_id
            )
            
            return refresh_token
            
        except Exception as e:
            logger.error(
                "Failed to create refresh token",
                user_id=user.id,
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(get_translated_message("token_creation_failed", "en"))
    
    async def create_token_pair_with_family(
        self,
        user: User,
        expires_at: Optional[datetime] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Create a new token pair with token family security.
        
        This method creates both access and refresh tokens as part of a new token family,
        providing advanced security through the token family pattern.
        
        Args:
            user: User for whom to create tokens
            expires_at: Optional family expiration time
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            Dict[str, str]: Token pair with metadata
            
        Raises:
            AuthenticationError: If token creation fails
        """
        try:
            # Generate shared JTI for token pair
            jti = TokenId.generate().value
            token_id = TokenId(jti)
            
            # Calculate family expiration if not provided
            if expires_at is None:
                expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            
            # Create token family
            token_family = await self.token_family_repository.create_family(
                user_id=user.id,
                initial_token_id=token_id,
                expires_at=expires_at,
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id
            )
            
            # Create token pair with family association
            access_token = await self.create_access_token(
                user=user,
                jti=jti,
                family_id=token_family.family_id,
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id
            )
            
            refresh_token = await self.create_refresh_token(
                user=user,
                jti=jti,
                family_id=token_family.family_id,
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id
            )
            
            logger.info(
                "Token pair with family created",
                user_id=user.id,
                family_id=token_family.family_id[:8] + "...",
                jti=jti[:8] + "...",
                correlation_id=correlation_id
            )
            
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "family_id": token_family.family_id,
                "jti": jti
            }
            
        except Exception as e:
            logger.error(
                "Failed to create token pair with family",
                user_id=user.id,
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(get_translated_message("token_creation_failed", "en"))
    
    async def refresh_tokens_with_family_security(
        self,
        refresh_token: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en"
    ) -> Dict[str, str]:
        """
        Refresh tokens using token family security patterns.
        
        This method implements secure token refresh with family-based reuse detection
        and automatic compromise response.
        
        Args:
            refresh_token: Current refresh token
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            language: Language for error messages
            
        Returns:
            Dict[str, str]: New token pair with metadata
            
        Raises:
            AuthenticationError: If refresh fails or security violation detected
        """
        try:
            # Decode and validate refresh token
            payload = jwt_decode(
                refresh_token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            
            jti = payload["jti"]
            user_id = int(payload["sub"])
            family_id = payload.get("family_id")
            
            # Get user
            user = await self.db_session.get(User, user_id)
            if not user or not user.is_active:
                logger.warning(
                    "Inactive user refresh attempt",
                    user_id=user_id,
                    correlation_id=correlation_id
                )
                raise AuthenticationError(get_translated_message("user_account_inactive", language))
            
            # Validate token family security
            token_id = TokenId(jti)
            
            if family_id:
                # Use token family security service for validation and refresh
                refresh_result = await self.token_family_security_service.refresh_token_with_family_security(
                    old_token_id=token_id,
                    family_id=family_id,
                    user_id=user_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    correlation_id=correlation_id
                )
                
                if not refresh_result.success:
                    logger.critical(
                        "Token family security violation during refresh",
                        user_id=user_id,
                        family_id=family_id[:8] + "...",
                        reason=refresh_result.failure_reason,
                        correlation_id=correlation_id
                    )
                    raise AuthenticationError(get_translated_message("security_violation_detected", language))
                
                # Create new token pair with new JTI
                new_jti = TokenId.generate().value
                
                # Add new token to family
                new_token_id = TokenId(new_jti)
                token_family = await self.token_family_repository.get_family_by_id(family_id)
                if token_family:
                    token_family.add_token(
                        new_token_id,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        correlation_id=correlation_id
                    )
                    await self.token_family_repository.update_family(token_family)
                
                # Create new token pair
                access_token = await self.create_access_token(
                    user=user,
                    jti=new_jti,
                    family_id=family_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    correlation_id=correlation_id
                )
                
                new_refresh_token = await self.create_refresh_token(
                    user=user,
                    jti=new_jti,
                    family_id=family_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    correlation_id=correlation_id
                )
                
                logger.info(
                    "Tokens refreshed with family security",
                    user_id=user_id,
                    family_id=family_id[:8] + "...",
                    old_jti=jti[:8] + "...",
                    new_jti=new_jti[:8] + "...",
                    correlation_id=correlation_id
                )
                
                return {
                    "access_token": access_token,
                    "refresh_token": new_refresh_token,
                    "token_type": "bearer",
                    "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                    "family_id": family_id,
                    "jti": new_jti
                }
                
            else:
                # Legacy token without family - create new family for future security
                logger.info(
                    "Upgrading legacy token to family security",
                    user_id=user_id,
                    jti=jti[:8] + "...",
                    correlation_id=correlation_id
                )
                
                # Create new token pair with family
                return await self.create_token_pair_with_family(
                    user=user,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    correlation_id=correlation_id
                )
                
        except PyJWTError as e:
            logger.error(
                "JWT decode failed during refresh",
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(get_translated_message("invalid_refresh_token", language))
        except Exception as e:
            logger.error(
                "Token refresh failed",
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(get_translated_message("token_refresh_failed", language))
    
    async def validate_token_with_family_security(
        self,
        token: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en"
    ) -> Mapping[str, Any]:
        """
        Validate a JWT token with token family security checks.
        
        Args:
            token: JWT token to validate
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            language: Language for error messages
            
        Returns:
            Mapping[str, Any]: Validated token payload
            
        Raises:
            AuthenticationError: If token is invalid or security violation detected
        """
        try:
            # Decode and validate token
            payload = jwt_decode(
                token,
                settings.JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            
            user_id = int(payload["sub"])
            jti = payload["jti"]
            family_id = payload.get("family_id")
            
            # Get user
            user = await self.db_session.get(User, user_id)
            if not user or not user.is_active:
                logger.warning(
                    "Invalid user in token",
                    user_id=user_id,
                    correlation_id=correlation_id
                )
                raise AuthenticationError(get_translated_message("user_is_invalid_or_inactive", language))
            
            # Validate token family security if family ID present
            if family_id:
                token_id = TokenId(jti)
                
                # Check for token reuse
                reuse_detected = await self.token_family_repository.check_token_reuse(
                    token_id=token_id,
                    family_id=family_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    correlation_id=correlation_id
                )
                
                if reuse_detected:
                    # Compromise the family
                    await self.token_family_repository.compromise_family(
                        family_id=family_id,
                        reason="Token reuse detected during validation",
                        detected_token=token_id,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        correlation_id=correlation_id
                    )
                    
                    logger.critical(
                        "Token reuse attack detected",
                        user_id=user_id,
                        family_id=family_id[:8] + "...",
                        jti=jti[:8] + "...",
                        correlation_id=correlation_id
                    )
                    raise AuthenticationError(get_translated_message("security_violation_detected", language))
                
                # Record token usage
                token_family = await self.token_family_repository.get_family_by_id(family_id)
                if token_family:
                    token_family.use_token(
                        token_id,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        correlation_id=correlation_id
                    )
                    await self.token_family_repository.update_family(token_family)
            
            logger.debug(
                "Token validated successfully",
                user_id=user_id,
                jti=jti[:8] + "...",
                family_id=family_id[:8] + "..." if family_id else None,
                correlation_id=correlation_id
            )
            
            return payload
            
        except PyJWTError as e:
            logger.error(
                "JWT validation failed",
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(get_translated_message("invalid_token", language))
        except Exception as e:
            logger.error(
                "Token validation failed",
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(get_translated_message("token_validation_failed", language))
    
    async def revoke_token_family(
        self,
        family_id: str,
        reason: str = "Manual revocation",
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Revoke an entire token family.
        
        Args:
            family_id: Token family ID to revoke
            reason: Reason for revocation
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if family was revoked, False if not found
        """
        try:
            result = await self.token_family_repository.revoke_family(
                family_id=family_id,
                reason=reason,
                correlation_id=correlation_id
            )
            
            logger.info(
                "Token family revoked",
                family_id=family_id[:8] + "...",
                reason=reason,
                correlation_id=correlation_id
            )
            
            return result
            
        except Exception as e:
            logger.error(
                "Failed to revoke token family",
                family_id=family_id[:8] + "...",
                error=str(e),
                correlation_id=correlation_id
            )
            raise
    
    async def get_user_token_families(
        self,
        user_id: int,
        status: Optional[TokenFamilyStatus] = None,
        limit: int = 100
    ) -> list[TokenFamily]:
        """
        Get token families for a user.
        
        Args:
            user_id: User ID
            status: Optional status filter
            limit: Maximum number of families to return
            
        Returns:
            List[TokenFamily]: List of token families
        """
        return await self.token_family_repository.get_user_families(
            user_id=user_id,
            status=status,
            limit=limit
        )
    
    async def get_security_metrics(
        self,
        user_id: Optional[int] = None,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get security metrics for monitoring.
        
        Args:
            user_id: Optional user ID filter
            time_window_hours: Time window for metrics
            
        Returns:
            Dict[str, Any]: Security metrics
        """
        return await self.token_family_repository.get_security_metrics(
            user_id=user_id,
            time_window_hours=time_window_hours
        ) 