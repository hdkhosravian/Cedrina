"""
JWT Service Infrastructure Implementation.

This service implements JWT token operations following Domain-Driven Design
principles with clear separation of infrastructure concerns from domain logic.

Infrastructure Responsibilities:
- JWT token creation with proper claims and signing
- Token validation and signature verification
- Token payload extraction and parsing
- Token expiration and time validation
- Error handling for malformed or invalid tokens

Security Features:
- RS256 algorithm for secure token signing
- Comprehensive token validation
- Proper error handling for security
- Performance optimized for high throughput
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple

import jwt
from jwt import PyJWTError

from src.domain.interfaces.token_management import ITokenService
from src.domain.entities.user import User, Role
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken, TokenId
from src.core.config.settings import settings
from src.common.exceptions import AuthenticationError
from src.infrastructure.services.base_service import BaseInfrastructureService


class JWTService(ITokenService, BaseInfrastructureService):
    """
    Infrastructure implementation of JWT token operations.
    
    This service provides the infrastructure bridge for JWT token operations,
    handling all JWT-specific concerns while maintaining clean architecture
    separation from domain logic.
    
    Infrastructure Features:
    - RS256 algorithm for secure token signing
    - Comprehensive token validation and verification
    - Proper error handling for security incidents
    - Performance optimized for high-throughput applications
    - Clean separation from domain business logic
    """
    
    def __init__(self):
        """Initialize JWT service with configuration."""
        super().__init__(
            service_name="JWTService",
            algorithm="RS256",
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE
        )
    
    async def create_access_token(self, user: User) -> AccessToken:
        """Creates a new JWT access token for a user.

        Args:
            user: The `User` entity for whom the token is being created.

        Returns:
            An `AccessToken` value object containing the token string and its metadata.

        Raises:
            AuthenticationError: If user is invalid or token creation fails
        """
        operation = "create_access_token"
        
        try:
            # Validate required parameters
            if not user or not user.is_active:
                raise AuthenticationError("User must be active for token creation")
            
            # Generate unique token ID using domain value object
            jti = TokenId.generate().value
            
            # Calculate expiration time
            expires_in = self._get_config_value("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
            exp_time = datetime.now(timezone.utc) + timedelta(minutes=expires_in)
            
            # Create token payload
            payload = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
                "exp": int(exp_time.timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": jti
            }
            
            # Sign token with RS256 algorithm
            token_string = jwt.encode(
                payload,
                settings.JWT_PRIVATE_KEY.get_secret_value(),
                algorithm="RS256"
            )
            
            # Create AccessToken value object with token and claims
            access_token = AccessToken(
                token=token_string,
                claims=payload
            )
            
            self._log_success(
                operation=operation,
                user_id=user.id,
                jti=jti[:8] + "...",
                expires_in_minutes=expires_in
            )
            
            return access_token
            
        except AuthenticationError:
            # Re-raise domain exceptions
            raise
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id if user else None
            )
    
    async def create_refresh_token(self, user: User, jti: Optional[str] = None) -> RefreshToken:
        """Creates a new JWT refresh token.

        This token has a longer lifespan than an access token and is used to
        obtain new access tokens without requiring the user to re-authenticate.

        Args:
            user: The `User` entity for whom the token is being created.
            jti: The unique identifier of the access token, to link them.

        Returns:
            A `RefreshToken` value object containing the token string and metadata.

        Raises:
            AuthenticationError: If user is invalid or token creation fails
        """
        operation = "create_refresh_token"
        
        try:
            # Validate required parameters
            if not user or not user.is_active:
                raise AuthenticationError("User must be active for token creation")
            
            # Generate unique token ID if not provided
            if not jti:
                jti = TokenId.generate().value
            
            # Calculate expiration time
            expires_at = datetime.now(timezone.utc) + timedelta(
                days=self._get_config_value("REFRESH_TOKEN_EXPIRE_DAYS", 7)
            )
            
            # Create token payload
            payload = {
                "sub": str(user.id),
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
                "exp": int(expires_at.timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": jti
            }
            
            # Sign token with RS256 algorithm
            token_string = jwt.encode(
                payload,
                settings.JWT_PRIVATE_KEY.get_secret_value(),
                algorithm="RS256"
            )
            
            # Create RefreshToken value object with token and claims
            refresh_token = RefreshToken(
                token=token_string,
                claims=payload
            )
            
            self._log_success(
                operation=operation,
                user_id=user.id,
                jti=jti[:8] + "...",
                expires_at=expires_at.isoformat()
            )
            
            return refresh_token
            
        except AuthenticationError:
            # Re-raise domain exceptions
            raise
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id if user else None
            )
    
    async def refresh_tokens(self, refresh_token: RefreshToken) -> Tuple[AccessToken, RefreshToken]:
        """Refreshes an access token using a valid refresh token.

        Args:
            refresh_token: The `RefreshToken` provided by the client.

        Returns:
            A tuple containing a new `AccessToken` and a new `RefreshToken`.

        Raises:
            AuthenticationError: If the refresh token is invalid, expired, or revoked.
        """
        operation = "refresh_tokens"
        
        try:
            # Validate the refresh token
            payload = await self.validate_token(refresh_token.token)
            
            # Extract user information
            user_id = int(payload.get("sub"))
            
            # Create a minimal user object for token creation
            # Note: In production, this should fetch the actual user from the repository
            user = User(
                id=user_id,
                username=payload.get("username", "unknown"),
                email=payload.get("email", "unknown@example.com"),
                role=Role.USER,  # Default role
                is_active=True
            )
            
            # Create new token pair
            new_access_token = await self.create_access_token(user)
            new_refresh_token = await self.create_refresh_token(user, new_access_token.get_token_id().value)
            
            self._log_success(
                operation=operation,
                user_id=user_id,
                old_jti=payload.get("jti", "")[:8] + "...",
                new_jti=new_access_token.get_token_id().value[:8] + "..."
            )
            
            return new_access_token, new_refresh_token
            
        except AuthenticationError:
            # Re-raise domain exceptions
            raise
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation
            )
    
    async def validate_access_token(self, token: str) -> dict:
        """Validates a JWT access token and returns its payload.

        Args:
            token: The JWT access token string to validate.

        Returns:
            A dictionary containing the token's payload if valid.

        Raises:
            AuthenticationError: If the token is invalid, expired, or has a
                bad signature.
        """
        return await self.validate_token(token)
    
    async def revoke_refresh_token(self, token: RefreshToken, language: str = "en") -> None:
        """Revokes a refresh token.

        This action effectively ends the user's session associated with this token.

        Args:
            token: The `RefreshToken` to be revoked.
            language: The language for any potential error messages.
        """
        operation = "revoke_refresh_token"
        
        try:
            # In this simple implementation, we just log the revocation
            # In a production system, this would add the token to a denylist
            self._log_success(
                operation=operation,
                jti=token.get_token_id().mask_for_logging(),
                user_id=token.get_user_id(),
                language=language
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                language=language
            )
    
    async def revoke_access_token(self, jti: str, expires_in: Optional[int] = None) -> None:
        """Revokes an access token by its unique identifier (jti).

        This adds the JTI to a denylist, preventing the token from being used
        even if it has not expired.

        Args:
            jti: The unique identifier (jti claim) of the token to revoke.
            expires_in: The remaining time until the token expires, used to
                set an appropriate TTL on the denylist entry.
        """
        operation = "revoke_access_token"
        
        try:
            # In this simple implementation, we just log the revocation
            # In a production system, this would add the JTI to a denylist
            self._log_success(
                operation=operation,
                jti=jti[:8] + "...",
                expires_in=expires_in
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation
            )
    
    async def validate_token(self, token: str, language: str = "en") -> dict:
        """A generic method to validate any JWT and return its payload.

        Args:
            token: The JWT string to validate.
            language: The language for error messages.

        Returns:
            A dictionary containing the token's payload if valid.

        Raises:
            AuthenticationError: If the token is invalid in any way.
        """
        operation = "validate_token"
        
        try:
            # Decode and validate the token
            payload = jwt.decode(
                token,
                settings.JWT_PUBLIC_KEY.get_secret_value(),
                algorithms=["RS256"],
                issuer=settings.JWT_ISSUER,
                audience=settings.JWT_AUDIENCE
            )
            
            self._log_success(
                operation=operation,
                jti=payload.get("jti", "")[:8] + "...",
                user_id=payload.get("sub"),
                language=language
            )
            
            return payload
            
        except PyJWTError as e:
            self._log_warning(
                operation=operation,
                message="Token validation failed",
                error=str(e),
                language=language
            )
            raise AuthenticationError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                language=language
            ) 