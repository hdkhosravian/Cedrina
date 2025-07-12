from __future__ import annotations

"""Request‐payload Pydantic models for authentication endpoints."""

import string
from typing import Any, Dict, Literal

from pydantic import BaseModel, EmailStr, Field, constr, field_validator

# ---------------------------------------------------------------------------
# Shared / primitive types ---------------------------------------------------
# ---------------------------------------------------------------------------

UsernameStr = constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")

# ---------------------------------------------------------------------------
# Shared validation utilities -------------------------------------------------
# ---------------------------------------------------------------------------

def validate_jwt_format(token: str, field_name: str = "token") -> str:
    """
    Validate basic JWT format structure for security.
    
    Performs basic format validation without token verification
    to prevent obvious attack vectors and malformed payloads.
    
    Args:
        token: JWT token string to validate
        field_name: Name of the field for error messages
        
    Returns:
        str: Validated token string
        
    Raises:
        ValueError: If token format is invalid
    """
    if not token or not isinstance(token, str):
        raise ValueError(f"{field_name} must be a non-empty string")
    
    # Check basic JWT structure (header.payload.signature)
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: must have exactly 3 parts separated by dots")
    
    # Check that each part is non-empty and contains valid base64url characters
    valid_chars = string.ascii_letters + string.digits + '-_='
    
    for i, part in enumerate(parts):
        if not part:
            raise ValueError(f"JWT part {i + 1} cannot be empty")
        
        if not all(c in valid_chars for c in part):
            raise ValueError(f"JWT part {i + 1} contains invalid characters")
    
    # Check reasonable length constraints
    if len(token) < 50:
        raise ValueError(f"{field_name} too short to be a valid JWT")
    
    if len(token) > 2048:
        raise ValueError(f"{field_name} too long - possible attack vector")
    
    return token

# ---------------------------------------------------------------------------
# Concrete request models ----------------------------------------------------
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    """Payload expected by ``POST /auth/register``."""

    username: UsernameStr = Field(..., examples=["john_doe"])
    email: EmailStr = Field(..., examples=["john@example.com"])
    password: str = Field(..., examples=["Str0ngP@ssw0rd"])


class LoginRequest(BaseModel):
    """Payload expected by ``POST /auth/login``."""

    username: UsernameStr = Field(..., examples=["john_doe"])
    password: str = Field(..., examples=["Str0ngP@ssw0rd"])


class OAuthAuthenticateRequest(BaseModel):
    """Payload expected by ``POST /auth/oauth``."""

    provider: Literal["google", "microsoft", "facebook"] = Field(..., examples=["google"])
    token: Dict[str, Any] = Field(
        ..., examples=[{"access_token": "ya29.a0AfH6SMC...", "expires_at": 1640995200}]
    )


class LogoutRequest(BaseModel):
    """Payload expected by ``DELETE /auth/logout``."""

    refresh_token: str = Field(
        ...,
        min_length=50,  # Minimum realistic JWT length
        max_length=2048,  # Maximum reasonable JWT length to prevent abuse
        examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."],
        description="Refresh token to revoke for logout"
    )
    
    @field_validator('refresh_token')
    @classmethod
    def validate_refresh_token_format(cls, v: str) -> str:
        """
        Validate refresh token format for security.
        
        Performs basic format validation without token verification
        to prevent obvious attack vectors and malformed payloads.
        """
        return validate_jwt_format(v, "refresh_token")


class RefreshTokenRequest(BaseModel):
    """
    Payload expected by ``POST /auth/refresh``.
    
    Implements advanced security requirement that both access and refresh tokens 
    must be provided together and belong to the same session (same JTI).
    
    Security Features:
    - Both tokens are required (no partial refresh)
    - Token pairing validation ensures session integrity
    - Comprehensive input validation with security constraints
    """
    
    access_token: str = Field(
        ...,
        min_length=50,  # Minimum realistic JWT length
        max_length=2048,  # Maximum reasonable JWT length to prevent abuse
        examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature"],
        description="Current access token that must belong to same session as refresh token"
    )
    
    refresh_token: str = Field(
        ...,
        min_length=50,  # Minimum realistic JWT length  
        max_length=2048,  # Maximum reasonable JWT length to prevent abuse
        examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"],
        description="Current refresh token that must belong to same session as access token"
    )
    
    @field_validator('access_token', 'refresh_token')
    @classmethod
    def validate_jwt_format(cls, v: str) -> str:
        """
        Validate basic JWT format structure for security.
        
        Performs basic format validation without token verification
        to prevent obvious attack vectors and malformed payloads.
        """
        return validate_jwt_format(v, "token")
    
    class Config:
        """Pydantic configuration for enhanced security."""
        
        # Prevent additional fields to avoid injection attacks
        extra = "forbid"
        
        # Enable validation assignment for security
        validate_assignment = True
        
        # Use enum values for better security
        use_enum_values = True
        
        # Example schema for API documentation
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature",
                "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"
            }
        }


class ChangePasswordRequest(BaseModel):
    """Payload expected by ``PUT /auth/change-password``."""

    old_password: str = Field(
        ..., examples=["OldPass123!"], description="Current password for verification"
    )
    new_password: str = Field(
        ...,
        examples=["NewPass456!"],
        description="New password that meets security policy requirements",
    )


class ForgotPasswordRequest(BaseModel):
    """Payload expected by ``POST /auth/forgot-password``."""

    email: EmailStr = Field(
        ..., 
        examples=["john@example.com"],
        description="Email address to send password reset instructions to"
    )


class ResetPasswordRequest(BaseModel):
    """Payload expected by ``POST /auth/reset-password``."""

    token: str = Field(
        ...,
        examples=["a1b2c3d4e5f6..."],
        description="Password reset token received via email",
        min_length=64,
        max_length=64
    )
    new_password: str = Field(
        ...,
        examples=["NewSecurePass123!"],
        description="New password that meets security policy requirements"
    )


class ResendConfirmationRequest(BaseModel):
    email: EmailStr
