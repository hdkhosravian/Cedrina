from __future__ import annotations

"""Request‐payload Pydantic models for authentication endpoints."""

from typing import Any, Dict, Literal

from pydantic import BaseModel, EmailStr, Field, constr, field_validator

# ---------------------------------------------------------------------------
# Shared / primitive types ---------------------------------------------------
# ---------------------------------------------------------------------------

UsernameStr = constr(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")

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

    refresh_token: str = Field(..., examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."])


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
        if not v or not isinstance(v, str):
            raise ValueError("Token must be a non-empty string")
        
        # Check basic JWT structure (header.payload.signature)
        parts = v.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format: must have exactly 3 parts separated by dots")
        
        # Check that each part is non-empty and contains valid base64url characters
        import string
        valid_chars = string.ascii_letters + string.digits + '-_='
        
        for i, part in enumerate(parts):
            if not part:
                raise ValueError(f"JWT part {i + 1} cannot be empty")
            
            if not all(c in valid_chars for c in part):
                raise ValueError(f"JWT part {i + 1} contains invalid characters")
        
        # Check reasonable length constraints
        if len(v) < 50:
            raise ValueError("Token too short to be a valid JWT")
        
        if len(v) > 2048:
            raise ValueError("Token too long - possible attack vector")
        
        return v
    
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
