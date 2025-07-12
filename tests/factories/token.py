from __future__ import annotations

"""Factory for generating fake token data for testing."""

import base64
import secrets
from typing import Any, Dict

from faker import Faker

from src.domain.value_objects.jwt_token import TokenId

fake = Faker()


def create_valid_token_id() -> str:
    """Create a valid TokenId string for testing.
    
    Returns:
        str: A valid 43-character base64url token ID
    """
    # Generate 32 bytes (256 bits) and encode as base64url
    raw_bytes = secrets.token_bytes(32)
    token_id = base64.urlsafe_b64encode(raw_bytes).rstrip(b'=').decode('ascii')
    return token_id


def create_fake_token(
    access_token: str = None, refresh_token: str = None, token_type: str = "Bearer"
) -> Dict[str, Any]:
    """Create a fake token dictionary for testing.

    Args:
        access_token (str, optional): Access token, defaults to a fake JWT-like string.
        refresh_token (str, optional): Refresh token, defaults to a fake JWT-like string.
        token_type (str, optional): Token type, defaults to 'Bearer'.

    Returns:
        Dict[str, Any]: A dictionary representing a token pair.

    """
    return {
        "access_token": (
            access_token
            if access_token
            else f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{fake.sha256()}.{fake.sha256()}"
        ),
        "refresh_token": (
            refresh_token
            if refresh_token
            else f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{fake.sha256()}.{fake.sha256()}"
        ),
        "token_type": token_type,
    }


def create_fake_jwt_claims(
    user_id: int = 1,
    username: str = "testuser",
    email: str = "test@example.com",
    role: str = "user",
    token_id: str = None,
    issuer: str = "test-issuer",
    audience: str = "test-audience",
    expires_in_hours: int = 1
) -> Dict[str, Any]:
    """Create fake JWT claims for testing.
    
    Args:
        user_id: User ID for the token
        username: Username for the token
        email: Email for the token
        role: User role for the token
        token_id: Token ID (JTI), defaults to a valid generated one
        issuer: Token issuer
        audience: Token audience
        expires_in_hours: Hours until token expires
        
    Returns:
        Dict[str, Any]: JWT claims dictionary
    """
    from datetime import datetime, timezone, timedelta
    
    if token_id is None:
        token_id = create_valid_token_id()
    
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=expires_in_hours)
    
    return {
        "sub": str(user_id),
        "username": username,
        "email": email,
        "role": role,
        "jti": token_id,
        "iss": issuer,
        "aud": audience,
        "exp": int(expires_at.timestamp()),
        "iat": int(now.timestamp()),
    }


def create_fake_access_token(
    user_id: int = 1,
    username: str = "testuser",
    email: str = "test@example.com",
    role: str = "user",
    token_id: str = None,
    expires_in_hours: int = 1
) -> str:
    """Create a fake JWT access token for testing.
    
    Args:
        user_id: User ID for the token
        username: Username for the token
        email: Email for the token
        role: User role for the token
        token_id: Token ID (JTI), defaults to a valid generated one
        expires_in_hours: Hours until token expires
        
    Returns:
        str: Encoded JWT access token
    """
    claims = create_fake_jwt_claims(
        user_id=user_id,
        username=username,
        email=email,
        role=role,
        token_id=token_id,
        expires_in_hours=expires_in_hours
    )
    
    # Create a fake JWT token (header.payload.signature)
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = base64.urlsafe_b64encode(str(claims).encode()).rstrip(b'=').decode('ascii')
    signature = fake.sha256()
    
    return f"{header}.{payload}.{signature}"


def create_fake_refresh_token(
    user_id: int = 1,
    token_id: str = None,
    expires_in_days: int = 7
) -> str:
    """Create a fake JWT refresh token for testing.
    
    Args:
        user_id: User ID for the token
        token_id: Token ID (JTI), defaults to a valid generated one
        expires_in_days: Days until token expires
        
    Returns:
        str: Encoded JWT refresh token
    """
    claims = create_fake_jwt_claims(
        user_id=user_id,
        username="",  # Refresh tokens typically don't include username
        email="",     # Refresh tokens typically don't include email
        role="",      # Refresh tokens typically don't include role
        token_id=token_id,
        expires_in_hours=expires_in_days * 24
    )
    
    # Create a fake JWT token (header.payload.signature)
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = base64.urlsafe_b64encode(str(claims).encode()).rstrip(b'=').decode('ascii')
    signature = fake.sha256()
    
    return f"{header}.{payload}.{signature}"
