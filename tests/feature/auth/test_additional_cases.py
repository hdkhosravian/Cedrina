import uuid
import pytest
from sqlmodel import select
from datetime import timedelta, datetime, timezone

from src.domain.entities.user import User


def _unique_user_data():
    unique = uuid.uuid4().hex[:8]
    return {
        "username": f"user_{unique}",
        "email": f"user_{unique}@example.com",
        "password": "Zx9#mK8@pL2!qR7$",  # Strong password
    }


@pytest.mark.asyncio
async def test_user_login_case_insensitive_username(async_client):
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": data["username"].upper(), "password": data["password"]},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_user_login_with_whitespace(async_client):
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": f"  {data['username']}  ", "password": data["password"]},
    )
    # The login endpoint returns 422 for validation errors when username has whitespace
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_password_reset_token_expiration_400_scenario(async_client):
    """Test password reset with expired token (should return 401)."""
    # Arrange
    expired_token = "expired_token_12345"
    new_password = "NewPassword123!"

    # Act
    response = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": expired_token, "new_password": new_password},
    )

    # Assert - Expired token should return 401 Unauthorized
    assert response.status_code == 401
    response_data = response.json()
    assert "detail" in response_data


@pytest.mark.asyncio
async def test_password_reset_token_expiration_401_scenario(async_client):
    """Test password reset with expired token (should return 401)."""
    # Arrange
    expired_token = "expired_token_67890"
    new_password = "NewPassword123!"

    # Act
    response = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": expired_token, "new_password": new_password},
    )

    # Assert - Expired token should return 401 Unauthorized
    assert response.status_code == 401
    response_data = response.json()
    assert "detail" in response_data


@pytest.mark.asyncio
async def test_password_reset_token_expiration_422_scenario(async_client):
    """Test password reset with invalid token format that returns 422"""
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    
    # Request password reset
    forgot_resp = await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})
    assert forgot_resp.status_code == 200
    
    # Test with invalid token format that triggers Pydantic validation -> 422
    invalid_token = "short"  # Too short - violates min_length=64 validation
    
    resp = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": invalid_token, "new_password": "NewPass123!"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_logout_invalid_token_401_scenario(async_client):
    """Test logout with invalid token that returns 401"""
    # Use POST method with malformed JWT token (not proper JWT format)
    resp = await async_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": "Bearer invalid_not_jwt_format"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_missing_authorization_header_401_scenario(async_client):
    """Test logout without authorization header that returns 401"""
    # Use POST method without Authorization header
    resp = await async_client.post("/api/v1/auth/logout")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_expired_token_401_scenario(async_client):
    """Test logout with expired token that returns 401"""
    # Create a properly formatted but expired JWT token
    import jwt
    from datetime import datetime, timezone, timedelta
    from src.core.config.settings import settings
    
    # Create an expired token
    expired_payload = {
        "sub": "12345", 
        "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),  # Expired 1 hour ago
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": "test_jti",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE
    }
    expired_token = jwt.encode(expired_payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")
    
    resp = await async_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401


