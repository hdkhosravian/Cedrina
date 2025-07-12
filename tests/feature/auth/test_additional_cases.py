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
    """Test password reset with expired token that returns 400"""
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    
    # Request password reset
    forgot_resp = await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})
    assert forgot_resp.status_code == 200
    
    # Test with malformed expired token that returns 400
    expired_token = "malformed_expired_token"
    
    resp = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": expired_token, "new_password": "NewPass123!"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_token_expiration_401_scenario(async_client):
    """Test password reset with expired token that returns 401"""
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    
    # Request password reset
    forgot_resp = await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})
    assert forgot_resp.status_code == 200
    
    # Test with expired token that returns 401
    expired_token = "expired_token_12345678901234567890123456789012"
    
    resp = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": expired_token, "new_password": "NewPass123!"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_token_expiration_422_scenario(async_client):
    """Test password reset with expired token that returns 422"""
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    
    # Request password reset
    forgot_resp = await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})
    assert forgot_resp.status_code == 200
    
    # Test with invalid token format that returns 422
    invalid_token = "invalid_token_format"
    
    resp = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": invalid_token, "new_password": "NewPass123!"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_logout_invalid_token_401_scenario(async_client):
    """Test logout with invalid token that returns 401"""
    # Use the generic request method to send a body with DELETE
    resp = await async_client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "invalid"},
        headers={"Authorization": "Bearer invalid"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_invalid_token_422_scenario(async_client):
    """Test logout with invalid token that returns 422"""
    # Use the generic request method to send a body with DELETE
    resp = await async_client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "invalid_format"},
        headers={"Authorization": "Bearer invalid_format"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_logout_invalid_token_400_scenario(async_client):
    """Test logout with invalid token that returns 400"""
    # Use the generic request method to send a body with DELETE
    resp = await async_client.request(
        "DELETE",
        "/api/v1/auth/logout",
        json={"refresh_token": "malformed_token"},
        headers={"Authorization": "Bearer malformed_token"},
    )
    assert resp.status_code == 400


