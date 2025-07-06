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
        "password": "SecurePass1!",
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
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_password_reset_token_expiration(async_client, async_session):
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})
    result = await async_session.execute(select(User).where(User.email == data["email"]))
    user = result.scalars().first()
    token = user.password_reset_token
    # artificially expire token
    user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await async_session.commit()
    resp = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "NewPass123!"},
    )
    assert resp.status_code in {400, 401}


@pytest.mark.asyncio
async def test_logout_invalid_token(async_client):
    resp = await async_client.delete(
        "/api/v1/auth/logout",
        json={"refresh_token": "invalid"},
        headers={"Authorization": "Bearer invalid"},
    )
    assert resp.status_code in {200, 401}


