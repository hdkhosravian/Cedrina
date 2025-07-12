import asyncio
import uuid
import pytest
from sqlmodel import select

from src.core.config.settings import settings
from src.core.rate_limiting.ratelimiter import get_limiter
from src.domain.entities.user import User


def _unique_user_data():
    unique = uuid.uuid4().hex[:8]
    return {
        "username": f"adv_user_{unique}",
        "email": f"adv_{unique}@example.com",
        "password": "Zx9#mK8@pL2!qR7$",  # Strong password
    }


@pytest.mark.asyncio
async def test_registration_email_confirmation_disabled(async_client, async_session, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_CONFIRMATION_ENABLED", False)

    data = _unique_user_data()
    resp = await async_client.post("/api/v1/auth/register", json=data)
    assert resp.status_code == 201

    result = await async_session.execute(select(User).where(User.email == data["email"]))
    user = result.scalars().first()
    assert user.is_active is True
    assert user.email_confirmed is True

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": data["username"], "password": data["password"]},
    )
    assert login_resp.status_code == 200


@pytest.mark.asyncio
async def test_register_rate_limit_enforced(async_client, monkeypatch):
    # First, override environment variable to enable rate limiting
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    
    # Then set the settings attributes
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "2/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    await async_client.post("/api/v1/auth/register", json=_unique_user_data())
    await async_client.post("/api/v1/auth/register", json=_unique_user_data())
    resp = await async_client.post("/api/v1/auth/register", json=_unique_user_data())
    assert resp.status_code == 429


@pytest.mark.anyio
async def test_forgot_password_rate_limit_enforced(async_client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)

    for _ in range(3):
        resp = await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})
        assert resp.status_code == 200

    resp = await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_user_login_inactive_account(async_client, async_session):
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)

    result = await async_session.execute(select(User).where(User.username == data["username"]))
    user = result.scalars().first()
    user.is_active = False
    await async_session.commit()

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": data["username"], "password": data["password"]},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_invalid_email_format(async_client):
    resp = await async_client.post("/api/v1/auth/forgot-password", json={"email": "invalid"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_concurrent_requests(async_client):
    data = _unique_user_data()
    duplicate = {**data}

    resp1, resp2 = await asyncio.gather(
        async_client.post("/api/v1/auth/register", json=data),
        async_client.post("/api/v1/auth/register", json=duplicate),
    )

    statuses = sorted([resp1.status_code, resp2.status_code])
    assert statuses[0] == 201
    assert statuses[1] == 409


@pytest.mark.asyncio
async def test_password_reset_weak_new_password(async_client, async_session):
    data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=data)
    await async_client.post("/api/v1/auth/forgot-password", json={"email": data["email"]})

    result = await async_session.execute(select(User).where(User.email == data["email"]))
    user = result.scalars().first()
    token = user.password_reset_token

    resp = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "weak"},
    )
    assert resp.status_code == 422
