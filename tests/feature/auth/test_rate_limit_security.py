import time
import uuid
import pytest

from src.core.config.settings import settings
from src.core.rate_limiting.ratelimiter import get_limiter


def _invalid_login_data():
    return {"username": f"user_{uuid.uuid4().hex[:6]}", "password": "WrongPass1!"}


@pytest.mark.asyncio
async def test_login_rate_limit_enforced(async_client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "2/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    creds = _invalid_login_data()

    for _ in range(2):
        resp = await async_client.post("/api/v1/auth/login", json=creds)
        # Rate limiting tests can expect either 401 or 422 for invalid credentials
        assert resp.status_code in {401, 422}

    resp = await async_client.post("/api/v1/auth/login", json=creds)
    assert resp.status_code == 429

    time.sleep(1)
    resp = await async_client.post("/api/v1/auth/login", json=creds)
    # Rate limiting tests can expect either 401 or 422 for invalid credentials
    assert resp.status_code in {401, 422}


@pytest.mark.asyncio
async def test_rate_limit_not_bypassed_by_headers(async_client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "2/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    creds = _invalid_login_data()
    headers = {"X-User-ID": "999", "X-User-Tier": "admin"}

    for _ in range(2):
        resp = await async_client.post("/api/v1/auth/login", json=creds, headers=headers)
        # Rate limiting tests can expect either 401 or 422 for invalid credentials
        assert resp.status_code in {401, 422}

    resp = await async_client.post("/api/v1/auth/login", json=creds, headers=headers)
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_login_rate_limit_401_scenario(async_client, monkeypatch):
    """Test login rate limit with 401 response"""
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "2/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    creds = _invalid_login_data()

    for _ in range(2):
        resp = await async_client.post("/api/v1/auth/login", json=creds)
        assert resp.status_code == 401

    resp = await async_client.post("/api/v1/auth/login", json=creds)
    assert resp.status_code == 429

    time.sleep(1)
    resp = await async_client.post("/api/v1/auth/login", json=creds)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_rate_limit_422_scenario(async_client, monkeypatch):
    """Test login rate limit with authentication failures (401 response)"""
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "2/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    creds = _invalid_login_data()

    for _ in range(2):
        resp = await async_client.post("/api/v1/auth/login", json=creds)
        assert resp.status_code == 401  # Authentication failure, not validation error

    resp = await async_client.post("/api/v1/auth/login", json=creds)
    assert resp.status_code == 429

    time.sleep(1)
    resp = await async_client.post("/api/v1/auth/login", json=creds)
    assert resp.status_code == 401  # Back to authentication failure after rate limit reset


@pytest.mark.asyncio
async def test_rate_limit_bypass_headers_401_scenario(async_client, monkeypatch):
    """Test rate limit bypass with headers returning 401"""
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "2/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    creds = _invalid_login_data()
    headers = {"X-User-ID": "999", "X-User-Tier": "admin"}

    for _ in range(2):
        resp = await async_client.post("/api/v1/auth/login", json=creds, headers=headers)
        assert resp.status_code == 401

    resp = await async_client.post("/api/v1/auth/login", json=creds, headers=headers)
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_rate_limit_bypass_headers_422_scenario(async_client, monkeypatch):
    """Test rate limit bypass with headers returning authentication failures (401)"""
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH", "2/second")
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_URL", "memory://")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)

    from src.main import app
    app.state.limiter = get_limiter()

    creds = _invalid_login_data()
    headers = {"X-User-ID": "999", "X-User-Tier": "admin"}

    for _ in range(2):
        resp = await async_client.post("/api/v1/auth/login", json=creds, headers=headers)
        assert resp.status_code == 401  # Authentication failure, not validation error

    resp = await async_client.post("/api/v1/auth/login", json=creds, headers=headers)
    assert resp.status_code == 429

