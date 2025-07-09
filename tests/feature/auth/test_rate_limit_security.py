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
        assert resp.status_code in {401, 422}

    resp = await async_client.post("/api/v1/auth/login", json=creds)
    assert resp.status_code == 429

    time.sleep(1)
    resp = await async_client.post("/api/v1/auth/login", json=creds)
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
        assert resp.status_code in {401, 422}

    resp = await async_client.post("/api/v1/auth/login", json=creds, headers=headers)
    assert resp.status_code == 429

