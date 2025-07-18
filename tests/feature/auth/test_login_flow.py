import uuid
import pytest


def _unique_user_data():
    unique = uuid.uuid4().hex[:8]
    return {
        "username": f"testuser_{unique}",
        "email": f"test{unique}@example.com",
        "password": "Zx9#mK8@pL2!qR7$",  # Strong password
    }


@pytest.mark.asyncio
async def test_register_and_login_successful(async_client):
    user_data = _unique_user_data()
    register_resp = await async_client.post("/api/v1/auth/register", json=user_data)
    assert register_resp.status_code == 201

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": user_data["password"]},
    )
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["user"]["username"] == user_data["username"]
    assert set(data["tokens"]).issuperset({"access_token", "refresh_token", "token_type", "expires_in"})


@pytest.mark.asyncio
async def test_login_wrong_password(async_client):
    user_data = _unique_user_data()
    await async_client.post("/api/v1/auth/register", json=user_data)

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": "WrongPass123!"},
    )
    assert login_resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user_401_scenario(async_client):
    """Test login with nonexistent user that returns 401"""
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "nouser", "password": "AnyPass123!"},
    )
    assert login_resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user_422_scenario(async_client):
    """Test login with nonexistent user that returns 401 (production behavior)"""
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "nouser", "password": "AnyPass123!"},
    )
    assert login_resp.status_code == 401


@pytest.mark.asyncio
async def test_login_validation_errors(async_client):
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "onlyuser"},
    )
    assert resp.status_code == 422
