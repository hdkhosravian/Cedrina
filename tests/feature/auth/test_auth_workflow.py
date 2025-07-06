import uuid
import pytest
from sqlmodel import select

from src.domain.entities.user import User


def _unique_user_data():
    unique = uuid.uuid4().hex[:8]
    return {
        "username": f"testuser_{unique}",
        "email": f"test{unique}@example.com",
        "password": "TempPass123!",
    }


@pytest.mark.asyncio
async def test_full_password_reset_flow(async_client, async_session):
    user_data = _unique_user_data()

    register = await async_client.post("/api/v1/auth/register", json=user_data)
    assert register.status_code == 201

    # login should succeed immediately after registration
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": user_data["password"]},
    )
    assert login_resp.status_code == 200
    tokens = login_resp.json()["tokens"]
    access_token = tokens["access_token"]

    # request password reset
    forgot = await async_client.post(
        "/api/v1/auth/forgot-password", json={"email": user_data["email"]}
    )
    assert forgot.status_code == 200

    # fetch reset token from database
    result = await async_session.execute(
        select(User).where(User.email == user_data["email"])
    )
    user = result.scalars().first()
    assert user is not None and user.password_reset_token
    reset_token = user.password_reset_token

    # perform password reset
    new_password = "NewPass456!"
    reset_resp = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": new_password},
    )
    assert reset_resp.status_code == 200

    # login should now require the new password
    old_login = await async_client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": user_data["password"]},
    )
    assert old_login.status_code in {401, 422}

    login_new = await async_client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": new_password},
    )
    assert login_new.status_code == 200
    new_tokens = login_new.json()["tokens"]

    # change password using authorized endpoint
    newest_password = "NewestPass789!"
    change_resp = await async_client.put(
        "/api/v1/auth/change-password",
        json={"old_password": new_password, "new_password": newest_password},
        headers={"Authorization": f"Bearer {new_tokens['access_token']}"},
    )
    assert change_resp.status_code == 200

    login_final = await async_client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": newest_password},
    )
    assert login_final.status_code == 200


@pytest.mark.asyncio
async def test_email_confirmation_flow(async_client, async_session, monkeypatch):
    monkeypatch.setattr(
        "src.core.config.settings.settings", "EMAIL_CONFIRMATION_ENABLED", True
    )

    user_data = _unique_user_data()

    register = await async_client.post("/api/v1/auth/register", json=user_data)
    assert register.status_code == 201

    result = await async_session.execute(
        select(User).where(User.email == user_data["email"])
    )
    user = result.scalars().first()
    assert user is not None
    assert not user.is_active
    assert user.email_confirmation_token

    # login should fail before confirmation
    login_before = await async_client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": user_data["password"]},
    )
    assert login_before.status_code in {401, 403, 422}

    token = user.email_confirmation_token
    confirm = await async_client.get(f"/api/v1/auth/confirm-email?token={token}")
    assert confirm.status_code == 200

    result = await async_session.execute(
        select(User).where(User.email == user_data["email"])
    )
    user_after = result.scalars().first()
    assert user_after.is_active
    assert user_after.email_confirmed
    assert user_after.email_confirmation_token is None

