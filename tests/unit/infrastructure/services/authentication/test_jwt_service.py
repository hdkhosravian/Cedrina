import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
from src.infrastructure.services.authentication.jwt_service import JWTService
from src.domain.entities.user import User, Role
from src.common.exceptions import AuthenticationError
from src.domain.value_objects.jwt_token import AccessToken, RefreshToken
import jwt

@pytest.fixture
def user():
    return User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)

@pytest.fixture
def jwt_service():
    return JWTService()

@pytest.mark.asyncio
async def test_create_access_token_success(jwt_service, user):
    token = await jwt_service.create_access_token(user)
    assert isinstance(token, AccessToken)
    assert token.claims["sub"] == str(user.id)
    assert token.claims["username"] == user.username
    assert not token.is_expired()

@pytest.mark.asyncio
async def test_create_access_token_inactive_user(jwt_service):
    user = User(id=2, username="inactive", email="inactive@example.com", role=Role.USER, is_active=False)
    with pytest.raises(AuthenticationError):
        await jwt_service.create_access_token(user)

@pytest.mark.asyncio
async def test_create_refresh_token_success(jwt_service, user):
    token = await jwt_service.create_refresh_token(user)
    assert isinstance(token, RefreshToken)
    assert token.claims["sub"] == str(user.id)
    assert not token.is_expired()

@pytest.mark.asyncio
async def test_validate_token_success(jwt_service, user):
    access_token = await jwt_service.create_access_token(user)
    payload = await jwt_service.validate_token(access_token.token)
    assert payload["sub"] == str(user.id)

@pytest.mark.asyncio
async def test_validate_token_tampered(jwt_service, user):
    access_token = await jwt_service.create_access_token(user)
    # Tamper with the token
    tampered = access_token.token[:-1] + ("A" if access_token.token[-1] != "A" else "B")
    with pytest.raises(AuthenticationError):
        await jwt_service.validate_token(tampered)

@pytest.mark.asyncio
async def test_refresh_tokens_success(jwt_service, user):
    refresh_token = await jwt_service.create_refresh_token(user)
    access_token, new_refresh_token = await jwt_service.refresh_tokens(refresh_token)
    assert isinstance(access_token, AccessToken)
    assert isinstance(new_refresh_token, RefreshToken)
    assert not access_token.is_expired()
    assert not new_refresh_token.is_expired()

@pytest.mark.asyncio
async def test_revoke_access_token_logs(jwt_service):
    # Just ensure it doesn't raise
    await jwt_service.revoke_access_token("some-jti")

@pytest.mark.asyncio
async def test_revoke_refresh_token_logs(jwt_service, user):
    refresh_token = await jwt_service.create_refresh_token(user)
    await jwt_service.revoke_refresh_token(refresh_token)

@pytest.mark.asyncio
async def test_validate_access_token_expired(jwt_service, user):
    # Create a token with a short expiry
    with patch("src.infrastructure.services.authentication.jwt_service.settings.ACCESS_TOKEN_EXPIRE_MINUTES", 0):
        token = await jwt_service.create_access_token(user)
    # Fast-forward time
    with patch("datetime.datetime") as mock_dt:
        mock_dt.now.return_value = datetime.now(timezone.utc) + timedelta(minutes=1)
        with pytest.raises(AuthenticationError):
            await jwt_service.validate_access_token(token.token) 