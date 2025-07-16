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
    # Tamper with the token by changing multiple characters in the middle
    # This ensures the signature validation will fail
    token_parts = access_token.token.split('.')
    if len(token_parts) == 3:  # Valid JWT has 3 parts
        # Tamper with the payload (second part)
        payload = token_parts[1]
        # Change a character in the middle of the payload
        if len(payload) > 10:
            tampered_payload = payload[:len(payload)//2] + "X" + payload[len(payload)//2+1:]
            tampered = f"{token_parts[0]}.{tampered_payload}.{token_parts[2]}"
        else:
            # Fallback: just change the last character
            tampered = access_token.token[:-1] + ("A" if access_token.token[-1] != "A" else "B")
    else:
        # Fallback: just change the last character
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
    # Create a token manually with already expired expiration time
    from datetime import datetime, timezone, timedelta
    import jwt
    from src.core.config.settings import settings
    
    # Create an expired token payload
    exp_time = datetime.now(timezone.utc) - timedelta(minutes=1)  # 1 minute ago
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": int(exp_time.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": "test-token-id"
    }
    
    # Create the expired token
    expired_token = jwt.encode(
        payload,
        settings.JWT_PRIVATE_KEY.get_secret_value(),
        algorithm="RS256"
    )
    
    # Try to validate the expired token
    with pytest.raises(AuthenticationError):
        await jwt_service.validate_access_token(expired_token) 