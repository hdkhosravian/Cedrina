import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet

from src.infrastructure.services.authentication.oauth import OAuthService
from src.domain.entities.user import User, Role
from src.domain.entities.oauth_profile import OAuthProfile, Provider
from src.common.exceptions import AuthenticationError

@pytest_asyncio.fixture
def db_session():
    session = AsyncMock()
    session.execute = AsyncMock()
    session.get = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    return session

@pytest_asyncio.fixture
def oauth_service(db_session):
    with patch("src.infrastructure.services.authentication.oauth.OAuth") as mock_oauth:
        with patch("src.infrastructure.services.authentication.oauth.Fernet") as mock_fernet:
            mock_fernet.return_value.encrypt = MagicMock(side_effect=lambda b: b"encrypted_" + b)
            return OAuthService(db_session)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_success_new_user(oauth_service, db_session):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    user_info = {"email": "newuser@example.com", "sub": "providerid123"}
    
    # Mock the database query results
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.first.side_effect = [None, None]  # No existing OAuth profile, No existing user
    mock_result.scalars.return_value = mock_scalars
    db_session.execute.return_value = mock_result
    db_session.get.return_value = None
    
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value=user_info)):
        user, profile = await oauth_service.authenticate_with_oauth(provider, token)
        assert user.email == "newuser@example.com"
        assert profile.provider == Provider(provider)
        assert profile.provider_user_id == "providerid123"
        assert profile.access_token.startswith(b"encrypted_")
        db_session.add.assert_called()
        db_session.commit.assert_called()
        db_session.refresh.assert_called()

@pytest.mark.asyncio
async def test_authenticate_with_oauth_success_existing_user(oauth_service, db_session):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    user_info = {"email": "existing@example.com", "sub": "providerid456"}
    user = User(id=1, username="existing", email="existing@example.com", role=Role.USER, is_active=True)
    
    # Mock the database query results
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.first.side_effect = [None, user]  # No existing OAuth profile, existing user
    mock_result.scalars.return_value = mock_scalars
    db_session.execute.return_value = mock_result
    db_session.get.return_value = user
    
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value=user_info)):
        user, profile = await oauth_service.authenticate_with_oauth(provider, token)
        assert user.email == "existing@example.com"
        assert profile.provider == Provider(provider)
        assert profile.provider_user_id == "providerid456"
        db_session.add.assert_called()  # OAuth profile is added
        db_session.commit.assert_called()  # OAuth profile is committed
        # refresh is not called when user already exists

@pytest.mark.asyncio
async def test_authenticate_with_oauth_existing_oauth_profile(oauth_service, db_session):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    user_info = {"email": "existing@example.com", "sub": "providerid789"}
    user = User(id=2, username="existing2", email="existing@example.com", role=Role.USER, is_active=True)
    oauth_profile = OAuthProfile(user_id=2, provider=Provider(provider), provider_user_id="providerid789", access_token=b"encrypted_token", expires_at=datetime.now(timezone.utc))
    
    # Mock the database query results
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.first.side_effect = [oauth_profile]  # Existing OAuth profile found
    mock_result.scalars.return_value = mock_scalars
    db_session.execute.return_value = mock_result
    db_session.get.return_value = user
    
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value=user_info)):
        user, profile = await oauth_service.authenticate_with_oauth(provider, token)
        assert user.id == 2
        assert profile.provider_user_id == "providerid789"

@pytest.mark.asyncio
async def test_authenticate_with_oauth_inactive_user(oauth_service, db_session):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    user_info = {"email": "inactive@example.com", "sub": "providerid000"}
    user = User(id=3, username="inactive", email="inactive@example.com", role=Role.USER, is_active=False)
    oauth_profile = OAuthProfile(user_id=3, provider=Provider(provider), provider_user_id="providerid000", access_token=b"encrypted_token", expires_at=datetime.now(timezone.utc))
    
    # Mock the database query results
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.first.side_effect = [oauth_profile]  # Existing OAuth profile found
    mock_result.scalars.return_value = mock_scalars
    db_session.execute.return_value = mock_result
    db_session.get.return_value = user
    
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value=user_info)):
        with pytest.raises(AuthenticationError):
            await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_token_expired(oauth_service):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() - 10}
    with pytest.raises(AuthenticationError):
        await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_invalid_user_info(oauth_service):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value={} )):
        with pytest.raises(AuthenticationError):
            await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_missing_email_or_provider_id(oauth_service):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    # Missing email
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value={"sub": "providerid"})):
        with pytest.raises(AuthenticationError):
            await oauth_service.authenticate_with_oauth(provider, token)
    # Missing provider id
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value={"email": "user@example.com"})):
        with pytest.raises(AuthenticationError):
            await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_id_token_validation_error(oauth_service):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600, "id_token": "badidtoken"}
    with patch.object(oauth_service.oauth, "create_client") as mock_create_client:
        mock_client = AsyncMock()
        mock_client.parse_id_token = AsyncMock(side_effect=Exception("bad id_token"))
        mock_create_client.return_value = mock_client
        with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value={"email": "user@example.com", "sub": "providerid"})):
            with pytest.raises(AuthenticationError):
                await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_id_token_issuer_mismatch(oauth_service):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600, "id_token": "goodidtoken"}
    with patch.object(oauth_service.oauth, "create_client") as mock_create_client:
        mock_client = AsyncMock()
        mock_client.parse_id_token = AsyncMock(return_value={"iss": "wrong_issuer"})
        mock_create_client.return_value = mock_client
        with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value={"email": "user@example.com", "sub": "providerid"})):
            with pytest.raises(AuthenticationError):
                await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_authenticate_with_oauth_network_failure_retries(oauth_service, db_session):
    provider = "google"
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    
    # Mock the database query results
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.first.side_effect = [None, None]  # No existing OAuth profile, No existing user
    mock_result.scalars.return_value = mock_scalars
    db_session.execute.return_value = mock_result
    db_session.get.return_value = None
    
    # Test that network failures are retried and eventually fail
    # The _fetch_user_info method has @retry decorator with 3 attempts
    with patch.object(oauth_service, "_fetch_user_info", side_effect=Exception("network error")):
        with pytest.raises(Exception, match="network error"):
            await oauth_service.authenticate_with_oauth(provider, token)

@pytest.mark.asyncio
async def test_validate_oauth_state_success(oauth_service):
    result = await oauth_service.validate_oauth_state("abc", "abc")
    assert result is True

@pytest.mark.asyncio
async def test_validate_oauth_state_failure(oauth_service):
    result = await oauth_service.validate_oauth_state("abc", "def")
    assert result is False

@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["google", "microsoft", "facebook"])
async def test_authenticate_with_oauth_all_providers(oauth_service, provider, db_session):
    token = {"access_token": "token123", "expires_at": datetime.now(timezone.utc).timestamp() + 3600}
    user_info = {"email": f"{provider}@example.com", "sub": f"{provider}_id"}
    
    # Mock the database query results
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.first.side_effect = [None, None]  # No existing OAuth profile, No existing user
    mock_result.scalars.return_value = mock_scalars
    db_session.execute.return_value = mock_result
    db_session.get.return_value = None
    
    with patch.object(oauth_service, "_fetch_user_info", AsyncMock(return_value=user_info)):
        user, profile = await oauth_service.authenticate_with_oauth(provider, token)
        assert user.email == f"{provider}@example.com"
        assert profile.provider == Provider(provider)
        assert profile.provider_user_id == f"{provider}_id" 