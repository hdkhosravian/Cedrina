import pytest
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime, timezone
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.domain.value_objects.token_requests import TokenCreationRequest, TokenRefreshRequest
from src.domain.value_objects.security_context import SecurityContext
from src.domain.entities.user import User, Role
from src.common.exceptions import AuthenticationError, SecurityViolationError
from src.infrastructure.database.session_factory import get_default_session_factory
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.fixture
def user():
    return User(id=1, username="testuser", email="test@example.com", role=Role.USER, is_active=True)

@pytest.fixture
def db_session():
    return AsyncMock(spec=AsyncSession)

@pytest.fixture
def domain_token_service():
    return DomainTokenService(session_factory=get_default_session_factory())

@pytest.mark.asyncio
async def test_create_token_pair_with_family_security_success(domain_token_service, user):
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id="corr-1")
    request = TokenCreationRequest(user=user, security_context=security_context)
    result = await domain_token_service.create_token_pair_with_family_security(request)
    assert result.access_token
    assert result.refresh_token
    assert result.family_id
    assert result.expires_in > 0

@pytest.mark.asyncio
async def test_create_token_pair_with_family_security_invalid_user(domain_token_service):
    user = User(id=2, username="inactive", email="inactive@example.com", role=Role.USER, is_active=False)
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id="corr-2")
    request = TokenCreationRequest(user=user, security_context=security_context)
    with pytest.raises(AuthenticationError):
        await domain_token_service.create_token_pair_with_family_security(request)

@pytest.mark.asyncio
async def test_refresh_tokens_with_family_security_success(domain_token_service, user):
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id="corr-3")
    creation_request = TokenCreationRequest(user=user, security_context=security_context)
    token_pair = await domain_token_service.create_token_pair_with_family_security(creation_request)
    refresh_request = TokenRefreshRequest(
        user=user,
        refresh_token=token_pair.refresh_token,
        security_context=security_context,
        correlation_id="corr-3"
    )
    result = await domain_token_service.refresh_tokens_with_family_security(refresh_request)
    assert result.access_token
    assert result.refresh_token
    assert result.family_id == token_pair.family_id

@pytest.mark.asyncio
async def test_refresh_tokens_with_family_security_invalid_token(domain_token_service, user):
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id="corr-4")
    refresh_request = TokenRefreshRequest(
        user=user,
        refresh_token="invalid.token.value",
        security_context=security_context,
        correlation_id="corr-4"
    )
    with pytest.raises(AuthenticationError):
        await domain_token_service.refresh_tokens_with_family_security(refresh_request)

@pytest.mark.asyncio
async def test_validate_token_with_family_security_success(domain_token_service, user):
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id="corr-5")
    creation_request = TokenCreationRequest(user=user, security_context=security_context)
    token_pair = await domain_token_service.create_token_pair_with_family_security(creation_request)
    payload = await domain_token_service.validate_token_with_family_security(
        access_token=token_pair.access_token,
        security_context=security_context,
        correlation_id="corr-5"
    )
    assert payload["sub"] == str(user.id)

@pytest.mark.asyncio
async def test_validate_token_with_family_security_invalid_token(domain_token_service, user):
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id="corr-6")
    with pytest.raises(AuthenticationError):
        await domain_token_service.validate_token_with_family_security(
            access_token="invalid.token.value",
            security_context=security_context,
            correlation_id="corr-6"
        ) 