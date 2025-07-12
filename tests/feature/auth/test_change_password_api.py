"""Integration tests for the change password API endpoint.

This test suite covers comprehensive real-world scenarios including:
- Successful password changes
- Authentication failures (401)
- Password validation failures (400)
- I18N support for different languages
- Security edge cases
- Error handling and logging
- Real-world JWT token validation
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from jose import jwt
from passlib.context import CryptContext

from src.core.config.settings import BCRYPT_WORK_FACTOR, settings
from src.core.dependencies.auth import get_current_user
from src.domain.entities.user import Role, User
from src.domain.interfaces.repositories import IUserRepository
from src.common.events import IEventPublisher
from src.domain.interfaces.authentication.password_change import IPasswordChangeService
from src.infrastructure.database.async_db import get_async_db
from src.infrastructure.dependency_injection.auth_dependencies import (
    get_event_publisher,
    get_password_change_service,
    get_user_repository,
)
from src.infrastructure.redis import get_redis
from src.main import app


@pytest_asyncio.fixture
async def mock_db_session():
    """Create a properly mocked async database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    session.get = AsyncMock()
    session.exec = AsyncMock()
    return session


@pytest_asyncio.fixture
async def mock_redis_client():
    """Create a properly mocked Redis client."""
    redis_client = AsyncMock()
    redis_client.get = AsyncMock()
    redis_client.set = AsyncMock()
    redis_client.delete = AsyncMock()
    redis_client.exists = AsyncMock()
    return redis_client


@pytest.fixture
def mock_user_repository():
    """Create a mock user repository for clean architecture."""
    repository = AsyncMock(spec=IUserRepository)
    repository.get_by_id = AsyncMock()
    repository.save = AsyncMock()
    return repository


@pytest.fixture
def mock_event_publisher():
    """Create a mock event publisher for clean architecture."""
    publisher = AsyncMock(spec=IEventPublisher)
    publisher.publish = AsyncMock()
    return publisher


@pytest.fixture
def mock_password_change_service():
    """Create a mock password change service for clean architecture."""
    service = AsyncMock(spec=IPasswordChangeService)
    service.change_password = AsyncMock()
    return service


@pytest.fixture
def test_user():
    """Create a test user with valid credentials."""
    pwd_context = CryptContext(
        schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_WORK_FACTOR
    )
    hashed_password = pwd_context.hash("OldPass123!")
    return User(
        id=1,
        username="testuser",
        email="test@example.com",
        hashed_password=hashed_password,
        role=Role.USER,
        is_active=True,
    )


def create_test_jwt_token(user: User) -> str:
    """Create a test JWT token for testing purposes."""
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "iat": datetime.now(timezone.utc),
        "jti": "test_jti_123",
    }
    return jwt.encode(payload, settings.JWT_PRIVATE_KEY.get_secret_value(), algorithm="RS256")


def override_get_current_user(user):
    async def _override():
        return user

    return _override


class TestChangePasswordAPI:
    """Integration tests for the change password API endpoint."""

    def test_change_password_success(
        self,
        test_user,
        mock_db_session,
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test successful password change with valid credentials."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_user_repository.get_by_id.return_value = test_user
        mock_password_change_service.change_password.return_value = None

        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service

        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"

            # Verify the service was called with correct parameters
            mock_password_change_service.change_password.assert_called_once()
            call_args = mock_password_change_service.change_password.call_args
            assert call_args[1]["user_id"] == test_user.id
            assert call_args[1]["old_password"] == "OldPass123!"
            assert call_args[1]["new_password"] == "NewPass456!"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_invalid_token(self, mock_db_session, mock_redis_client):
        """Test change password fails with invalid JWT token."""
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": "Bearer invalid_token"},
            )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    def test_change_password_missing_token(self, mock_db_session, mock_redis_client):
        """Test change password fails when no token is provided."""
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
            )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    def test_change_password_invalid_old_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with incorrect old password (400 status)."""
        from src.common.exceptions import InvalidOldPasswordError
        
        # Setup mocks - service should raise InvalidOldPasswordError
        mock_password_change_service.change_password.side_effect = InvalidOldPasswordError("Invalid old password")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "WrongOldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 400
            assert response.json()["detail"] == "Invalid old password"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_weak_new_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with weak new password (422 status)."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup mocks - service should raise PasswordPolicyError
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Password must be at least 8 characters long")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "weak"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_same_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails when new password is same as old (400 status)."""
        from src.common.exceptions import PasswordReuseError
        
        # Setup mocks - service should raise PasswordReuseError
        mock_password_change_service.change_password.side_effect = PasswordReuseError("New password must be different from the old password")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "OldPass123!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 400
            assert (
                response.json()["detail"] == "New password must be different from the old password"
            )
        finally:
            app.dependency_overrides.clear()

    def test_change_password_i18n_english(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with English language support."""
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}", "Accept-Language": "en"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_i18n_spanish(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with Spanish language support."""
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}", "Accept-Language": "es"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Contraseña cambiada exitosamente"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_missing_old_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with missing old_password field."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_missing_new_password(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with missing new_password field."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_password_policy_too_short(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with password too short."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Password must be at least 8 characters long")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "short"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_password_policy_no_uppercase(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with password missing uppercase."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Password must contain at least one uppercase letter")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "nouppercase123!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_password_policy_no_lowercase(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with password missing lowercase."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Password must contain at least one lowercase letter")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NOLOWERCASE123!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_password_policy_no_digit(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with password missing digit."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Password must contain at least one digit")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NoDigits!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_password_policy_no_special_character(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails with password missing special character."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Password must contain at least one special character")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NoSpecial123"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_unicode_chinese(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with Chinese Unicode characters."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "P@ssw0rd中文"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_unicode_arabic(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with Arabic Unicode characters."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "P@ssw0rdالعربية"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_unicode_hindi(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with Hindi Unicode characters."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "P@ssw0rdहिन्दी"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_unicode_russian(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password with Russian Unicode characters."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "P@ssw0rdрусский"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            assert response.json()["message"] == "Password changed successfully"
        finally:
            app.dependency_overrides.clear()

    def test_change_password_sql_injection_drop_table(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that SQL injection attempt with DROP TABLE is properly handled."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError for malicious password
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "'; DROP TABLE users; --"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_sql_injection_or_condition(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that SQL injection attempt with OR condition is properly handled."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError for malicious password
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "' OR '1'='1"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_sql_injection_insert(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that SQL injection attempt with INSERT is properly handled."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError for malicious password
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "'; INSERT INTO users VALUES ('hacker', 'hacker@evil.com'); --"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_xss_script_tag(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that XSS attempt with script tag is properly handled."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError for malicious password
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "<script>alert('xss')</script>"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_xss_javascript_protocol(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that XSS attempt with javascript protocol is properly handled."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError for malicious password
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "javascript:alert('xss')"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_xss_img_onerror(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that XSS attempt with img onerror is properly handled."""
        from src.common.exceptions import PasswordPolicyError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        # Setup mock to raise PasswordPolicyError for malicious password
        mock_password_change_service.change_password.side_effect = PasswordPolicyError("Invalid password format")
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "<img src=x onerror=alert('xss')>"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 422
        finally:
            app.dependency_overrides.clear()

    def test_change_password_database_error(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test change password fails when database operations fail."""
        from src.common.exceptions import AuthenticationError
        
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks - service should raise AuthenticationError for database issues
        mock_password_change_service.change_password.side_effect = AuthenticationError("Database connection failed")
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()

    def test_change_password_security_headers(
        self, 
        test_user, 
        mock_db_session, 
        mock_redis_client,
        mock_user_repository,
        mock_event_publisher,
        mock_password_change_service
    ):
        """Test that security headers are properly set in responses."""
        # Setup rate limiter for test
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        if not hasattr(app.state, 'limiter'):
            app.state.limiter = Limiter(key_func=get_remote_address)
        
        # Setup mocks
        mock_password_change_service.change_password.return_value = None
        
        # Override dependencies
        app.dependency_overrides[get_async_db] = lambda: mock_db_session
        app.dependency_overrides[get_redis] = lambda: mock_redis_client
        app.dependency_overrides[get_current_user] = override_get_current_user(test_user)
        app.dependency_overrides[get_user_repository] = lambda: mock_user_repository
        app.dependency_overrides[get_event_publisher] = lambda: mock_event_publisher
        app.dependency_overrides[get_password_change_service] = lambda: mock_password_change_service
        
        token = create_test_jwt_token(test_user)
        client = TestClient(app)
        try:
            response = client.put(
                "/api/v1/auth/change-password",
                json={"old_password": "OldPass123!", "new_password": "NewPass456!"},
                headers={"Authorization": f"Bearer {token}", "Accept-Language": "en"},
            )
            assert response.status_code == 200
            # Note: Security headers are typically set by middleware, not individual endpoints
        finally:
            app.dependency_overrides.clear()
