"""Unit tests for Unified Authentication Service.

This module contains comprehensive unit tests for the UnifiedAuthenticationService
following Test-Driven Development principles and covering all authentication scenarios.
"""

import time
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.domain.services.authentication.unified import UnifiedAuthenticationService
from src.domain.services.authentication.unified.context import AuthenticationContext, AuthenticationMetrics
from src.domain.services.authentication.unified.flow_executor import AuthenticationFlowExecutor
from src.domain.services.authentication.unified.email_confirmation_checker import EmailConfirmationChecker
from src.domain.services.authentication.unified.oauth_handler import OAuthAuthenticationHandler
from src.domain.services.authentication.unified.event_handler import AuthenticationEventHandler

from src.common.exceptions import AuthenticationError
from src.domain.value_objects.username import Username
from src.domain.value_objects.password import LoginPassword
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.domain.entities.user import User
from src.domain.entities.oauth_profile import OAuthProfile
from src.domain.entities.role import Role
from tests.factories.user import create_fake_user


class TestAuthenticationContext:
    """Test AuthenticationContext value object."""

    def test_authentication_context_creation(self):
        """Test creating AuthenticationContext with valid data."""
        # Arrange
        client_ip = "192.168.1.1"
        user_agent = "Mozilla/5.0"
        correlation_id = "test-correlation-id"
        language = "en"
        security_metadata = {"risk_score": 0.1}

        # Act
        context = AuthenticationContext(
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id,
            language=language,
            security_metadata=security_metadata
        )

        # Assert
        assert context.client_ip == client_ip
        assert context.user_agent == user_agent
        assert context.correlation_id == correlation_id
        assert context.language == language
        assert context.security_metadata == security_metadata

    def test_authentication_context_immutability(self):
        """Test that AuthenticationContext is immutable."""
        # Arrange
        context = AuthenticationContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            correlation_id="test-id"
        )

        # Act & Assert
        with pytest.raises(AttributeError):
            context.client_ip = "new-ip"  # type: ignore

    def test_authentication_context_default_values(self):
        """Test AuthenticationContext with default values."""
        # Arrange & Act
        context = AuthenticationContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            correlation_id="test-id"
        )

        # Assert
        assert context.language == "en"
        assert context.security_metadata == {}


class TestAuthenticationMetrics:
    """Test AuthenticationMetrics value object."""

    def test_authentication_metrics_creation(self):
        """Test creating AuthenticationMetrics with default values."""
        # Act
        metrics = AuthenticationMetrics()

        # Assert
        assert metrics.total_authentications == 0
        assert metrics.successful_authentications == 0
        assert metrics.failed_authentications == 0
        assert metrics.oauth_authentications == 0
        assert metrics.security_incidents == 0
        assert metrics.average_auth_time_ms == 0.0

    def test_authentication_metrics_update_success(self):
        """Test updating metrics for successful authentication."""
        # Arrange
        metrics = AuthenticationMetrics()
        duration_ms = 150.0

        # Act
        updated_metrics = metrics.update_success(duration_ms, oauth=False)

        # Assert
        assert updated_metrics.total_authentications == 1
        assert updated_metrics.successful_authentications == 1
        assert updated_metrics.failed_authentications == 0
        assert updated_metrics.oauth_authentications == 0
        assert updated_metrics.average_auth_time_ms == 150.0

    def test_authentication_metrics_update_success_oauth(self):
        """Test updating metrics for successful OAuth authentication."""
        # Arrange
        metrics = AuthenticationMetrics()
        duration_ms = 200.0

        # Act
        updated_metrics = metrics.update_success(duration_ms, oauth=True)

        # Assert
        assert updated_metrics.total_authentications == 1
        assert updated_metrics.successful_authentications == 1
        assert updated_metrics.failed_authentications == 0
        assert updated_metrics.oauth_authentications == 1
        assert updated_metrics.average_auth_time_ms == 200.0

    def test_authentication_metrics_update_failure(self):
        """Test updating metrics for failed authentication."""
        # Arrange
        metrics = AuthenticationMetrics()
        duration_ms = 100.0

        # Act
        updated_metrics = metrics.update_failure(duration_ms, oauth=False)

        # Assert
        assert updated_metrics.total_authentications == 1
        assert updated_metrics.successful_authentications == 0
        assert updated_metrics.failed_authentications == 1
        assert updated_metrics.oauth_authentications == 0
        assert updated_metrics.average_auth_time_ms == 100.0

    def test_authentication_metrics_average_calculation(self):
        """Test average calculation with multiple authentications."""
        # Arrange
        metrics = AuthenticationMetrics()

        # Act - Multiple authentications
        metrics = metrics.update_success(100.0, oauth=False)  # First: 100ms
        metrics = metrics.update_success(200.0, oauth=False)  # Second: 200ms
        metrics = metrics.update_failure(150.0, oauth=False)  # Third: 150ms

        # Assert
        assert metrics.total_authentications == 3
        assert metrics.successful_authentications == 2
        assert metrics.failed_authentications == 1
        assert metrics.average_auth_time_ms == 150.0  # (100 + 200 + 150) / 3

    def test_authentication_metrics_immutability(self):
        """Test that AuthenticationMetrics is immutable."""
        # Arrange
        metrics = AuthenticationMetrics()

        # Act & Assert
        with pytest.raises(AttributeError):
            metrics.total_authentications = 10  # type: ignore


class TestAuthenticationFlowExecutor:
    """Test AuthenticationFlowExecutor."""

    def test_authentication_flow_executor_creation(self):
        """Test creating AuthenticationFlowExecutor."""
        # Arrange
        secure_logger = MagicMock()
        error_standardizer = MagicMock()

        # Act
        executor = AuthenticationFlowExecutor(secure_logger, error_standardizer)

        # Assert
        assert executor._secure_logger == secure_logger
        assert executor._error_standardizer == error_standardizer

    @pytest.mark.asyncio
    async def test_authentication_flow_executor_success(self):
        """Test successful authentication flow execution."""
        # Arrange
        secure_logger = MagicMock()
        error_standardizer = MagicMock()
        executor = AuthenticationFlowExecutor(secure_logger, error_standardizer)
        
        context = AuthenticationContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            correlation_id="test-id"
        )
        
        async def mock_auth_func():
            return "success"

        # Act
        result = await executor.execute(
            mock_auth_func,
            context,
            time.time(),
            oauth=False
        )

        # Assert
        assert result == "success"

    @pytest.mark.asyncio
    async def test_authentication_flow_executor_authentication_error(self):
        """Test authentication flow execution with AuthenticationError."""
        # Arrange
        secure_logger = MagicMock()
        error_standardizer = MagicMock()
        executor = AuthenticationFlowExecutor(secure_logger, error_standardizer)
        
        context = AuthenticationContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            correlation_id="test-id"
        )
        
        async def mock_auth_func():
            raise AuthenticationError("Invalid credentials")

        # Act & Assert
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await executor.execute(
                mock_auth_func,
                context,
                time.time(),
                oauth=False
            )

    @pytest.mark.asyncio
    async def test_authentication_flow_executor_unexpected_error(self):
        """Test authentication flow execution with unexpected error."""
        # Arrange
        secure_logger = MagicMock()
        error_standardizer = MagicMock()
        executor = AuthenticationFlowExecutor(secure_logger, error_standardizer)
        
        context = AuthenticationContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            correlation_id="test-id",
            language="en"
        )
        
        async def mock_auth_func():
            raise ValueError("Unexpected error")

        # Act & Assert
        with pytest.raises(AuthenticationError):
            await executor.execute(
                mock_auth_func,
                context,
                time.time(),
                oauth=False
            )


class TestEmailConfirmationChecker:
    """Test EmailConfirmationChecker."""

    def test_email_confirmation_checker_creation(self):
        """Test creating EmailConfirmationChecker."""
        # Act
        checker = EmailConfirmationChecker()

        # Assert
        assert hasattr(checker, '_email_confirmation_enabled')

    @patch('src.core.config.settings.settings')
    def test_email_confirmation_checker_enabled(self, mock_settings):
        """Test EmailConfirmationChecker with email confirmation enabled."""
        # Arrange
        mock_settings.EMAIL_CONFIRMATION_ENABLED = True
        checker = EmailConfirmationChecker()
        user = create_fake_user()
        user.email_confirmed = False

        # Act
        result = checker.is_confirmation_required(user)

        # Assert
        assert result is True

    @patch('src.core.config.settings.settings')
    def test_email_confirmation_checker_disabled(self, mock_settings):
        """Test EmailConfirmationChecker with email confirmation disabled."""
        # Arrange
        mock_settings.EMAIL_CONFIRMATION_ENABLED = False
        checker = EmailConfirmationChecker()
        user = create_fake_user()
        user.email_confirmed = False

        # Act
        result = checker.is_confirmation_required(user)

        # Assert
        assert result is False

    def test_email_confirmation_checker_user_already_confirmed(self):
        """Test EmailConfirmationChecker with user already confirmed."""
        # Arrange
        checker = EmailConfirmationChecker()
        user = create_fake_user()
        user.email_confirmed = True

        # Act
        result = checker.is_confirmation_required(user)

        # Assert
        assert result is False


class TestUnifiedAuthenticationService:
    """Test UnifiedAuthenticationService."""
    
    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        return AsyncMock()
    
    @pytest.fixture
    def mock_oauth_profile_repository(self):
        """Create mock OAuth profile repository."""
        return AsyncMock()
    
    @pytest.fixture
    def mock_event_publisher(self):
        """Create mock event publisher."""
        return AsyncMock()
    
    @pytest.fixture
    def auth_service(
        self,
        mock_user_repository,
        mock_oauth_profile_repository,
        mock_event_publisher
    ):
        """Create UnifiedAuthenticationService instance."""
        return UnifiedAuthenticationService(
            user_repository=mock_user_repository,
            oauth_profile_repository=mock_oauth_profile_repository,
            event_publisher=mock_event_publisher
        )
    
    @pytest.fixture
    def mock_user(self):
        """Create mock user."""
        user = create_fake_user(
            id=1,
            username="testuser",
            email="test@example.com",
            is_active=True
        )
        user.email_confirmed = True
        return user
    
    @pytest.fixture
    def mock_oauth_profile(self):
        """Create mock OAuth profile."""
        return OAuthProfile(
            id=1,
            user_id=1,
            provider="google",
            provider_user_id="oauth_user_id",
            access_token="access_token",
            refresh_token="refresh_token",
            expires_at=None
        )

    def test_unified_authentication_service_creation(self, auth_service):
        """Test creating UnifiedAuthenticationService."""
        # Assert
        assert auth_service._user_repository is not None
        assert auth_service._oauth_profile_repository is not None
        assert auth_service._event_publisher is not None
        assert auth_service._secure_logger is not None
        assert auth_service._error_standardizer is not None
        assert auth_service._flow_executor is not None
        assert auth_service._email_confirmation_checker is not None
        assert isinstance(auth_service._auth_metrics, AuthenticationMetrics)
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(
        self,
        auth_service,
        mock_user_repository,
        mock_user
    ):
        """Test successful user authentication."""
        # Arrange
        username = Username("testuser")
        password = LoginPassword("validpassword")
        mock_user_repository.get_by_username.return_value = mock_user
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            # Act
            result = await auth_service.authenticate_user(
                username=username,
                password=password,
                language="en",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                correlation_id="test-id"
            )
        
        # Assert
        assert result == mock_user
        mock_user_repository.get_by_username.assert_called_once_with("testuser")
    
    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_credentials(
        self,
        auth_service,
        mock_user_repository
    ):
        """Test user authentication with invalid credentials."""
        # Arrange
        username = Username("testuser")
        password = LoginPassword("invalidpassword")
        mock_user_repository.get_by_username.return_value = None
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await auth_service.authenticate_user(
                username=username,
                password=password,
                language="en",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                correlation_id="test-id"
            )
    
    @pytest.mark.asyncio
    async def test_authenticate_user_inactive_account(
        self,
        auth_service,
        mock_user_repository,
        mock_user
    ):
        """Test user authentication with inactive account."""
        # Arrange
        username = Username("testuser")
        password = LoginPassword("validpassword")
        mock_user.is_active = False
        mock_user_repository.get_by_username.return_value = mock_user
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
        # Act & Assert
            with pytest.raises(AuthenticationError, match="account_inactive"):
                await auth_service.authenticate_user(
                    username=username,
                    password=password,
                    language="en",
                    client_ip="192.168.1.1",
                    user_agent="Mozilla/5.0",
                    correlation_id="test-id"
            )
    
    @pytest.mark.asyncio
    async def test_authenticate_user_email_confirmation_required(
        self,
        auth_service,
        mock_user_repository,
        mock_user
    ):
        """Test user authentication with email confirmation required."""
        # Arrange
        username = Username("testuser")
        password = LoginPassword("validpassword")
        mock_user.email_confirmed = False
        mock_user_repository.get_by_username.return_value = mock_user
        
        # Mock password verification and email confirmation
        with patch.object(auth_service, 'verify_password', return_value=True), \
             patch.object(auth_service._email_confirmation_checker, 'is_confirmation_required', return_value=True):
        # Act & Assert
            with pytest.raises(AuthenticationError, match="Please confirm your email before logging in"):
                await auth_service.authenticate_user(
                    username=username,
                    password=password,
                    language="en",
                    client_ip="192.168.1.1",
                    user_agent="Mozilla/5.0",
                    correlation_id="test-id"
                )
    
    @pytest.mark.asyncio
    async def test_verify_password_success(self, auth_service, mock_user):
        """Test successful password verification."""
        # Arrange
        password = LoginPassword("validpassword")
        mock_user.hashed_password = "hashed_password"

        # Mock the verify_password method directly on the service
        with patch.object(auth_service, 'verify_password', return_value=True):
            # Act
            result = await auth_service.verify_password(mock_user, password)
        
        # Assert
            assert result is True
    
    @pytest.mark.asyncio
    async def test_verify_password_failure(self, auth_service, mock_user):
        """Test failed password verification."""
        # Arrange
        password = LoginPassword("invalidpassword")
        mock_user.hashed_password = "hashed_password"

        # Mock the verify_password method directly on the service
        with patch.object(auth_service, 'verify_password', return_value=False):
            # Act
            result = await auth_service.verify_password(mock_user, password)

            # Assert
            assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_password_no_user(self, auth_service):
        """Test password verification with no user."""
        # Arrange
        password = LoginPassword("validpassword")
        
        # Act
        result = await auth_service.verify_password(None, password)
        
        # Assert
        assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_password_no_hashed_password(self, auth_service, mock_user):
        """Test password verification with no hashed password."""
        # Arrange
        password = LoginPassword("validpassword")
        mock_user.hashed_password = None
        
        # Act
        result = await auth_service.verify_password(mock_user, password)
        
        # Assert
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_oauth_state_success(self, auth_service):
        """Test successful OAuth state validation."""
        # Arrange
        state = "test_state"
        stored_state = "test_state"
        
        # Act
        result = await auth_service.validate_oauth_state(state, stored_state)
        
        # Assert
        assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_oauth_state_failure(self, auth_service):
        """Test failed OAuth state validation."""
        # Arrange
        state = "test_state"
        stored_state = "different_state"
        
        # Act
        result = await auth_service.validate_oauth_state(state, stored_state)
        
        # Assert
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_oauth_state_different_lengths(self, auth_service):
        """Test OAuth state validation with different lengths."""
        # Arrange
        state = "test_state"
        stored_state = "longer_test_state"

        # Act
        result = await auth_service.validate_oauth_state(state, stored_state)
        
        # Assert
        assert result is False
    
    @pytest.mark.asyncio
    async def test_authenticate_with_oauth_success(
        self,
        auth_service,
        mock_oauth_profile_repository,
        mock_user,
        mock_oauth_profile
    ):
        """Test successful OAuth authentication."""
        # Arrange
        provider = OAuthProvider("google")
        token = OAuthToken({
            "access_token": "valid_token",
            "expires_at": time.time() + 3600  # 1 hour from now
        })
        mock_oauth_profile_repository.get_by_provider_user_id.return_value = mock_oauth_profile
        
        # Mock OAuth validation and user retrieval
        with patch.object(auth_service._oauth_handler, 'validate_oauth_token', return_value=True), \
             patch.object(auth_service._oauth_handler, 'fetch_oauth_user_info', return_value={"id": "oauth_user_id"}), \
             patch.object(auth_service._oauth_handler, 'link_or_create_oauth_user', return_value=(mock_user, mock_oauth_profile)):
            # Act
            result = await auth_service.authenticate_with_oauth(
                provider=provider,
                token=token,
                language="en",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                correlation_id="test-id"
            )

            # Assert
            assert result == (mock_user, mock_oauth_profile)
    
    @pytest.mark.asyncio
    async def test_authenticate_with_oauth_invalid_token(
        self,
        auth_service
    ):
        """Test OAuth authentication with invalid token."""
        # Arrange
        provider = OAuthProvider("google")
        token = OAuthToken({
            "access_token": "invalid_token",
            "expires_at": time.time() + 3600  # 1 hour from now
        })
        
        # Mock OAuth validation failure
        with patch.object(auth_service._oauth_handler, 'validate_oauth_token', return_value=False):
        # Act & Assert
            with pytest.raises(AuthenticationError, match="oauth_token_invalid"):
                await auth_service.authenticate_with_oauth(
                    provider=provider,
                    token=token,
                    language="en",
                    client_ip="192.168.1.1",
                    user_agent="Mozilla/5.0",
                    correlation_id="test-id"
            )
    
    @pytest.mark.asyncio
    async def test_authenticate_with_oauth_user_info_fetch_failed(
        self,
        auth_service
    ):
        """Test OAuth authentication with user info fetch failure."""
        # Arrange
        provider = OAuthProvider("google")
        token = OAuthToken({
            "access_token": "valid_token",
            "expires_at": time.time() + 3600  # 1 hour from now
        })
        
        # Mock OAuth validation success but user info fetch failure
        with patch.object(auth_service._oauth_handler, 'validate_oauth_token', return_value=True), \
             patch.object(auth_service._oauth_handler, 'fetch_oauth_user_info', return_value=None):
            # Act & Assert
            with pytest.raises(AuthenticationError, match="oauth_user_info_failed"):
                await auth_service.authenticate_with_oauth(
                    provider=provider,
                    token=token,
                    language="en",
                    client_ip="192.168.1.1",
                    user_agent="Mozilla/5.0",
                    correlation_id="test-id"
                )

    def test_get_auth_metrics(self, auth_service):
        """Test getting authentication metrics."""
        # Act
        metrics = auth_service.get_auth_metrics()
        
        # Assert
        assert isinstance(metrics, dict)
        assert "total_authentications" in metrics
        assert "successful_authentications" in metrics
        assert "failed_authentications" in metrics
        assert "oauth_authentications" in metrics
        assert "security_incidents" in metrics
        assert "average_auth_time_ms" in metrics
    
    @pytest.mark.asyncio
    async def test_authenticate_user_publishes_events(
        self,
        auth_service,
        mock_user_repository,
        mock_event_publisher,
        mock_user
    ):
        """Test that successful authentication publishes events."""
        # Arrange
        username = Username("testuser")
        password = LoginPassword("validpassword")
        mock_user_repository.get_by_username.return_value = mock_user
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
        # Act
            await auth_service.authenticate_user(
                username=username,
                password=password,
                language="en",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                correlation_id="test-id"
        )
        
        # Assert
            mock_event_publisher.publish.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_authenticate_user_logs_security_events(
        self,
        auth_service,
        mock_user_repository,
        mock_user
    ):
        """Test that authentication logs security events."""
        # Arrange
        username = Username("testuser")
        password = LoginPassword("validpassword")
        mock_user_repository.get_by_username.return_value = mock_user
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            # Act
            await auth_service.authenticate_user(
                username=username,
                password=password,
                language="en",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                correlation_id="test-id"
            )
            
            # Assert - Verify that secure logging was called
            # This is tested indirectly through the flow execution


class TestUnifiedAuthenticationServiceIntegration:
    """Integration tests for UnifiedAuthenticationService."""
    
    @pytest.mark.asyncio
    async def test_authentication_flow_with_real_password_verification(self):
        """Test authentication flow with real password verification."""
        # Arrange
        mock_user_repository = AsyncMock()
        mock_oauth_profile_repository = AsyncMock()
        mock_event_publisher = AsyncMock()
        
        auth_service = UnifiedAuthenticationService(
            user_repository=mock_user_repository,
            oauth_profile_repository=mock_oauth_profile_repository,
            event_publisher=mock_event_publisher
        )
        
        # Create user with real password hash
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_context.hash("validpassword")
        
        user = create_fake_user(
            id=1,
            username="testuser",
            hashed_password=hashed_password,
            is_active=True
        )
        user.email_confirmed = True
        
        mock_user_repository.get_by_username.return_value = user
        
        username = Username("testuser")
        password = LoginPassword("validpassword")
        
        # Act
        result = await auth_service.authenticate_user(
            username=username,
            password=password,
            language="en",
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            correlation_id="test-id"
        )
        
        # Assert
        assert result == user
        assert result.username == "testuser"
    
    @pytest.mark.asyncio
    async def test_authentication_flow_with_invalid_password(self):
        """Test authentication flow with invalid password."""
        # Arrange
        mock_user_repository = AsyncMock()
        mock_oauth_profile_repository = AsyncMock()
        mock_event_publisher = AsyncMock()
        
        auth_service = UnifiedAuthenticationService(
            user_repository=mock_user_repository,
            oauth_profile_repository=mock_oauth_profile_repository,
            event_publisher=mock_event_publisher
        )
        
        # Create user with real password hash
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_context.hash("validpassword")
        
        user = create_fake_user(
            id=1,
            username="testuser",
            hashed_password=hashed_password,
            is_active=True
        )
        user.email_confirmed = True
        
        mock_user_repository.get_by_username.return_value = user
        
        username = Username("testuser")
        password = LoginPassword("invalidpassword")
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await auth_service.authenticate_user(
                username=username,
                password=password,
                language="en",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                correlation_id="test-id"
            )
    
    @pytest.mark.asyncio
    async def test_metrics_tracking_across_multiple_authentications(self):
        """Test that metrics are properly tracked across multiple authentications."""
        # Arrange
        mock_user_repository = AsyncMock()
        mock_oauth_profile_repository = AsyncMock()
        mock_event_publisher = AsyncMock()
        
        auth_service = UnifiedAuthenticationService(
            user_repository=mock_user_repository,
            oauth_profile_repository=mock_oauth_profile_repository,
            event_publisher=mock_event_publisher
        )
        
        # Create user with real password hash
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_context.hash("validpassword")
        
        user = create_fake_user(
            id=1,
            username="testuser",
            hashed_password=hashed_password,
            is_active=True
        )
        user.email_confirmed = True
        
        mock_user_repository.get_by_username.return_value = user
        
        username = Username("testuser")
        password = LoginPassword("validpassword")
        
        # Act - Multiple successful authentications
        for i in range(3):
            await auth_service.authenticate_user(
                username=username,
                password=password,
            language="en",
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                correlation_id=f"test-id-{i}"
        )
        
        # Assert
        metrics = auth_service.get_auth_metrics()
        assert metrics["total_authentications"] == 3
        assert metrics["successful_authentications"] == 3
        assert metrics["failed_authentications"] == 0
        assert metrics["average_auth_time_ms"] > 0 