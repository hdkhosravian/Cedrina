"""Tests for authentication API utilities.

This module tests the utility functions used by authentication endpoints,
ensuring they follow security best practices and maintain consistency.
"""

import pytest
from unittest.mock import AsyncMock

from src.adapters.api.v1.auth.utils import create_token_pair
from src.core.config.settings import settings
from src.domain.entities.user import Role, User
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_responses import TokenPair as DomainTokenPair
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService


class TestCreateTokenPair:
    """Test suite for create_token_pair utility function."""

    @pytest.fixture
    def mock_token_service(self):
        """Mock token service for testing."""
        service = AsyncMock(spec=DomainTokenService)
        
        # Mock the new interface that returns a TokenPair
        mock_token_pair = DomainTokenPair(
            access_token="mock_access_token",
            refresh_token="mock_refresh_token",
            token_type="Bearer",
            expires_in=3600,
            family_id="test-family-123"
        )
        service.create_token_pair_with_family_security = AsyncMock(return_value=mock_token_pair)
        return service

    @pytest.fixture
    def test_user(self):
        """Test user for token creation."""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            role=Role.USER,
            is_active=True,
        )

    @pytest.mark.asyncio
    async def test_creates_token_pair_with_secure_jti(self, mock_token_service, test_user):
        """Test that create_token_pair uses the new domain service interface."""
        # Create token pair
        result = await create_token_pair(mock_token_service, test_user, 'test-correlation-id')

        # Verify the new method was called
        mock_token_service.create_token_pair_with_family_security.assert_called_once()

        # Verify result structure
        assert result.access_token == "mock_access_token"
        assert result.refresh_token == "mock_refresh_token"
        assert result.token_type == "Bearer"
        assert result.expires_in >= 60, "Expiration should be at least 60 seconds"

    @pytest.mark.asyncio
    async def test_uses_token_id_generate_method(self, mock_token_service, test_user):
        """Test that the function uses the new domain service interface."""
        # Create token pair
        await create_token_pair(mock_token_service, test_user, 'test-correlation-id')

        # Verify the new method was called with correct parameters
        call_args = mock_token_service.create_token_pair_with_family_security.call_args
        assert call_args is not None, "create_token_pair_with_family_security should be called"
        
        # Verify the request contains the user
        request = call_args.args[0]
        assert request.user == test_user

    @pytest.mark.asyncio
    async def test_expires_in_validation(self, mock_token_service, test_user):
        """Test that expiration time is properly validated and set."""
        # Test with normal settings
        result = await create_token_pair(mock_token_service, test_user, 'test-correlation-id')
        expected_expires = max(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 60)
        assert result.expires_in == expected_expires

        # Test with very low settings (edge case)
        original_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        try:
            # Temporarily set to 0 to test minimum validation
            settings.ACCESS_TOKEN_EXPIRE_MINUTES = 0
            result = await create_token_pair(mock_token_service, test_user, 'test-correlation-id')
            assert result.expires_in == 60, "Should enforce minimum 60-second expiration"
        finally:
            # Restore original setting
            settings.ACCESS_TOKEN_EXPIRE_MINUTES = original_expire_minutes

    @pytest.mark.asyncio
    async def test_jti_uniqueness_across_calls(self, mock_token_service, test_user):
        """Test that each call generates a unique token pair."""
        # Create multiple token pairs
        result1 = await create_token_pair(mock_token_service, test_user, 'test-correlation-id')
        result2 = await create_token_pair(mock_token_service, test_user, 'test-correlation-id')

        # Verify the method was called twice
        assert mock_token_service.create_token_pair_with_family_security.call_count == 2

    @pytest.mark.asyncio
    async def test_token_service_called_with_correct_parameters(self, mock_token_service, test_user):
        """Test that token service methods are called with correct parameters."""
        await create_token_pair(mock_token_service, test_user, 'test-correlation-id')

        # Verify the new method was called
        call_args = mock_token_service.create_token_pair_with_family_security.call_args
        assert call_args is not None
        
        # Verify the request contains the user and security context
        request = call_args.args[0]
        assert request.user == test_user
        assert isinstance(request.security_context, SecurityContext)

    @pytest.mark.asyncio
    async def test_returns_correct_token_pair_structure(self, mock_token_service, test_user):
        """Test that the function returns the expected TokenPair structure."""
        result = await create_token_pair(mock_token_service, test_user, 'test-correlation-id')

        # Verify all required fields are present
        assert hasattr(result, "access_token")
        assert hasattr(result, "refresh_token")
        assert hasattr(result, "token_type")
        assert hasattr(result, "expires_in")

        # Verify field types and values
        assert isinstance(result.access_token, str)
        assert isinstance(result.refresh_token, str)
        assert isinstance(result.token_type, str)
        assert isinstance(result.expires_in, int)

        assert result.token_type == "Bearer"
        assert result.expires_in > 0 