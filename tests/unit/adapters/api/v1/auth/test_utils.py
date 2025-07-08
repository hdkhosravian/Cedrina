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
from src.infrastructure.services.authentication.token import TokenService


class TestCreateTokenPair:
    """Test suite for create_token_pair utility function."""

    @pytest.fixture
    def mock_token_service(self):
        """Mock token service for testing."""
        service = AsyncMock(spec=TokenService)
        service.create_access_token = AsyncMock(return_value="mock_access_token")
        service.create_refresh_token = AsyncMock(return_value="mock_refresh_token")
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
        """Test that create_token_pair uses cryptographically secure JTI generation."""
        # Create token pair
        result = await create_token_pair(mock_token_service, test_user)

        # Verify both tokens were created
        mock_token_service.create_access_token.assert_called_once()
        mock_token_service.create_refresh_token.assert_called_once()

        # Extract the JTI used for both tokens
        access_call_args = mock_token_service.create_access_token.call_args
        refresh_call_args = mock_token_service.create_refresh_token.call_args

        access_jti = access_call_args.kwargs.get("jti")
        refresh_jti = refresh_call_args.kwargs.get("jti")

        # Verify both tokens use the same JTI
        assert access_jti == refresh_jti, "Both tokens should use the same JTI"

        # Verify JTI is cryptographically secure (256-bit entropy)
        token_id = TokenId(access_jti)
        assert token_id.is_cryptographically_secure(), "JTI should be cryptographically secure"
        assert token_id.get_entropy_bits() >= 256, "JTI should provide at least 256 bits of entropy"

        # Verify result structure
        assert result.access_token == "mock_access_token"
        assert result.refresh_token == "mock_refresh_token"
        assert result.token_type == "Bearer"
        assert result.expires_in >= 60, "Expiration should be at least 60 seconds"

    @pytest.mark.asyncio
    async def test_uses_token_id_generate_method(self, mock_token_service, test_user):
        """Test that the function uses TokenId.generate() for secure JTI creation."""
        # Create token pair
        await create_token_pair(mock_token_service, test_user)

        # Extract the JTI used
        access_call_args = mock_token_service.create_access_token.call_args
        jti_used = access_call_args.kwargs.get("jti")

        # Verify JTI format matches TokenId.generate() output
        # TokenId.generate() produces 43-character base64url strings
        assert len(jti_used) == 43, "JTI should be 43 characters (256 bits base64url)"
        assert all(c in TokenId.VALID_CHARS for c in jti_used), "JTI should contain only valid base64url characters"

    @pytest.mark.asyncio
    async def test_expires_in_validation(self, mock_token_service, test_user):
        """Test that expiration time is properly validated and set."""
        # Test with normal settings
        result = await create_token_pair(mock_token_service, test_user)
        expected_expires = max(settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, 60)
        assert result.expires_in == expected_expires

        # Test with very low settings (edge case)
        original_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        try:
            # Temporarily set to 0 to test minimum validation
            settings.ACCESS_TOKEN_EXPIRE_MINUTES = 0
            result = await create_token_pair(mock_token_service, test_user)
            assert result.expires_in == 60, "Should enforce minimum 60-second expiration"
        finally:
            # Restore original setting
            settings.ACCESS_TOKEN_EXPIRE_MINUTES = original_expire_minutes

    @pytest.mark.asyncio
    async def test_jti_uniqueness_across_calls(self, mock_token_service, test_user):
        """Test that each call generates a unique JTI."""
        # Create multiple token pairs
        result1 = await create_token_pair(mock_token_service, test_user)
        result2 = await create_token_pair(mock_token_service, test_user)

        # Extract JTIs used
        jti1 = mock_token_service.create_access_token.call_args_list[0].kwargs.get("jti")
        jti2 = mock_token_service.create_access_token.call_args_list[1].kwargs.get("jti")

        # Verify JTIs are unique
        assert jti1 != jti2, "Each call should generate a unique JTI"

    @pytest.mark.asyncio
    async def test_token_service_called_with_correct_parameters(self, mock_token_service, test_user):
        """Test that token service methods are called with correct parameters."""
        await create_token_pair(mock_token_service, test_user)

        # Verify access token creation
        access_call = mock_token_service.create_access_token.call_args
        assert access_call.kwargs["user"] == test_user
        assert "jti" in access_call.kwargs

        # Verify refresh token creation
        refresh_call = mock_token_service.create_refresh_token.call_args
        assert refresh_call.kwargs["user"] == test_user
        assert "jti" in refresh_call.kwargs

        # Verify both use the same JTI
        assert access_call.kwargs["jti"] == refresh_call.kwargs["jti"]

    @pytest.mark.asyncio
    async def test_returns_correct_token_pair_structure(self, mock_token_service, test_user):
        """Test that the function returns the expected TokenPair structure."""
        result = await create_token_pair(mock_token_service, test_user)

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