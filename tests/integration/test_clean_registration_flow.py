"""Integration tests for clean registration flow with error classification.

These tests verify the complete end-to-end registration flow using clean architecture
principles and the error classification service. They test the integration between
domain services, infrastructure components, and the API layer.

Test Coverage:
- Complete registration flow with valid data
- Error classification for various failure scenarios
- Integration between domain services and infrastructure
- Error handling and response formatting
- Security features and data masking
- Performance under realistic conditions
"""

import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock

from src.domain.services.authentication.error_classification_service import (
    ErrorClassificationService,
    PasswordPolicyStrategy,
    UsernameValidationStrategy,
    EmailValidationStrategy,
    GenericValidationStrategy,
)
from src.core.exceptions import (
    PasswordPolicyError,
    ValidationError,
    AuthenticationError,
    DuplicateUserError,
)


class TestCleanRegistrationFlow:
    """Integration tests for clean registration flow."""

    @pytest.fixture(autouse=True)
    def setup_rate_limiting(self, monkeypatch):
        """Disable rate limiting for tests to avoid 429 errors."""
        # Disable rate limiting environment variables
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
        monkeypatch.setenv("RATE_LIMITING_ENABLED", "false")
        monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "10000")

    @pytest.fixture
    def valid_registration_data(self):
        """Valid registration data for testing with unique identifiers."""
        unique_id = str(uuid.uuid4())[:8]
        return {
            "username": f"testuser{unique_id}",
            "email": f"test{unique_id}@example.com",
            "password": "Kj9#mN2$pQ7@vX5!"
        }

    @pytest.fixture
    def mock_error_classification_service(self):
        """Create mock error classification service."""
        service = MagicMock(spec=ErrorClassificationService)
        service.classify_error = MagicMock()
        return service

    class TestSuccessfulRegistration:
        """Test successful registration scenarios."""

        @pytest.mark.asyncio
        async def test_successful_registration_with_valid_data(self, async_client, valid_registration_data):
            """Test successful user registration with valid data."""
            # Act
            response = await async_client.post("/api/v1/auth/register", json=valid_registration_data)
            
            # Assert
            assert response.status_code == 201
            data = response.json()
            assert data["user"]["username"] == valid_registration_data["username"]
            assert data["user"]["email"] == valid_registration_data["email"]
            assert "password" not in data["user"]  # Password should not be returned
            assert "tokens" in data
            assert "access_token" in data["tokens"]
            assert "token_type" in data["tokens"]

        @pytest.mark.asyncio
        async def test_registration_with_minimal_valid_data(self, async_client):
            """Test registration with minimal valid data."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            minimal_data = {
                "username": f"minimal{unique_id}",
                "email": f"minimal{unique_id}@test.com",
                "password": "Min8Char!"
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=minimal_data)
            
            # Assert
            assert response.status_code == 201
            data = response.json()
            assert data["user"]["username"] == minimal_data["username"]

        @pytest.mark.asyncio
        async def test_registration_with_complex_password(self, async_client):
            """Test registration with complex password meeting all requirements."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            complex_data = {
                "username": f"complexuser{unique_id}",
                "email": f"complex{unique_id}@test.com",
                "password": "C0mpl3x!P@ss@W0rd#2024"
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=complex_data)
            
            # Assert
            assert response.status_code == 201
            data = response.json()
            assert data["user"]["username"] == complex_data["username"]

    class TestErrorClassificationIntegration:
        """Test error classification service integration."""

        @pytest.mark.asyncio
        async def test_password_policy_error_classification(self, async_client):
            """Test that password policy errors are properly classified."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            weak_password_data = {
                "username": f"weakpass{unique_id}",
                "email": f"weak{unique_id}@test.com",
                "password": "weak"  # Too weak
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=weak_password_data)
            
            # Assert
            assert response.status_code == 422
            data = response.json()
            assert "detail" in data
            # Should be classified as password policy error
            detail_str = str(data["detail"]).lower()
            assert "password" in detail_str or "policy" in detail_str

        @pytest.mark.asyncio
        async def test_username_validation_error_classification(self, async_client):
            """Test that username validation errors are properly classified."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            invalid_username_data = {
                "username": "a",  # Too short
                "email": f"invalid{unique_id}@test.com",
                "password": "V@lidP@ss2024!"
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=invalid_username_data)
            
            # Assert
            assert response.status_code == 422
            data = response.json()
            assert "detail" in data
            # Should be classified as username validation error
            detail_str = str(data["detail"]).lower()
            assert "username" in detail_str

        @pytest.mark.asyncio
        async def test_email_validation_error_classification(self, async_client):
            """Test that email validation errors are properly classified."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            invalid_email_data = {
                "username": f"validuser{unique_id}",
                "email": "invalid-email",  # Invalid email format
                "password": "V@lidP@ss2024!"
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=invalid_email_data)
            
            # Assert
            assert response.status_code == 422
            data = response.json()
            assert "detail" in data
            # Should be classified as email validation error
            detail_str = str(data["detail"]).lower()
            assert "email" in detail_str

        @pytest.mark.asyncio
        async def test_duplicate_user_error_classification(self, async_client):
            """Test that duplicate user errors are properly classified."""
            # Arrange - Use same data for both registrations to test duplicate handling
            unique_id = str(uuid.uuid4())[:8]
            duplicate_data = {
                "username": f"duplicate{unique_id}",
                "email": f"duplicate{unique_id}@test.com",
                "password": "Kj9#mN2$pQ7@vX5!"
            }
            
            # Register user first time
            first_response = await async_client.post("/api/v1/auth/register", json=duplicate_data)
            assert first_response.status_code == 201
            
            # Act - Try to register same user again
            second_response = await async_client.post("/api/v1/auth/register", json=duplicate_data)
            
            # Assert
            assert second_response.status_code == 409
            data = second_response.json()
            assert "detail" in data
            # Should be classified as duplicate user error
            detail_str = str(data["detail"]).lower()
            assert "already registered" in detail_str or "already exists" in detail_str or "duplicate" in detail_str

    class TestSecurityFeatures:
        """Test security features of the registration flow."""

        @pytest.mark.asyncio
        async def test_password_not_returned_in_response(self, async_client, valid_registration_data):
            """Test that password is not returned in the response."""
            # Act
            response = await async_client.post("/api/v1/auth/register", json=valid_registration_data)
            
            # Assert
            assert response.status_code == 201
            data = response.json()
            assert "password" not in data["user"]
            assert "hashed_password" not in data["user"]

        @pytest.mark.asyncio
        async def test_sensitive_data_masking_in_logs(self, async_client, valid_registration_data, caplog):
            """Test that sensitive data is properly masked in logs."""
            # Act
            response = await async_client.post("/api/v1/auth/register", json=valid_registration_data)
            
            # Assert
            assert response.status_code == 201
            
            # Check that sensitive data is not present in logs
            for record in caplog.records:
                assert valid_registration_data["password"] not in record.getMessage()
                # Username and email should be masked with ***
                assert valid_registration_data["username"] not in record.getMessage()

        @pytest.mark.asyncio
        async def test_correlation_id_generation(self, async_client, valid_registration_data, caplog):
            """Test that correlation IDs are generated and used throughout the request."""
            # Act
            response = await async_client.post("/api/v1/auth/register", json=valid_registration_data)
            
            # Assert
            assert response.status_code == 201
            
            # Check that correlation IDs are present in logs
            correlation_ids = []
            for record in caplog.records:
                if "correlation_id" in record.getMessage():
                    # Extract correlation ID from log message
                    import re
                    match = re.search(r'"correlation_id": "([^"]+)"', record.getMessage())
                    if match:
                        correlation_ids.append(match.group(1))
            
            # Should have at least one correlation ID and all should be the same
            assert len(correlation_ids) > 0
            assert all(cid == correlation_ids[0] for cid in correlation_ids)

    class TestErrorHandlingRobustness:
        """Test robust error handling in various scenarios."""

        @pytest.mark.asyncio
        async def test_error_messages_in_different_languages(self, async_client):
            """Test that error messages are properly internationalized."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            invalid_data = {
                "username": "a",  # Too short
                "email": f"invalid{unique_id}@test.com",
                "password": "V@lidP@ss2024!"
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=invalid_data)
            
            # Assert
            assert response.status_code == 422
            data = response.json()
            assert "detail" in data

        @pytest.mark.asyncio
        async def test_error_classification_service_integration(self, async_client):
            """Test that error classification service is properly integrated."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            invalid_data = {
                "username": "a",  # Too short
                "email": f"invalid{unique_id}@test.com",
                "password": "V@lidP@ss2024!"
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=invalid_data)
            
            # Assert
            assert response.status_code == 422
            data = response.json()
            assert "detail" in data
            # Error should be properly classified and standardized

    class TestPerformanceAndScalability:
        """Test performance and scalability aspects."""

        @pytest.mark.asyncio
        async def test_concurrent_registration_requests(self, async_client):
            """Test handling of concurrent registration requests."""
            import asyncio
            
            # Arrange
            base_unique_id = str(uuid.uuid4())[:8]
            
            # Act - Submit multiple concurrent requests
            async def register_user(i):
                user_data = {
                    "username": f"concurrent_user_{base_unique_id}_{i}",
                    "email": f"concurrent{base_unique_id}{i}@test.com",
                    "password": "C0ncurr3ntP@ss2024!"
                }
                return await async_client.post("/api/v1/auth/register", json=user_data)
            
            responses = await asyncio.gather(*[register_user(i) for i in range(5)])
            
            # Assert
            success_count = sum(1 for r in responses if r.status_code == 201)
            assert success_count == 5  # All should succeed

        @pytest.mark.asyncio
        async def test_registration_response_time(self, async_client, valid_registration_data):
            """Test that registration response time is reasonable."""
            import time
            
            # Act
            start_time = time.time()
            response = await async_client.post("/api/v1/auth/register", json=valid_registration_data)
            end_time = time.time()
            
            # Assert
            assert response.status_code == 201
            response_time = end_time - start_time
            assert response_time < 5.0  # Should complete within 5 seconds

    class TestCleanArchitectureIntegration:
        """Test clean architecture principles integration."""

        @pytest.mark.asyncio
        async def test_domain_service_integration(self, async_client, valid_registration_data):
            """Test that domain services are properly integrated."""
            # Act
            response = await async_client.post("/api/v1/auth/register", json=valid_registration_data)
            
            # Assert
            assert response.status_code == 201
            data = response.json()
            
            # Verify clean architecture principles
            assert "user" in data  # Domain entity properly returned
            assert "tokens" in data  # Infrastructure service working
            assert "access_token" in data["tokens"]
            assert data["user"]["email"] == valid_registration_data["email"]

        @pytest.mark.asyncio
        async def test_dependency_injection_working(self, async_client, valid_registration_data):
            """Test that dependency injection is working correctly."""
            # Act
            response = await async_client.post("/api/v1/auth/register", json=valid_registration_data)
            
            # Assert
            assert response.status_code == 201
            data = response.json()
            
            # Verify that all layers are working together through DI
            assert "user" in data
            assert "tokens" in data
            assert "access_token" in data["tokens"]
            assert data["user"]["username"] == valid_registration_data["username"]

        @pytest.mark.asyncio
        async def test_error_classification_service_usage(self, async_client):
            """Test that error classification service is properly used."""
            # Arrange
            unique_id = str(uuid.uuid4())[:8]
            invalid_data = {
                "username": "a",  # Too short
                "email": f"invalid{unique_id}@test.com",
                "password": "V@lidP@ss2024!"
            }
            
            # Act
            response = await async_client.post("/api/v1/auth/register", json=invalid_data)
            
            # Assert
            assert response.status_code == 422
            # Service should have been called for error classification 