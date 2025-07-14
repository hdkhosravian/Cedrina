"""Comprehensive tests for UserRegistrationService.

This test suite validates the user registration service following
advanced Test-Driven Development (TDD) principles and enterprise-grade
testing standards.

Test Categories:
- User Registration Success/Failure Scenarios
- Username and Email Availability Checks
- Password Policy Enforcement
- Domain Event Publishing
- Error Handling and Classification
- Performance and Concurrency
- Real-World Edge Cases
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.common.exceptions import DuplicateUserError, PasswordPolicyError, AuthenticationError
from src.domain.validation.secure_username import UsernameValidationError
from src.domain.entities.user import User, Role
from src.domain.events.authentication_events import UserRegisteredEvent
from src.domain.services.authentication.user_registration_service import UserRegistrationService
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username


class TestUserRegistrationService:
    """Comprehensive test suite for UserRegistrationService."""
    
    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        repository = AsyncMock()
        repository.get_by_username = AsyncMock()
        repository.get_by_email = AsyncMock()
        repository.save = AsyncMock()
        return repository
    
    @pytest.fixture
    def mock_event_publisher(self):
        """Create mock event publisher."""
        publisher = AsyncMock()
        publisher.publish = AsyncMock()
        return publisher
    
    @pytest.fixture
    def mock_confirmation_token_service(self):
        """Create mock confirmation token service."""
        service = AsyncMock()
        service.generate_token = AsyncMock()
        return service
    
    @pytest.fixture
    def mock_confirmation_email_service(self):
        """Create mock confirmation email service."""
        service = AsyncMock()
        service.send_confirmation_email = AsyncMock()
        return service
    
    @pytest.fixture
    def service(self, mock_user_repository, mock_event_publisher, mock_confirmation_token_service, mock_confirmation_email_service):
        """Create UserRegistrationService instance."""
        return UserRegistrationService(
            user_repository=mock_user_repository,
            event_publisher=mock_event_publisher,
            confirmation_token_service=mock_confirmation_token_service,
            confirmation_email_service=mock_confirmation_email_service
        )
    
    @pytest.fixture
    def valid_username(self):
        """Create valid username."""
        return Username("testuser")
    
    @pytest.fixture
    def valid_email(self):
        """Create valid email."""
        return Email("test@example.com")
    
    @pytest.fixture
    def valid_password(self):
        """Create valid password."""
        return Password("MyStr0ng#P@ssw0rd", language="en")

    # ============================================================================
    # USER REGISTRATION SUCCESS TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_register_user_success(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test successful user registration."""
        # Arrange
        correlation_id = "test-correlation-id"
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act
        result = await service.register_user(
            username=valid_username,
            email=valid_email,
            password=valid_password,
            language="en",
            correlation_id=correlation_id,
            user_agent="Test Browser",
            ip_address="192.168.1.1"
        )
        
        # Assert
        assert result == created_user
        mock_user_repository.get_by_username.assert_called_once_with(str(valid_username))
        mock_user_repository.get_by_email.assert_called_once_with(str(valid_email))
        mock_user_repository.save.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event was published
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, UserRegisteredEvent)
        assert published_event.user_id == created_user.id
        assert published_event.email == created_user.email
        assert published_event.correlation_id == correlation_id
    
    @pytest.mark.asyncio
    async def test_register_user_with_custom_role(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test user registration with custom role."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.ADMIN,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act
        result = await service.register_user(
            username=valid_username,
            email=valid_email,
            password=valid_password,
            language="en",
            role=Role.ADMIN
        )
        
        # Assert
        assert result == created_user
        assert result.role == Role.ADMIN

    # ============================================================================
    # USERNAME AVAILABILITY TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_register_user_with_existing_username(self, service, mock_user_repository, valid_username, valid_email, valid_password):
        """Test user registration with existing username."""
        # Arrange
        existing_user = User(id=1, username=str(valid_username), email="existing@example.com")
        mock_user_repository.get_by_username.return_value = existing_user
        
        # Act & Assert
        with pytest.raises(DuplicateUserError, match="Username already registered"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=valid_password,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_register_user_with_existing_email(self, service, mock_user_repository, valid_username, valid_email, valid_password):
        """Test user registration with existing email."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        existing_user = User(id=1, username="existinguser", email=str(valid_email))
        mock_user_repository.get_by_email.return_value = existing_user
        
        # Act & Assert
        with pytest.raises(DuplicateUserError, match="Email already registered"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=valid_password,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_check_username_availability_available(self, service, mock_user_repository):
        """Test username availability check when username is available."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        
        # Act
        result = await service.check_username_availability("newuser")
        
        # Assert
        assert result is True
        mock_user_repository.get_by_username.assert_called_once_with("newuser")
    
    @pytest.mark.asyncio
    async def test_check_username_availability_unavailable(self, service, mock_user_repository):
        """Test username availability check when username is unavailable."""
        # Arrange
        existing_user = User(id=1, username="existinguser", email="test@example.com")
        mock_user_repository.get_by_username.return_value = existing_user
        
        # Act
        result = await service.check_username_availability("existinguser")
        
        # Assert
        assert result is False
        mock_user_repository.get_by_username.assert_called_once_with("existinguser")
    
    @pytest.mark.asyncio
    async def test_check_username_availability_invalid_format(self, service):
        """Test username availability check with invalid format."""
        # Act
        result = await service.check_username_availability("")
        
        # Assert
        assert result is False
    
    @pytest.mark.asyncio
    async def test_check_email_availability_available(self, service, mock_user_repository):
        """Test email availability check when email is available."""
        # Arrange
        mock_user_repository.get_by_email.return_value = None
        
        # Act
        result = await service.check_email_availability("new@example.com")
        
        # Assert
        assert result is True
        mock_user_repository.get_by_email.assert_called_once_with("new@example.com")
    
    @pytest.mark.asyncio
    async def test_check_email_availability_unavailable(self, service, mock_user_repository):
        """Test email availability check when email is unavailable."""
        # Arrange
        existing_user = User(id=1, username="existinguser", email="existing@example.com")
        mock_user_repository.get_by_email.return_value = existing_user
        
        # Act
        result = await service.check_email_availability("existing@example.com")
        
        # Assert
        assert result is False
        mock_user_repository.get_by_email.assert_called_once_with("existing@example.com")
    
    @pytest.mark.asyncio
    async def test_check_email_availability_invalid_format(self, service):
        """Test email availability check with invalid format."""
        # Act
        result = await service.check_email_availability("invalid-email")
        
        # Assert
        assert result is False

    # ============================================================================
    # PASSWORD POLICY TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_register_user_with_weak_password(self, service, mock_user_repository, valid_username, valid_email):
        """Test user registration with weak password."""
        # Arrange
        weak_passwords = [
            "password",  # Too short, no uppercase, no digit, no special
            "Password",  # No digit, no special
            "Password1",  # No special
            "password1!",  # No uppercase
            "PASSWORD1!",  # No lowercase
            "Pass1",  # Too short
            "A" * 129 + "1!",  # Too long
        ]
        
        for weak_password in weak_passwords:
            with pytest.raises(PasswordPolicyError):
                await service.register_user(
                    username=valid_username,
                    email=valid_email,
                    password=weak_password,
                    language="en"
                )
    
    @pytest.mark.asyncio
    async def test_register_user_with_password_missing_uppercase(self, service, mock_user_repository, valid_username, valid_email):
        """Test user registration with password missing uppercase."""
        # Arrange
        password_without_uppercase = "password123!"
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None

        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one uppercase letter"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=password_without_uppercase,
                language="en"
            )

    @pytest.mark.asyncio
    async def test_register_user_with_password_missing_lowercase(self, service, mock_user_repository, valid_username, valid_email):
        """Test user registration with password missing lowercase."""
        # Arrange
        password_without_lowercase = "PASSWORD123!"
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None

        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one lowercase letter"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=password_without_lowercase,
                language="en"
            )

    @pytest.mark.asyncio
    async def test_register_user_with_password_missing_digit(self, service, mock_user_repository, valid_username, valid_email):
        """Test user registration with password missing digit."""
        # Arrange
        password_without_digit = "Password!"
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None

        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one digit"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=password_without_digit,
                language="en"
            )

    @pytest.mark.asyncio
    async def test_register_user_with_password_missing_special_character(self, service, mock_user_repository, valid_username, valid_email):
        """Test user registration with password missing special character."""
        # Arrange
        password_without_special = "Password123"
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None

        # Act & Assert
        with pytest.raises(PasswordPolicyError, match="Password must contain at least one special character"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=password_without_special,
                language="en"
            )

    # ============================================================================
    # DOMAIN EVENT TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_user_registered_event_publishing(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test that user registered event is published correctly."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        correlation_id = "test-correlation-id"
        
        # Act
        await service.register_user(
            username=valid_username,
            email=valid_email,
            password=valid_password,
            language="en",
            correlation_id=correlation_id,
            user_agent="Test Browser",
            ip_address="192.168.1.1"
        )
        
        # Assert
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        
        assert isinstance(published_event, UserRegisteredEvent)
        assert published_event.user_id == created_user.id
        assert published_event.email == created_user.email
        assert published_event.correlation_id == correlation_id

    # ============================================================================
    # ERROR HANDLING TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_register_user_with_repository_error(self, service, mock_user_repository, valid_username, valid_email, valid_password):
        """Test user registration when repository throws error."""
        # Arrange
        mock_user_repository.get_by_username.side_effect = Exception("Database connection failed")
        
        # Act & Assert
        with pytest.raises(DuplicateUserError, match="Username already registered"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=valid_password,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_register_user_with_event_publisher_error(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test user registration when event publisher throws error."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        mock_event_publisher.publish.side_effect = Exception("Event publishing failed")
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.register_user(
                username=valid_username,
                email=valid_email,
                password=valid_password,
                language="en"
            )

    # ============================================================================
    # PERFORMANCE TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_register_user_performance(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test user registration performance."""
        import time
        
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act
        start_time = time.time()
        await service.register_user(
            username=valid_username,
            email=valid_email,
            password=valid_password,
            language="en"
        )
        end_time = time.time()
        
        # Assert
        assert (end_time - start_time) < 1.0  # Should complete within 1 second
    
    @pytest.mark.asyncio
    async def test_concurrent_user_registrations(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test concurrent user registrations."""
        import asyncio
        
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act
        tasks = [
            service.register_user(
                username=Username(f"user{i}"),
                email=Email(f"user{i}@example.com"),
                password=valid_password,
                language="en",
                correlation_id=f"test-{i}"
            )
            for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Assert
        assert len(results) == 5
        assert all(not isinstance(result, Exception) for result in results)
        assert mock_event_publisher.publish.call_count == 5

    # ============================================================================
    # EDGE CASES AND BOUNDARY CONDITIONS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_register_user_with_very_long_username(self, service, mock_user_repository, mock_event_publisher, valid_email, valid_password):
        """Test user registration with very long username."""
        # Arrange
        long_username = Username("a" * 100)
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(long_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act
        result = await service.register_user(
            username=long_username,
            email=valid_email,
            password=valid_password,
            language="en"
        )
        
        # Assert
        assert result == created_user
    
    @pytest.mark.asyncio
    async def test_register_user_with_special_characters_in_username(self, service, mock_user_repository, mock_event_publisher, valid_email, valid_password):
        """Test user registration with special characters in username."""
        # Arrange
        special_username = "test@user#123"
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None

        # Act & Assert - Should fail due to security validation
        with pytest.raises(UsernameValidationError, match="Username format is invalid"):
            await service.register_user(
                username=special_username,
                email=valid_email,
                password=valid_password,
                language="en"
            )

    @pytest.mark.asyncio
    async def test_register_user_with_unicode_username(self, service, mock_user_repository, mock_event_publisher, valid_email, valid_password):
        """Test user registration with Unicode username."""
        # Arrange
        unicode_username = "tëstüser"
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None

        # Act & Assert - Should fail due to security validation
        with pytest.raises(UsernameValidationError, match="Username format is invalid"):
            await service.register_user(
                username=unicode_username,
                email=valid_email,
                password=valid_password,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_register_user_with_different_languages(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test user registration with different languages."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        languages = ["en", "es", "fr", "de", "ar"]
        
        for language in languages:
            # Act
            result = await service.register_user(
                username=valid_username,
                email=valid_email,
                password=valid_password,
                language=language
            )
            
            # Assert
            assert result == created_user
            mock_user_repository.save.reset_mock()
    
    @pytest.mark.asyncio
    async def test_register_user_with_null_context_values(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test user registration with null context values."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act
        result = await service.register_user(
            username=valid_username,
            email=valid_email,
            password=valid_password,
            language="en",
            correlation_id=None,
            user_agent=None,
            ip_address=None
        )
        
        # Assert
        assert result == created_user
    
    @pytest.mark.asyncio
    async def test_register_user_with_empty_context_values(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test user registration with empty context values."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act
        result = await service.register_user(
            username=valid_username,
            email=valid_email,
            password=valid_password,
            language="en",
            correlation_id="",
            user_agent="",
            ip_address=""
        )
        
        # Assert
        assert result == created_user

    # ============================================================================
    # SECURITY TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_register_user_with_sql_injection_attempt(self, service, mock_user_repository, valid_email, valid_password):
        """Test user registration with SQL injection attempt in username."""
        # Arrange
        malicious_username_str = "'; DROP TABLE users; --"
        
        # Act & Assert - Should fail due to security validation
        with pytest.raises(UsernameValidationError):
            await service.register_user(
                username=malicious_username_str,
                email=valid_email,
                password=valid_password,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_register_user_with_xss_attempt(self, service, mock_user_repository, valid_email, valid_password):
        """Test user registration with XSS attempt in username."""
        # Arrange
        malicious_username = "<script>alert('xss')</script>"
        
        # Act & Assert - Should fail due to security validation
        with pytest.raises(UsernameValidationError):
            await service.register_user(
                username=malicious_username,
                email=valid_email,
                password=valid_password,
                language="en"
            )

    # ============================================================================
    # REAL-WORLD SCENARIOS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_user_registration_workflow_scenario(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email, valid_password):
        """Test complete user registration workflow scenario."""
        # Arrange
        mock_user_repository.get_by_username.return_value = None
        mock_user_repository.get_by_email.return_value = None
        
        created_user = User(
            id=1,
            username=str(valid_username),
            email=str(valid_email),
            hashed_password="hashed_password",
            role=Role.USER,
            is_active=True,
            email_confirmed=True
        )
        mock_user_repository.save.return_value = created_user
        
        # Act - Simulate new user registration
        result = await service.register_user(
            username=valid_username,
            email=valid_email,
            password=valid_password,
            language="en",
            correlation_id="registration-2024-001",
            user_agent="Chrome/91.0.4472.124",
            ip_address="192.168.1.100"
        )
        
        # Assert
        assert result == created_user
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event details
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.user_id == 1
        assert published_event.correlation_id == "registration-2024-001"
        assert published_event.ip_address == "192.168.1.100"
        assert published_event.user_agent == "Chrome/91.0.4472.124"
    
    @pytest.mark.asyncio
    async def test_user_registration_with_weak_password_attempts(self, service, mock_user_repository, valid_username, valid_email):
        """Test user registration with various weak password attempts."""
        weak_passwords = [
            "password",  # Too short, no uppercase, no digit, no special
            "Password",  # No digit, no special
            "Password1",  # No special
            "password1!",  # No uppercase
            "PASSWORD1!",  # No lowercase
            "Pass1",  # Too short
            "A" * 129 + "1!",  # Too long
        ]
        
        for weak_password in weak_passwords:
            with pytest.raises(PasswordPolicyError):
                await service.register_user(
                    username=valid_username,
                    email=valid_email,
                    password=weak_password,
                    language="en"
                )
    
    @pytest.mark.asyncio
    async def test_user_registration_with_strong_password_variations(self, service, mock_user_repository, mock_event_publisher, valid_username, valid_email):
        """Test user registration with various strong password variations."""
        strong_passwords = [
            Password("StrongPass1!", language="en"),
            Password("MySecureP@ss2", language="en"),
            Password("Complex#Pass3", language="en"),
            Password("Very$Secure4", language="en"),
            Password("Super^Strong5", language="en"),
            Password("Ultra&Secure6", language="en"),
            Password("Mega*Strong7", language="en"),
            Password("Hyper+Secure8", language="en"),
        ]
        
        for i, strong_password in enumerate(strong_passwords):
            mock_user_repository.get_by_username.return_value = None
            mock_user_repository.get_by_email.return_value = None
            
            created_user = User(
                id=i + 1,
                username=f"user{i}",
                email=f"user{i}@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                is_active=True,
                email_confirmed=True
            )
            mock_user_repository.save.return_value = created_user
            
            await service.register_user(
                username=Username(f"user{i}"),
                email=Email(f"user{i}@example.com"),
                password=strong_password,
                language="en"
            )
            
            mock_user_repository.save.assert_called()
            mock_user_repository.save.reset_mock() 