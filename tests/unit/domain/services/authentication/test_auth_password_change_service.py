"""Comprehensive tests for PasswordChangeService.

This test suite validates the password change service following
advanced Test-Driven Development (TDD) principles and enterprise-grade
testing standards.

Test Categories:
- Password Change Success/Failure Scenarios
- Security Validation and Policy Enforcement
- Domain Event Publishing
- Error Handling and Classification
- Performance and Concurrency
- Real-World Edge Cases
"""

import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from src.common.exceptions import (
    AuthenticationError,
    InvalidOldPasswordError,
    PasswordPolicyError,
    PasswordReuseError,
)
from src.domain.entities.user import User, Role
from src.domain.events.authentication_events import PasswordChangedEvent
from src.domain.services.authentication.password_change_service import PasswordChangeService
from src.domain.value_objects.password import Password


class TestPasswordChangeService:
    """Comprehensive test suite for PasswordChangeService."""
    
    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        repository = AsyncMock()
        repository.get_by_id = AsyncMock()
        repository.save = AsyncMock()
        return repository
    
    @pytest.fixture
    def mock_event_publisher(self):
        """Create mock event publisher."""
        publisher = AsyncMock()
        publisher.publish = AsyncMock()
        return publisher
    
    @pytest.fixture
    def mock_user(self):
        """Create test user."""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password="$2b$12$tpooGzXbY6HtSK9xnwj0f.dI9SwSIt4bAg9gjRnJfyOCY5K4.xzHS",
            is_active=True,
            role=Role.USER,
            email_confirmed=True
        )
    
    @pytest.fixture
    def service(self, mock_user_repository, mock_event_publisher):
        """Create PasswordChangeService instance."""
        return PasswordChangeService(
            user_repository=mock_user_repository,
            event_publisher=mock_event_publisher
        )

    # ============================================================================
    # PASSWORD CHANGE SUCCESS TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_success(self, service, mock_user_repository, mock_event_publisher, mock_user):
        """Test successful password change."""
        # Arrange
        user_id = 1
        old_password = "OldStr0ng!Key"
        new_password = "NewStr0ng!Key"
        correlation_id = str(uuid.uuid4())

        mock_user_repository.get_by_id.return_value = mock_user
        mock_user_repository.save.return_value = mock_user

        # Act
        await service.change_password(
            user_id=user_id,
            old_password=old_password,
            new_password=new_password,
            language="en",
            client_ip="192.168.1.1",
            user_agent="Test Browser",
            correlation_id=correlation_id
        )
        
        # Assert
        mock_user_repository.get_by_id.assert_called_once_with(user_id)
        mock_user_repository.save.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event was published
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, PasswordChangedEvent)
        assert published_event.user_id == user_id
        # Check metadata for additional information
        assert published_event.metadata["username"] == mock_user.username
    
    @pytest.mark.asyncio
    async def test_change_password_with_generated_correlation_id(self, service, mock_user_repository, mock_event_publisher, mock_user):
        """Test password change with auto-generated correlation ID."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        mock_user_repository.save.return_value = mock_user
        
        # Act
        await service.change_password(
            user_id=1,
            old_password="OldStr0ng!Key",
            new_password="NewStr0ng!Key",
            language="en"
        )
        
        # Assert
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.correlation_id is not None

    # ============================================================================
    # INPUT VALIDATION TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_with_none_old_password(self, service):
        """Test password change with None old password."""
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password=None,
                new_password="NewStr0ng!Key",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_none_new_password(self, service):
        """Test password change with None new password."""
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password=None,
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_empty_old_password(self, service):
        """Test password change with empty old password."""
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password="",
                new_password="NewStr0ng!Key",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_empty_new_password(self, service):
        """Test password change with empty new password."""
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_whitespace_only_passwords(self, service):
        """Test password change with whitespace-only passwords."""
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password="   ",
                new_password="NewStr0ng!Key",
                language="en"
            )
        
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="  \t  ",
                language="en"
            )

    # ============================================================================
    # USER VALIDATION TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_with_nonexistent_user(self, service, mock_user_repository):
        """Test password change with nonexistent user."""
        # Arrange
        mock_user_repository.get_by_id.return_value = None
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="User not found"):
            await service.change_password(
                user_id=999,
                old_password="OldStr0ng!Key",
                new_password="NewStr0ng!Key",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_inactive_user(self, service, mock_user_repository, mock_user):
        """Test password change with inactive user."""
        # Arrange
        mock_user.is_active = False
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="User account is inactive"):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="NewStr0ng!Key",
                language="en"
            )

    # ============================================================================
    # PASSWORD VERIFICATION TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_with_incorrect_old_password(self, service, mock_user_repository, mock_user):
        """Test password change with incorrect old password."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(InvalidOldPasswordError, match="Invalid old password"):
            await service.change_password(
                user_id=1,
                old_password="WrongStr0ng!Key",
                new_password="NewStr0ng!Key",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_weak_new_password(self, service, mock_user_repository, mock_user):
        """Test password change with weak new password."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="weak",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_same_password(self, service, mock_user_repository, mock_user):
        """Test password change with same password."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordReuseError, match="password_reuse_not_allowed"):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="OldStr0ng!Key",
                language="en"
            )

    # ============================================================================
    # PASSWORD POLICY TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_with_password_missing_uppercase(self, service, mock_user_repository, mock_user):
        """Test password change with password missing uppercase."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="newpassword123!",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_password_missing_lowercase(self, service, mock_user_repository, mock_user):
        """Test password change with password missing lowercase."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="NEWPASSWORD123!",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_password_missing_digit(self, service, mock_user_repository, mock_user):
        """Test password change with password missing digit."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="NewPassword!",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_password_missing_special_character(self, service, mock_user_repository, mock_user):
        """Test password change with password missing special character."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="NewPassword123",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_password_too_short(self, service, mock_user_repository, mock_user):
        """Test password change with password too short."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="New1!",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_password_too_long(self, service, mock_user_repository, mock_user):
        """Test password change with password too long."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        long_password = "A" * 129 + "1!"
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password=long_password,
                language="en"
            )

    # ============================================================================
    # DOMAIN EVENT TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_password_changed_event_publishing(self, service, mock_user_repository, mock_event_publisher, mock_user):
        """Test that password changed event is published correctly."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        mock_user_repository.save.return_value = mock_user
        correlation_id = str(uuid.uuid4())
        
        # Act
        await service.change_password(
            user_id=1,
            old_password="OldStr0ng!Key",
            new_password="NewStr0ng!Key",
            language="en",
            client_ip="192.168.1.1",
            user_agent="Test Browser",
            correlation_id=correlation_id
        )
        
        # Assert
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        
        assert isinstance(published_event, PasswordChangedEvent)
        assert published_event.user_id == mock_user.id
        assert published_event.correlation_id == correlation_id
        # Check metadata for additional information
        assert published_event.metadata["username"] == mock_user.username
        assert published_event.metadata["user_agent"] == "Test Browser"
        assert published_event.metadata["ip_address"] == "192.168.1.1"
        assert published_event.metadata["change_method"] == "self_service"
        assert published_event.metadata["forced_change"] is False

    # ============================================================================
    # ERROR HANDLING TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_with_repository_error(self, service, mock_user_repository):
        """Test password change when repository throws error."""
        # Arrange
        mock_user_repository.get_by_id.side_effect = Exception("Database connection failed")
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="NewStr0ng!Key",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_event_publisher_error(self, service, mock_user_repository, mock_event_publisher, mock_user):
        """Test password change when event publisher throws error."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        mock_user_repository.save.return_value = mock_user
        mock_event_publisher.publish.side_effect = Exception("Event publishing failed")
        
        # Act & Assert
        with pytest.raises(AuthenticationError, match="service_unavailable"):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="NewStr0ng!Key",
                language="en"
            )

    # ============================================================================
    # PERFORMANCE TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_performance(self, service, mock_user_repository, mock_event_publisher, mock_user):
        """Test password change performance."""
        import time
        
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        mock_user_repository.save.return_value = mock_user
        
        # Act
        start_time = time.time()
        await service.change_password(
            user_id=1,
            old_password="OldStr0ng!Key",
            new_password="NewStr0ng!Key",
            language="en"
        )
        end_time = time.time()
        
        # Assert
        assert (end_time - start_time) < 1.0  # Should complete within 1 second (bcrypt hashing takes time)
    
    @pytest.mark.asyncio
    async def test_concurrent_password_changes(self, service, mock_user_repository, mock_event_publisher, mock_user):
        """Test concurrent password changes."""
        import asyncio
        
        # Arrange - Create fresh mock users for each concurrent operation
        mock_users = []
        for i in range(5):
            user = User(
                id=1,
                username="testuser",
                email="test@example.com",
                hashed_password="$2b$12$tpooGzXbY6HtSK9xnwj0f.dI9SwSIt4bAg9gjRnJfyOCY5K4.xzHS",
                is_active=True,
                role=Role.USER,
                email_confirmed=True
            )
            mock_users.append(user)
        
        # Configure repository to return different users for each call
        mock_user_repository.get_by_id.side_effect = mock_users
        mock_user_repository.save.return_value = mock_user
        
        # Act
        tasks = [
            service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password=f"NewStr0ng!Key{i}",
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
    async def test_change_password_with_very_long_passwords(self, service, mock_user_repository, mock_user):
        """Test password change with very long passwords."""
        # Arrange - Create a fresh mock user for this test
        fresh_mock_user = User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password="$2b$12$tpooGzXbY6HtSK9xnwj0f.dI9SwSIt4bAg9gjRnJfyOCY5K4.xzHS",
            is_active=True,
            role=Role.USER,
            email_confirmed=True
        )
        mock_user_repository.get_by_id.return_value = fresh_mock_user
        mock_user_repository.save.return_value = fresh_mock_user
        
        # Create long passwords that alternate characters to avoid consecutive identical characters
        long_old_password = "OldStr0ng!Key"  # Use the standard test password
        long_new_password = "Ab" * 60 + "a1!@#"  # Long new password
        
        # Act
        await service.change_password(
            user_id=1,
            old_password=long_old_password,
            new_password=long_new_password,
            language="en"
        )
        
        # Assert
        mock_user_repository.save.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_change_password_with_special_characters(self, service, mock_user_repository, mock_user):
        """Test password change with special characters in passwords."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        special_old_password = "OldStr0ng!Key"
        special_new_password = "New!@#$%^&*()_+-=[]{}|;:,.<>?847"
        
        # Act
        await service.change_password(
            user_id=1,
            old_password=special_old_password,
            new_password=special_new_password,
            language="en"
        )
        
        # Assert
        mock_user_repository.save.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_change_password_with_unicode_passwords(self, service, mock_user_repository, mock_user):
        """Test password change with Unicode passwords."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        unicode_old_password = "OldStr0ng!Key"
        unicode_new_password = "NewPässwörd847!"
        
        # Act
        await service.change_password(
            user_id=1,
            old_password=unicode_old_password,
            new_password=unicode_new_password,
            language="en"
        )
        
        # Assert
        mock_user_repository.save.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_change_password_with_different_languages(self, service, mock_user_repository, mock_user):
        """Test password change with different languages."""
        languages = ["en", "es", "fr", "de", "ar"]
    
        for language in languages:
            # Arrange - Create a fresh mock user for each test to avoid password hash conflicts
            fresh_mock_user = User(
                id=1,
                username="testuser",
                email="test@example.com",
                hashed_password="$2b$12$tpooGzXbY6HtSK9xnwj0f.dI9SwSIt4bAg9gjRnJfyOCY5K4.xzHS",
                is_active=True,
                role=Role.USER,
                email_confirmed=True
            )
            mock_user_repository.get_by_id.return_value = fresh_mock_user
            mock_user_repository.save.return_value = fresh_mock_user
            
            # Act
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="NewStr0ng!Key",
                language=language
            )
            
            # Assert
            mock_user_repository.save.assert_called()
            mock_user_repository.save.reset_mock()
    
    @pytest.mark.asyncio
    async def test_change_password_with_null_context_values(self, service, mock_user_repository, mock_user):
        """Test password change with null context values."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act
        await service.change_password(
            user_id=1,
            old_password="OldStr0ng!Key",
            new_password="NewStr0ng!Key",
            language="en",
            client_ip=None,
            user_agent=None,
            correlation_id=None
        )
        
        # Assert
        mock_user_repository.save.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_change_password_with_empty_context_values(self, service, mock_user_repository, mock_user):
        """Test password change with empty context values."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act
        await service.change_password(
            user_id=1,
            old_password="OldStr0ng!Key",
            new_password="NewStr0ng!Key",
            language="en",
            client_ip="",
            user_agent="",
            correlation_id=""
        )
        
        # Assert
        mock_user_repository.save.assert_called_once()

    # ============================================================================
    # SECURITY TESTS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_change_password_with_sql_injection_attempt(self, service, mock_user_repository, mock_user):
        """Test password change with SQL injection attempt."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="'; DROP TABLE users; --",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_xss_attempt(self, service, mock_user_repository, mock_user):
        """Test password change with XSS attempt."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="<script>alert('xss')</script>",
                language="en"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_with_path_traversal_attempt(self, service, mock_user_repository, mock_user):
        """Test password change with path traversal attempt."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(PasswordPolicyError):
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password="../../../etc/passwd",
                language="en"
            )

    # ============================================================================
    # REAL-WORLD SCENARIOS
    # ============================================================================
    
    @pytest.mark.asyncio
    async def test_password_change_workflow_scenario(self, service, mock_user_repository, mock_event_publisher, mock_user):
        """Test complete password change workflow scenario."""
        # Arrange
        mock_user_repository.get_by_id.return_value = mock_user
        mock_user_repository.save.return_value = mock_user
        
        # Act - Simulate user changing password after security alert
        await service.change_password(
            user_id=1,
            old_password="OldStr0ng!Key",
            new_password="SecureStr0ng!Key",
            language="en",
            client_ip="192.168.1.100",
            user_agent="Chrome/91.0.4472.124",
            correlation_id="security-alert-2024-001"
        )
        
        # Assert
        mock_user_repository.save.assert_called_once()
        mock_event_publisher.publish.assert_called_once()
        
        # Verify event details
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert published_event.user_id == 1
        assert published_event.correlation_id == "security-alert-2024-001"
        # Check metadata for additional information
        assert published_event.metadata["ip_address"] == "192.168.1.100"
        assert published_event.metadata["user_agent"] == "Chrome/91.0.4472.124"
    
    @pytest.mark.asyncio
    async def test_password_change_with_weak_password_attempts(self, service, mock_user_repository, mock_user):
        """Test password change with various weak password attempts."""
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
                await service.change_password(
                    user_id=1,
                    old_password="OldStr0ng!Key",
                    new_password=weak_password,
                    language="en"
                )
    
    @pytest.mark.asyncio
    async def test_password_change_with_strong_password_variations(self, service, mock_user_repository, mock_user):
        """Test password change with various strong password variations."""
        strong_passwords = [
            "Str0ng!Key1",
            "MySecureP@ss2",
            "Complex#Pass3",
            "Very$Secure4",
            "Super^Strong5",
            "Ultra&Secure6",
            "Mega*Strong7",
            "Hyper+Secure8",
        ]
        
        for strong_password in strong_passwords:
            # Create a fresh mock user for each test to avoid password hash conflicts
            fresh_mock_user = User(
                id=1,
                username="testuser",
                email="test@example.com",
                hashed_password="$2b$12$tpooGzXbY6HtSK9xnwj0f.dI9SwSIt4bAg9gjRnJfyOCY5K4.xzHS",
                is_active=True,
                role=Role.USER,
                email_confirmed=True
            )
            mock_user_repository.get_by_id.return_value = fresh_mock_user
            mock_user_repository.save.return_value = fresh_mock_user
            
            await service.change_password(
                user_id=1,
                old_password="OldStr0ng!Key",
                new_password=strong_password,
                language="en"
            )
            mock_user_repository.save.assert_called()
            mock_user_repository.save.reset_mock() 