"""
Unit tests for TokenFamilySecurityService.

This module tests the token family security service following TDD principles
and ensuring comprehensive coverage of security scenarios.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

from src.domain.services.authentication.token_family_security_service import TokenFamilySecurityService
from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext


class TestTokenFamilySecurityService:
    """Test suite for TokenFamilySecurityService."""
    
    @pytest.fixture
    def mock_repository(self):
        """Mock token family repository."""
        return AsyncMock()
    
    @pytest.fixture
    def security_service(self, mock_repository):
        """Create TokenFamilySecurityService with mocked dependencies."""
        return TokenFamilySecurityService(token_family_repository=mock_repository)
    
    @pytest.fixture
    def sample_token_family(self):
        """Create a sample token family for testing."""
        return TokenFamily(
            family_id="test-family-123",
            user_id=1,
            status=TokenFamilyStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            last_used_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            security_score=1.0
        )
    
    @pytest.fixture
    def security_context(self):
        """Create a sample security context."""
        return SecurityContext.create_for_request(
            client_ip="192.168.1.1",
            user_agent="Test-Agent/1.0",
            correlation_id="test-correlation-123"
        )
    
    @pytest.mark.asyncio
    async def test_compromise_family_on_violation_success(self, security_service, mock_repository, sample_token_family):
        """Test successful family compromise on security violation."""
        # Arrange
        reason = "Token reuse detected"
        detected_token = TokenId.generate()
        
        # Act
        result = await security_service.compromise_family_on_violation(
            family_id=sample_token_family.family_id,
            reason=reason,
            detected_token=detected_token,
            client_ip="192.168.1.1",
            user_agent="Test-Agent",
            correlation_id="test-123"
        )
        
        # Assert
        assert result is True
        mock_repository.compromise_family.assert_called_once_with(
            family_id=sample_token_family.family_id,
            reason=reason,
            detected_token=detected_token,
            client_ip="192.168.1.1",
            user_agent="Test-Agent",
            correlation_id="test-123"
        )
    
    @pytest.mark.asyncio
    async def test_compromise_family_on_violation_repository_error(self, security_service, mock_repository):
        """Test family compromise when repository operation fails."""
        # Arrange
        mock_repository.compromise_family.side_effect = Exception("Database error")
        
        # Act & Assert
        with pytest.raises(Exception, match="Database error"):
            await security_service.compromise_family_on_violation(
                family_id="test-family",
                reason="Test violation",
                detected_token=TokenId.generate()
            )
    
    @pytest.mark.asyncio
    async def test_handle_reuse_attack_success(self, security_service, mock_repository, sample_token_family):
        """Test successful handling of token reuse attack."""
        # Arrange
        detected_token = TokenId.generate()
        
        # Act
        await security_service._handle_reuse_attack(
            family=sample_token_family,
            detected_token=detected_token,
            correlation_id="test-123"
        )
        
        # Assert
        mock_repository.update_family.assert_called_once_with(sample_token_family)
        assert sample_token_family.status == TokenFamilyStatus.COMPROMISED
        assert sample_token_family.compromise_reason == "Token reuse attack detected"
    
    @pytest.mark.asyncio
    async def test_handle_reuse_attack_already_compromised(self, security_service, mock_repository, sample_token_family):
        """Test handling reuse attack on already compromised family."""
        # Arrange
        sample_token_family.status = TokenFamilyStatus.COMPROMISED
        detected_token = TokenId.generate()
        
        # Act
        await security_service._handle_reuse_attack(
            family=sample_token_family,
            detected_token=detected_token,
            correlation_id="test-123"
        )
        
        # Assert
        # Should still update the family even if already compromised
        mock_repository.update_family.assert_called_once_with(sample_token_family)
    
    def test_security_metrics_initialization(self, security_service):
        """Test that security metrics are properly initialized."""
        metrics = security_service._security_metrics
        
        assert metrics["reuse_attacks_detected"] == 0
        assert metrics["families_compromised"] == 0
        assert metrics["security_violations"] == 0
    
    @pytest.mark.asyncio
    async def test_compromise_family_on_violation_updates_metrics(self, security_service, mock_repository):
        """Test that security metrics are updated on family compromise."""
        # Arrange
        initial_metrics = security_service._security_metrics.copy()
        
        # Act
        await security_service.compromise_family_on_violation(
            family_id="test-family",
            reason="Test violation",
            detected_token=TokenId.generate()
        )
        
        # Assert
        assert security_service._security_metrics["families_compromised"] == initial_metrics["families_compromised"] + 1
        assert security_service._security_metrics["security_violations"] == initial_metrics["security_violations"] + 1
    
    @pytest.mark.asyncio
    async def test_handle_reuse_attack_updates_metrics(self, security_service, mock_repository, sample_token_family):
        """Test that security metrics are updated on reuse attack."""
        # Arrange
        initial_metrics = security_service._security_metrics.copy()
        detected_token = TokenId.generate()
        
        # Act
        await security_service._handle_reuse_attack(
            family=sample_token_family,
            detected_token=detected_token,
            correlation_id="test-123"
        )
        
        # Assert
        assert security_service._security_metrics["reuse_attacks_detected"] == initial_metrics["reuse_attacks_detected"] + 1 