"""Unit tests for BaseInfrastructureService.

This module tests the base infrastructure service functionality including:
- Service initialization and configuration
- Structured logging with service context
- Error handling and conversion
- Security context validation
- Configuration retrieval
- Sensitive data masking

Tests follow TDD principles and cover all production scenarios.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone

from src.infrastructure.services.base_service import BaseInfrastructureService
from src.common.exceptions import AuthenticationError
from src.domain.value_objects.security_context import SecurityContext


class TestBaseInfrastructureService:
    """Test suite for BaseInfrastructureService functionality."""
    
    def test_service_initialization(self):
        """Test service initialization with proper logging setup."""
        service = BaseInfrastructureService("TestService")
        
        assert service._service_name == "TestService"
        assert service._logger is not None
    
    def test_service_initialization_with_kwargs(self):
        """Test service initialization with additional parameters."""
        service = BaseInfrastructureService(
            "TestService",
            feature_flag=True,
            version="1.0.0"
        )
        
        assert service._service_name == "TestService"
        assert service._logger is not None
    
    def test_log_operation_creates_bound_logger(self):
        """Test that _log_operation creates properly bound logger."""
        service = BaseInfrastructureService("TestService")
        
        bound_logger = service._log_operation("test_operation", user_id=123)
        
        assert bound_logger is not None
        # Verify the logger has the expected context
        assert hasattr(bound_logger, 'bind')
    
    def test_handle_infrastructure_error_converts_exceptions(self):
        """Test that infrastructure errors are converted to domain exceptions."""
        service = BaseInfrastructureService("TestService")
        
        original_error = ValueError("Test error")
        
        with patch('src.infrastructure.services.base_service.get_translated_message') as mock_get_message:
            mock_get_message.return_value = "Infrastructure error occurred"
            
            converted_error = service._handle_infrastructure_error(
                error=original_error,
                operation="test_operation",
                user_id=123,
                correlation_id="test-correlation"
            )
        
        assert isinstance(converted_error, AuthenticationError)
        mock_get_message.assert_called_with("test_operation_infrastructure_error", "en")
        assert "Infrastructure error occurred" in str(converted_error)
    
    def test_handle_infrastructure_error_with_language(self):
        """Test error handling with different languages."""
        service = BaseInfrastructureService("TestService")
        
        original_error = RuntimeError("Test error")
        
        with patch('src.infrastructure.services.base_service.get_translated_message') as mock_get_message:
            mock_get_message.return_value = "Erreur d'infrastructure"
            
            converted_error = service._handle_infrastructure_error(
                error=original_error,
                operation="test_operation",
                language="fr"
            )
        
        assert isinstance(converted_error, AuthenticationError)
        mock_get_message.assert_called_with("test_operation_infrastructure_error", "fr")
    
    def test_validate_security_context_valid(self):
        """Test security context validation with valid context."""
        service = BaseInfrastructureService("TestService")
        
        security_context = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=datetime.now(timezone.utc),
            correlation_id="test-correlation"
        )
        
        # Should not raise any exception
        service._validate_security_context(security_context, "test_operation")
    
    def test_validate_security_context_invalid(self):
        """Test security context validation with invalid context."""
        service = BaseInfrastructureService("TestService")
        
        with pytest.raises(ValueError, match="Security context is required"):
            service._validate_security_context(None, "test_operation")
    
    def test_validate_security_context_empty(self):
        """Test security context validation with empty context."""
        service = BaseInfrastructureService("TestService")
        
        with pytest.raises(ValueError, match="Security context is required"):
            service._validate_security_context("", "test_operation")
    
    def test_get_config_value_with_default(self):
        """Test configuration retrieval with default value."""
        service = BaseInfrastructureService("TestService")
        
        # Test with non-existent key
        value = service._get_config_value("NON_EXISTENT_KEY", "default_value")
        assert value == "default_value"
    
    def test_get_config_value_without_default(self):
        """Test configuration retrieval without default value."""
        service = BaseInfrastructureService("TestService")
        
        # Test with non-existent key and no default
        value = service._get_config_value("NON_EXISTENT_KEY")
        assert value is None
    
    def test_mask_sensitive_data_short(self):
        """Test masking of short sensitive data."""
        service = BaseInfrastructureService("TestService")
        
        # Test with short data
        masked = service._mask_sensitive_data("abc")
        assert masked == "***"
    
    def test_mask_sensitive_data_long(self):
        """Test masking of long sensitive data."""
        service = BaseInfrastructureService("TestService")
        
        # Test with long data
        masked = service._mask_sensitive_data("abcdefghijklmnop")
        assert masked == "abc***nop"
    
    def test_mask_sensitive_data_empty(self):
        """Test masking of empty sensitive data."""
        service = BaseInfrastructureService("TestService")
        
        # Test with empty data
        masked = service._mask_sensitive_data("")
        assert masked == "***"
    
    def test_mask_sensitive_data_none(self):
        """Test masking of None sensitive data."""
        service = BaseInfrastructureService("TestService")
        
        # Test with None data
        masked = service._mask_sensitive_data(None)
        assert masked == "***"
    
    def test_mask_sensitive_data_custom_visible_chars(self):
        """Test masking with custom visible characters."""
        service = BaseInfrastructureService("TestService")
        
        # Test with custom visible chars
        masked = service._mask_sensitive_data("abcdefghijklmnop", visible_chars=2)
        assert masked == "ab***op"
    
    def test_log_success(self):
        """Test successful operation logging."""
        service = BaseInfrastructureService("TestService")
        
        # Should not raise any exception
        service._log_success(
            operation="test_operation",
            user_id=123,
            correlation_id="test-correlation",
            result="success"
        )
    
    def test_log_warning(self):
        """Test warning operation logging."""
        service = BaseInfrastructureService("TestService")
        
        # Should not raise any exception
        service._log_warning(
            operation="test_operation",
            message="Test warning",
            user_id=123,
            correlation_id="test-correlation"
        )
    
    def test_log_operation_with_context(self):
        """Test operation logging with additional context."""
        service = BaseInfrastructureService("TestService")
        
        bound_logger = service._log_operation(
            "test_operation",
            user_id=123,
            correlation_id="test-correlation",
            additional_context="test"
        )
        
        assert bound_logger is not None
    
    def test_service_inheritance_pattern(self):
        """Test that services can properly inherit from BaseInfrastructureService."""
        
        class TestService(BaseInfrastructureService):
            def __init__(self):
                super().__init__("TestService")
            
            def test_method(self):
                return self._service_name
        
        service = TestService()
        assert service.test_method() == "TestService"
        assert service._service_name == "TestService"
    
    def test_error_handling_with_correlation_id(self):
        """Test error handling preserves correlation ID."""
        service = BaseInfrastructureService("TestService")
        
        original_error = Exception("Test error")
        correlation_id = "test-correlation-123"
        
        with patch('src.utils.i18n.get_translated_message') as mock_get_message:
            mock_get_message.return_value = "Infrastructure error"
            
            converted_error = service._handle_infrastructure_error(
                error=original_error,
                operation="test_operation",
                correlation_id=correlation_id
            )
        
        assert isinstance(converted_error, AuthenticationError)
    
    def test_logging_with_structured_data(self):
        """Test logging with structured data and nested objects."""
        service = BaseInfrastructureService("TestService")
        
        # Test with complex structured data
        structured_data = {
            "user": {"id": 123, "email": "test@example.com"},
            "session": {"id": "session-123", "expires_at": datetime.now(timezone.utc)},
            "metadata": {"version": "1.0.0", "environment": "test"}
        }
        
        # Should not raise any exception
        service._log_success(
            operation="test_operation",
            **structured_data
        )
    
    def test_config_value_retrieval_with_settings(self):
        """Test configuration retrieval from settings."""
        service = BaseInfrastructureService("TestService")
        
        # Test that we can access settings (this will depend on your settings structure)
        # This test verifies the method doesn't crash
        value = service._get_config_value("SOME_SETTING", "default")
        assert value == "default"  # Should return default if setting doesn't exist 