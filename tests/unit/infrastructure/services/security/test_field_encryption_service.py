"""
Unit Tests for FieldEncryptionService.

This module tests the field encryption service with real cryptographic operations
to ensure proper encryption/decryption of sensitive token data.

Test Coverage:
- Token list encryption/decryption
- Usage history encryption/decryption
- Error handling for invalid data
- Key management and validation
- Performance characteristics
"""

import pytest
import json
from unittest.mock import patch

from src.infrastructure.services.security.field_encryption_service import FieldEncryptionService
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.token_usage_record import TokenUsageRecord
from tests.factories.token import create_valid_token_id


class TestFieldEncryptionService:
    """Test suite for FieldEncryptionService with real encryption."""
    
    @pytest.fixture
    def service(self):
        """Create service instance with real encryption."""
        return FieldEncryptionService()
    
    @pytest.fixture
    def sample_token_list(self):
        """Create sample token list for testing."""
        return [
            TokenId(create_valid_token_id()),
            TokenId(create_valid_token_id()),
            TokenId(create_valid_token_id())
        ]
    
    @pytest.fixture
    def sample_usage_history(self):
        """Create sample usage history for testing."""
        from datetime import datetime, timezone
        from src.domain.value_objects.token_usage_event import TokenUsageEvent
        from src.domain.value_objects.security_context import SecurityContext
        
        return [
            TokenUsageRecord(
                token_id=TokenId(create_valid_token_id()),
                event_type=TokenUsageEvent.USED,
                timestamp=datetime.now(timezone.utc),
                security_context=SecurityContext.create_for_request(
                    client_ip="192.168.1.100",
                    user_agent="Test Agent"
                )
            ),
            TokenUsageRecord(
                token_id=TokenId(create_valid_token_id()),
                event_type=TokenUsageEvent.USED,
                timestamp=datetime.now(timezone.utc),
                security_context=SecurityContext.create_for_request(
                    client_ip="192.168.1.101",
                    user_agent="Test Agent 2"
                )
            )
        ]
    
    def test_service_initialization(self, service):
        """Test service initialization with real encryption key."""
        assert service is not None
        assert hasattr(service, '_fernet')
        assert service._fernet is not None
        assert hasattr(service, 'encrypt_token_list')
        assert hasattr(service, 'decrypt_token_list')
        assert hasattr(service, 'encrypt_usage_history')
        assert hasattr(service, 'decrypt_usage_history')
    
    async def test_token_list_encryption_decryption_round_trip(self, service, sample_token_list):
        """Test token list encryption and decryption round trip."""
        # Encrypt the token list
        encrypted_data = await service.encrypt_token_list(sample_token_list)
        
        # Verify encryption produces bytes
        assert isinstance(encrypted_data, bytes)
        assert len(encrypted_data) > 0
        
        # Decrypt the data
        decrypted_tokens = await service.decrypt_token_list(encrypted_data)
        
        # Verify decryption produces original tokens
        assert len(decrypted_tokens) == len(sample_token_list)
        for original, decrypted in zip(sample_token_list, decrypted_tokens):
            assert isinstance(decrypted, TokenId)
            assert decrypted.value == original.value
    
    async def test_usage_history_encryption_decryption_round_trip(self, service, sample_usage_history):
        """Test usage history encryption and decryption round trip."""
        # Encrypt the usage history
        encrypted_data = await service.encrypt_usage_history(sample_usage_history)
        
        # Verify encryption produces bytes
        assert isinstance(encrypted_data, bytes)
        assert len(encrypted_data) > 0
        
        # Decrypt the data
        decrypted_history = await service.decrypt_usage_history(encrypted_data)
        
        # Verify decryption produces original history
        assert len(decrypted_history) == len(sample_usage_history)
        for original, decrypted in zip(sample_usage_history, decrypted_history):
            assert isinstance(decrypted, TokenUsageRecord)
            assert decrypted.token_id.value == original.token_id.value
            assert decrypted.event_type == original.event_type
            assert decrypted.timestamp == original.timestamp
            if original.security_context:
                assert decrypted.security_context.client_ip == original.security_context.client_ip
                assert decrypted.security_context.user_agent == original.security_context.user_agent
    
    async def test_empty_token_list_encryption(self, service):
        """Test encryption of empty token list."""
        empty_list = []
        encrypted_data = await service.encrypt_token_list(empty_list)
        
        # Should still produce encrypted bytes
        assert isinstance(encrypted_data, bytes)
        assert len(encrypted_data) > 0
        
        # Decrypt should return empty list
        decrypted_tokens = await service.decrypt_token_list(encrypted_data)
        assert decrypted_tokens == []
    
    async def test_empty_usage_history_encryption(self, service):
        """Test encryption of empty usage history."""
        empty_history = []
        encrypted_data = await service.encrypt_usage_history(empty_history)
        
        # Should still produce encrypted bytes
        assert isinstance(encrypted_data, bytes)
        assert len(encrypted_data) > 0
        
        # Decrypt should return empty list
        decrypted_history = await service.decrypt_usage_history(encrypted_data)
        assert decrypted_history == []
    
    async def test_token_list_decryption_with_invalid_data(self, service):
        """Test token list decryption with invalid encrypted data."""
        invalid_data = b"invalid_encrypted_data"
        
        with pytest.raises(Exception):
            await service.decrypt_token_list(invalid_data)
    
    async def test_usage_history_decryption_with_invalid_data(self, service):
        """Test usage history decryption with invalid encrypted data."""
        invalid_data = b"invalid_encrypted_data"
        
        with pytest.raises(Exception):
            await service.decrypt_usage_history(invalid_data)
    
    async def test_token_list_decryption_with_none(self, service):
        """Test token list decryption with None data."""
        # The service doesn't handle None inputs directly, that's handled by the repository
        # So we test that it raises an appropriate error
        with pytest.raises(Exception):
            await service.decrypt_token_list(None)
    
    async def test_usage_history_decryption_with_none(self, service):
        """Test usage history decryption with None data."""
        # The service doesn't handle None inputs directly, that's handled by the repository
        # So we test that it raises an appropriate error
        with pytest.raises(Exception):
            await service.decrypt_usage_history(None)
    
    async def test_different_service_instances_same_key(self, sample_token_list):
        """Test that different service instances can decrypt each other's data."""
        # Use the same custom key for both services (valid Fernet key format)
        from cryptography.fernet import Fernet
        custom_key = Fernet.generate_key().decode()
        service1 = FieldEncryptionService(encryption_key=custom_key)
        service2 = FieldEncryptionService(encryption_key=custom_key)
        
        # Encrypt with first service
        encrypted_data = await service1.encrypt_token_list(sample_token_list)
        
        # Decrypt with second service
        decrypted_tokens = await service2.decrypt_token_list(encrypted_data)
        
        # Should work since they use the same key
        assert len(decrypted_tokens) == len(sample_token_list)
        for original, decrypted in zip(sample_token_list, decrypted_tokens):
            assert decrypted.value == original.value
    
    async def test_encryption_produces_different_results(self, service, sample_token_list):
        """Test that encryption produces different results each time (due to IV)."""
        # Encrypt same data twice
        encrypted1 = await service.encrypt_token_list(sample_token_list)
        encrypted2 = await service.encrypt_token_list(sample_token_list)
        
        # Results should be different (due to random IV)
        assert encrypted1 != encrypted2
        
        # But both should decrypt to the same original data
        decrypted1 = await service.decrypt_token_list(encrypted1)
        decrypted2 = await service.decrypt_token_list(encrypted2)
        
        assert len(decrypted1) == len(decrypted2) == len(sample_token_list)
        for orig, dec1, dec2 in zip(sample_token_list, decrypted1, decrypted2):
            assert dec1.value == dec2.value == orig.value
    
    def test_service_with_custom_key(self):
        """Test service initialization with custom encryption key."""
        custom_key = "test_key_that_will_be_processed_by_service"
        service = FieldEncryptionService(encryption_key=custom_key)
        
        assert service is not None
        assert hasattr(service, '_fernet')
        assert service._fernet is not None
    
    async def test_large_token_list_encryption(self, service):
        """Test encryption of large token list."""
        # Create a large token list
        large_token_list = [TokenId(create_valid_token_id()) for _ in range(1000)]
        
        # Encrypt and decrypt
        encrypted_data = await service.encrypt_token_list(large_token_list)
        decrypted_tokens = await service.decrypt_token_list(encrypted_data)
        
        # Verify all tokens are preserved
        assert len(decrypted_tokens) == len(large_token_list)
        for original, decrypted in zip(large_token_list, decrypted_tokens):
            assert decrypted.value == original.value
    
    async def test_encryption_performance(self, service, sample_token_list):
        """Test encryption performance characteristics."""
        import time
        
        # Measure encryption time
        start_time = time.time()
        encrypted_data = await service.encrypt_token_list(sample_token_list)
        encryption_time = time.time() - start_time
        
        # Measure decryption time
        start_time = time.time()
        decrypted_tokens = await service.decrypt_token_list(encrypted_data)
        decryption_time = time.time() - start_time
        
        # Performance should be reasonable (less than 1 second for small data)
        assert encryption_time < 1.0
        assert decryption_time < 1.0
        
        # Verify correctness wasn't compromised for performance
        assert len(decrypted_tokens) == len(sample_token_list)
    
    async def test_concurrent_encryption_operations(self, service, sample_token_list):
        """Test concurrent encryption operations."""
        import asyncio
        
        # Create multiple encryption tasks
        tasks = [
            service.encrypt_token_list(sample_token_list)
            for _ in range(10)
        ]
        
        # Run them concurrently
        encrypted_results = await asyncio.gather(*tasks)
        
        # All should succeed
        assert len(encrypted_results) == 10
        for encrypted_data in encrypted_results:
            assert isinstance(encrypted_data, bytes)
            assert len(encrypted_data) > 0
            
            # Verify each can be decrypted correctly
            decrypted_tokens = await service.decrypt_token_list(encrypted_data)
            assert len(decrypted_tokens) == len(sample_token_list)