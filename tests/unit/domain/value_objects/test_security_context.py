"""Tests for the SecurityContext value object.

This module contains comprehensive tests for the SecurityContext value object,
ensuring it properly validates security context information and handles edge cases in production scenarios.
"""

from datetime import datetime, timezone
from typing import Optional

import pytest
from src.domain.value_objects.security_context import SecurityContext
from src.common.exceptions import ValidationError


class TestSecurityContext:
    """Test cases for SecurityContext value object."""

    def test_valid_security_context_creation(self):
        """Test creating a valid security context."""
        # Arrange
        client_ip = "192.168.1.100"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        request_timestamp = datetime.now(timezone.utc)
        correlation_id = "req-123456"
        
        # Act
        security_context = SecurityContext(
            client_ip=client_ip,
            user_agent=user_agent,
            request_timestamp=request_timestamp,
            correlation_id=correlation_id
        )
        
        # Assert
        assert security_context.client_ip == client_ip
        assert security_context.user_agent == user_agent
        assert security_context.request_timestamp == request_timestamp
        assert security_context.correlation_id == correlation_id

    def test_security_context_without_correlation_id(self):
        """Test creating security context without correlation ID."""
        # Arrange
        client_ip = "10.0.0.1"
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        request_timestamp = datetime.now(timezone.utc)
        
        # Act
        security_context = SecurityContext(
            client_ip=client_ip,
            user_agent=user_agent,
            request_timestamp=request_timestamp
        )
        
        # Assert
        assert security_context.client_ip == client_ip
        assert security_context.user_agent == user_agent
        assert security_context.request_timestamp == request_timestamp
        assert security_context.correlation_id is None

    def test_security_context_empty_client_ip(self):
        """Test that empty client IP raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Client IP address is required"):
            SecurityContext(
                client_ip="",
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )

    def test_security_context_none_client_ip(self):
        """Test that None client IP raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Client IP address is required"):
            SecurityContext(
                client_ip=None,  # type: ignore
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )

    def test_security_context_invalid_ip_format(self):
        """Test that invalid IP format raises ValidationError."""
        # Arrange
        invalid_ips = [
            "256.1.2.3",  # Invalid octet
            "1.2.3.4.5",  # Too many octets
            "1.2.3",      # Too few octets
            "192.168.1",  # Incomplete
            "invalid",    # Not an IP
            "192.168.1.256",  # Invalid last octet
        ]
        
        # Act & Assert
        for invalid_ip in invalid_ips:
            with pytest.raises(ValidationError, match="Invalid IP address format"):
                SecurityContext(
                    client_ip=invalid_ip,
                    user_agent="Mozilla/5.0",
                    request_timestamp=datetime.now(timezone.utc)
                )

    def test_security_context_valid_ipv4_addresses(self):
        """Test that valid IPv4 addresses are accepted."""
        # Arrange
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "8.8.8.8",
            "255.255.255.255",
            "0.0.0.0",
        ]
        
        # Act & Assert
        for valid_ip in valid_ips:
            security_context = SecurityContext(
                client_ip=valid_ip,
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )
            assert security_context.client_ip == valid_ip

    def test_security_context_valid_ipv6_addresses(self):
        """Test that valid IPv6 addresses are accepted."""
        # Arrange
        valid_ipv6 = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
            "::1",
            "fe80::1",
        ]
        
        # Act & Assert
        for valid_ip in valid_ipv6:
            security_context = SecurityContext(
                client_ip=valid_ip,
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )
            assert security_context.client_ip == valid_ip

    def test_security_context_empty_user_agent(self):
        """Test that empty user agent raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="User-Agent is required"):
            SecurityContext(
                client_ip="192.168.1.1",
                user_agent="",
                request_timestamp=datetime.now(timezone.utc)
            )

    def test_security_context_none_user_agent(self):
        """Test that None user agent raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="User-Agent is required"):
            SecurityContext(
                client_ip="192.168.1.1",
                user_agent=None,  # type: ignore
                request_timestamp=datetime.now(timezone.utc)
            )

    def test_security_context_user_agent_too_long(self):
        """Test that user agent exceeding maximum length raises ValidationError."""
        # Arrange
        long_user_agent = "A" * 1001  # Exceeds 1000 character limit
        
        # Act & Assert
        with pytest.raises(ValidationError, match="User-Agent exceeds maximum length"):
            SecurityContext(
                client_ip="192.168.1.1",
                user_agent=long_user_agent,
                request_timestamp=datetime.now(timezone.utc)
            )

    def test_security_context_none_timestamp(self):
        """Test that None timestamp raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Request timestamp is required"):
            SecurityContext(
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                request_timestamp=None  # type: ignore
            )

    def test_security_context_timezone_naive_timestamp(self):
        """Test that timezone-naive timestamp raises ValidationError."""
        # Arrange
        naive_timestamp = datetime.now()  # No timezone info
        
        # Act & Assert
        with pytest.raises(ValidationError, match="Request timestamp must be timezone-aware"):
            SecurityContext(
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                request_timestamp=naive_timestamp
            )

    def test_security_context_correlation_id_too_long(self):
        """Test that correlation ID exceeding maximum length raises ValidationError."""
        # Arrange
        long_correlation_id = "A" * 101  # Exceeds 100 character limit
        
        # Act & Assert
        with pytest.raises(ValidationError, match="Correlation ID exceeds maximum length"):
            SecurityContext(
                client_ip="192.168.1.1",
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc),
                correlation_id=long_correlation_id
            )

    def test_security_context_create_for_request(self):
        """Test create_for_request factory method."""
        # Arrange
        client_ip = "192.168.1.100"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        correlation_id = "req-123456"
        
        # Act
        security_context = SecurityContext.create_for_request(
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id
        )
        
        # Assert
        assert security_context.client_ip == client_ip
        assert security_context.user_agent == user_agent
        assert security_context.correlation_id == correlation_id
        assert security_context.request_timestamp.tzinfo == timezone.utc
        assert isinstance(security_context.request_timestamp, datetime)

    def test_security_context_create_for_request_without_correlation_id(self):
        """Test create_for_request factory method without correlation ID."""
        # Arrange
        client_ip = "10.0.0.1"
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        
        # Act
        security_context = SecurityContext.create_for_request(
            client_ip=client_ip,
            user_agent=user_agent
        )
        
        # Assert
        assert security_context.client_ip == client_ip
        assert security_context.user_agent == user_agent
        assert security_context.correlation_id is None
        assert security_context.request_timestamp.tzinfo == timezone.utc

    def test_security_context_is_internal_network(self):
        """Test is_internal_network method."""
        # Arrange
        internal_ips = [
            "10.0.0.1",
            "10.255.255.255",
            "192.168.1.1",
            "192.168.255.255",
            "172.16.0.1",
            "172.31.255.255",
        ]
        external_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222",
        ]
        
        # Act & Assert
        for internal_ip in internal_ips:
            security_context = SecurityContext(
                client_ip=internal_ip,
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )
            assert security_context.is_internal_network() is True
        
        for external_ip in external_ips:
            security_context = SecurityContext(
                client_ip=external_ip,
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )
            assert security_context.is_internal_network() is False

    def test_security_context_get_masked_ip(self):
        """Test get_masked_ip method."""
        # Arrange
        test_cases = [
            ("192.168.1.100", "192.168.xxx.xxx"),
            ("10.0.0.1", "10.0.xxx.xxx"),
            ("172.16.0.1", "172.16.xxx.xxx"),
            ("8.8.8.8", "8.8.xxx.xxx"),
        ]
        
        # Act & Assert
        for ip, expected_mask in test_cases:
            security_context = SecurityContext(
                client_ip=ip,
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )
            assert security_context.get_masked_ip() == expected_mask

    def test_security_context_get_masked_ip_ipv6(self):
        """Test get_masked_ip method with IPv6 addresses."""
        # Arrange
        ipv6_addresses = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "::1",
            "fe80::1",
        ]
        
        # Act & Assert
        for ipv6 in ipv6_addresses:
            security_context = SecurityContext(
                client_ip=ipv6,
                user_agent="Mozilla/5.0",
                request_timestamp=datetime.now(timezone.utc)
            )
            assert security_context.get_masked_ip() == "xxx.xxx.xxx.xxx"

    def test_security_context_get_masked_user_agent(self):
        """Test get_masked_user_agent method."""
        # Arrange
        short_user_agent = "Mozilla/5.0 (Windows NT 10.0)"
        long_user_agent = "A" * 100  # 100 characters
        
        # Act
        security_context_short = SecurityContext(
            client_ip="192.168.1.1",
            user_agent=short_user_agent,
            request_timestamp=datetime.now(timezone.utc)
        )
        security_context_long = SecurityContext(
            client_ip="192.168.1.1",
            user_agent=long_user_agent,
            request_timestamp=datetime.now(timezone.utc)
        )
        
        # Assert
        assert security_context_short.get_masked_user_agent() == short_user_agent
        assert security_context_long.get_masked_user_agent() == long_user_agent[:47] + "..."

    def test_security_context_to_audit_dict(self):
        """Test to_audit_dict method."""
        # Arrange
        client_ip = "192.168.1.100"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        request_timestamp = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        correlation_id = "req-123456"
        
        security_context = SecurityContext(
            client_ip=client_ip,
            user_agent=user_agent,
            request_timestamp=request_timestamp,
            correlation_id=correlation_id
        )
        
        # Act
        audit_dict = security_context.to_audit_dict()
        
        # Assert
        assert audit_dict["client_ip"] == "192.168.xxx.xxx"
        assert audit_dict["user_agent"] == user_agent[:47] + "..."
        assert audit_dict["request_timestamp"] == "2023-01-01T12:00:00+00:00"
        assert audit_dict["correlation_id"] == correlation_id
        assert audit_dict["is_internal"] is True

    def test_security_context_immutability(self):
        """Test that security context is immutable."""
        # Arrange
        security_context = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=datetime.now(timezone.utc)
        )
        
        # Act & Assert
        with pytest.raises(AttributeError):
            security_context.client_ip = "10.0.0.1"  # type: ignore

    def test_security_context_equality(self):
        """Test security context equality."""
        # Arrange
        timestamp = datetime.now(timezone.utc)
        security_context1 = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        security_context2 = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        security_context3 = SecurityContext(
            client_ip="10.0.0.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        
        # Act & Assert
        assert security_context1 == security_context2
        assert security_context1 != security_context3
        assert security_context1 != "invalid"  # Different type

    def test_security_context_hash(self):
        """Test security context hash."""
        # Arrange
        timestamp = datetime.now(timezone.utc)
        security_context1 = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        security_context2 = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        security_context3 = SecurityContext(
            client_ip="10.0.0.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        
        # Act & Assert
        assert hash(security_context1) == hash(security_context2)
        assert hash(security_context1) != hash(security_context3)

    def test_security_context_production_scenario_high_volume(self):
        """Test security context creation under high-volume scenario simulation."""
        # Act & Assert - Simulate high-volume processing
        security_contexts = []
        for i in range(50):  # Simulate 50 security context creations
            security_context = SecurityContext.create_for_request(
                client_ip=f"192.168.1.{i}",
                user_agent=f"Mozilla/5.0 (Test Browser {i})",
                correlation_id=f"req-{i:06d}"
            )
            security_contexts.append(security_context)
            assert security_context.client_ip == f"192.168.1.{i}"
            assert security_context.user_agent == f"Mozilla/5.0 (Test Browser {i})"
            assert security_context.correlation_id == f"req-{i:06d}"
            assert security_context.is_internal_network() is True
        
        # All security contexts should be valid
        for context in security_contexts:
            assert isinstance(context, SecurityContext)
            assert context.client_ip is not None
            assert context.user_agent is not None
            assert context.request_timestamp is not None

    def test_security_context_production_scenario_mixed_networks(self):
        """Test security context creation with mixed network types."""
        # Arrange
        network_configs = [
            ("192.168.1.1", True),   # Internal
            ("10.0.0.1", True),      # Internal
            ("172.16.0.1", True),    # Internal
            ("8.8.8.8", False),      # External
            ("1.1.1.1", False),      # External
            ("208.67.222.222", False), # External
        ]
        
        # Act & Assert
        for ip, expected_internal in network_configs:
            security_context = SecurityContext.create_for_request(
                client_ip=ip,
                user_agent="Mozilla/5.0"
            )
            assert security_context.is_internal_network() == expected_internal

    def test_security_context_security_logging_masking(self):
        """Test that security context masking provides privacy protection."""
        # Arrange
        sensitive_ip = "192.168.1.100"
        sensitive_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        security_context = SecurityContext.create_for_request(
            client_ip=sensitive_ip,
            user_agent=sensitive_user_agent
        )
        
        # Act
        masked_ip = security_context.get_masked_ip()
        masked_user_agent = security_context.get_masked_user_agent()
        audit_dict = security_context.to_audit_dict()
        
        # Assert
        # Ensure sensitive data is masked
        assert "192.168.1.100" not in masked_ip
        assert "192.168.1.100" not in audit_dict["client_ip"]
        
        # Ensure user agent is truncated if too long
        if len(sensitive_user_agent) > 50:
            assert len(masked_user_agent) <= 50
            assert len(audit_dict["user_agent"]) <= 50

    def test_security_context_edge_case_boundary_values(self):
        """Test security context with boundary values."""
        # Arrange
        max_length_user_agent = "A" * 1000  # Exactly at limit
        max_length_correlation_id = "A" * 100  # Exactly at limit
        
        # Act
        security_context = SecurityContext(
            client_ip="192.168.1.1",
            user_agent=max_length_user_agent,
            request_timestamp=datetime.now(timezone.utc),
            correlation_id=max_length_correlation_id
        )
        
        # Assert
        assert security_context.user_agent == max_length_user_agent
        assert security_context.correlation_id == max_length_correlation_id

    def test_security_context_edge_case_special_characters(self):
        """Test security context with special characters in user agent."""
        # Arrange
        special_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 [Special: @#$%^&*()]"
        
        # Act
        security_context = SecurityContext(
            client_ip="192.168.1.1",
            user_agent=special_user_agent,
            request_timestamp=datetime.now(timezone.utc)
        )
        
        # Assert
        assert security_context.user_agent == special_user_agent

    def test_security_context_hash_consistency(self):
        """Test that hash values are consistent for same security contexts."""
        # Arrange
        timestamp = datetime.now(timezone.utc)
        security_context1 = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        security_context2 = SecurityContext(
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_timestamp=timestamp,
            correlation_id="req-123"
        )
        
        # Act & Assert
        assert hash(security_context1) == hash(security_context2)
        
        # Hash should be consistent across multiple calls
        assert hash(security_context1) == hash(security_context1)
        assert hash(security_context2) == hash(security_context2) 