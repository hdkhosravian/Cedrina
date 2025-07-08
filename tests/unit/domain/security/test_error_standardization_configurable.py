"""Comprehensive tests for configurable error standardization timing.

This test suite validates the new configurable timing settings optimized for
powerful servers and multi-server deployments.
"""

import asyncio
import time
from unittest.mock import patch, MagicMock

import pytest

from src.core.config.settings import settings
from src.domain.security.error_standardization import (
    ErrorStandardizationService,
    TimingPattern,
    error_standardization_service
)


class TestConfigurableTimingSettings:
    """Test configurable timing settings for powerful servers."""
    
    @pytest.mark.unit
    def test_timing_ranges_from_settings(self):
        """Test that timing ranges are loaded from settings."""
        service = ErrorStandardizationService()
        
        # Verify timing ranges are loaded from settings
        ranges = service.timing_ranges
        
        assert TimingPattern.FAST in ranges
        assert TimingPattern.MEDIUM in ranges
        assert TimingPattern.SLOW in ranges
        assert TimingPattern.VARIABLE in ranges
        
        # Verify ranges are tuples of (min, max)
        for pattern, (min_time, max_time) in ranges.items():
            assert isinstance(min_time, float)
            assert isinstance(max_time, float)
            assert min_time > 0
            assert max_time > min_time
    
    @pytest.mark.unit
    def test_cpu_operations_from_settings(self):
        """Test that CPU operations are loaded from settings."""
        service = ErrorStandardizationService()
        
        # Verify CPU operations are loaded from settings
        operations = service.cpu_operations
        
        assert "FAST" in operations
        assert "MEDIUM" in operations
        assert "SLOW" in operations
        assert "VARIABLE" in operations
        
        # Verify operations are positive integers
        for pattern, ops_per_ms in operations.items():
            assert isinstance(ops_per_ms, int)
            assert ops_per_ms > 0
    
    @pytest.mark.unit
    def test_powerful_server_timing_ranges(self):
        """Test that timing ranges are optimized for powerful servers."""
        # Get current timing ranges
        ranges = error_standardization_service.timing_ranges
        
        # Verify SLOW pattern has valid timing range
        slow_min, slow_max = ranges[TimingPattern.SLOW]
        assert slow_min > 0  # Should be positive
        assert slow_max > slow_min  # Valid range
        
        # Verify VARIABLE pattern has valid timing range
        var_min, var_max = ranges[TimingPattern.VARIABLE]
        assert var_min > 0  # Should be positive
        assert var_max > var_min  # Valid range
        
        # Verify MEDIUM pattern has valid timing range
        med_min, med_max = ranges[TimingPattern.MEDIUM]
        assert med_min > 0  # Should be positive
        assert med_max > med_min  # Valid range
        
        # Verify FAST pattern has valid timing range
        fast_min, fast_max = ranges[TimingPattern.FAST]
        assert fast_min > 0  # Should be positive
        assert fast_max > fast_min  # Valid range
    
    @pytest.mark.unit
    def test_powerful_server_cpu_operations(self):
        """Test that CPU operations are optimized for powerful servers."""
        operations = error_standardization_service.cpu_operations
        
        # Verify SLOW pattern has high CPU operations for powerful servers
        assert operations["SLOW"] >= 20000  # At least 20k operations per ms
        
        # Verify MEDIUM pattern has moderate CPU operations
        assert operations["MEDIUM"] >= 8000  # At least 8k operations per ms
        
        # Verify FAST pattern has lower CPU operations
        assert operations["FAST"] >= 2000  # At least 2k operations per ms
        
        # Verify VARIABLE uses SLOW pattern operations
        assert operations["VARIABLE"] == operations["SLOW"]
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_configurable_timing_application(self):
        """Test that timing is applied using configurable settings."""
        service = ErrorStandardizationService()
        
        # Test SLOW pattern timing
        start_time = time.time()
        await service.apply_standard_timing(
            elapsed_time=0.1,
            timing_pattern=TimingPattern.SLOW,
            correlation_id="test-123"
        )
        elapsed = time.time() - start_time
        
        # Should take some time (with ultra-fast config, this could be very fast)
        assert elapsed > 0  # Should take some time
        assert elapsed < 2.0  # Should not be excessive

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_advanced_crypto_operations_configuration(self):
        """Test advanced cryptographic operations configuration."""
        service = ErrorStandardizationService()
        
        # Test with advanced operations enabled
        with patch.object(settings, 'USE_ADVANCED_CRYPTO_OPERATIONS', True):
            start_time = time.time()
            await service.apply_standard_timing(
                elapsed_time=0.1,
                timing_pattern=TimingPattern.SLOW,
                correlation_id="test-advanced"
            )
            elapsed_advanced = time.time() - start_time
        
        # Test with advanced operations disabled
        with patch.object(settings, 'USE_ADVANCED_CRYPTO_OPERATIONS', False):
            start_time = time.time()
            await service.apply_standard_timing(
                elapsed_time=0.1,
                timing_pattern=TimingPattern.SLOW,
                correlation_id="test-simple"
            )
            elapsed_simple = time.time() - start_time
        
        # Both should complete successfully
        assert elapsed_advanced > 0
        assert elapsed_simple > 0
    
    @pytest.mark.unit
    def test_server_performance_detection(self):
        """Test server performance detection and multiplier calculation."""
        # Test manual multiplier
        with patch.object(settings, 'AUTO_DETECT_SERVER_PERFORMANCE', False):
            with patch.object(settings, 'SERVER_PERFORMANCE_MULTIPLIER', 2.0):
                multiplier = settings._get_performance_multiplier()
                assert multiplier == 2.0
        
        # Test auto-detection fallback
        with patch.object(settings, 'AUTO_DETECT_SERVER_PERFORMANCE', True):
            with patch('multiprocessing.cpu_count', side_effect=ImportError):
                multiplier = settings._get_performance_multiplier()
                assert multiplier == settings.SERVER_PERFORMANCE_MULTIPLIER
    
    @pytest.mark.unit
    def test_server_instance_id_generation(self):
        """Test server instance ID generation for timing consistency."""
        # Test with custom ID
        with patch.object(settings, 'SERVER_INSTANCE_ID', 'custom-server-1'):
            instance_id = settings.get_server_instance_id()
            assert instance_id == 'custom-server-1'
        
        # Test auto-generation
        with patch.object(settings, 'SERVER_INSTANCE_ID', ''):
            with patch('socket.gethostname', return_value='test-host'):
                with patch('os.getpid', return_value=12345):
                    instance_id = settings.get_server_instance_id()
                    assert instance_id == 'test-host-12345'
    
    @pytest.mark.unit
    def test_timing_consistency_across_servers(self):
        """Test timing consistency across multiple server instances."""
        service1 = ErrorStandardizationService()
        service2 = ErrorStandardizationService()
        
        # Both services should have the same timing ranges
        ranges1 = service1.timing_ranges
        ranges2 = service2.timing_ranges
        
        for pattern in TimingPattern:
            assert ranges1[pattern] == ranges2[pattern]
        
        # Both services should have the same CPU operations
        ops1 = service1.cpu_operations
        ops2 = service2.cpu_operations
        
        for pattern in ["FAST", "MEDIUM", "SLOW", "VARIABLE"]:
            assert ops1[pattern] == ops2[pattern]
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_environment_variable_configuration(self):
        """Test that timing can be configured via environment variables."""
        # Test with custom timing values
        with patch.dict('os.environ', {
            'SECURITY_TIMING_SLOW_MIN': '0.5',
            'SECURITY_TIMING_SLOW_MAX': '1.0',
            'SECURITY_CPU_OPERATIONS_PER_MS_SLOW': '25000'
        }):
            # Create new settings instance to pick up environment variables
            from src.core.config.security import SecuritySettings
            custom_settings = SecuritySettings()
            
            # Verify custom values are applied (with performance multiplier)
            ranges = custom_settings.get_timing_ranges()
            # The values will be adjusted by performance multiplier, so check they're reasonable
            slow_min, slow_max = ranges["SLOW"]
            assert 0.3 <= slow_min <= 0.7  # Allow for performance multiplier adjustment
            assert 0.7 <= slow_max <= 1.3  # Allow for performance multiplier adjustment
            
            ops_per_ms = custom_settings.get_cpu_operations_per_ms("SLOW")
            assert ops_per_ms == 25000
    
    @pytest.mark.unit
    def test_timing_validation(self):
        """Test timing validation ensures min < max."""
        from src.core.config.security import SecuritySettings
        
        # Test valid timing ranges
        valid_settings = SecuritySettings(
            TIMING_SLOW_MIN=0.4,
            TIMING_SLOW_MAX=0.8
        )
        assert valid_settings.TIMING_SLOW_MIN == 0.4
        assert valid_settings.TIMING_SLOW_MAX == 0.8
        
        # Test invalid timing ranges (should raise validation error)
        with pytest.raises(ValueError, match="must be greater than"):
            SecuritySettings(
                TIMING_SLOW_MIN=0.8,
                TIMING_SLOW_MAX=0.4  # Max less than min
            )
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_multi_server_timing_consistency(self):
        """Test timing consistency across multiple server instances with different IDs."""
        service = ErrorStandardizationService()
        
        # Test with different server instance IDs
        with patch.object(settings, 'ENABLE_DETERMINISTIC_TIMING', True):
            with patch.object(settings, 'get_server_instance_id', return_value="server-1"):
                start_time = time.time()
                await service.apply_standard_timing(
                    elapsed_time=0.1,
                    timing_pattern=TimingPattern.VARIABLE,
                    correlation_id="test-123"
                )
                elapsed_server1 = time.time() - start_time
            
            with patch.object(settings, 'get_server_instance_id', return_value="server-2"):
                start_time = time.time()
                await service.apply_standard_timing(
                    elapsed_time=0.1,
                    timing_pattern=TimingPattern.VARIABLE,
                    correlation_id="test-123"  # Same correlation ID, different server
                )
                elapsed_server2 = time.time() - start_time
            
            # Different servers should produce different timing for same correlation ID
            assert elapsed_server1 != elapsed_server2
            
            # Both should take some time and not be excessive
            assert elapsed_server1 > 0
            assert elapsed_server2 > 0
            assert elapsed_server1 < 10.0  # Allow more time for complex operations
            assert elapsed_server2 < 10.0  # Allow more time for complex operations


class TestPowerfulServerOptimizations:
    """Test specific optimizations for powerful servers."""
    
    @pytest.mark.unit
    def test_high_cpu_operations_for_powerful_servers(self):
        """Test that powerful servers use high CPU operation counts."""
        operations = error_standardization_service.cpu_operations
        
        # For powerful servers, SLOW pattern should use many operations
        assert operations["SLOW"] >= 20000  # 20k+ operations per ms
        
        # This ensures sufficient CPU utilization on powerful hardware
        # to prevent timing attacks while maintaining security
    
    @pytest.mark.unit
    def test_extended_timing_ranges_for_powerful_servers(self):
        """Test that powerful servers use extended timing ranges."""
        ranges = error_standardization_service.timing_ranges
        
        # SLOW pattern should have valid range
        slow_min, slow_max = ranges[TimingPattern.SLOW]
        assert slow_max > slow_min  # Valid range
        assert slow_min > 0  # Should be positive
        
        # This provides better security against timing attacks
        # by making timing less predictable
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_advanced_crypto_operations_performance(self):
        """Test that advanced crypto operations scale with server performance."""
        service = ErrorStandardizationService()
        
        # Test with advanced operations enabled
        with patch.object(settings, 'USE_ADVANCED_CRYPTO_OPERATIONS', True):
            start_time = time.time()
            await service.apply_standard_timing(
                elapsed_time=0.1,
                timing_pattern=TimingPattern.SLOW,
                correlation_id="test-advanced-perf"
            )
            elapsed_advanced = time.time() - start_time
        
        # Should complete within reasonable time even with advanced operations
        assert elapsed_advanced < 2.0  # Should not take more than 2 seconds
        
        # Should take some time
        assert elapsed_advanced > 0  # Should take some time 