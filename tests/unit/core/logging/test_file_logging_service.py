"""Tests for the file logging service.

This module provides comprehensive tests for the file-based logging service,
ensuring proper file handling, rotation, retention, and integration with
existing security logging systems.

Test Categories:
- File creation and writing
- Log rotation and retention
- Directory structure management
- Security integration
- Performance monitoring
- Error handling and resilience
"""

import json
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, Mock, patch

import pytest
import structlog

# Add project root to Python path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from src.core.logging.file_logging_service import (
    FileLoggingService,
    LogLevel,
    LogRotationConfig,
    LogRetentionConfig,
    PerformanceMetrics,
    FileLoggingConfig,
)

# Mock the SecurityEvent to avoid database dependencies
class MockSecurityEvent:
    """Mock SecurityEvent for testing without database dependencies."""
    
    def __init__(self, **kwargs):
        self.event_id = kwargs.get('event_id', str(uuid.uuid4()))
        self.timestamp = kwargs.get('timestamp', datetime.utcnow())
        self.event_type = kwargs.get('event_type', 'test_event')
        self.level = kwargs.get('level', MockSecurityEventLevel.HIGH)
        self.description = kwargs.get('description', 'Test event')
        self.correlation_id = kwargs.get('correlation_id')
        self.user_context = kwargs.get('user_context')
        self.request_context = kwargs.get('request_context')
        self.security_context = kwargs.get('security_context')
        self.risk_score = kwargs.get('risk_score', 0)
        self.threat_indicators = kwargs.get('threat_indicators', [])
        self.integrity_hash = kwargs.get('integrity_hash', 'test_hash')
        self.audit_trail = kwargs.get('audit_trail', {})

class MockSecurityEventLevel:
    """Mock SecurityEventLevel enum."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TestFileLoggingService:
    """Test suite for FileLoggingService following TDD principles."""

    @pytest.fixture
    def temp_log_dir(self) -> Path:
        """Create a temporary directory for test logs."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def basic_config(self, temp_log_dir: Path) -> FileLoggingConfig:
        """Create a basic file logging configuration for tests."""
        return FileLoggingConfig(
            log_directory=temp_log_dir,
            enable_file_logging=True,
            log_level=LogLevel.INFO,
            enable_json_format=True,
            rotation_config=LogRotationConfig(
                max_size_mb=10,
                max_files=5,
                rotate_on_startup=False
            ),
            retention_config=LogRetentionConfig(
                max_age_days=30,
                max_total_size_gb=1.0,
                cleanup_interval_hours=24
            )
        )

    @pytest.fixture
    def file_logging_service(self, basic_config: FileLoggingConfig) -> FileLoggingService:
        """Create a FileLoggingService instance for testing."""
        return FileLoggingService(config=basic_config)

    def test_service_initialization_creates_log_directory(self, temp_log_dir: Path):
        """Test that service initialization creates the log directory structure."""
        config = FileLoggingConfig(
            log_directory=temp_log_dir / "logs",
            enable_file_logging=True
        )
        
        service = FileLoggingService(config=config)
        
        # Verify directory structure is created
        assert (temp_log_dir / "logs").exists()
        assert (temp_log_dir / "logs" / "application").exists()
        assert (temp_log_dir / "logs" / "security").exists()
        assert (temp_log_dir / "logs" / "performance").exists()
        assert (temp_log_dir / "logs" / "audit").exists()
        assert (temp_log_dir / "logs" / "error").exists()

    def test_service_initialization_with_existing_directory(self, temp_log_dir: Path):
        """Test that service works with pre-existing log directories."""
        log_dir = temp_log_dir / "existing_logs"
        log_dir.mkdir(parents=True)
        
        config = FileLoggingConfig(
            log_directory=log_dir,
            enable_file_logging=True
        )
        
        service = FileLoggingService(config=config)
        
        # Should not raise exception and should create subdirectories
        assert log_dir.exists()
        assert (log_dir / "application").exists()

    def test_log_application_event_creates_structured_log_entry(self, file_logging_service: FileLoggingService):
        """Test that application events are logged with proper structure."""
        event_data = {
            "event_type": "user_registration",
            "user_id": 12345,
            "correlation_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"source": "registration_service"}
        }
        
        file_logging_service.log_application_event(
            level=LogLevel.INFO,
            message="User registration completed successfully",
            **event_data
        )
        
        # Verify log file was created
        app_log_file = file_logging_service._get_log_file_path("application")
        assert app_log_file.exists()
        
        # Verify log content structure
        with open(app_log_file, 'r') as f:
            log_content = f.read()
            log_entry = json.loads(log_content.strip())
            
        assert log_entry["level"] == "info"
        assert log_entry["message"] == "User registration completed successfully"
        assert log_entry["event_type"] == "user_registration"
        assert log_entry["user_id"] == 12345
        assert "timestamp" in log_entry
        assert "correlation_id" in log_entry

    def test_log_security_event_integration(self, file_logging_service: FileLoggingService):
        """Test that security events are properly logged to security log file."""
        security_event = MockSecurityEvent(
            event_type="authentication_failure",
            level=MockSecurityEventLevel.HIGH,
            description="Failed login attempt detected",
            user_context={"username_masked": "te***abc123"},
            risk_score=75,
            threat_indicators=["brute_force_pattern"]
        )
        
        file_logging_service.log_security_event(security_event)
        
        # Verify security log file was created
        security_log_file = file_logging_service._get_log_file_path("security")
        assert security_log_file.exists()
        
        # Verify security event structure
        with open(security_log_file, 'r') as f:
            log_content = f.read()
            log_entry = json.loads(log_content.strip())
            
        assert log_entry["event_type"] == "authentication_failure"
        assert log_entry["risk_score"] == 75
        assert log_entry["threat_indicators"] == ["brute_force_pattern"]
        assert log_entry["category"] == "HIGH"
        assert "integrity_hash" in log_entry

    def test_log_performance_metrics(self, file_logging_service: FileLoggingService):
        """Test that performance metrics are logged correctly."""
        metrics = PerformanceMetrics(
            endpoint="/api/v1/auth/login",
            method="POST",
            response_time_ms=125.5,
            status_code=200,
            request_size_bytes=256,
            response_size_bytes=512,
            database_query_count=3,
            database_query_time_ms=45.2,
            cache_hits=2,
            cache_misses=1,
            memory_usage_mb=128.5,
            cpu_usage_percent=15.2
        )
        
        file_logging_service.log_performance_metrics(metrics)
        
        # Verify performance log file was created
        perf_log_file = file_logging_service._get_log_file_path("performance")
        assert perf_log_file.exists()
        
        # Verify performance metrics structure
        with open(perf_log_file, 'r') as f:
            log_content = f.read()
            log_entry = json.loads(log_content.strip())
            
        assert log_entry["endpoint"] == "/api/v1/auth/login"
        assert log_entry["response_time_ms"] == 125.5
        assert log_entry["database_query_count"] == 3
        assert log_entry["memory_usage_mb"] == 128.5
        assert "timestamp" in log_entry

    def test_log_rotation_when_file_exceeds_size_limit(self, temp_log_dir: Path):
        """Test that log files are rotated when they exceed size limits."""
        config = FileLoggingConfig(
            log_directory=temp_log_dir,
            enable_file_logging=True,
            rotation_config=LogRotationConfig(
                max_size_mb=0.001,  # Very small size to trigger rotation
                max_files=3,
                rotate_on_startup=False
            )
        )
        
        service = FileLoggingService(config=config)
        
        # Generate multiple log entries to exceed size limit
        for i in range(100):
            service.log_application_event(
                level=LogLevel.INFO,
                message=f"Test log entry {i}" * 100,  # Make entries large
                iteration=i
            )
        
        # Verify rotation occurred
        app_log_dir = temp_log_dir / "application"
        log_files = list(app_log_dir.glob("*.log*"))
        
        # Should have current log file plus rotated files
        assert len(log_files) > 1
        assert any("application.log.1" in str(f) for f in log_files)

    def test_log_retention_removes_old_files(self, temp_log_dir: Path):
        """Test that old log files are removed based on retention policy."""
        config = FileLoggingConfig(
            log_directory=temp_log_dir,
            enable_file_logging=True,
            retention_config=LogRetentionConfig(
                max_age_days=1,  # Very short retention for testing
                max_total_size_gb=0.001,  # Very small size limit
                cleanup_interval_hours=0.001  # Immediate cleanup
            )
        )
        
        service = FileLoggingService(config=config)
        
        # Create some old log files manually
        app_log_dir = temp_log_dir / "application"
        old_file = app_log_dir / "old_application.log"
        old_file.write_text("old log content")
        
        # Set file modification time to past
        old_time = time.time() - (2 * 24 * 60 * 60)  # 2 days ago
        os.utime(old_file, (old_time, old_time))
        
        # Trigger cleanup
        service._cleanup_old_logs()
        
        # Verify old file was removed
        assert not old_file.exists()

    def test_log_file_path_generation(self, file_logging_service: FileLoggingService):
        """Test that log file paths are generated correctly."""
        app_path = file_logging_service._get_log_file_path("application")
        security_path = file_logging_service._get_log_file_path("security")
        
        assert "application/application.log" in str(app_path)
        assert "security/security.log" in str(security_path)
        assert app_path.parent.name == "application"
        assert security_path.parent.name == "security"

    def test_log_level_filtering(self, temp_log_dir: Path):
        """Test that log entries below configured level are filtered out."""
        config = FileLoggingConfig(
            log_directory=temp_log_dir,
            enable_file_logging=True,
            log_level=LogLevel.WARNING  # Only WARNING and above
        )
        
        service = FileLoggingService(config=config)
        
        # Log entries at different levels
        service.log_application_event(LogLevel.DEBUG, "Debug message")
        service.log_application_event(LogLevel.INFO, "Info message")
        service.log_application_event(LogLevel.WARNING, "Warning message")
        service.log_application_event(LogLevel.ERROR, "Error message")
        
        # Verify only WARNING and ERROR were logged
        app_log_file = service._get_log_file_path("application")
        with open(app_log_file, 'r') as f:
            log_content = f.read()
            
        assert "Debug message" not in log_content
        assert "Info message" not in log_content
        assert "Warning message" in log_content
        assert "Error message" in log_content

    def test_json_formatting_is_valid(self, file_logging_service: FileLoggingService):
        """Test that JSON log formatting produces valid JSON."""
        test_data = {
            "complex_data": {
                "nested": {"value": 123},
                "list": [1, 2, 3],
                "special_chars": "Test with üñíçødé"
            }
        }
        
        file_logging_service.log_application_event(
            level=LogLevel.INFO,
            message="Test JSON formatting",
            **test_data
        )
        
        # Verify JSON is valid
        app_log_file = file_logging_service._get_log_file_path("application")
        with open(app_log_file, 'r') as f:
            log_content = f.read()
            
        # Should not raise exception
        log_entry = json.loads(log_content.strip())
        assert log_entry["complex_data"]["nested"]["value"] == 123

    def test_error_handling_with_invalid_log_directory(self):
        """Test error handling when log directory cannot be created."""
        # Try to create log directory in a read-only location
        config = FileLoggingConfig(
            log_directory=Path("/root/invalid_logs"),  # Should fail on most systems
            enable_file_logging=True
        )
        
        with pytest.raises((PermissionError, OSError, FileNotFoundError)):
            FileLoggingService(config=config)

    def test_concurrent_logging_thread_safety(self, file_logging_service: FileLoggingService):
        """Test that concurrent logging operations are thread-safe."""
        import threading
        
        def log_worker(worker_id: int):
            for i in range(10):
                file_logging_service.log_application_event(
                    level=LogLevel.INFO,
                    message=f"Worker {worker_id} message {i}",
                    worker_id=worker_id,
                    message_id=i
                )
        
        # Create multiple threads
        threads = []
        for worker_id in range(5):
            thread = threading.Thread(target=log_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all messages were logged
        app_log_file = file_logging_service._get_log_file_path("application")
        with open(app_log_file, 'r') as f:
            log_lines = f.readlines()
            
        # Should have 50 log entries (5 workers * 10 messages each)
        assert len(log_lines) == 50

    def test_audit_trail_integration(self, file_logging_service: FileLoggingService):
        """Test that audit trail events are properly logged."""
        audit_event = {
            "audit_type": "policy_change",
            "actor_user_id": 123,
            "target_resource": "user_permissions",
            "action": "update",
            "before_state": {"role": "user"},
            "after_state": {"role": "admin"},
            "reason": "Promotion approved by manager",
            "approval_id": "APPR-001"
        }
        
        file_logging_service.log_audit_event(**audit_event)
        
        # Verify audit log file was created
        audit_log_file = file_logging_service._get_log_file_path("audit")
        assert audit_log_file.exists()
        
        # Verify audit event structure
        with open(audit_log_file, 'r') as f:
            log_content = f.read()
            log_entry = json.loads(log_content.strip())
            
        assert log_entry["audit_type"] == "policy_change"
        assert log_entry["actor_user_id"] == 123
        assert log_entry["before_state"]["role"] == "user"
        assert log_entry["after_state"]["role"] == "admin"

    def test_performance_metrics_calculation(self, file_logging_service: FileLoggingService):
        """Test that performance metrics are calculated and logged correctly."""
        # Test with context manager for automatic timing
        with file_logging_service.measure_performance("/api/v1/test", "GET") as metrics:
            # Simulate some work
            time.sleep(0.01)  # 10ms
            metrics.add_database_query(5.5)  # Add query time
            metrics.add_cache_hit()
            metrics.add_cache_miss()
        
        # Verify performance log was created
        perf_log_file = file_logging_service._get_log_file_path("performance")
        assert perf_log_file.exists()
        
        # Verify performance data
        with open(perf_log_file, 'r') as f:
            log_content = f.read()
            log_entry = json.loads(log_content.strip())
            
        assert log_entry["endpoint"] == "/api/v1/test"
        assert log_entry["method"] == "GET"
        assert log_entry["response_time_ms"] >= 10  # At least 10ms
        assert log_entry["database_query_time_ms"] == 5.5
        assert log_entry["cache_hits"] == 1
        assert log_entry["cache_misses"] == 1

    def test_disabled_file_logging(self, temp_log_dir: Path):
        """Test that file logging can be disabled via configuration."""
        config = FileLoggingConfig(
            log_directory=temp_log_dir,
            enable_file_logging=False  # Disabled
        )
        
        service = FileLoggingService(config=config)
        
        # Attempt to log
        service.log_application_event(
            level=LogLevel.INFO,
            message="This should not be written to file"
        )
        
        # Verify no log files were created
        log_files = list(temp_log_dir.rglob("*.log"))
        assert len(log_files) == 0

    def test_log_correlation_across_categories(self, file_logging_service: FileLoggingService):
        """Test that correlation IDs work across different log categories."""
        correlation_id = str(uuid.uuid4())
        
        # Log to different categories with same correlation ID
        file_logging_service.log_application_event(
            level=LogLevel.INFO,
            message="Starting user operation",
            correlation_id=correlation_id,
            operation="user_update"
        )
        
        security_event = MockSecurityEvent(
            event_type="user_modification",
            description="User profile updated",
            correlation_id=correlation_id
        )
        file_logging_service.log_security_event(security_event)
        
        metrics = PerformanceMetrics(
            endpoint="/api/v1/users/123",
            method="PUT",
            response_time_ms=85.3,
            correlation_id=correlation_id
        )
        file_logging_service.log_performance_metrics(metrics)
        
        # Verify correlation ID appears in all log files
        app_log_file = file_logging_service._get_log_file_path("application")
        security_log_file = file_logging_service._get_log_file_path("security")
        perf_log_file = file_logging_service._get_log_file_path("performance")
        
        for log_file in [app_log_file, security_log_file, perf_log_file]:
            with open(log_file, 'r') as f:
                content = f.read()
                assert correlation_id in content


class TestLogRotationConfig:
    """Test suite for log rotation configuration."""

    def test_log_rotation_config_validation(self):
        """Test that log rotation configuration validates inputs."""
        # Valid configuration
        config = LogRotationConfig(
            max_size_mb=100,
            max_files=10,
            rotate_on_startup=True
        )
        assert config.max_size_mb == 100
        assert config.max_files == 10
        assert config.rotate_on_startup is True

    def test_log_rotation_config_invalid_values(self):
        """Test that invalid rotation configuration values are rejected."""
        with pytest.raises(ValueError):
            LogRotationConfig(max_size_mb=-1)  # Negative size
            
        with pytest.raises(ValueError):
            LogRotationConfig(max_files=0)  # Zero files


class TestLogRetentionConfig:
    """Test suite for log retention configuration."""

    def test_log_retention_config_validation(self):
        """Test that log retention configuration validates inputs."""
        config = LogRetentionConfig(
            max_age_days=30,
            max_total_size_gb=5.0,
            cleanup_interval_hours=24
        )
        assert config.max_age_days == 30
        assert config.max_total_size_gb == 5.0
        assert config.cleanup_interval_hours == 24

    def test_log_retention_config_invalid_values(self):
        """Test that invalid retention configuration values are rejected."""
        with pytest.raises(ValueError):
            LogRetentionConfig(max_age_days=-1)  # Negative days
            
        with pytest.raises(ValueError):
            LogRetentionConfig(max_total_size_gb=-1.0)  # Negative size


class TestPerformanceMetrics:
    """Test suite for performance metrics data structure."""

    def test_performance_metrics_creation(self):
        """Test that performance metrics can be created with required fields."""
        metrics = PerformanceMetrics(
            endpoint="/api/v1/test",
            method="GET",
            response_time_ms=123.45
        )
        
        assert metrics.endpoint == "/api/v1/test"
        assert metrics.method == "GET"
        assert metrics.response_time_ms == 123.45
        assert metrics.status_code == 200  # Default value

    def test_performance_metrics_optional_fields(self):
        """Test that performance metrics work with optional fields."""
        metrics = PerformanceMetrics(
            endpoint="/api/v1/test",
            method="POST",
            response_time_ms=200.0,
            database_query_count=5,
            cache_hits=3,
            memory_usage_mb=256.5
        )
        
        assert metrics.database_query_count == 5
        assert metrics.cache_hits == 3
        assert metrics.memory_usage_mb == 256.5

    def test_performance_metrics_add_operations(self):
        """Test performance metrics helper methods."""
        metrics = PerformanceMetrics(
            endpoint="/api/v1/test",
            method="GET",
            response_time_ms=100.0
        )
        
        # Test adding database queries
        metrics.add_database_query(25.5)
        metrics.add_database_query(15.2)
        
        assert metrics.database_query_count == 2
        assert metrics.database_query_time_ms == 40.7
        
        # Test adding cache operations
        metrics.add_cache_hit()
        metrics.add_cache_hit()
        metrics.add_cache_miss()
        
        assert metrics.cache_hits == 2
        assert metrics.cache_misses == 1