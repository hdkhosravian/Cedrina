"""File-based logging service for comprehensive log management.

This module provides enterprise-grade file logging capabilities that complement
the existing structured logging system. It includes log rotation, retention,
performance monitoring, and seamless integration with security logging.

Key Features:
- Structured file logging with JSON format
- Automatic log rotation and retention policies
- Performance metrics collection and logging
- Security event integration
- Audit trail management
- Thread-safe concurrent logging
- Configurable log levels and formatting
- GDPR-compliant data handling
"""

import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union
from dataclasses import dataclass, field

import structlog
from pydantic import BaseModel, validator

from src.domain.security.logging_service import SecurityEvent


class LogLevel(Enum):
    """Log level enumeration for structured logging."""
    
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class LogRotationConfig:
    """Configuration for log file rotation policies."""
    
    max_size_mb: float = 100.0  # Maximum size before rotation
    max_files: int = 10         # Maximum number of rotated files to keep
    rotate_on_startup: bool = False  # Whether to rotate logs on service startup
    
    def __post_init__(self):
        """Validate rotation configuration values."""
        if self.max_size_mb <= 0:
            raise ValueError("max_size_mb must be positive")
        if self.max_files <= 0:
            raise ValueError("max_files must be positive")


@dataclass
class LogRetentionConfig:
    """Configuration for log retention policies."""
    
    max_age_days: int = 30      # Maximum age in days before deletion
    max_total_size_gb: float = 10.0  # Maximum total size across all logs
    cleanup_interval_hours: int = 24  # How often to run cleanup
    
    def __post_init__(self):
        """Validate retention configuration values."""
        if self.max_age_days <= 0:
            raise ValueError("max_age_days must be positive")
        if self.max_total_size_gb <= 0:
            raise ValueError("max_total_size_gb must be positive")
        if self.cleanup_interval_hours <= 0:
            raise ValueError("cleanup_interval_hours must be positive")


@dataclass
class PerformanceMetrics:
    """Performance metrics data structure for monitoring and logging."""
    
    # Request identification
    endpoint: str
    method: str
    correlation_id: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Performance data
    response_time_ms: float = 0.0
    status_code: int = 200
    request_size_bytes: Optional[int] = None
    response_size_bytes: Optional[int] = None
    
    # Database metrics
    database_query_count: int = 0
    database_query_time_ms: float = 0.0
    
    # Cache metrics
    cache_hits: int = 0
    cache_misses: int = 0
    
    # System metrics
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    
    def add_database_query(self, query_time_ms: float) -> None:
        """Add a database query to the metrics."""
        self.database_query_count += 1
        self.database_query_time_ms += query_time_ms
    
    def add_cache_hit(self) -> None:
        """Record a cache hit."""
        self.cache_hits += 1
    
    def add_cache_miss(self) -> None:
        """Record a cache miss."""
        self.cache_misses += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for JSON serialization."""
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
            "response_time_ms": self.response_time_ms,
            "status_code": self.status_code,
            "request_size_bytes": self.request_size_bytes,
            "response_size_bytes": self.response_size_bytes,
            "database_query_count": self.database_query_count,
            "database_query_time_ms": self.database_query_time_ms,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_usage_percent": self.cpu_usage_percent,
        }


@dataclass
class FileLoggingConfig:
    """Configuration for file-based logging system."""
    
    log_directory: Path
    enable_file_logging: bool = True
    log_level: LogLevel = LogLevel.INFO
    enable_json_format: bool = True
    rotation_config: LogRotationConfig = field(default_factory=LogRotationConfig)
    retention_config: LogRetentionConfig = field(default_factory=LogRetentionConfig)
    
    def __post_init__(self):
        """Convert string path to Path object if needed."""
        if isinstance(self.log_directory, str):
            self.log_directory = Path(self.log_directory)


class PerformanceContext:
    """Context manager for automatic performance measurement."""
    
    def __init__(self, metrics: PerformanceMetrics, file_logging_service: 'FileLoggingService'):
        self.metrics = metrics
        self.file_logging_service = file_logging_service
        self.start_time = None
    
    def __enter__(self) -> PerformanceMetrics:
        """Start performance measurement."""
        self.start_time = time.time()
        return self.metrics
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End measurement and log results."""
        if self.start_time is not None:
            elapsed_ms = (time.time() - self.start_time) * 1000
            self.metrics.response_time_ms = elapsed_ms
            
            if exc_type is not None:
                self.metrics.status_code = 500  # Internal server error
            
            self.file_logging_service.log_performance_metrics(self.metrics)


class FileLoggingService:
    """Enterprise-grade file logging service with rotation and retention."""
    
    # Log category directories
    LOG_CATEGORIES = {
        "application": "application",
        "security": "security", 
        "performance": "performance",
        "audit": "audit",
        "error": "error"
    }
    
    def __init__(self, config: FileLoggingConfig):
        """Initialize file logging service with configuration.
        
        Args:
            config: File logging configuration
            
        Raises:
            PermissionError: If log directory cannot be created
            ValueError: If configuration is invalid
        """
        self.config = config
        self._lock = threading.RLock()  # For thread safety
        self._last_cleanup = time.time()
        
        # Initialize logger
        self._logger = structlog.get_logger(__name__)
        
        if self.config.enable_file_logging:
            self._setup_log_directories()
            self._setup_file_handlers()
            
            if self.config.rotation_config.rotate_on_startup:
                self._rotate_logs_if_needed()
    
    def _setup_log_directories(self) -> None:
        """Create log directory structure if it doesn't exist.
        
        Raises:
            PermissionError: If directories cannot be created
        """
        try:
            # Create main log directory
            self.config.log_directory.mkdir(parents=True, exist_ok=True)
            
            # Create category subdirectories
            for category in self.LOG_CATEGORIES.values():
                category_dir = self.config.log_directory / category
                category_dir.mkdir(parents=True, exist_ok=True)
                
        except PermissionError as e:
            self._logger.error("Failed to create log directories", error=str(e))
            raise
    
    def _setup_file_handlers(self) -> None:
        """Set up file handlers for different log categories."""
        # File handlers are created on-demand when logging occurs
        # This avoids creating empty log files
        pass
    
    def _get_log_file_path(self, category: str) -> Path:
        """Get the current log file path for a category.
        
        Args:
            category: Log category (application, security, etc.)
            
        Returns:
            Path: Path to the current log file
        """
        category_dir = self.config.log_directory / self.LOG_CATEGORIES[category]
        return category_dir / f"{category}.log"
    
    def _write_log_entry(self, category: str, log_data: Dict[str, Any]) -> None:
        """Write a log entry to the appropriate file.
        
        Args:
            category: Log category
            log_data: Log data to write
        """
        if not self.config.enable_file_logging:
            return
        
        with self._lock:
            log_file = self._get_log_file_path(category)
            
            # Check if rotation is needed
            self._rotate_logs_if_needed(log_file)
            
            # Write log entry
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    if self.config.enable_json_format:
                        json.dump(log_data, f, ensure_ascii=False, default=str)
                        f.write('\n')
                    else:
                        # Simple text format
                        timestamp = log_data.get('timestamp', datetime.now(timezone.utc).isoformat())
                        level = log_data.get('level', 'INFO').upper()
                        message = log_data.get('message', '')
                        f.write(f"{timestamp} - {level} - {message}\n")
                        
            except OSError as e:
                self._logger.error("Failed to write log entry", error=str(e), category=category)
            
            # Cleanup old logs if needed
            self._cleanup_if_needed()
    
    def _should_log(self, level: LogLevel) -> bool:
        """Check if a log level should be recorded based on configuration.
        
        Args:
            level: Log level to check
            
        Returns:
            bool: True if level should be logged
        """
        level_order = {
            LogLevel.DEBUG: 0,
            LogLevel.INFO: 1,
            LogLevel.WARNING: 2,
            LogLevel.ERROR: 3,
            LogLevel.CRITICAL: 4
        }
        
        return level_order[level] >= level_order[self.config.log_level]
    
    def _rotate_logs_if_needed(self, log_file: Optional[Path] = None) -> None:
        """Rotate log files if they exceed size limits.
        
        Args:
            log_file: Specific file to check, or None to check all
        """
        max_size_bytes = self.config.rotation_config.max_size_mb * 1024 * 1024
        
        if log_file:
            files_to_check = [log_file]
        else:
            files_to_check = [
                self._get_log_file_path(category) 
                for category in self.LOG_CATEGORIES.keys()
            ]
        
        for file_path in files_to_check:
            if file_path.exists() and file_path.stat().st_size > max_size_bytes:
                self._rotate_log_file(file_path)
    
    def _rotate_log_file(self, log_file: Path) -> None:
        """Rotate a specific log file.
        
        Args:
            log_file: Path to the log file to rotate
        """
        try:
            # Shift existing rotated files
            for i in range(self.config.rotation_config.max_files - 1, 0, -1):
                old_file = log_file.with_suffix(f".log.{i}")
                new_file = log_file.with_suffix(f".log.{i + 1}")
                
                if old_file.exists():
                    if new_file.exists():
                        new_file.unlink()  # Remove oldest file
                    old_file.rename(new_file)
            
            # Rotate current file to .1
            if log_file.exists():
                rotated_file = log_file.with_suffix(".log.1")
                if rotated_file.exists():
                    rotated_file.unlink()
                log_file.rename(rotated_file)
                
        except OSError as e:
            self._logger.error("Failed to rotate log file", file=str(log_file), error=str(e))
    
    def _cleanup_if_needed(self) -> None:
        """Cleanup old logs if cleanup interval has passed."""
        current_time = time.time()
        cleanup_interval_seconds = self.config.retention_config.cleanup_interval_hours * 3600
        
        if current_time - self._last_cleanup > cleanup_interval_seconds:
            self._cleanup_old_logs()
            self._last_cleanup = current_time
    
    def _cleanup_old_logs(self) -> None:
        """Remove old log files based on retention policy."""
        cutoff_time = time.time() - (self.config.retention_config.max_age_days * 24 * 3600)
        max_size_bytes = self.config.retention_config.max_total_size_gb * 1024 * 1024 * 1024
        
        # Find all log files
        all_log_files = []
        for category_dir in self.config.log_directory.iterdir():
            if category_dir.is_dir():
                all_log_files.extend(category_dir.glob("*.log*"))
        
        # Remove files older than retention period
        for log_file in all_log_files:
            try:
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    self._logger.info("Removed old log file", file=str(log_file))
            except OSError as e:
                self._logger.error("Failed to remove old log file", file=str(log_file), error=str(e))
        
        # Check total size and remove oldest files if needed
        remaining_files = [f for f in all_log_files if f.exists()]
        total_size = sum(f.stat().st_size for f in remaining_files)
        
        if total_size > max_size_bytes:
            # Sort by modification time (oldest first)
            remaining_files.sort(key=lambda f: f.stat().st_mtime)
            
            for log_file in remaining_files:
                try:
                    file_size = log_file.stat().st_size
                    log_file.unlink()
                    total_size -= file_size
                    self._logger.info("Removed log file for size limit", file=str(log_file))
                    
                    if total_size <= max_size_bytes:
                        break
                except OSError as e:
                    self._logger.error("Failed to remove log file", file=str(log_file), error=str(e))
    
    def log_application_event(
        self,
        level: LogLevel,
        message: str,
        **kwargs: Any
    ) -> None:
        """Log an application event to the application log file.
        
        Args:
            level: Log level
            message: Log message
            **kwargs: Additional context data
        """
        if not self._should_log(level):
            return
        
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.value,
            "message": message,
            "category": "application",
            **kwargs
        }
        
        self._write_log_entry("application", log_data)
    
    def log_security_event(self, security_event: SecurityEvent) -> None:
        """Log a security event to the security log file.
        
        Args:
            security_event: Security event to log
        """
        log_data = {
            "timestamp": security_event.timestamp.isoformat(),
            "event_id": security_event.event_id,
            "event_type": security_event.event_type,
            "category": (security_event.level.value if hasattr(security_event.level, 'value') else str(security_event.level)).upper(),
            "description": security_event.description,
            "correlation_id": security_event.correlation_id,
            "user_context": security_event.user_context,
            "request_context": security_event.request_context,
            "security_context": security_event.security_context,
            "risk_score": security_event.risk_score,
            "threat_indicators": security_event.threat_indicators,
            "integrity_hash": security_event.integrity_hash,
            "audit_trail": security_event.audit_trail
        }
        
        self._write_log_entry("security", log_data)
    
    def log_performance_metrics(self, metrics: PerformanceMetrics) -> None:
        """Log performance metrics to the performance log file.
        
        Args:
            metrics: Performance metrics to log
        """
        log_data = metrics.to_dict()
        log_data["category"] = "performance"
        
        self._write_log_entry("performance", log_data)
    
    def log_audit_event(self, **kwargs: Any) -> None:
        """Log an audit event to the audit log file.
        
        Args:
            **kwargs: Audit event data
        """
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "audit",
            **kwargs
        }
        
        self._write_log_entry("audit", log_data)
    
    def log_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        **kwargs: Any
    ) -> None:
        """Log an error to the error log file.
        
        Args:
            error: Exception that occurred
            context: Additional context information
            **kwargs: Additional data
        """
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": "error",
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context or {},
            "category": "error",
            **kwargs
        }
        
        self._write_log_entry("error", log_data)
    
    @contextmanager
    def measure_performance(
        self,
        endpoint: str,
        method: str,
        correlation_id: Optional[str] = None
    ) -> Generator[PerformanceMetrics, None, None]:
        """Context manager for measuring and logging performance metrics.
        
        Args:
            endpoint: API endpoint being measured
            method: HTTP method
            correlation_id: Request correlation ID
            
        Yields:
            PerformanceMetrics: Metrics object for adding additional data
        """
        metrics = PerformanceMetrics(
            endpoint=endpoint,
            method=method,
            correlation_id=correlation_id
        )
        
        with PerformanceContext(metrics, self):
            yield metrics
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get statistics about the current log files.
        
        Returns:
            Dict: Log file statistics
        """
        stats = {
            "categories": {},
            "total_files": 0,
            "total_size_mb": 0.0
        }
        
        for category in self.LOG_CATEGORIES.keys():
            category_dir = self.config.log_directory / self.LOG_CATEGORIES[category]
            if category_dir.exists():
                log_files = list(category_dir.glob("*.log*"))
                total_size = sum(f.stat().st_size for f in log_files if f.exists())
                
                stats["categories"][category] = {
                    "file_count": len(log_files),
                    "size_mb": total_size / (1024 * 1024),
                    "current_file": str(self._get_log_file_path(category))
                }
                
                stats["total_files"] += len(log_files)
                stats["total_size_mb"] += total_size / (1024 * 1024)
        
        return stats