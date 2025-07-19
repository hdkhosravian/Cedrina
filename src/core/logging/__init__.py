"""Logging configuration module for comprehensive logging system.

This module configures the application's complete logging system including:
- Structured console/JSON logging via structlog
- File-based logging with rotation and retention
- Security event logging integration
- Performance metrics logging
- Audit trail management

The logging system provides:
- Development-friendly console output
- Production-ready JSON structured logs
- Automated file rotation and cleanup
- Security-compliant data masking
- Performance monitoring integration
- Comprehensive audit trails
"""

import os
from pathlib import Path
from typing import Optional

import structlog
from structlog.types import Processor

from src.core.config.settings import settings
from .file_logging_service import (
    FileLoggingService,
    FileLoggingConfig,
    LogLevel,
    LogRotationConfig,
    LogRetentionConfig,
)


def configure_logging(
    log_level: str = "INFO", 
    json_logs: bool = False,
    enable_file_logging: bool = True,
    log_directory: Optional[Path] = None
):
    """Configures the application's comprehensive logging system.

    This function sets up both console and file logging with:
    1. ISO format timestamps
    2. Log level inclusion
    3. JSON formatting for production (when LOG_JSON=True)
    4. Console formatting for development
    5. File-based logging with rotation
    6. Security event integration
    7. Performance metrics logging
    8. Audit trail management

    Args:
        log_level: Minimum log level to record
        json_logs: Whether to use JSON format for console output
        enable_file_logging: Whether to enable file-based logging
        log_directory: Custom log directory path

    Returns:
        FileLoggingService: Configured file logging service instance
    """
    # Configure structlog for console/memory logging
    processors = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        (
            structlog.processors.JSONRenderer()
            if settings.LOG_JSON or json_logs
            else structlog.dev.ConsoleRenderer()
        ),
    ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure file logging if enabled
    file_logging_service = None
    if enable_file_logging:
        # Determine log directory from settings
        if log_directory is None:
            log_directory = Path(getattr(settings, 'LOG_DIRECTORY', './logs'))
        
        # Convert log level string to enum
        log_level_enum = LogLevel.INFO
        try:
            log_level_enum = LogLevel(log_level.lower())
        except ValueError:
            log_level_enum = LogLevel.INFO

        # Create file logging configuration using environment settings
        file_config = FileLoggingConfig(
            log_directory=log_directory,
            enable_file_logging=True,
            log_level=log_level_enum,
            enable_json_format=True,
            rotation_config=LogRotationConfig(
                max_size_mb=float(getattr(settings, 'LOG_MAX_SIZE_MB', 100)),
                max_files=int(getattr(settings, 'LOG_MAX_FILES', 10)),
                rotate_on_startup=getattr(settings, 'LOG_ROTATE_ON_STARTUP', False)
            ),
            retention_config=LogRetentionConfig(
                max_age_days=int(getattr(settings, 'LOG_MAX_AGE_DAYS', 30)),
                max_total_size_gb=float(getattr(settings, 'LOG_MAX_TOTAL_SIZE_GB', 10)),
                cleanup_interval_hours=int(getattr(settings, 'LOG_CLEANUP_INTERVAL_HOURS', 24))
            )
        )

        # Initialize file logging service
        try:
            file_logging_service = FileLoggingService(config=file_config)
            
            # Log successful initialization
            file_logging_service.log_application_event(
                level=LogLevel.INFO,
                message="File logging service initialized successfully",
                log_directory=str(log_directory),
                config={
                    "max_size_mb": file_config.rotation_config.max_size_mb,
                    "max_files": file_config.rotation_config.max_files,
                    "max_age_days": file_config.retention_config.max_age_days,
                    "json_format": file_config.enable_json_format
                }
            )
            
        except Exception as e:
            # Log error but don't fail application startup
            logger = structlog.get_logger(__name__)
            logger.error(
                "Failed to initialize file logging service",
                error=str(e),
                log_directory=str(log_directory)
            )
            file_logging_service = None

    return file_logging_service


def get_logger(name: str = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance.
    
    Args:
        name: Logger name (optional)
        
    Returns:
        BoundLogger: Configured structlog logger
    """
    return structlog.get_logger(name)


def setup_production_logging() -> FileLoggingService:
    """Set up production-grade logging configuration.
    
    Returns:
        FileLoggingService: Configured file logging service
    """
    return configure_logging(
        log_level="INFO",
        json_logs=True,
        enable_file_logging=True,
        log_directory=Path("/var/log/cedrina")
    )


def setup_development_logging() -> Optional[FileLoggingService]:
    """Set up development-friendly logging configuration.
    
    Returns:
        FileLoggingService: Configured file logging service (or None if disabled)
    """
    return configure_logging(
        log_level="DEBUG",
        json_logs=False,
        enable_file_logging=True,
        log_directory=Path("./logs")
    )


# Initialize logging system based on environment settings
file_logging_service = configure_logging(
    log_level=getattr(settings, 'LOG_LEVEL', 'INFO'),
    json_logs=getattr(settings, 'LOG_JSON', False),
    enable_file_logging=getattr(settings, 'ENABLE_FILE_LOGGING', True)
)

# Create a singleton logger instance for the application
logger = structlog.get_logger()

# Export the file logging service for application use
__all__ = [
    'configure_logging',
    'get_logger', 
    'setup_production_logging',
    'setup_development_logging',
    'logger',
    'file_logging_service',
    'FileLoggingService',
    'FileLoggingConfig',
    'LogLevel',
    'LogRotationConfig',
    'LogRetentionConfig'
]
