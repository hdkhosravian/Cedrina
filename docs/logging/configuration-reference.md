# Cedrina Logging Configuration Reference

## Overview

This document provides a comprehensive reference for all logging configuration options available in the Cedrina file logging system. The system uses environment variables for configuration and integrates seamlessly with the existing environment file structure.

## Environment Variables Reference

### Core Logging Configuration

#### `ENABLE_FILE_LOGGING`
- **Type**: Boolean (`true`/`false`)
- **Default**: `true`
- **Description**: Master switch to enable or disable file-based logging
- **Example**: `ENABLE_FILE_LOGGING=true`
- **Notes**: When disabled, only console logging is available

#### `LOG_DIRECTORY`
- **Type**: String (Path)
- **Default**: `./logs`
- **Description**: Directory where log files will be stored
- **Examples**: 
  - Development: `LOG_DIRECTORY=./logs`
  - Production: `LOG_DIRECTORY=/var/log/cedrina`
- **Notes**: Directory must be writable by the application user

#### `LOG_LEVEL`
- **Type**: String (Enum)
- **Default**: `INFO`
- **Valid Values**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- **Description**: Minimum log level to record
- **Example**: `LOG_LEVEL=INFO`
- **Notes**: Lower levels include all higher levels

#### `LOG_JSON`
- **Type**: Boolean (`true`/`false`)
- **Default**: `true`
- **Description**: Enable JSON format for console output
- **Example**: `LOG_JSON=true`
- **Notes**: File logging always uses JSON format

### Log Rotation Configuration

#### `LOG_MAX_SIZE_MB`
- **Type**: Float
- **Default**: `100.0`
- **Unit**: Megabytes (MB)
- **Description**: Maximum file size before rotation
- **Examples**:
  - Development: `LOG_MAX_SIZE_MB=50`
  - Production: `LOG_MAX_SIZE_MB=500`
- **Range**: `1.0` to `10000.0`

#### `LOG_MAX_FILES`
- **Type**: Integer
- **Default**: `10`
- **Description**: Maximum number of rotated files to keep per category
- **Examples**:
  - Development: `LOG_MAX_FILES=5`
  - Production: `LOG_MAX_FILES=30`
- **Range**: `1` to `1000`

#### `LOG_ROTATE_ON_STARTUP`
- **Type**: Boolean (`true`/`false`)
- **Default**: `false`
- **Description**: Whether to rotate logs when the application starts
- **Example**: `LOG_ROTATE_ON_STARTUP=false`
- **Notes**: Useful for ensuring clean startup logs

### Log Retention Configuration

#### `LOG_MAX_AGE_DAYS`
- **Type**: Integer
- **Default**: `30`
- **Unit**: Days
- **Description**: Maximum age of log files before deletion
- **Examples**:
  - Development: `LOG_MAX_AGE_DAYS=7`
  - Staging: `LOG_MAX_AGE_DAYS=30`
  - Production: `LOG_MAX_AGE_DAYS=90`
- **Range**: `1` to `3650` (10 years)

#### `LOG_MAX_TOTAL_SIZE_GB`
- **Type**: Float
- **Default**: `10.0`
- **Unit**: Gigabytes (GB)
- **Description**: Maximum total size of all log files
- **Examples**:
  - Development: `LOG_MAX_TOTAL_SIZE_GB=2`
  - Production: `LOG_MAX_TOTAL_SIZE_GB=20`
- **Range**: `0.1` to `1000.0`

#### `LOG_CLEANUP_INTERVAL_HOURS`
- **Type**: Integer
- **Default**: `24`
- **Unit**: Hours
- **Description**: How often to run cleanup operations
- **Examples**:
  - Development: `LOG_CLEANUP_INTERVAL_HOURS=24`
  - Production: `LOG_CLEANUP_INTERVAL_HOURS=6`
- **Range**: `1` to `168` (1 week)

### Security Configuration

#### `AUDIT_INTEGRITY_KEY`
- **Type**: String
- **Default**: `""` (empty)
- **Description**: Key for HMAC-based audit log integrity protection
- **Example**: `AUDIT_INTEGRITY_KEY=your-secure-32-character-key-here`
- **Requirements**: 
  - Minimum 32 characters
  - Required for production environments
  - Should be cryptographically secure
- **Notes**: Used for audit trail tamper detection

## Environment-Specific Configurations

### Development Environment (.env.development)

**Purpose**: Local development with detailed logging and shorter retention

```bash
# Basic Configuration
ENABLE_FILE_LOGGING=true
LOG_DIRECTORY=./logs
LOG_LEVEL=DEBUG
LOG_JSON=false

# Rotation Settings (Smaller files, frequent rotation)
LOG_MAX_SIZE_MB=50
LOG_MAX_FILES=5
LOG_ROTATE_ON_STARTUP=false

# Retention Settings (Short retention for local testing)
LOG_MAX_AGE_DAYS=7
LOG_MAX_TOTAL_SIZE_GB=2
LOG_CLEANUP_INTERVAL_HOURS=24

# Security (Optional for development)
# AUDIT_INTEGRITY_KEY=""
```

**Characteristics**:
- Verbose logging with DEBUG level
- Console-friendly non-JSON output
- Quick rotation for testing
- Short retention to save disk space
- No integrity protection (optional)

### Staging Environment (.env.staging)

**Purpose**: Pre-production testing with production-like logging

```bash
# Basic Configuration
ENABLE_FILE_LOGGING=true
LOG_DIRECTORY=/var/log/cedrina
LOG_LEVEL=INFO
LOG_JSON=true

# Rotation Settings (Medium files, balanced rotation)
LOG_MAX_SIZE_MB=200
LOG_MAX_FILES=15
LOG_ROTATE_ON_STARTUP=false

# Retention Settings (Medium retention for testing cycles)
LOG_MAX_AGE_DAYS=30
LOG_MAX_TOTAL_SIZE_GB=5
LOG_CLEANUP_INTERVAL_HOURS=12

# Security (Recommended for staging)
AUDIT_INTEGRITY_KEY=your-audit-integrity-key-here-replace-with-secure-value
```

**Characteristics**:
- Production-like JSON logging
- Balanced rotation and retention
- Integrity protection enabled
- Moderate cleanup frequency

### Production Environment (.env.production)

**Purpose**: Production deployment with maximum reliability and compliance

```bash
# Basic Configuration
ENABLE_FILE_LOGGING=true
LOG_DIRECTORY=/var/log/cedrina
LOG_LEVEL=INFO
LOG_JSON=true

# Rotation Settings (Large files, extensive history)
LOG_MAX_SIZE_MB=500
LOG_MAX_FILES=30
LOG_ROTATE_ON_STARTUP=false

# Retention Settings (Long retention for compliance)
LOG_MAX_AGE_DAYS=90
LOG_MAX_TOTAL_SIZE_GB=20
LOG_CLEANUP_INTERVAL_HOURS=6

# Security (Required for production)
AUDIT_INTEGRITY_KEY=your-audit-integrity-key-here-replace-with-secure-value
```

**Characteristics**:
- Structured JSON logging
- Large files with extensive rotation history
- Long retention for compliance requirements
- Frequent cleanup to manage disk space
- Mandatory integrity protection

## Configuration Validation

### Automatic Validation

The system automatically validates configuration values:

```python
class FileLoggingConfig:
    """Configuration with built-in validation."""
    
    def __post_init__(self):
        # Validate log directory
        if not self.log_directory.exists():
            self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Validate rotation settings
        if self.rotation_config.max_size_mb <= 0:
            raise ValueError("max_size_mb must be positive")
        
        if self.rotation_config.max_files <= 0:
            raise ValueError("max_files must be positive")
        
        # Validate retention settings
        if self.retention_config.max_age_days <= 0:
            raise ValueError("max_age_days must be positive")
        
        if self.retention_config.max_total_size_gb <= 0:
            raise ValueError("max_total_size_gb must be positive")
```

### Common Validation Errors

1. **Invalid LOG_DIRECTORY**: Directory doesn't exist or is not writable
2. **Invalid LOG_LEVEL**: Not one of the valid log levels
3. **Invalid Numeric Values**: Negative or zero values for size/count settings
4. **Missing AUDIT_INTEGRITY_KEY**: Required in production but not set

### Validation Commands

```bash
# Test configuration loading
python -c "
from src.core.config.settings import settings
print('✓ Settings loaded successfully')
print(f'  LOG_DIRECTORY: {settings.LOG_DIRECTORY}')
print(f'  ENABLE_FILE_LOGGING: {settings.ENABLE_FILE_LOGGING}')
print(f'  LOG_LEVEL: {settings.LOG_LEVEL}')
"

# Test logging service initialization
python -c "
from src.core.logging import file_logging_service
if file_logging_service:
    print('✓ File logging service initialized')
    print('Configuration:')
    config = file_logging_service.config
    print(f'  Directory: {config.log_directory}')
    print(f'  Max Size: {config.rotation_config.max_size_mb}MB')
    print(f'  Max Files: {config.rotation_config.max_files}')
    print(f'  Max Age: {config.retention_config.max_age_days} days')
else:
    print('✗ File logging service not initialized')
"
```

## Advanced Configuration Patterns

### High-Volume Logging

For applications with high logging volume:

```bash
# Larger files, more frequent rotation
LOG_MAX_SIZE_MB=1000
LOG_MAX_FILES=50
LOG_CLEANUP_INTERVAL_HOURS=2

# Shorter retention with larger total size
LOG_MAX_AGE_DAYS=14
LOG_MAX_TOTAL_SIZE_GB=100
```

### Compliance-Heavy Environments

For environments with strict compliance requirements:

```bash
# Longer retention periods
LOG_MAX_AGE_DAYS=2555  # 7 years
LOG_MAX_TOTAL_SIZE_GB=500

# More frequent integrity checks
LOG_CLEANUP_INTERVAL_HOURS=1

# Mandatory integrity protection
AUDIT_INTEGRITY_KEY=64-character-cryptographically-secure-key-for-compliance
```

### Resource-Constrained Environments

For environments with limited disk space:

```bash
# Smaller files, aggressive cleanup
LOG_MAX_SIZE_MB=10
LOG_MAX_FILES=3
LOG_MAX_AGE_DAYS=1
LOG_MAX_TOTAL_SIZE_GB=0.5
LOG_CLEANUP_INTERVAL_HOURS=6
```

### Development Debug Mode

For intensive debugging sessions:

```bash
# Maximum verbosity
LOG_LEVEL=DEBUG
LOG_JSON=false  # Human-readable console output

# Rapid rotation for testing
LOG_MAX_SIZE_MB=5
LOG_MAX_FILES=20
LOG_ROTATE_ON_STARTUP=true

# Very short retention
LOG_MAX_AGE_DAYS=1
LOG_CLEANUP_INTERVAL_HOURS=1
```

## Configuration Best Practices

### Security Considerations

1. **Audit Integrity Key**:
   - Use cryptographically secure random strings
   - Minimum 32 characters, recommend 64
   - Store securely (environment variables, secrets management)
   - Rotate periodically in production

2. **File Permissions**:
   - Log directory: 755 (rwxr-xr-x)
   - Log files: 644 (rw-r--r--)
   - Avoid world-writable permissions

3. **Sensitive Data**:
   - All sensitive data is automatically masked
   - Configure additional masking if needed
   - Regular audit of log content for data leaks

### Performance Considerations

1. **Disk I/O Optimization**:
   - Use SSD storage for log directories when possible
   - Consider separate disk/partition for logs
   - Monitor disk I/O during peak logging

2. **File Size Balance**:
   - Larger files: Fewer I/O operations, slower searches
   - Smaller files: More I/O operations, faster searches
   - Recommended: 100-500MB for balanced performance

3. **Cleanup Frequency**:
   - More frequent: Better disk space management, higher CPU usage
   - Less frequent: Lower CPU usage, potential disk space issues
   - Recommended: 6-24 hours based on volume

### Monitoring Configuration

Set up monitoring for configuration-related metrics:

```bash
# Disk usage monitoring
df -h /var/log/cedrina

# Log file count and sizes
find /var/log/cedrina -name "*.log*" | wc -l
du -sh /var/log/cedrina/*

# Configuration verification
python -c "
from src.core.logging import file_logging_service
if file_logging_service:
    stats = file_logging_service.get_log_statistics()
    config = file_logging_service.config
    
    print('Current Statistics:')
    print(f'  Total files: {stats[\"total_files\"]}')
    print(f'  Total size: {stats[\"total_size_mb\"]:.1f}MB')
    
    print('Configuration Limits:')
    print(f'  Max size per file: {config.rotation_config.max_size_mb}MB')
    print(f'  Max files per category: {config.rotation_config.max_files}')
    print(f'  Max total size: {config.retention_config.max_total_size_gb}GB')
    print(f'  Max age: {config.retention_config.max_age_days} days')
    
    # Check if approaching limits
    if stats['total_size_mb'] > (config.retention_config.max_total_size_gb * 1000 * 0.8):
        print('⚠️  Warning: Approaching total size limit')
    
    if stats['total_files'] > (config.rotation_config.max_files * 5 * 0.8):
        print('⚠️  Warning: Approaching file count limit')
"
```

## Troubleshooting Configuration Issues

### Common Configuration Problems

1. **Logs Not Created**:
   ```bash
   # Check if file logging is enabled
   echo $ENABLE_FILE_LOGGING
   
   # Verify directory permissions
   ls -la $(echo $LOG_DIRECTORY)
   
   # Test directory creation
   mkdir -p $LOG_DIRECTORY && echo "Directory OK" || echo "Directory FAILED"
   ```

2. **Excessive Disk Usage**:
   ```bash
   # Check current usage
   du -sh $LOG_DIRECTORY
   
   # Verify cleanup settings
   echo "Max total size: ${LOG_MAX_TOTAL_SIZE_GB}GB"
   echo "Max age: ${LOG_MAX_AGE_DAYS} days"
   echo "Cleanup interval: ${LOG_CLEANUP_INTERVAL_HOURS} hours"
   
   # Manual cleanup
   find $LOG_DIRECTORY -name "*.log.*" -mtime +$LOG_MAX_AGE_DAYS -delete
   ```

3. **Performance Issues**:
   ```bash
   # Check log levels
   echo "Current log level: $LOG_LEVEL"
   
   # Monitor I/O
   iostat -x 1 5
   
   # Check file sizes
   find $LOG_DIRECTORY -name "*.log" -exec ls -lh {} \;
   ```

### Configuration Recovery

If configuration becomes corrupted or problematic:

```bash
# Reset to minimal configuration
export ENABLE_FILE_LOGGING=true
export LOG_DIRECTORY=./logs
export LOG_LEVEL=INFO
export LOG_JSON=true
export LOG_MAX_SIZE_MB=100
export LOG_MAX_FILES=10
export LOG_MAX_AGE_DAYS=30
export LOG_MAX_TOTAL_SIZE_GB=10
export LOG_CLEANUP_INTERVAL_HOURS=24

# Test with minimal config
python -c "
from src.core.logging import file_logging_service, LogLevel
if file_logging_service:
    file_logging_service.log_application_event(
        level=LogLevel.INFO,
        message='Configuration test',
        test_recovery=True
    )
    print('✓ Recovery test successful')
else:
    print('✗ Recovery test failed')
"
```

This configuration reference provides comprehensive guidance for properly configuring the Cedrina file logging system across all environments and use cases.