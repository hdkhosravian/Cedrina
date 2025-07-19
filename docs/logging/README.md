# Cedrina Enhanced Logging System

## Overview

Cedrina's enhanced logging system provides comprehensive, production-ready logging capabilities that complement the existing security-focused logging infrastructure. The system offers structured JSON logging, automated file rotation, retention policies, and seamless integration with security audit trails.

## Architecture

The logging system consists of several key components:

- **Console Logging** - Structured logging via `structlog` for development and real-time monitoring
- **File Logging** - Persistent, categorized log files with rotation and retention
- **Security Integration** - Seamless integration with existing security event logging
- **Performance Monitoring** - Automated performance metrics collection
- **Audit Trails** - Compliance-ready audit logging for regulatory requirements

## Directory Structure

```
logs/
├── application/     # Application events and business logic
│   └── application.log
├── security/        # Security events and threat detection  
│   └── security.log
├── performance/     # API and system performance metrics
│   └── performance.log
├── audit/          # Compliance and regulatory audit trail
│   └── audit.log
└── error/          # Error handling and debugging
    └── error.log
```

## Configuration

### Environment Variables

Configure the logging system using these environment variables:

```bash
# File Logging Configuration
ENABLE_FILE_LOGGING=true          # Enable/disable file logging
LOG_DIRECTORY=./logs              # Log directory path
LOG_LEVEL=INFO                    # Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_JSON=true                     # Enable JSON format for console output

# Log Rotation Configuration  
LOG_MAX_SIZE_MB=100               # Maximum file size before rotation (MB)
LOG_MAX_FILES=10                  # Maximum number of rotated files to keep
LOG_ROTATE_ON_STARTUP=false       # Rotate logs on application startup

# Log Retention Configuration
LOG_MAX_AGE_DAYS=30               # Maximum age before deletion (days)
LOG_MAX_TOTAL_SIZE_GB=10          # Maximum total size across all logs (GB)
LOG_CLEANUP_INTERVAL_HOURS=24     # How often to run cleanup (hours)
```

### Development Configuration (.env.development)

```bash
ENABLE_FILE_LOGGING=true
LOG_DIRECTORY=./logs
LOG_LEVEL=DEBUG
LOG_JSON=false
LOG_MAX_SIZE_MB=50
LOG_MAX_FILES=5
LOG_MAX_AGE_DAYS=7
```

### Production Configuration (.env.production)

```bash
ENABLE_FILE_LOGGING=true
LOG_DIRECTORY=/var/log/cedrina
LOG_LEVEL=INFO
LOG_JSON=true
LOG_MAX_SIZE_MB=500
LOG_MAX_FILES=20
LOG_MAX_AGE_DAYS=90
LOG_MAX_TOTAL_SIZE_GB=50
```

## Usage Examples

### Basic Application Logging

```python
from src.core.logging import file_logging_service, LogLevel

# Log application events
if file_logging_service:
    file_logging_service.log_application_event(
        level=LogLevel.INFO,
        message="User registration completed",
        user_id=12345,
        correlation_id="abc-123-def",
        metadata={"source": "web_ui", "version": "v2.1"}
    )
```

### Security Event Integration

```python
from src.domain.security.logging_service import secure_logging_service

# Create security event (existing service)
security_event = secure_logging_service.log_authentication_attempt(
    username="user@example.com",
    success=True,
    correlation_id="abc-123-def",
    ip_address="192.168.1.100"
)

# Log to file (new service)
if file_logging_service:
    file_logging_service.log_security_event(security_event)
```

### Performance Monitoring

```python
from src.core.logging.file_logging_service import PerformanceMetrics

# Using context manager (automatic timing)
if file_logging_service:
    with file_logging_service.measure_performance("/api/v1/users", "POST") as metrics:
        # Your code here
        metrics.add_database_query(12.5)
        metrics.add_cache_hit()

# Manual performance logging
metrics = PerformanceMetrics(
    endpoint="/api/v1/auth/login",
    method="POST",
    response_time_ms=145.2,
    status_code=200,
    database_query_count=3
)

if file_logging_service:
    file_logging_service.log_performance_metrics(metrics)
```

### Audit Trail Logging

```python
# Log compliance-ready audit events
if file_logging_service:
    file_logging_service.log_audit_event(
        audit_type="permission_change",
        actor_user_id=1,
        target_user_id=12345,
        action="role_update",
        before_state={"role": "user"},
        after_state={"role": "admin"},
        justification="Manager approval",
        compliance_flags=["SOX", "GDPR"]
    )
```

### Error Logging

```python
try:
    # Your code here
    pass
except Exception as e:
    if file_logging_service:
        file_logging_service.log_error(
            error=e,
            context={
                "operation": "user_authentication",
                "user_id": 12345,
                "retry_count": 3
            },
            severity="high"
        )
```

## Log Correlation

Use correlation IDs to trace operations across different log categories:

```python
import uuid

correlation_id = str(uuid.uuid4())

# Application event
file_logging_service.log_application_event(
    level=LogLevel.INFO,
    message="Starting password reset",
    correlation_id=correlation_id
)

# Security event
security_event = secure_logging_service.log_authentication_attempt(
    username="user@example.com",
    success=True,
    correlation_id=correlation_id
)

# Performance monitoring
with file_logging_service.measure_performance("/reset", "POST", correlation_id) as metrics:
    # Process request
    pass
```

## Log Format

### JSON Structure

All log entries use structured JSON format:

```json
{
  "timestamp": "2025-07-19T08:30:00.773780+00:00",
  "level": "info",
  "message": "User registration completed",
  "category": "application",
  "correlation_id": "abc-123-def-456",
  "user_id": 12345,
  "operation": "registration",
  "metadata": {
    "source": "web_ui",
    "version": "v2.1"
  }
}
```

### Security Event Format

```json
{
  "timestamp": "2025-07-19T08:30:00.717737+00:00",
  "event_id": "3b66547e-83c4-45e7-8de4-5cc0688c3494",
  "event_type": "authentication_failure",
  "category": "MEDIUM",
  "description": "Authentication failed - invalid_credentials",
  "correlation_id": "abc-123-def-456",
  "user_context": {
    "username_masked": "us***er123",
    "is_authenticated": false
  },
  "request_context": {
    "ip_address_masked": "192.168.1.***",
    "user_agent_sanitized": "Chrome/***"
  },
  "risk_score": 55,
  "threat_indicators": ["multiple_failures"],
  "integrity_hash": "08465167cac32d852c0ae3bdd8d8a38a..."
}
```

## Log Analysis

### Command Line Tools

```bash
# Real-time monitoring
tail -f logs/*/*.log

# Search across all logs
grep -r "correlation_id" logs/

# Extract correlation IDs
jq '.correlation_id' logs/*/*.log | sort | uniq -c

# Find high-risk security events
jq 'select(.risk_score > 70)' logs/security/security.log

# Performance analysis
jq 'select(.response_time_ms > 1000)' logs/performance/performance.log

# Error analysis by type
jq -r '.error_type' logs/error/error.log | sort | uniq -c
```

### Log Aggregation

For production environments, consider integrating with:

- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk** for enterprise log management
- **Prometheus + Grafana** for metrics visualization
- **AWS CloudWatch** for cloud-native monitoring

## Security Considerations

### Data Masking

The logging system automatically masks sensitive information:

- **Usernames**: `user123` → `us***er123`
- **Email addresses**: `user@domain.com` → `us***@do***.com`
- **IP addresses**: `192.168.1.100` → `192.168.1.***`
- **Tokens**: `abc123def456` → `abc1***f456`

### Integrity Protection

Security events include HMAC integrity hashes to detect tampering:

```bash
# Set integrity key for production
export AUDIT_INTEGRITY_KEY="your-secure-key-here"
```

### Compliance Features

- **GDPR**: Privacy-compliant data masking and retention
- **SOX**: Audit trail integrity and non-repudiation
- **HIPAA**: Secure handling of sensitive data
- **PCI DSS**: Payment card data protection

## Troubleshooting

### Common Issues

1. **Logs not appearing**
   - Check `ENABLE_FILE_LOGGING=true`
   - Verify log directory permissions
   - Check available disk space

2. **Permission errors**
   ```bash
   sudo chown -R app:app /var/log/cedrina
   sudo chmod 755 /var/log/cedrina
   ```

3. **High disk usage**
   - Reduce `LOG_MAX_AGE_DAYS`
   - Decrease `LOG_MAX_TOTAL_SIZE_GB`
   - Increase `LOG_CLEANUP_INTERVAL_HOURS`

4. **Missing correlation**
   - Ensure correlation IDs are passed between services
   - Check middleware is capturing request IDs

### Debug Mode

Enable debug logging for troubleshooting:

```bash
LOG_LEVEL=DEBUG python -c "
from src.core.logging import file_logging_service
print('File logging enabled:', file_logging_service is not None)
if file_logging_service:
    print('Log directory:', file_logging_service.config.log_directory)
    print('Statistics:', file_logging_service.get_log_statistics())
"
```

## Integration with Existing Systems

### FastAPI Integration

```python
from fastapi import Request
from src.core.logging import file_logging_service

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    
    if file_logging_service:
        with file_logging_service.measure_performance(
            str(request.url.path), 
            request.method,
            correlation_id
        ) as metrics:
            response = await call_next(request)
            metrics.status_code = response.status_code
            return response
```

### Celery Integration

```python
from celery import Task
from src.core.logging import file_logging_service, LogLevel

class LoggedTask(Task):
    def __call__(self, *args, **kwargs):
        if file_logging_service:
            file_logging_service.log_application_event(
                level=LogLevel.INFO,
                message=f"Task {self.name} started",
                task_id=self.request.id,
                task_name=self.name
            )
        
        try:
            result = super().__call__(*args, **kwargs)
            if file_logging_service:
                file_logging_service.log_application_event(
                    level=LogLevel.INFO,
                    message=f"Task {self.name} completed",
                    task_id=self.request.id
                )
            return result
        except Exception as e:
            if file_logging_service:
                file_logging_service.log_error(
                    error=e,
                    context={"task_id": self.request.id, "task_name": self.name}
                )
            raise
```

## Performance Impact

The file logging system is designed for minimal performance impact:

- **Asynchronous writes** prevent blocking application threads
- **Efficient JSON serialization** using native Python libraries
- **Thread-safe operations** for concurrent access
- **Lazy log file creation** to avoid unnecessary I/O
- **Configurable log levels** to control verbosity

Typical overhead: <1ms per log entry for JSON serialization and file I/O.

## Monitoring the Logging System

### Health Checks

```python
def check_logging_health():
    if not file_logging_service:
        return {"status": "disabled"}
    
    stats = file_logging_service.get_log_statistics()
    
    return {
        "status": "healthy",
        "total_files": stats["total_files"],
        "total_size_mb": stats["total_size_mb"],
        "log_directory": str(file_logging_service.config.log_directory),
        "config": {
            "max_size_mb": file_logging_service.config.rotation_config.max_size_mb,
            "max_age_days": file_logging_service.config.retention_config.max_age_days
        }
    }
```

### Metrics

Monitor these key metrics:

- Log file sizes and counts
- Write latency and throughput
- Disk space utilization
- Cleanup job execution frequency
- Error rates in log writing

## Future Enhancements

Planned improvements:

- **Structured log queries** with embedded SQLite
- **Real-time log streaming** via WebSocket
- **Machine learning** anomaly detection
- **Automated alert generation** for critical events
- **Log compression** for long-term storage
- **Multi-tenant logging** with isolation

## Support

For issues or questions:

1. Check this documentation
2. Review the demonstration script: `demo_logging_integration.py`
3. Run the standalone tests: `test_logging_standalone.py`
4. Check the codebase: `src/core/logging/`
5. Create an issue in the project repository