# Troubleshooting Guide

This guide helps you diagnose and resolve common issues when working with Cedrina.

## Table of Contents

- [Common Issues](#common-issues)
- [Database Issues](#database-issues)
- [Authentication Issues](#authentication-issues)
- [Performance Issues](#performance-issues)
- [Security Issues](#security-issues)
- [Testing Issues](#testing-issues)
- [Deployment Issues](#deployment-issues)
- [Debugging Tools](#debugging-tools)

## Common Issues

### 1. Import Errors

**Error**: `ModuleNotFoundError: No module named 'src'`

**Causes**:
- PYTHONPATH not set correctly
- Virtual environment not activated
- Poetry not installed or not in PATH

**Solutions**:
```bash
# Set PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or use Makefile (recommended)
make run-dev-local

# Or install in development mode
poetry install

# Check Poetry installation
poetry --version
```

### 2. Configuration Errors

**Error**: `pydantic.error_wrappers.ValidationError`

**Causes**:
- Missing required environment variables
- Invalid configuration values
- Malformed connection strings

**Solutions**:
```bash
# Check environment file
cat .env

# Validate configuration
poetry run python -c "
from src.core.config.app import AppConfig
try:
    config = AppConfig()
    print('Configuration valid')
except Exception as e:
    print(f'Configuration error: {e}')
"

# Check specific configuration
poetry run python -c "
from src.core.config.database import DatabaseConfig
config = DatabaseConfig()
print(f'Database URL: {config.url}')
"
```

### 3. Permission Errors

**Error**: `PermissionError: [Errno 13] Permission denied`

**Causes**:
- Incorrect file permissions
- Running as wrong user
- Docker volume permissions

**Solutions**:
```bash
# Fix file permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem
chmod 755 src/

# Fix directory permissions
sudo chown -R $USER:$USER .

# For Docker
docker-compose down
docker-compose up -d
```

## Database Issues

### 1. Connection Refused

**Error**: `psycopg2.OperationalError: could not connect to server`

**Diagnosis**:
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Check port availability
sudo netstat -tulpn | grep :5432

# Test connection
psql -h localhost -U cedrina -d cedrina -c "SELECT 1;"
```

**Solutions**:
```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql
CREATE DATABASE cedrina;
CREATE DATABASE cedrina_test;
CREATE USER cedrina WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE cedrina TO cedrina;
GRANT ALL PRIVILEGES ON DATABASE cedrina_test TO cedrina;
ALTER USER cedrina CREATEDB;
\q

# For Docker
docker-compose restart postgres
```

### 2. Migration Errors

**Error**: `alembic.util.exc.CommandError: Can't locate revision identified by`

**Solutions**:
```bash
# Check migration history
poetry run alembic history

# Reset migrations (development only)
poetry run alembic stamp head
poetry run alembic revision --autogenerate -m "Initial migration"
poetry run alembic upgrade head

# For production, check specific revision
poetry run alembic current
poetry run alembic upgrade head
```

### 3. Connection Pool Exhausted

**Error**: `QueuePool limit of size X overflow Y reached`

**Solutions**:
```python
# Adjust pool settings in src/infrastructure/database/database.py
DATABASE_CONFIG = {
    "pool_size": 30,  # Increase pool size
    "max_overflow": 50,  # Increase overflow
    "pool_pre_ping": True,
    "pool_recycle": 3600,
}
```

### 4. Slow Queries

**Diagnosis**:
```sql
-- Check slow queries
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- Analyze table statistics
ANALYZE;
```

**Solutions**:
```sql
-- Create missing indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);

-- Optimize queries
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'test@example.com';
```

## Authentication Issues

### 1. JWT Key Errors

**Error**: `FileNotFoundError: [Errno 2] No such file or directory: './keys/private.pem'`

**Solutions**:
```bash
# Generate JWT keys
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Set proper permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem

# Verify keys exist
ls -la keys/
```

### 2. Token Validation Errors

**Error**: `jwt.exceptions.InvalidTokenError`

**Diagnosis**:
```bash
# Check JWT configuration
poetry run python -c "
from src.core.config.auth import AuthConfig
config = AuthConfig()
print(f'JWT Algorithm: {config.jwt_algorithm}')
print(f'Private Key: {config.jwt_private_key_path}')
print(f'Public Key: {config.jwt_public_key_path}')
"
```

**Solutions**:
```bash
# Regenerate keys
rm keys/private.pem keys/public.pem
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Restart application
docker-compose restart app
# Or
make run-dev-local
```

### 3. OAuth Configuration Issues

**Error**: `authlib.integrations.base_client.OAuthError`

**Diagnosis**:
```bash
# Check OAuth configuration
poetry run python -c "
from src.core.config.auth import AuthConfig
config = AuthConfig()
print(f'Google Client ID: {config.google_client_id}')
print(f'Microsoft Client ID: {config.microsoft_client_id}')
"
```

**Solutions**:
```bash
# Verify OAuth credentials
# 1. Check Google Console: https://console.developers.google.com/
# 2. Verify redirect URIs match exactly
# 3. Ensure client ID and secret are correct

# Test OAuth flow
curl -X GET "http://localhost:8000/api/v1/auth/oauth/google"
```

## Performance Issues

### 1. High Memory Usage

**Diagnosis**:
```bash
# Check memory usage
free -h
ps aux | grep uvicorn
docker stats

# Check for memory leaks
poetry run python -c "
import psutil
process = psutil.Process()
print(f'Memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB')
"
```

**Solutions**:
```python
# Optimize database connections
DATABASE_CONFIG = {
    "pool_size": 10,  # Reduce pool size
    "max_overflow": 20,
    "pool_recycle": 1800,  # Recycle connections more frequently
}

# Enable garbage collection
import gc
gc.collect()
```

### 2. Slow Response Times

**Diagnosis**:
```bash
# Enable query logging
export SQLALCHEMY_ECHO=true

# Monitor response times
curl -w "@curl-format.txt" -o /dev/null -s "http://localhost:8000/api/v1/health"

# Check database performance
docker-compose exec postgres psql -U cedrina -d cedrina -c "
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 5;
"
```

**Solutions**:
```python
# Add database indexes
# Optimize queries
# Implement caching
# Use connection pooling
```

### 3. Rate Limiting Issues

**Error**: `slowapi.errors.RateLimitExceeded`

**Diagnosis**:
```bash
# Check rate limiting configuration
poetry run python -c "
from src.core.config.rate_limiting import RateLimitingConfig
config = RateLimitingConfig()
print(f'Rate limiting enabled: {config.enabled}')
print(f'Default limit: {config.default_limit}')
print(f'Default window: {config.default_window}')
"
```

**Solutions**:
```python
# Adjust rate limits for development
RATE_LIMIT_ENABLED=false  # Disable for development

# Or increase limits
RATE_LIMIT_DEFAULT_LIMIT=1000
RATE_LIMIT_DEFAULT_WINDOW=60
```

## Security Issues

### 1. SSL/TLS Configuration

**Error**: `ssl.SSLError`

**Diagnosis**:
```bash
# Check SSL configuration
poetry run python -c "
from src.core.config.database import DatabaseConfig
config = DatabaseConfig()
print(f'SSL Mode: {config.ssl_mode}')
"
```

**Solutions**:
```bash
# Development (disable SSL)
POSTGRES_SSL_MODE=disable

# Production (require SSL)
POSTGRES_SSL_MODE=require

# Test SSL connection
psql "postgresql://cedrina:password@localhost:5432/cedrina?sslmode=require"
```

### 2. Password Policy Violations

**Error**: `PasswordPolicyError`

**Diagnosis**:
```python
# Check password policy
from src.domain.security.policy import PasswordPolicy
policy = PasswordPolicy()
print(f'Min length: {policy.min_length}')
print(f'Require uppercase: {policy.require_uppercase}')
print(f'Require lowercase: {policy.require_lowercase}')
print(f'Require digits: {policy.require_digits}')
print(f'Require special: {policy.require_special}')
```

**Solutions**:
```python
# Use strong passwords
# Example: SecurePassword123!
# - At least 8 characters
# - Contains uppercase and lowercase
# - Contains digits
# - Contains special characters
```

### 3. Session Security Issues

**Error**: `SessionExpiredError`

**Diagnosis**:
```bash
# Check session configuration
poetry run python -c "
from src.core.config.auth import AuthConfig
config = AuthConfig()
print(f'Session timeout: {config.session_inactivity_timeout_minutes} minutes')
print(f'Max sessions: {config.max_concurrent_sessions_per_user}')
"
```

**Solutions**:
```python
# Adjust session settings
SESSION_INACTIVITY_TIMEOUT_MINUTES=60  # Increase timeout
MAX_CONCURRENT_SESSIONS_PER_USER=10    # Increase limit
```

## Testing Issues

### 1. Test Database Connection

**Error**: `Database connection failed during tests`

**Solutions**:
```bash
# Create test database
sudo -u postgres psql
CREATE DATABASE cedrina_test;
GRANT ALL PRIVILEGES ON DATABASE cedrina_test TO cedrina;
\q

# Run test migrations
poetry run bash -c "
export DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina_test
alembic upgrade head
"

# Run tests
make test
```

### 2. Test Coverage Issues

**Error**: `Coverage below threshold`

**Solutions**:
```bash
# Run tests with coverage
poetry run pytest --cov=src --cov-report=html

# Check coverage report
open htmlcov/index.html

# Add missing tests
# Focus on uncovered lines in the report
```

### 3. Test Performance Issues

**Error**: `Tests taking too long`

**Solutions**:
```bash
# Run tests in parallel
poetry run pytest -n auto

# Run specific test categories
poetry run pytest tests/unit/ -v
poetry run pytest tests/integration/ -v

# Use test database
export TEST_MODE=true
export DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina_test
```

## Deployment Issues

### 1. Docker Build Failures

**Error**: `Docker build failed`

**Solutions**:
```bash
# Clean Docker cache
docker system prune -a

# Rebuild without cache
docker-compose build --no-cache

# Check Dockerfile
cat Dockerfile

# Verify dependencies
cat pyproject.toml
```

### 2. Container Startup Issues

**Error**: `Container failed to start`

**Diagnosis**:
```bash
# Check container logs
docker-compose logs app
docker-compose logs postgres
docker-compose logs redis

# Check container status
docker-compose ps

# Check health checks
docker-compose exec app curl http://localhost:8000/api/v1/health
```

**Solutions**:
```bash
# Restart services
docker-compose down
docker-compose up -d

# Check resource usage
docker stats

# Increase memory/CPU limits
# In docker-compose.yml
services:
  app:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
```

### 3. Production Deployment Issues

**Error**: `Application not accessible`

**Diagnosis**:
```bash
# Check firewall
sudo ufw status

# Check nginx configuration
sudo nginx -t
sudo systemctl status nginx

# Check SSL certificates
sudo certbot certificates
```

**Solutions**:
```bash
# Configure firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp

# Configure nginx
sudo nano /etc/nginx/sites-available/cedrina

# Renew SSL certificates
sudo certbot renew
```

## Debugging Tools

### 1. Logging Configuration

```python
# Enable debug logging
LOG_LEVEL=DEBUG

# Structured logging
import structlog
logger = structlog.get_logger()
logger.info("Debug message", user_id=123, action="login")
```

### 2. Database Debugging

```bash
# Enable SQL logging
export SQLALCHEMY_ECHO=true

# Check database connections
docker-compose exec postgres psql -U cedrina -d cedrina -c "
SELECT * FROM pg_stat_activity WHERE state = 'active';
"
```

### 3. Performance Profiling

```python
# Profile specific functions
import cProfile
import pstats

def profile_function():
    profiler = cProfile.Profile()
    profiler.enable()
    # Your code here
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats()
```

### 4. Memory Profiling

```python
# Memory profiling
import tracemalloc

tracemalloc.start()
# Your code here
current, peak = tracemalloc.get_traced_memory()
print(f"Current memory usage: {current / 1024 / 1024:.2f} MB")
print(f"Peak memory usage: {peak / 1024 / 1024:.2f} MB")
tracemalloc.stop()
```

### 5. Network Debugging

```bash
# Check network connectivity
curl -v http://localhost:8000/api/v1/health

# Check DNS resolution
nslookup api.example.com

# Check SSL certificate
openssl s_client -connect api.example.com:443 -servername api.example.com
```

## Getting Help

### 1. Check Logs

```bash
# Application logs
docker-compose logs app

# Database logs
docker-compose logs postgres

# System logs
sudo journalctl -u docker
sudo journalctl -u postgresql
```

### 2. Enable Debug Mode

```bash
# Enable debug mode
export DEBUG=true
export LOG_LEVEL=DEBUG

# Restart application
docker-compose restart app
```

### 3. Community Support

- **GitHub Issues**: [Report bugs](https://github.com/hdkhosravian/cedrina/issues)
- **GitHub Discussions**: [Ask questions](https://github.com/hdkhosravian/cedrina/discussions)
- **Documentation**: Check the [Reference](../reference/) section

### 4. Create Minimal Reproduction

```bash
# Create minimal test case
poetry run python -c "
# Minimal code to reproduce the issue
"

# Include environment information
poetry run python -c "
import platform
import sys
print(f'Python: {sys.version}')
print(f'Platform: {platform.platform()}')
print(f'Architecture: {platform.architecture()}')
"
```

## Prevention

### 1. Regular Maintenance

```bash
# Update dependencies
poetry update

# Run security checks
poetry run bandit -r src/

# Update Docker images
docker-compose pull
docker-compose build --no-cache
```

### 2. Monitoring

```bash
# Set up health checks
curl http://localhost:8000/api/v1/health

# Monitor resource usage
docker stats

# Check for updates
poetry show --outdated
```

### 3. Backup Strategy

```bash
# Database backup
docker-compose exec postgres pg_dump -U cedrina cedrina > backup.sql

# Configuration backup
cp .env .env.backup

# Code backup
git push origin main
```

---

*Last updated: January 2025* 