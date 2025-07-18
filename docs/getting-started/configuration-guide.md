# Configuration Guide

This guide explains all configuration options available in Cedrina and how to properly configure them for different environments.

## Table of Contents

- [Configuration Overview](#configuration-overview)
- [Environment Variables](#environment-variables)
- [Database Configuration](#database-configuration)
- [Security Configuration](#security-configuration)
- [Rate Limiting Configuration](#rate-limiting-configuration)
- [Email Configuration](#email-configuration)
- [OAuth Configuration](#oauth-configuration)
- [Internationalization](#internationalization)
- [Environment-Specific Configurations](#environment-specific-configurations)
- [Configuration Validation](#configuration-validation)

## Configuration Overview

Cedrina uses a layered configuration system based on Pydantic Settings, providing:

- **Type Safety**: All configuration values are validated at startup
- **Environment Override**: Environment variables override default values
- **Nested Configuration**: Organized into logical groups
- **Validation**: Automatic validation of required fields and formats

### Configuration Structure

```
src/core/config/
├── __init__.py
├── app.py          # Main application configuration
├── auth.py         # Authentication settings
├── database.py     # Database configuration
├── email.py        # Email service configuration
├── logging.py      # Logging configuration
├── rate_limiting.py # Rate limiting settings
└── security.py     # Security settings
```

## Environment Variables

### Application Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `APP_ENV` | str | `development` | Application environment |
| `DEBUG` | bool | `True` | Enable debug mode |
| `LOG_LEVEL` | str | `INFO` | Logging level |
| `SECRET_KEY` | str | - | Application secret key |

### Database Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DATABASE_URL` | str | - | Full database connection URL |
| `POSTGRES_HOST` | str | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | int | `5432` | PostgreSQL port |
| `POSTGRES_DB` | str | `cedrina` | Database name |
| `POSTGRES_DB_TEST` | str | `cedrina_test` | Test database name |
| `POSTGRES_USER` | str | `cedrina` | Database user |
| `POSTGRES_PASSWORD` | str | - | Database password |
| `POSTGRES_SSL_MODE` | str | `prefer` | SSL mode |

### Redis Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `REDIS_URL` | str | - | Full Redis connection URL |
| `REDIS_HOST` | str | `localhost` | Redis host |
| `REDIS_PORT` | int | `6379` | Redis port |
| `REDIS_DB` | int | `0` | Redis database number |

## Database Configuration

### Connection String Format

```
postgresql://username:password@host:port/database?sslmode=mode
```

### SSL Configuration

```bash
# Development (no SSL)
POSTGRES_SSL_MODE=disable

# Production (SSL required)
POSTGRES_SSL_MODE=require

# Flexible SSL
POSTGRES_SSL_MODE=prefer
```

### Connection Pooling

```python
# Configured in src/infrastructure/database/database.py
DATABASE_CONFIG = {
    "pool_size": 20,
    "max_overflow": 30,
    "pool_pre_ping": True,
    "pool_recycle": 3600,
    "echo": False  # Set to True for query logging
}
```

### Example Configurations

#### Development
```bash
DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina
POSTGRES_SSL_MODE=disable
```

#### Production
```bash
DATABASE_URL=postgresql://cedrina:password@prod-db.example.com:5432/cedrina
POSTGRES_SSL_MODE=require
```

#### Docker
```bash
DATABASE_URL=postgresql://cedrina:password@postgres:5432/cedrina
POSTGRES_HOST=postgres
POSTGRES_SSL_MODE=disable
```

## Security Configuration

### JWT Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `JWT_PRIVATE_KEY_PATH` | str | - | Path to private key file |
| `JWT_PUBLIC_KEY_PATH` | str | - | Path to public key file |
| `JWT_ISSUER` | str | - | JWT issuer claim |
| `JWT_AUDIENCE` | str | - | JWT audience claim |
| `JWT_ALGORITHM` | str | `RS256` | JWT signing algorithm |

### Token Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ACCESS_TOKEN_EXPIRE_MINUTES` | int | `15` | Access token expiration |
| `REFRESH_TOKEN_EXPIRE_DAYS` | int | `7` | Refresh token expiration |
| `SESSION_INACTIVITY_TIMEOUT_MINUTES` | int | `30` | Session timeout |
| `MAX_CONCURRENT_SESSIONS_PER_USER` | int | `5` | Max sessions per user |

### Security Headers

```python
# Configured in src/main.py
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'"
}
```

### Key Generation

```bash
# Generate RSA key pair
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Set proper permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

## Rate Limiting Configuration

### Basic Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RATE_LIMIT_ENABLED` | bool | `True` | Enable rate limiting |
| `RATE_LIMIT_DEFAULT_LIMIT` | int | `100` | Default requests per window |
| `RATE_LIMIT_DEFAULT_WINDOW` | int | `60` | Default window in seconds |

### Advanced Configuration

```python
# Configured in src/core/rate_limiting/config.py
RATE_LIMIT_CONFIG = {
    "default": "100/minute",
    "auth": "5/minute",
    "registration": "3/minute",
    "password_reset": "3/hour",
    "api": "1000/hour"
}
```

### Custom Rate Limits

```python
# Define custom rate limits for specific endpoints
@limiter.limit("5/minute")
async def login_endpoint(request: Request):
    pass

@limiter.limit("3/hour")
async def password_reset_endpoint(request: Request):
    pass
```

## Email Configuration

### SMTP Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_HOST` | str | - | SMTP server host |
| `SMTP_PORT` | int | `587` | SMTP server port |
| `SMTP_USER` | str | - | SMTP username |
| `SMTP_PASSWORD` | str | - | SMTP password |
| `SMTP_TLS` | bool | `True` | Enable TLS |
| `SMTP_SSL` | bool | `False` | Enable SSL |

### Email Templates

```python
# Template configuration
EMAIL_TEMPLATES = {
    "email_confirmation": {
        "subject": "Confirm your email address",
        "template": "email_confirmation_{locale}.html"
    },
    "password_reset": {
        "subject": "Reset your password",
        "template": "password_reset_{locale}.html"
    }
}
```

### Example Configurations

#### Gmail
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_TLS=true
SMTP_SSL=false
```

#### SendGrid
```bash
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=your-sendgrid-api-key
SMTP_TLS=true
SMTP_SSL=false
```

## OAuth Configuration

### Google OAuth

| Variable | Type | Description |
|----------|------|-------------|
| `GOOGLE_CLIENT_ID` | str | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | str | Google OAuth client secret |

### Microsoft OAuth

| Variable | Type | Description |
|----------|------|-------------|
| `MICROSOFT_CLIENT_ID` | str | Microsoft OAuth client ID |
| `MICROSOFT_CLIENT_SECRET` | str | Microsoft OAuth client secret |

### Facebook OAuth

| Variable | Type | Description |
|----------|------|-------------|
| `FACEBOOK_CLIENT_ID` | str | Facebook OAuth client ID |
| `FACEBOOK_CLIENT_SECRET` | str | Facebook OAuth client secret |

### OAuth Setup

1. **Create OAuth Application**
   ```bash
   # Google Console: https://console.developers.google.com/
   # Microsoft Azure: https://portal.azure.com/
   # Facebook Developers: https://developers.facebook.com/
   ```

2. **Configure Redirect URIs**
   ```
   http://localhost:8000/api/v1/auth/oauth/google/callback
   http://localhost:8000/api/v1/auth/oauth/microsoft/callback
   http://localhost:8000/api/v1/auth/oauth/facebook/callback
   ```

3. **Set Environment Variables**
   ```bash
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   MICROSOFT_CLIENT_ID=your-microsoft-client-id
   MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
   FACEBOOK_CLIENT_ID=your-facebook-client-id
   FACEBOOK_CLIENT_SECRET=your-facebook-client-secret
   ```

## Internationalization

### Locale Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DEFAULT_LOCALE` | str | `en` | Default locale |
| `SUPPORTED_LOCALES` | str | `en,ar,es,fa` | Comma-separated supported locales |

### Translation Files

```
locales/
├── en/
│   └── LC_MESSAGES/
│       ├── messages.po
│       └── messages.mo
├── ar/
│   └── LC_MESSAGES/
│       ├── messages.po
│       └── messages.mo
└── messages.pot
```

### Translation Management

```bash
# Extract messages
pybabel extract -F babel.cfg -o locales/messages.pot src/

# Update translations
pybabel update -i locales/messages.pot -d locales -D messages

# Compile translations
pybabel compile -d locales -D messages
```

## Environment-Specific Configurations

### Development Environment

```bash
# .env.development
APP_ENV=development
DEBUG=true
LOG_LEVEL=DEBUG
DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina
REDIS_URL=redis://localhost:6379/0
POSTGRES_SSL_MODE=disable
RATE_LIMIT_ENABLED=false
```

### Testing Environment

```bash
# .env.test
APP_ENV=test
DEBUG=false
LOG_LEVEL=WARNING
DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina_test
REDIS_URL=redis://localhost:6379/1
POSTGRES_SSL_MODE=disable
RATE_LIMIT_ENABLED=false
SMTP_HOST=localhost
SMTP_PORT=1025
```

### Staging Environment

```bash
# .env.staging
APP_ENV=staging
DEBUG=false
LOG_LEVEL=INFO
DATABASE_URL=postgresql://cedrina:password@staging-db.example.com:5432/cedrina
REDIS_URL=redis://staging-redis.example.com:6379/0
POSTGRES_SSL_MODE=prefer
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_LIMIT=100
RATE_LIMIT_DEFAULT_WINDOW=60
```

### Production Environment

```bash
# .env.production
APP_ENV=production
DEBUG=false
LOG_LEVEL=WARNING
DATABASE_URL=postgresql://cedrina:password@prod-db.example.com:5432/cedrina
REDIS_URL=redis://prod-redis.example.com:6379/0
POSTGRES_SSL_MODE=require
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_LIMIT=50
RATE_LIMIT_DEFAULT_WINDOW=60
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=your-sendgrid-api-key
```

## Configuration Validation

### Environment Validation

```bash
# Validate configuration
poetry run python -c "
from src.core.config.app import AppConfig
try:
    config = AppConfig()
    print('✅ Configuration is valid')
    print(f'Environment: {config.app_env}')
    print(f'Database: {config.database.url}')
    print(f'Redis: {config.redis.url}')
except Exception as e:
    print(f'❌ Configuration error: {e}')
"
```

### Database Connection Test

```bash
# Test database connection
poetry run python -c "
import asyncio
from src.infrastructure.database.database import get_database

async def test_db():
    db = get_database()
    try:
        await db.connect()
        print('✅ Database connection successful')
        await db.disconnect()
    except Exception as e:
        print(f'❌ Database connection failed: {e}')

asyncio.run(test_db())
"
```

### Redis Connection Test

```bash
# Test Redis connection
poetry run python -c "
import redis
from src.core.config.app import AppConfig

config = AppConfig()
try:
    r = redis.from_url(config.redis.url)
    r.ping()
    print('✅ Redis connection successful')
except Exception as e:
    print(f'❌ Redis connection failed: {e}')
"
```

### Configuration Checklist

- [ ] All required environment variables are set
- [ ] Database connection string is valid
- [ ] Redis connection string is valid
- [ ] JWT keys are generated and accessible
- [ ] Email configuration is complete (if using email features)
- [ ] OAuth credentials are configured (if using OAuth)
- [ ] Rate limiting settings are appropriate for environment
- [ ] SSL/TLS settings are configured for production
- [ ] Logging level is appropriate for environment
- [ ] Supported locales are configured

## Configuration Best Practices

### Security

1. **Never commit secrets to version control**
   ```bash
   # Add to .gitignore
   .env
   .env.*
   keys/
   *.pem
   ```

2. **Use strong, unique passwords**
   ```bash
   # Generate secure passwords
   openssl rand -base64 32
   ```

3. **Rotate secrets regularly**
   ```bash
   # Update JWT keys periodically
   openssl genrsa -out keys/private.pem 2048
   openssl rsa -in keys/private.pem -pubout -out keys/public.pem
   ```

### Performance

1. **Optimize database connections**
   ```python
   # Adjust pool size based on load
   DATABASE_CONFIG = {
       "pool_size": 20,  # Adjust based on concurrent users
       "max_overflow": 30,
       "pool_pre_ping": True
   }
   ```

2. **Configure appropriate rate limits**
   ```python
   # Different limits for different endpoints
   RATE_LIMIT_CONFIG = {
       "auth": "5/minute",
       "api": "1000/hour",
       "admin": "100/minute"
   }
   ```

### Monitoring

1. **Enable structured logging**
   ```bash
   LOG_LEVEL=INFO
   LOG_FORMAT=json
   ```

2. **Configure health checks**
   ```python
   # Health check endpoints
   /api/v1/health
   /api/v1/health/detailed
   ```

## Next Steps

After configuring Cedrina:

1. **Test the Configuration**: Run validation scripts
2. **Set Up Monitoring**: Configure logging and health checks
3. **Deploy**: Follow the [Deployment Guide](../deployment/overview.md)
4. **Monitor**: Set up monitoring and alerting
5. **Maintain**: Regular configuration reviews and updates

---

*Last updated: January 2025* 