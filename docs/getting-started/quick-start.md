# Quick Start Guide

This guide will help you get Cedrina up and running quickly for development and testing purposes.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.12+** - [Download Python](https://www.python.org/downloads/)
- **PostgreSQL 16+** - [Download PostgreSQL](https://www.postgresql.org/download/)
- **Redis 7.2+** (optional, for rate limiting) - [Download Redis](https://redis.io/download)
- **Docker & Docker Compose** (optional) - [Download Docker](https://www.docker.com/products/docker-desktop/)
- **Poetry** (recommended) - [Install Poetry](https://python-poetry.org/docs/#installation)

## Installation Options

### Option 1: Docker (Recommended for Quick Start)

The fastest way to get started is using Docker Compose:

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Start all services with Docker Compose
docker-compose up -d

# Run database migrations
docker-compose exec app alembic upgrade head

# Create an admin user (if script exists)
docker-compose exec app python -m src.scripts.create_admin
```

**Alternative using Makefile:**
```bash
# Build and start development environment
make build
make run-dev

# Run tests
make test

# Check health
make check-health
```

### Option 2: Local Development Setup

For development work, you may prefer a local setup:

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install dependencies using Poetry (recommended)
poetry install

# Or using pip (if requirements.txt exists)
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Initialize database
make db-init

# Run database migrations
make db-migrate

# Start the application
make run-dev-local
```

## Environment Configuration

Create a `.env` file with the following configuration:

```bash
# Application Configuration
APP_ENV=development
DEBUG=true
LOG_LEVEL=INFO

# Database Configuration
DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=cedrina
POSTGRES_DB_TEST=cedrina_test
POSTGRES_USER=cedrina
POSTGRES_PASSWORD=your_secure_password
POSTGRES_SSL_MODE=prefer

# Redis Configuration (optional, for rate limiting)
REDIS_URL=redis://localhost:6379/0
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# JWT Configuration
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
JWT_ISSUER=https://api.example.com
JWT_AUDIENCE=cedrina:api:v1
JWT_ALGORITHM=RS256

# OAuth Configuration (optional)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
FACEBOOK_CLIENT_ID=your_facebook_client_id
FACEBOOK_CLIENT_SECRET=your_facebook_client_secret

# Security Configuration
SESSION_INACTIVITY_TIMEOUT_MINUTES=30
MAX_CONCURRENT_SESSIONS_PER_USER=5
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
SECRET_KEY=your_secret_key_here

# Rate Limiting Configuration
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_LIMIT=100
RATE_LIMIT_DEFAULT_WINDOW=60

# Email Configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_TLS=true
SMTP_SSL=false

# Internationalization
DEFAULT_LOCALE=en
SUPPORTED_LOCALES=en,ar,es,fa
```

## API Usage Examples

### 1. User Registration

```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'
```

**Expected Response:**
```json
{
  "message": "User registered successfully. Please check your email for confirmation.",
  "user_id": "uuid-here",
  "status": "pending_confirmation"
}
```

### 2. User Login

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePassword123!"
  }'
```

**Expected Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

### 3. Refresh Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

### 4. Access Protected Endpoints

```bash
curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer your_access_token_here"
```

### 5. OAuth Login (Google)

```bash
# Redirect users to this URL for Google OAuth
GET "http://localhost:8000/api/v1/auth/oauth/google"
```

### 6. Email Confirmation

```bash
curl -X POST "http://localhost:8000/api/v1/auth/confirm-email" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_confirmation_token_here"
  }'
```

### 7. Password Reset

```bash
# Request password reset
curl -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }'

# Reset password with token
curl -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_reset_token_here",
    "new_password": "NewSecurePassword123!"
  }'
```

## Testing the Installation

### 1. Health Check

```bash
curl "http://localhost:8000/api/v1/health"
```

**Expected Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z",
  "version": "0.1.0",
  "services": {
    "database": "healthy",
    "redis": "healthy"
  }
}
```

### 2. API Documentation

Visit the interactive API documentation:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 3. Run Tests

```bash
# Run all tests
make test

# Or using pytest directly
poetry run pytest

# Run with coverage
poetry run pytest --cov=src --cov-report=html

# Run specific test categories
poetry run pytest tests/unit/
poetry run pytest tests/integration/
poetry run pytest tests/feature/
poetry run pytest tests/performance/
poetry run pytest tests/security/
```

## Development Commands

### Using Makefile (Recommended)

```bash
# Build and run development environment
make build
make run-dev

# Run tests
make test

# Database operations
make db-init
make db-migrate
make db-rollback

# Code quality
make lint
make format

# Cleanup
make clean
make clean-volumes

# Health check
make check-health
```

### Database Operations

```bash
# Create a new migration
poetry run alembic revision --autogenerate -m "Description of changes"

# Apply migrations
make db-migrate

# Rollback migrations
make db-rollback

# View migration history
poetry run alembic history

# Initialize database
make db-init

# Drop database
make db-drop
```

### Code Quality

```bash
# Run linting
make lint

# Format code
make format

# Run type checking
poetry run mypy src/

# Run security checks
poetry run bandit -r src/

# Run all quality checks
make lint && make format
```

### Development Server

```bash
# Start development server with auto-reload
make run-dev-local

# Or using uvicorn directly
poetry run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Start with specific environment
APP_ENV=development poetry run uvicorn src.main:app --reload

# Start with custom configuration
poetry run uvicorn src.main:app --reload --log-level debug
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Error

**Error**: `psycopg2.OperationalError: could not connect to server`

**Solution**:
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Start PostgreSQL if not running
sudo systemctl start postgresql

# Create database and user
sudo -u postgres psql
CREATE DATABASE cedrina;
CREATE DATABASE cedrina_test;
CREATE USER cedrina WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE cedrina TO cedrina;
GRANT ALL PRIVILEGES ON DATABASE cedrina_test TO cedrina;
```

#### 2. Redis Connection Error

**Error**: `redis.exceptions.ConnectionError`

**Solution**:
```bash
# Check if Redis is running
redis-cli ping

# Start Redis if not running
sudo systemctl start redis

# Or start Redis manually
redis-server
```

#### 3. JWT Key Errors

**Error**: `FileNotFoundError: [Errno 2] No such file or directory: './keys/private.pem'`

**Solution**:
```bash
# Generate JWT keys
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Set proper permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

#### 4. Import Errors

**Error**: `ModuleNotFoundError: No module named 'src'`

**Solution**:
```bash
# Install in development mode
poetry install

# Or set PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or use the Makefile which sets PYTHONPATH automatically
make run-dev-local
```

#### 5. Poetry Issues

**Error**: `poetry: command not found`

**Solution**:
```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Or using pip
pip install poetry

# Add to PATH (if needed)
export PATH="$HOME/.local/bin:$PATH"
```

### Performance Issues

#### 1. Slow Database Queries

```bash
# Enable query logging
export SQLALCHEMY_ECHO=true

# Check database performance
docker-compose exec postgres psql -U cedrina -d cedrina -c "SELECT * FROM pg_stat_activity;"

# Or for local PostgreSQL
psql -h localhost -U cedrina -d cedrina -c "SELECT * FROM pg_stat_activity;"
```

#### 2. Memory Issues

```bash
# Monitor memory usage
docker stats

# Check application logs
docker-compose logs app

# Or for local development
poetry run uvicorn src.main:app --reload --log-level debug
```

#### 3. Test Failures

```bash
# Run tests with verbose output
poetry run pytest -v

# Run specific failing test
poetry run pytest tests/path/to/test_file.py::test_function -v

# Run tests with coverage and see what's missing
poetry run pytest --cov=src --cov-report=term-missing
```

## Next Steps

After successful installation:

1. **Review Architecture**: Read the [Architecture Overview](../architecture/overview.md)
2. **Understand Security**: Study the [Security Architecture](../architecture/security-architecture.md)
3. **Explore Domain Design**: Learn about [Domain-Driven Design](../architecture/domain-design.md)
4. **Set Up Development**: Follow the [Development Guide](../development/README.md)
5. **Learn Testing**: Review the [Testing Strategy](../architecture/testing-strategy.md)
6. **Deploy to Production**: Review the [Deployment Guide](../deployment/overview.md)

## Support

- **Documentation**: Check the [Reference](../reference/) section
- **Issues**: Report bugs on [GitHub Issues](https://github.com/hdkhosravian/cedrina/issues)
- **Discussions**: Join the [GitHub Discussions](https://github.com/hdkhosravian/cedrina/discussions)
- **Security**: Follow the [Security Policy](https://github.com/hdkhosravian/cedrina/security/policy)

---

*Last updated: January 2025* 