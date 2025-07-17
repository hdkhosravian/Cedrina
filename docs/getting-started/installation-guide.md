# Installation Guide

This guide provides detailed installation instructions for Cedrina in various environments and scenarios.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Environment Setup](#environment-setup)
- [Configuration](#configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **Operating System**: Linux, macOS, or Windows (with WSL2 for Windows)
- **Python**: 3.12 or higher
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB free space
- **Network**: Internet connection for dependencies

### Recommended Requirements

- **CPU**: 4+ cores
- **Memory**: 16GB RAM
- **Storage**: SSD with 50GB free space
- **Network**: Stable internet connection

### Dependencies

#### Required
- **PostgreSQL 16+**: Database server
- **Python 3.12+**: Runtime environment
- **Poetry**: Dependency management (recommended)

#### Optional
- **Redis 7.2+**: Rate limiting and caching
- **Docker & Docker Compose**: Containerized deployment
- **Git**: Version control

## Installation Methods

### Method 1: Docker Installation (Recommended)

#### Prerequisites
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
```

#### Installation Steps
```bash
# Clone repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Create environment file
cp .env.example .env

# Edit environment variables
nano .env

# Build and start services
docker-compose up -d

# Wait for services to be healthy
docker-compose ps

# Run migrations
docker-compose exec app alembic upgrade head

# Verify installation
curl http://localhost:8000/api/v1/health
```

### Method 2: Local Installation

#### Prerequisites Installation

**Ubuntu/Debian:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.12
sudo apt install python3.12 python3.12-venv python3.12-dev

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Install Redis
sudo apt install redis-server

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Install build dependencies
sudo apt install build-essential libpq-dev
```

**macOS:**
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.12
brew install python@3.12

# Install PostgreSQL
brew install postgresql@16

# Install Redis
brew install redis

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -
```

**Windows (WSL2):**
```bash
# Install WSL2 and Ubuntu
wsl --install -d Ubuntu

# Follow Ubuntu instructions above
```

#### Installation Steps
```bash
# Clone repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Create environment file
cp .env.example .env

# Edit environment variables
nano .env

# Initialize database
make db-init

# Run migrations
make db-migrate

# Start development server
make run-dev-local
```

### Method 3: Production Installation

#### Prerequisites
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-dev postgresql postgresql-contrib redis-server nginx

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -
```

#### Installation Steps
```bash
# Clone repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install dependencies
poetry install --only=main

# Create production environment
cp .env.example .env.prod

# Edit production environment
nano .env.prod

# Set up database
make db-init

# Run migrations
make db-migrate

# Build production image
make build-prod

# Start production services
make run-prod
```

## Environment Setup

### Database Setup

#### PostgreSQL Configuration
```bash
# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql

CREATE DATABASE cedrina;
CREATE DATABASE cedrina_test;
CREATE USER cedrina WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE cedrina TO cedrina;
GRANT ALL PRIVILEGES ON DATABASE cedrina_test TO cedrina;
ALTER USER cedrina CREATEDB;
\q
```

#### Redis Configuration
```bash
# Start Redis service
sudo systemctl start redis
sudo systemctl enable redis

# Test Redis connection
redis-cli ping
```

### Security Setup

#### JWT Keys Generation
```bash
# Create keys directory
mkdir -p keys

# Generate private key
openssl genrsa -out keys/private.pem 2048

# Generate public key
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Set proper permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem
```

#### SSL Certificate (Production)
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Configuration

### Environment Variables

Create a `.env` file with the following structure:

```bash
# Application Configuration
APP_ENV=development
DEBUG=true
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key-here

# Database Configuration
DATABASE_URL=postgresql://cedrina:password@localhost:5432/cedrina
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=cedrina
POSTGRES_DB_TEST=cedrina_test
POSTGRES_USER=cedrina
POSTGRES_PASSWORD=your_secure_password
POSTGRES_SSL_MODE=prefer

# Redis Configuration
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

# Security Configuration
SESSION_INACTIVITY_TIMEOUT_MINUTES=30
MAX_CONCURRENT_SESSIONS_PER_USER=5
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_LIMIT=100
RATE_LIMIT_DEFAULT_WINDOW=60

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_TLS=true
SMTP_SSL=false

# OAuth Configuration (optional)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
FACEBOOK_CLIENT_ID=your_facebook_client_id
FACEBOOK_CLIENT_SECRET=your_facebook_client_secret

# Internationalization
DEFAULT_LOCALE=en
SUPPORTED_LOCALES=en,ar,es,fa
```

### Configuration Validation

```bash
# Validate environment configuration
poetry run python -c "
from src.core.config.app import AppConfig
from src.core.config.database import DatabaseConfig
config = AppConfig()
print('Configuration loaded successfully')
print(f'Database URL: {config.database.url}')
print(f'Redis URL: {config.redis.url}')
"
```

## Verification

### Health Check
```bash
# Check application health
curl http://localhost:8000/api/v1/health

# Expected response:
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

### API Documentation
```bash
# Check API documentation
curl http://localhost:8000/docs

# Check OpenAPI schema
curl http://localhost:8000/openapi.json
```

### Database Connection
```bash
# Test database connection
poetry run python -c "
from src.infrastructure.database.database import get_database
import asyncio

async def test_db():
    db = get_database()
    try:
        await db.connect()
        print('Database connection successful')
        await db.disconnect()
    except Exception as e:
        print(f'Database connection failed: {e}')

asyncio.run(test_db())
"
```

### Test Suite
```bash
# Run test suite
make test

# Run with coverage
poetry run pytest --cov=src --cov-report=html

# Check test results
open htmlcov/index.html
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
psql -h localhost -U cedrina -d cedrina -c "SELECT 1;"

# Check logs
sudo tail -f /var/log/postgresql/postgresql-16-main.log
```

#### 2. Redis Connection Issues
```bash
# Check Redis status
sudo systemctl status redis

# Test connection
redis-cli ping

# Check logs
sudo tail -f /var/log/redis/redis-server.log
```

#### 3. Permission Issues
```bash
# Fix file permissions
chmod 600 keys/private.pem
chmod 644 keys/public.pem
chmod 755 src/

# Fix directory permissions
sudo chown -R $USER:$USER .
```

#### 4. Port Conflicts
```bash
# Check port usage
sudo netstat -tulpn | grep :8000
sudo netstat -tulpn | grep :5432
sudo netstat -tulpn | grep :6379

# Kill conflicting processes
sudo kill -9 <PID>
```

#### 5. Memory Issues
```bash
# Check memory usage
free -h
docker stats

# Increase swap (if needed)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Performance Optimization

#### Database Optimization
```sql
-- Check slow queries
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;

-- Analyze table statistics
ANALYZE;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

#### Application Optimization
```bash
# Enable query logging
export SQLALCHEMY_ECHO=true

# Monitor application performance
poetry run uvicorn src.main:app --reload --log-level debug

# Check memory usage
ps aux | grep uvicorn
```

### Security Hardening

#### Firewall Configuration
```bash
# Configure UFW firewall
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 8000/tcp
sudo ufw allow 5432/tcp
sudo ufw allow 6379/tcp
sudo ufw status
```

#### SSL/TLS Configuration
```bash
# Generate self-signed certificate (development)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Configure Nginx (production)
sudo nano /etc/nginx/sites-available/cedrina
```

## Next Steps

After successful installation:

1. **Read the Architecture Documentation**: [Architecture Overview](../architecture/overview.md)
2. **Set Up Development Environment**: [Development Guide](../development/README.md)
3. **Configure Security**: [Security Architecture](../architecture/security-architecture.md)
4. **Learn Testing**: [Testing Strategy](../architecture/testing-strategy.md)
5. **Deploy to Production**: [Deployment Guide](../deployment/overview.md)

---

*Last updated: January 2025* 