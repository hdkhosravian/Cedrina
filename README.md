# Cedrina - Advanced Authentication & Authorization Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7.2+-red.svg)](https://redis.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cedrina is a production-ready authentication and authorization platform built with FastAPI, featuring advanced security patterns, comprehensive audit trails, and enterprise-grade scalability. The platform implements a unified token architecture with database-only storage and advanced token family security patterns.

## 🚀 Key Features

### **Advanced Security Architecture**
- **Unified Token Architecture**: Database-only token and session management with token family security
- **Token Family Security**: Advanced reuse detection and family-wide revocation on compromise
- **Zero-Trust Validation**: Comprehensive token validation with threat detection
- **Defense-in-Depth**: Multi-layered security with encrypted storage and audit trails
- **Rate Limiting**: Sophisticated rate limiting with multiple algorithms and abuse prevention

### **Authentication & Authorization**
- **Multi-Provider OAuth**: Google, Microsoft, and Facebook integration
- **JWT Token Management**: RS256-signed access and refresh tokens with advanced security
- **Session Management**: Database-only session tracking with activity monitoring
- **Role-Based Access Control**: Granular permissions with Casbin integration
- **Password Security**: Bcrypt hashing with additional AES-256-GCM encryption layer

### **Enterprise Features**
- **Comprehensive Audit Logging**: Detailed security events and user activity tracking
- **Internationalization**: Multi-language support with Babel integration
- **Health Monitoring**: Real-time system health checks and performance metrics
- **Database Migrations**: Alembic-managed schema evolution
- **Container Support**: Docker and Docker Compose for easy deployment

## 🏗️ Architecture

### **Clean Architecture with DDD**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Adapters      │    │      Core       │    │    Domain       │
│                 │    │                 │    │                 │
│ • REST API      │◄──►│ • Application   │◄──►│ • Entities      │
│ • WebSockets    │    │ • Middleware    │    │ • Services      │
│ • External      │    │ • Lifecycle     │    │ • Value Objects │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │ Infrastructure  │
                       │                 │
                       │ • Database      │
                       │ • Repositories  │
                       │ • External      │
                       └─────────────────┘
```

### **Unified Token Architecture**
- **Database-Only Storage**: Eliminates Redis complexity for token/session management
- **Token Family Security**: Groups related tokens for security correlation and reuse detection
- **ACID Transactions**: Ensures consistency and data integrity
- **Advanced Threat Detection**: Real-time security monitoring and incident response
- **Performance Optimized**: Sub-millisecond response times for high-throughput applications

## 🔧 Core Components

### **Authentication System**
- **Username/Password**: Secure authentication with bcrypt hashing and AES encryption
- **OAuth 2.0**: Google, Microsoft, and Facebook integration with profile synchronization
- **JWT Tokens**: RS256-signed access and refresh tokens with token family security
- **Session Management**: Database-only session tracking with activity monitoring
- **Rate Limiting**: Protection against brute force attacks with multiple algorithms

### **Database & Storage**
- **PostgreSQL 16**: Primary database with connection pooling and ACID transactions
- **Redis 7.2**: Optional caching and rate limiting (no longer used for authentication)
- **Alembic**: Database migrations with version control
- **SQLModel**: Type-safe ORM with Pydantic integration

### **Security Features**
- **🔐 Defense-in-Depth**: Multi-layered security architecture with enterprise-grade implementations
- **🛡️ Token Family Security**: Advanced reuse detection and family-wide revocation
- **🔍 Comprehensive Auditing**: Detailed security events and forensic analysis
- **⚡ Performance Optimized**: Sub-millisecond response times for high-throughput applications
- **🌐 Internationalization**: Multi-language support with security-focused translations

## 📦 Installation

### **Prerequisites**
- Python 3.11+
- PostgreSQL 16+
- Redis 7.2+ (optional, for rate limiting)
- Docker & Docker Compose (optional)

### **Quick Start with Docker**

```bash
# Clone the repository
git clone https://github.com/your-org/cedrina.git
cd cedrina

# Start with Docker Compose
docker-compose up -d

# Run database migrations
docker-compose exec api alembic upgrade head

# Create admin user
docker-compose exec api python -m src.scripts.create_admin
```

### **Manual Installation**

```bash
# Clone the repository
git clone https://github.com/your-org/cedrina.git
cd cedrina

# Install dependencies
poetry install

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
alembic upgrade head

# Start the application
uvicorn src.main:app --reload
```

## 🔧 Configuration

### **Environment Variables**

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/cedrina
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=cedrina
POSTGRES_USER=cedrina
POSTGRES_PASSWORD=your_password

# Redis Configuration (optional for rate limiting)
REDIS_URL=redis://localhost:6379/0

# JWT Configuration
JWT_PRIVATE_KEY_PATH=/path/to/private.pem
JWT_PUBLIC_KEY_PATH=/path/to/public.pem
JWT_ISSUER=https://api.example.com
JWT_AUDIENCE=cedrina:api:v1

# OAuth Configuration
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
```

## 🚀 API Usage

### **Authentication Endpoints**

```bash
# User Registration
POST /api/v1/auth/register
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "secure_password"
}

# User Login
POST /api/v1/auth/login
{
  "username": "john_doe",
  "password": "secure_password"
}

# Refresh Token
POST /api/v1/auth/refresh
{
  "refresh_token": "your_refresh_token"
}

# OAuth Login
GET /api/v1/auth/oauth/google
GET /api/v1/auth/oauth/microsoft
GET /api/v1/auth/oauth/facebook

# Password Reset
POST /api/v1/auth/forgot-password
{
  "email": "john@example.com"
}

# Change Password
POST /api/v1/auth/change-password
{
  "current_password": "old_password",
  "new_password": "new_secure_password"
}
```

### **Protected Endpoints**

```bash
# Get current user
GET /api/v1/auth/me
Authorization: Bearer your_access_token

# Logout
POST /api/v1/auth/logout
Authorization: Bearer your_access_token

# Admin endpoints
GET /api/v1/admin/users
Authorization: Bearer admin_access_token
```

## 🧪 Testing

### **Run All Tests**

```bash
# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/feature/
```

### **Test Categories**

- **Unit Tests**: Individual component testing with mocked dependencies
- **Integration Tests**: End-to-end workflow testing
- **Feature Tests**: Complete user journey testing
- **Security Tests**: Authentication and authorization testing
- **Performance Tests**: Load and stress testing

## 📊 Monitoring & Health

### **Health Check**

```bash
GET /health
Authorization: Bearer admin_token

Response:
{
  "status": "ok",
  "env": "production",
  "message": "System operational",
  "services": {
    "database": {"status": "healthy"},
    "redis": {"status": "healthy"}
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Monitoring Scripts**

```bash
# Session monitoring
/usr/local/bin/monitor_sessions.sh

# Performance metrics
curl -H "Authorization: Bearer admin_token" /api/v1/admin/metrics
```

## 🔒 Security Features

### **Token Family Security**
- **Reuse Detection**: Identifies and responds to token reuse attacks
- **Family-wide Revocation**: Compromises entire families on security violations
- **Threat Pattern Analysis**: Detects sophisticated attack patterns
- **Audit Trail Generation**: Comprehensive logging for compliance

### **Advanced Security Patterns**
- **Zero-Trust Validation**: Validates all tokens with comprehensive security checks
- **Defense-in-Depth**: Multiple security layers with encrypted storage
- **Rate Limiting**: Sophisticated abuse prevention with multiple algorithms
- **Session Management**: Database-only storage with activity tracking

## 📚 Documentation

- [API Reference](docs/reference/api-reference.md)
- [Architecture Guide](docs/architecture/)
- [Security Guide](docs/security/)
- [Deployment Guide](docs/deployment/)
- [Development Guide](docs/development/)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**

```bash
# Install development dependencies
poetry install --with dev

# Set up pre-commit hooks
pre-commit install

# Run linting
flake8 src/
black src/
isort src/

# Run type checking
mypy src/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/cedrina/issues)
- **Security**: [SECURITY.md](SECURITY.md)

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
- [SQLModel](https://sqlmodel.tiangolo.com/) for type-safe database operations
- [Pydantic](https://pydantic-docs.helpmanual.io/) for data validation
- [Alembic](https://alembic.sqlalchemy.org/) for database migrations
- [Casbin](https://casbin.org/) for authorization management