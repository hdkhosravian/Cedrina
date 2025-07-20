# Cedrina - Advanced Authentication & Authorization Platform

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.113+-green.svg)](https://fastapi.tiangolo.com/)
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
- **Rate Limiting**: Sophisticated rate limiting with multiple algorithms and bypass detection

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
- Python 3.12+
- PostgreSQL 16+
- Redis 7.2+ (optional, for rate limiting)
- Docker & Docker Compose (optional)

### **Quick Start with Docker**

```bash
# Clone the repository
git clone https://github.com/hdkhosravian/cedrina.git
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
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install dependencies
poetry install

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
make db-migrate

# Start the application
make run-dev-local
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
  "password": "SecurePassword123!"
}

# User Login
POST /api/v1/auth/login
{
  "username": "john_doe",
  "password": "SecurePassword123!"
}

# Refresh Token
POST /api/v1/auth/refresh
Headers: 
  Authorization: Bearer <access_token>
  X-Refresh-Token: <refresh_token>
Body: {}

# OAuth Authentication
POST /api/v1/auth/oauth
{
  "provider": "google",
  "token": {
    "access_token": "...",
    "expires_at": 1640995200
  }
}

# Password Reset
POST /api/v1/auth/forgot-password
{
  "email": "john@example.com"
}

# Change Password
PUT /api/v1/auth/change-password
Headers: Authorization: Bearer <access_token>
{
  "old_password": "OldPass123!",
  "new_password": "NewPass456!"
}

# Logout
POST /api/v1/auth/logout
{
  "refresh_token": "..."
}

# Confirm Email
GET /api/v1/auth/confirm-email?token=...

# Resend Confirmation
POST /api/v1/auth/resend-confirmation
{
  "email": "john@example.com"
}
```

### **System Endpoints**

```bash
# Health Check (Admin only)
GET /api/v1/health
Headers: Authorization: Bearer <admin_access_token>

# Metrics (Admin only)
GET /api/v1/metrics
Headers: Authorization: Bearer <admin_access_token>
```

## 🧪 Testing

### **Run All Tests**

```bash
# Run with coverage
make test

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
GET /api/v1/health
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
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### **Development Commands**

```bash
# Run tests
make test

# Format code
make format

# Run linting
make lint

# Database operations
make db-migrate
make db-rollback

# Start development server
make run-dev-local
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
- [SECURITY TODO](docs/security/SECURITY_IMPROVEMENT_PLAN.md) - Security Update planning

## 📚 Documentation

### **Getting Started**
- [Quick Start Guide](docs/getting-started/quick-start.md) - Get up and running quickly
- [Installation Guide](docs/getting-started/installation-guide.md) - Detailed setup instructions
- [Configuration Guide](docs/getting-started/configuration-guide.md) - Complete configuration reference

### **Architecture & Design**
- [Architecture Overview](docs/architecture/overview.md) - System design and principles
- [Domain Design](docs/architecture/domain-design.md) - Domain-Driven Design implementation
- [Security Architecture](docs/architecture/security-architecture.md) - Security patterns and features
- [Testing Strategy](docs/architecture/testing-strategy.md) - Comprehensive testing approach

### **Features & Functionality**
- [Features Overview](docs/features/README.md) - Complete feature overview and integration
- [Authentication System](docs/features/authentication/README.md) - User authentication flows
- [Authorization System](docs/features/authorization/README.md) - Access control and permissions
- [Token Management](docs/features/token-management/README.md) - JWT and session handling
- [Email Services](docs/features/email-services/README.md) - Email confirmation and notifications
- [Rate Limiting](docs/features/rate-limiting/README.md) - Abuse prevention and protection

### **Development & Deployment**
- [Development Guide](docs/development/README.md) - Development workflow and best practices
- [Feature Development Framework](docs/development/feature-development.md) - Comprehensive enterprise feature implementation methodology
- [API Reference](docs/reference/api-reference.md) - Complete API documentation
- [Database Schema](docs/reference/database-schema.md) - Database schema reference
- [Error Codes](docs/reference/error-codes.md) - Error handling reference

### **Advanced Topics**
- [Security Overview](docs/security/overview.md) - Security guidelines and recommendations
- [Performance Optimization](docs/advanced/) - Scaling and optimization techniques
- [Monitoring & Observability](docs/advanced/) - Health checks and metrics

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**

```bash
# Install development dependencies
poetry install --with dev

# Set up pre-commit hooks
pre-commit install

# Run linting
make lint

# Run type checking
mypy src/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/](docs/) - Comprehensive guides and references
- **Issues**: [GitHub Issues](https://github.com/hdkhosravian/cedrina/issues)
- **Security**: [SECURITY.md](SECURITY.md)

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) for the excellent web framework
- [SQLModel](https://sqlmodel.tiangolo.com/) for type-safe database operations
- [Pydantic](https://pydantic-docs.helpmanual.io/) for data validation
- [Alembic](https://alembic.sqlalchemy.org/) for database migrations
- [Casbin](https://casbin.org/) for authorization management
