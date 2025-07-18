# Getting Started with Cedrina

Welcome to Cedrina! This section provides everything you need to get up and running quickly.

## Quick Navigation

- **[Quick Start Guide](quick-start.md)** - Get Cedrina running in minutes
- **[Installation Guide](installation-guide.md)** - Detailed installation instructions
- **[Configuration Guide](configuration-guide.md)** - Complete configuration reference
- **[Troubleshooting Guide](troubleshooting.md)** - Solve common issues

## What is Cedrina?

Cedrina is an enterprise-grade FastAPI template designed for building scalable REST and real-time applications. It features:

- **🔐 Advanced Authentication**: JWT tokens, OAuth integration, session management
- **🛡️ Security-First**: Rate limiting, input validation, security headers
- **🏗️ Clean Architecture**: Domain-Driven Design, SOLID principles, hexagonal architecture
- **🧪 Test-Driven Development**: Comprehensive testing with real-world scenarios
- **🌍 Internationalization**: Multi-language support with Babel
- **📊 Monitoring**: Health checks, structured logging, performance metrics

## Choose Your Path

### 🚀 Quick Start (5 minutes)
If you want to get Cedrina running immediately:

1. **Clone the repository**
   ```bash
   git clone https://github.com/hdkhosravian/cedrina.git
   cd cedrina
   ```

2. **Start with Docker** (recommended)
   ```bash
   docker-compose up -d
   docker-compose exec app alembic upgrade head
   ```

3. **Verify installation**
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

4. **Explore the API**
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

### 🛠️ Development Setup (15 minutes)
For development work with full control:

1. **Install dependencies**
   ```bash
   poetry install
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Initialize database**
   ```bash
   make db-init
   make db-migrate
   ```

4. **Start development server**
   ```bash
   make run-dev-local
   ```

### 🏭 Production Deployment (30 minutes)
For production deployment:

1. **Follow the [Installation Guide](installation-guide.md)**
2. **Configure security settings**
3. **Set up monitoring and logging**
4. **Deploy with Docker or native installation**

## System Requirements

### Minimum Requirements
- **Python**: 3.12+
- **PostgreSQL**: 16+
- **Redis**: 7.2+ (optional)
- **Memory**: 4GB RAM
- **Storage**: 10GB free space

### Recommended Requirements
- **CPU**: 4+ cores
- **Memory**: 16GB RAM
- **Storage**: SSD with 50GB free space
- **Network**: Stable internet connection

## Key Features

### Authentication & Authorization
- JWT token-based authentication
- OAuth integration (Google, Microsoft, Facebook)
- Session management with inactivity timeout
- Role-based access control (RBAC)
- Attribute-based access control (ABAC)

### Security Features
- Rate limiting with Redis backend
- Input validation and sanitization
- Security headers and CORS protection
- Password policy enforcement
- Token family security

### Development Experience
- Hot reloading with uvicorn
- Comprehensive test suite
- Code quality tools (ruff, black, mypy)
- Docker development environment
- Makefile for common tasks

### Production Ready
- Health checks and monitoring
- Structured logging with structlog
- Database connection pooling
- SSL/TLS support
- Internationalization (i18n)

## Next Steps

After getting Cedrina running:

1. **📚 Read the Architecture**: [Architecture Overview](../architecture/overview.md)
2. **🔧 Configure Security**: [Security Architecture](../architecture/security-architecture.md)
3. **🧪 Learn Testing**: [Testing Strategy](../architecture/testing-strategy.md)
4. **🏗️ Understand Design**: [Domain Design](../architecture/domain-design.md)
5. **🚀 Deploy**: [Deployment Guide](../deployment/overview.md)

## Getting Help

### Documentation
- **Architecture**: [Architecture Overview](../architecture/overview.md)
- **Development**: [Development Guide](../development/README.md)
- **API Reference**: [API Reference](../reference/api-reference.md)

### Community
- **Issues**: [GitHub Issues](https://github.com/hdkhosravian/cedrina/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hdkhosravian/cedrina/discussions)
- **Security**: [Security Policy](https://github.com/hdkhosravian/cedrina/security/policy)

### Troubleshooting
- **Common Issues**: [Troubleshooting Guide](troubleshooting.md)
- **Configuration**: [Configuration Guide](configuration-guide.md)
- **Installation**: [Installation Guide](installation-guide.md)

## Examples

### Basic API Usage

```bash
# Register a user
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'

# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePassword123!"
  }'

# Access protected endpoint
curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer your_access_token_here"
```

### Development Commands

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

## Contributing

We welcome contributions! Please see our [Contributing Guide](../../CONTRIBUTING.md) for details.

## License

Cedrina is licensed under the MIT License. See the [LICENSE](../../LICENSE) file for details.

---

*Last updated: January 2025* 