# Architecture Overview

Cedrina implements a sophisticated **Domain-Driven Design (DDD)** architecture with **Clean Architecture** principles, **Test-Driven Development (TDD)**, and advanced security patterns. This architecture ensures separation of concerns, testability, maintainability, and production-grade scalability.

## 🏗️ Layered Architecture

Cedrina implements a four-layer architecture following the dependency inversion principle with clear boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                    Interface Layer                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   REST API      │  │   WebSockets    │  │   CLI       │ │
│  │   Controllers   │  │   Handlers      │  │   Commands  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Core Layer                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │  Application    │  │   Middleware    │  │   Lifecycle │ │
│  │   Services      │  │   Components    │  │   Management│ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Domain Layer                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Entities      │  │   Value Objects │  │   Services  │ │
│  │   Aggregates    │  │   Domain Events │  │   Repositories│ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Infrastructure Layer                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Database      │  │   External      │  │   Caching   │ │
│  │   Repositories  │  │   Services      │  │   & Storage │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

#### 1. Interface Layer (`src/adapters/`)
- **Purpose**: Handles external communication and data transformation
- **Components**:
  - REST API controllers and route handlers (`src/adapters/api/v1/auth/routes/`)
  - WebSocket handlers for real-time communication (`src/adapters/websockets/`)
  - Request/response DTOs and validation (`src/adapters/api/v1/auth/schemas/`)
  - Environment-based access control for documentation endpoints
- **Dependencies**: Core layer only
- **Key Features**:
  - Thin controllers focusing on HTTP concerns
  - Centralized error handling with I18N support
  - Security context extraction and validation
  - Request/response transformation

#### 2. Core Layer (`src/core/`)
- **Purpose**: Orchestrates business workflows and manages application state
- **Components**:
  - Application factory and lifecycle management (`src/core/application.py`)
  - Middleware components (authentication, rate limiting, logging)
  - Dependency injection and configuration management
  - Exception handlers and error standardization
- **Dependencies**: Domain layer only
- **Key Features**:
  - Factory pattern for application creation
  - Comprehensive middleware stack
  - Structured logging with security context
  - Rate limiting with advanced algorithms

#### 3. Domain Layer (`src/domain/`)
- **Purpose**: Contains business logic and domain rules
- **Components**:
  - **Entities**: Business objects with identity (`src/domain/entities/`)
  - **Value Objects**: Immutable domain concepts (`src/domain/value_objects/`)
  - **Domain Services**: Complex business operations (`src/domain/services/`)
  - **Repository Interfaces**: Data access contracts (`src/domain/interfaces/`)
  - **Domain Events**: Event-driven communication (`src/domain/events/`)
- **Dependencies**: None (pure business logic)
- **Key Features**:
  - Rich domain models with business rules
  - Immutable value objects for data integrity
  - Domain events for loose coupling
  - Repository pattern for data access abstraction

#### 4. Infrastructure Layer (`src/infrastructure/`)
- **Purpose**: Implements technical concerns and external integrations
- **Components**:
  - Database repositories and ORM models (`src/infrastructure/repositories/`)
  - External service integrations (OAuth, email) (`src/infrastructure/services/`)
  - Database connection management (`src/infrastructure/database/`)
  - Security implementations (JWT, encryption)
- **Dependencies**: Domain layer interfaces
- **Key Features**:
  - SQLAlchemy async/await support
  - Repository pattern implementations
  - External service adapters
  - Connection pooling and health checks

## 🎯 Architecture Principles

### Clean Architecture
- **Dependency Rule**: Dependencies point inward, with the domain layer at the center
- **Independence**: Domain layer is independent of frameworks and external concerns
- **Testability**: Each layer can be tested independently
- **Maintainability**: Changes in one layer don't affect others

### Domain-Driven Design (DDD)
- **Ubiquitous Language**: Code and documentation use consistent business terminology
- **Bounded Contexts**: Clear boundaries between different domain areas
- **Aggregates**: Transactional boundaries for data consistency
- **Value Objects**: Immutable objects representing domain concepts
- **Domain Events**: Event-driven communication for loose coupling

### SOLID Principles
- **Single Responsibility**: Each class has one reason to change
- **Open/Closed**: Open for extension, closed for modification
- **Liskov Substitution**: Derived classes can substitute base classes
- **Interface Segregation**: Clients depend only on interfaces they use
- **Dependency Inversion**: Depend on abstractions, not concretions

## 🔐 Security Architecture

### Defense-in-Depth
Cedrina implements multiple security layers with advanced threat detection:

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Layers                         │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Input Validation & Sanitization                 │
│  • Pydantic validation with custom validators             │
│  • Input sanitization and encoding                        │
│  • SQL injection prevention with parameterized queries    │
│  • XSS protection with output encoding                    │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Authentication & Authorization                  │
│  • Multi-factor authentication support                     │
│  • JWT token validation with RS256 algorithm              │
│  • Role-based access control (RBAC) with Casbin           │
│  • Attribute-based access control (ABAC)                  │
│  • Token family security for session management           │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Rate Limiting & Abuse Prevention               │
│  • Advanced rate limiting algorithms (token bucket,       │
│    sliding window, fixed window)                          │
│  • Brute force attack protection                          │
│  • DDoS mitigation with hierarchical quotas               │
│  • IP spoofing detection and prevention                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Data Protection                                │
│  • AES-256-GCM encryption for sensitive data             │
│  • Bcrypt password hashing with configurable work factor │
│  • Token family security with correlation tracking        │
│  • Secure session management with inactivity timeouts     │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Audit & Monitoring                             │
│  • Structured security events for SIEM integration       │
│  • Comprehensive audit logging with correlation IDs       │
│  • Real-time threat detection and response                │
│  • Privacy-compliant data handling                       │
└─────────────────────────────────────────────────────────────┘
```

### Advanced Security Features

#### Token Family Security
- **Database-Only Storage**: Eliminates Redis complexity for token management
- **Token Family Correlation**: Groups related tokens for security analysis
- **ACID Transactions**: Ensures consistency and data integrity
- **Advanced Threat Detection**: Real-time security monitoring

#### Rate Limiting Architecture
- **Multi-Algorithm Support**: Token bucket, sliding window, fixed window
- **Hierarchical Quotas**: Global, user, endpoint, and tier-based limits
- **Dynamic Configuration**: Environment-based rate limiting policies
- **Bypass Detection**: IP spoofing and header manipulation detection

#### Security Event System
- **Structured Events**: SIEM-compatible event format
- **Threat Intelligence**: Risk scoring and attack pattern detection
- **Privacy Compliance**: PII masking and data protection
- **Audit Trails**: Comprehensive logging for compliance

## 🗄️ Database Architecture

### Schema Design
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Users       │    │   OAuth Profiles│    │   Token Families│
│                 │    │                 │    │                 │
│ • id (PK)       │◄──►│ • user_id (FK)  │◄──►│ • user_id (FK)  │
│ • username      │    │ • provider      │    │ • family_id     │
│ • email         │    │ • provider_id   │    │ • token_hash    │
│ • password_hash │    │ • profile_data  │    │ • created_at    │
│ • is_active     │    │ • created_at    │    │ • expires_at    │
│ • created_at    │    └─────────────────┘    │ • is_revoked    │
└─────────────────┘                           └─────────────────┘
         │                                              │
         ▼                                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Sessions     │    │   Email Confirm │    │   Password Reset│
│                 │    │                 │    │                 │
│ • id (PK)       │    │ • id (PK)       │    │ • id (PK)       │
│ • user_id (FK)  │    │ • user_id (FK)  │    │ • user_id (FK)  │
│ • session_id    │    │ • token_hash    │    │ • token_hash    │
│ • ip_address    │    │ • expires_at    │    │ • expires_at    │
│ • user_agent    │    │ • is_confirmed  │    │ • is_used       │
│ • created_at    │    │ • created_at    │    │ • created_at    │
│ • last_activity │    └─────────────────┘    └─────────────────┘
└─────────────────┘
```

### Data Flow Patterns
1. **Command Query Responsibility Segregation (CQRS)**: Separate read and write models
2. **Event Sourcing**: Domain events for audit trails
3. **Optimistic Locking**: Concurrent modification handling
4. **Soft Deletes**: Data retention for compliance

### Database Features
- **PostgreSQL 16**: Advanced features and performance
- **Async/Await Support**: Non-blocking database operations
- **Connection Pooling**: Efficient connection management
- **Health Checks**: Database availability monitoring
- **Migration Management**: Alembic for schema evolution

## ⚡ Performance & Scalability

### Performance Optimizations
- **Async/Await**: Non-blocking I/O operations throughout
- **Connection Pooling**: Efficient database and Redis connection management
- **Query Optimization**: Indexed queries and efficient joins
- **Caching Strategy**: Multi-level caching with Redis
- **Compression**: Response compression for bandwidth efficiency

### Scalability Patterns
- **Horizontal Scaling**: Stateless application design
- **Database Sharding**: Partitioned data storage support
- **Load Balancing**: Multiple application instances
- **Microservices Ready**: Modular architecture for service decomposition

### Advanced Rate Limiting
- **Multi-Algorithm Support**: Token bucket, sliding window, fixed window
- **Hierarchical Quotas**: Global, user, endpoint, and tier-based limits
- **Dynamic Configuration**: Environment-based rate limiting policies
- **Performance Monitoring**: Real-time metrics and alerting

## 🔧 Configuration Architecture

### Environment-Based Configuration
```python
# Configuration hierarchy
1. Environment variables (highest priority)
2. Configuration files (.env)
3. Default values (lowest priority)
```

### Configuration Categories
- **Database**: Connection strings, pool settings, SSL configuration
- **Security**: JWT keys, encryption settings, rate limiting
- **OAuth**: Provider configurations for Google, Microsoft, Facebook
- **Email**: SMTP settings, templates, confirmation features
- **Rate Limiting**: Algorithm parameters, quotas, bypass rules
- **Monitoring**: Logging, metrics, health check settings

### Advanced Configuration Features
- **Type Safety**: Pydantic settings with validation
- **Secret Management**: Secure handling of sensitive configuration
- **Environment Detection**: Automatic configuration based on environment
- **Validation**: Comprehensive configuration validation

## 🧪 Testing Architecture

### Test Pyramid Implementation
```
┌─────────────────────────────────────────────────────────────┐
│                    Test Pyramid                            │
├─────────────────────────────────────────────────────────────┤
│  End-to-End Tests (<5%)                                   │
│  • Full system workflows                                  │
│  • Production-like environment                            │
│  • External integrations                                  │
├─────────────────────────────────────────────────────────────┤
│  Acceptance Tests (5-10%)                                 │
│  • Business scenario testing                              │
│  • User journey validation                               │
│  • BDD-style specifications                              │
├─────────────────────────────────────────────────────────────┤
│  Integration Tests (15-20%)                               │
│  • Component interaction testing                          │
│  • Database integration                                  │
│  • External service mocking                              │
├─────────────────────────────────────────────────────────────┤
│  Unit Tests (70-80%)                                      │
│  • Individual component testing                           │
│  • Fast execution (<1ms)                                 │
│  • Isolated dependencies                                 │
└─────────────────────────────────────────────────────────────┘
```

### Advanced Testing Features
- **TDD Workflow**: Test-first development approach
- **Property-Based Testing**: Systematic edge case exploration with Hypothesis
- **Performance Testing**: Load and stress testing with Locust
- **Security Testing**: Vulnerability assessment and penetration testing
- **Chaos Testing**: Failure mode simulation
- **Async Testing**: Comprehensive async/await testing support

### Test Categories
- **Unit Tests**: Domain logic, value objects, entities
- **Integration Tests**: Repository implementations, external services
- **Feature Tests**: End-to-end business scenarios
- **Security Tests**: Authentication, authorization, rate limiting
- **Performance Tests**: Load testing, stress testing
- **Chaos Tests**: Failure mode simulation

## 📊 Monitoring & Observability

### Metrics Collection
- **Application Metrics**: Request rates, response times, error rates
- **Business Metrics**: User registrations, authentication success rates
- **Infrastructure Metrics**: CPU, memory, disk usage
- **Security Metrics**: Failed login attempts, suspicious activities

### Logging Strategy
- **Structured Logging**: JSON-formatted logs with structlog
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Correlation IDs**: Request tracing across services
- **Audit Logging**: Security event tracking with privacy compliance

### Health Checks
- **Application Health**: Service availability and dependencies
- **Database Health**: Connection pool status and query performance
- **External Services**: OAuth provider availability
- **Custom Health Checks**: Business logic validation

### Advanced Monitoring Features
- **Security Event Correlation**: Real-time threat detection
- **Performance Monitoring**: Response time tracking and alerting
- **Error Tracking**: Comprehensive error classification and reporting
- **Business Intelligence**: User behavior and system usage analytics

## 🚀 Deployment Architecture

### Container Strategy
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Application   │    │   Database      │
│                 │    │   Containers    │    │   Cluster       │
│ • Nginx/HAProxy │◄──►│ • FastAPI App  │◄──►│ • PostgreSQL   │
│ • SSL Termination│    │ • Multiple      │    │ • Read Replicas│
│ • Rate Limiting │    │   Instances     │    │ • Connection    │
└─────────────────┘    └─────────────────┘    │   Pooling       │
                                              └─────────────────┘
         │                                              │
         ▼                                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Monitoring    │    │   Caching       │    │   Backup        │
│   Stack         │    │   Layer         │    │   System        │
│ • Prometheus    │    │ • Redis Cluster │    │ • Automated     │
│ • Grafana       │    │ • Session Store │    │   Backups       │
│ • Alerting      │    │ • Rate Limiting │    │ • Point-in-Time │
└─────────────────┘    └─────────────────┘    │   Recovery      │
                                              └─────────────────┘
```

### Environment Strategy
- **Development**: Local development with hot reloading
- **Staging**: Production-like environment for testing
- **Production**: High-availability deployment with monitoring

### Deployment Features
- **Docker Compose**: Multi-service orchestration
- **Health Checks**: Comprehensive service monitoring
- **Volume Management**: Persistent data storage
- **Network Isolation**: Secure service communication
- **Environment Configuration**: Environment-specific settings

## 🎯 Benefits of This Architecture

### Maintainability
- **Separation of Concerns**: Clear boundaries between layers
- **Testability**: Each layer can be tested independently
- **Modularity**: Components can be modified without affecting others
- **Documentation**: Self-documenting code structure

### Scalability
- **Horizontal Scaling**: Stateless application design
- **Performance**: Optimized database queries and caching
- **Reliability**: Fault-tolerant design with health checks
- **Monitoring**: Comprehensive observability

### Security
- **Defense-in-Depth**: Multiple security layers
- **Audit Trail**: Comprehensive logging and monitoring
- **Compliance**: Data protection and privacy features
- **Threat Detection**: Real-time security monitoring

### Developer Experience
- **Clear Structure**: Intuitive code organization
- **Fast Development**: Hot reloading and efficient tooling
- **Quality Assurance**: Automated testing and code quality tools
- **Documentation**: Comprehensive guides and examples

### Production Readiness
- **High Availability**: Fault-tolerant design
- **Performance**: Optimized for high-throughput scenarios
- **Security**: Enterprise-grade security features
- **Monitoring**: Comprehensive observability and alerting
- **Compliance**: Audit trails and data protection

---

*Last updated: January 2025* 