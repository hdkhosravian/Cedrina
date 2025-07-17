# Development Guide

This guide provides comprehensive information for developers working on Cedrina, covering development philosophy, workflow, best practices, and tools based on the actual codebase implementation.

## 🎯 Development Philosophy

### Test-Driven Development (TDD)
Cedrina follows a strict **double-loop TDD** approach where acceptance tests drive unit test design:

```
┌─────────────────────────────────────────────────────────────┐
│                Double-Loop TDD Workflow                    │
├─────────────────────────────────────────────────────────────┤
│  Outer Loop: Acceptance Tests                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. Write Failing Acceptance Test                   │   │
│  │    • Define business requirement                   │   │
│  │    • Write end-to-end test that fails             │   │
│  │    • Focus on user behavior                       │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Inner Loop: Unit Tests                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 2. Write Failing Unit Test                         │   │
│  │    • Define component behavior                     │   │
│  │    • Write focused unit test                       │   │
│  │    • Mock external dependencies                    │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ 3. Write Minimal Code                              │   │
│  │    • Implement to make test pass                   │   │
│  │    • Keep implementation simple                    │   │
│  │    • Focus only on current test                    │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ 4. Refactor Code                                   │   │
│  │    • Improve code quality                          │   │
│  │    • Apply SOLID principles                        │   │
│  │    • Maintain all tests passing                    │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Repeat Inner Loop Until Acceptance Test Passes          │
│  Then Move to Next Acceptance Test                      │
└─────────────────────────────────────────────────────────────┘
```

### Domain-Driven Design (DDD)
- **Ubiquitous Language**: Code and documentation use consistent business terminology
- **Bounded Contexts**: Authentication, Authorization, User Management, Security
- **Aggregates**: User (aggregate root), Session, TokenFamily
- **Value Objects**: Email, Username, Password, JWT tokens
- **Domain Events**: UserLoggedInEvent, PasswordChangedEvent, SecurityIncidentEvent

### Clean Architecture
- **Dependency Rule**: Dependencies point inward (Infrastructure → Domain)
- **Independence**: Domain layer is independent of frameworks
- **Testability**: Each layer can be tested independently
- **Maintainability**: Changes in one layer don't affect others

### SOLID Principles
- **Single Responsibility**: Each class has one reason to change
- **Open/Closed**: Open for extension, closed for modification
- **Liskov Substitution**: Derived classes can substitute base classes
- **Interface Segregation**: Clients depend only on interfaces they use
- **Dependency Inversion**: Depend on abstractions, not concretions

## 🛠️ Development Workflow

### 1. Environment Setup

```bash
# Clone repository
git clone https://github.com/hdkhosravian/cedrina.git
cd cedrina

# Install dependencies
poetry install

# Set up pre-commit hooks
pre-commit install

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Set up database
make db-init
make db-migrate

# Run tests to verify setup
make test
```

### 2. Development Process

#### Feature Development (TDD Example)
```bash
# Create feature branch
git checkout -b feature/password-reset-functionality

# Write acceptance test first
pytest tests/feature/auth/test_password_reset_flow.py::test_forgot_password_workflow

# Write unit tests for domain service
pytest tests/unit/domain/services/authentication/test_password_reset_service.py

# Implement domain service following TDD
# Follow Red → Green → Refactor cycle

# Implement infrastructure layer
pytest tests/unit/infrastructure/services/test_password_reset_email_service.py

# Implement API layer
pytest tests/unit/adapters/api/v1/auth/test_password_reset_routes.py

# Run all tests
make test

# Check code quality
make lint
make type-check

# Commit changes
git add .
git commit -m "feat: implement password reset functionality

- Add PasswordResetService domain service
- Implement email confirmation service
- Add comprehensive test coverage (95%+)
- Follow TDD and DDD principles
- Include security logging and audit trails"
```

#### Bug Fixes (Real Example)
```bash
# Create bug fix branch
git checkout -b fix/jwt-token-validation-edge-case

# Write failing test that reproduces bug
pytest tests/unit/infrastructure/services/authentication/test_jwt_service.py::test_token_validation_with_malformed_payload

# Fix the bug in JWT service
# Ensure test passes

# Add regression test
pytest tests/unit/infrastructure/services/authentication/test_jwt_service.py::test_token_validation_regression

# Run full test suite
make test

# Commit fix
git commit -m "fix: resolve JWT token validation edge case

- Fix token validation logic in JWTService
- Add regression test to prevent recurrence
- Update security logging for malformed tokens
- Follow TDD principles"
```

### 3. Code Review Process

#### Before Submitting PR
```bash
# Run all quality checks
make quality-check

# Ensure all tests pass with coverage
pytest --cov=src --cov-report=html --cov-fail-under=50

# Update documentation
# Add/update relevant docstrings and comments

# Check for security issues
bandit -r src/

# Verify performance
pytest tests/performance/

# Run security tests
pytest tests/security/
```

#### PR Checklist
- [ ] All tests pass (unit, integration, feature, security)
- [ ] Code coverage > 50% (95%+ for critical components)
- [ ] Code follows PEP 8 and project style guide
- [ ] Type hints are complete and accurate
- [ ] Documentation is updated
- [ ] Security implications are considered
- [ ] Performance impact is assessed
- [ ] DDD principles are followed
- [ ] SOLID principles are maintained
- [ ] No security vulnerabilities detected
- [ ] Rate limiting and input validation implemented

## 🧪 Testing Strategy

### Test Categories

#### 1. Unit Tests (70-80%)
**Purpose**: Test individual components in isolation
**Location**: `tests/unit/`
**Characteristics**:
- Fast execution (<1ms per test)
- No external dependencies
- Focused on single responsibility
- High coverage of business logic

```python
# Real example from codebase
@pytest.mark.asyncio
async def test_change_password_success(self, service, mock_user_repository, mock_event_publisher, mock_user):
    """Test successful password change."""
    # Arrange
    user_id = 1
    old_password = "OldStr0ng!Key"
    new_password = "NewStr0ng!Key"
    correlation_id = str(uuid.uuid4())

    mock_user_repository.get_by_id.return_value = mock_user
    mock_user_repository.save.return_value = mock_user

    # Act
    await service.change_password(
        user_id=user_id,
        old_password=old_password,
        new_password=new_password,
        language="en",
        client_ip="192.168.1.1",
        user_agent="Test Browser",
        correlation_id=correlation_id
    )
    
    # Assert
    mock_user_repository.get_by_id.assert_called_once_with(user_id)
    mock_user_repository.save.assert_called_once()
    mock_event_publisher.publish.assert_called_once()
```

#### 2. Integration Tests (15-20%)
**Purpose**: Test component interactions
**Location**: `tests/integration/`
**Characteristics**:
- Test component boundaries
- Use test database
- Mock external services
- Verify data flow

```python
# Real example from codebase
@pytest.mark.asyncio
async def test_user_registration_with_email_confirmation(async_client, monkeypatch):
    """Test complete user registration flow with email confirmation."""
    # Mock email service
    mock_email_service = AsyncMock()
    monkeypatch.setattr(
        "src.infrastructure.services.email_confirmation_email_service.EmailConfirmationEmailService.send_confirmation_email", 
        mock_email_service
    )
    
    # Test data
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "SecurePass123!"
    }
    
    # Act
    response = await async_client.post("/api/v1/auth/register", json=user_data)
    
    # Assert
    assert response.status_code == 201
    mock_email_service.assert_called_once()
```

#### 3. Feature Tests (5-10%)
**Purpose**: Test complete user journeys
**Location**: `tests/feature/`
**Characteristics**:
- End-to-end user scenarios
- Real-world usage patterns
- Business requirement validation
- BDD-style specifications

```python
# Real example from codebase
@pytest.mark.asyncio
async def test_complete_authentication_workflow(async_client):
    """Test complete authentication workflow from registration to login."""
    # Given: User registration
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "SecurePass123!"
    }
    register_response = await async_client.post("/api/v1/auth/register", json=user_data)
    assert register_response.status_code == 201
    
    # When: User logs in
    login_data = {
        "username": "testuser",
        "password": "SecurePass123!"
    }
    login_response = await async_client.post("/api/v1/auth/login", json=login_data)
    
    # Then: Login succeeds with tokens
    assert login_response.status_code == 200
    response_data = login_response.json()
    assert "tokens" in response_data
    assert "user" in response_data
```

#### 4. End-to-End Tests (<5%)
**Purpose**: Test full system workflows
**Location**: `tests/e2e/`
**Characteristics**:
- Production-like environment
- External service integration
- Performance testing
- Security testing

### Advanced Testing Techniques

#### Property-Based Testing
```python
# Example using Hypothesis
from hypothesis import given, strategies as st

@given(st.text(min_size=3, max_size=50, alphabet=st.characters(whitelist_categories=('L', 'N'))))
def test_username_validation_property(username):
    """Test username validation with property-based testing."""
    try:
        Username(username)
        # Valid username should not raise exception
    except ValueError:
        # Invalid username should raise ValueError
        pass
```

#### Chaos Testing
```python
@pytest.mark.asyncio
async def test_database_connection_failure_handling():
    """Test system behavior when database is unavailable."""
    # Arrange: Simulate database failure
    with patch('src.infrastructure.database.database.engine') as mock_engine:
        mock_engine.execute.side_effect = Exception("Database connection failed")
        
        # Act & Assert: System should handle failure gracefully
        with pytest.raises(AuthenticationError):
            await auth_service.authenticate_user(username, password)
```

#### Security Testing
```python
@pytest.mark.asyncio
async def test_brute_force_attack_detection(async_client):
    """Test rate limiting and brute force detection."""
    # Attempt multiple failed logins
    for i in range(10):
        response = await async_client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "WrongPassword123!"
        })
        
        if i < 5:
            assert response.status_code == 401
        else:
            # Should be rate limited after 5 attempts
            assert response.status_code == 429
```

## 🏗️ Domain-Driven Design Implementation

### 1. Domain Entities (Real Examples)

```python
# Real User entity from codebase
class User(SQLModel, table=True):
    """Represents a User entity and acts as an Aggregate Root."""
    
    id: Optional[int] = Field(primary_key=True)
    username: str = Field(unique=True, index=True)
    email: EmailStr = Field(unique=True, index=True)
    hashed_password: Optional[str] = Field()
    role: Role = Field(default=Role.USER)
    is_active: bool = Field(default=True)
    email_confirmed: bool = Field(default_factory=lambda: True)
    created_at: datetime = Field()
    updated_at: Optional[datetime] = Field()
    password_reset_token: Optional[str] = Field()
    password_reset_token_expires_at: Optional[datetime] = Field()
    email_confirmation_token: Optional[str] = Field()
    
    def verify_password(self, password: str) -> bool:
        """Verify a password against the user's hashed password."""
        if not self.hashed_password:
            return False
        
        try:
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            return pwd_context.verify(password, self.hashed_password)
        except Exception:
            return False
    
    def set_password(self, password: str) -> None:
        """Set a new password for the user."""
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.hashed_password = pwd_context.hash(password)
```

### 2. Value Objects (Real Examples)

```python
# Real Email value object from codebase
@dataclass(frozen=True, slots=True)
class Email:
    """Immutable email address with comprehensive validation."""
    
    value: str
    MAX_LENGTH: ClassVar[int] = 254
    MIN_LENGTH: ClassVar[int] = 5
    EMAIL_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    BLOCKED_DOMAINS: ClassVar[set] = {
        "10minutemail.com", "tempmail.org", "guerrillamail.com"
    }
    
    def __post_init__(self):
        """Performs validation and normalization after initialization."""
        normalized_value = self.value.strip().lower()
        object.__setattr__(self, "value", normalized_value)
        
        self._validate_length(normalized_value)
        self._validate_format(normalized_value)
        self._validate_domain(normalized_value)
    
    def mask_for_logging(self) -> str:
        """Returns a masked version of the email for safe logging."""
        local, domain_part = self.value.split("@")
        masked_local = f"{local[:2]}{'*' * (len(local) - 2)}"
        masked_domain = f"{domain_part[:1]}{'*' * (len(domain_part) - 2)}{domain_part[-1:]}"
        return f"{masked_local}@{masked_domain}"
```

### 3. Domain Services (Real Examples)

```python
# Real domain service from codebase
class PasswordChangeService(IPasswordChangeService, BaseAuthenticationService):
    """Clean architecture password change service following DDD principles."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        event_publisher: IEventPublisher,
    ):
        super().__init__(event_publisher)
        self._user_repository = user_repository
    
    async def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Change user password with comprehensive security validation."""
        # Generate correlation ID if not provided
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        context = ServiceContext(
            correlation_id=correlation_id,
            language=language,
            client_ip=client_ip,
            user_agent=user_agent,
            operation="password_change"
        )
        
        async with self._operation_context(context) as ctx:
            # Step 1: Validate input parameters
            self._validate_required_parameters({
                "old_password": old_password,
                "new_password": new_password
            }, ctx)
            
            # Step 2: Retrieve and validate user
            user = await self._get_and_validate_user(user_id, ctx)
            
            # Step 3: Create domain value objects
            old_password_obj = Password(old_password)
            new_password_obj = Password(new_password)
            
            # Step 4: Verify old password
            await self._verify_old_password(user, old_password_obj, ctx)
            
            # Step 5: Check password reuse
            self._check_password_reuse(old_password_obj, new_password_obj, ctx)
            
            # Step 6: Update user password
            await self._update_user_password(user, new_password_obj, ctx)
            
            # Step 7: Publish domain event
            await self._publish_password_changed_event(user, ctx)
```

## 🔧 Code Quality Tools

### 1. Linting and Formatting

```bash
# Run all quality checks
make quality-check

# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/
```

### 2. Security Analysis

```bash
# Security scanning
bandit -r src/

# Dependency vulnerability check
safety check

# License compliance
pip-licenses
```

### 3. Performance Analysis

```bash
# Performance testing
pytest tests/performance/

# Memory profiling
python -m memory_profiler src/main.py

# CPU profiling
python -m cProfile -o profile.stats src/main.py
```

## 📊 Performance Optimization

### 1. Database Optimization

```python
# Real optimized query from codebase
class UserRepository(IUserRepository):
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID with proper validation and error handling."""
        if user_id <= 0:
            logger.warning("Invalid user ID provided", user_id=user_id)
            raise ValueError("User ID must be a positive integer")

        try:
            if self.session_factory:
                async with self.session_factory.create_session() as session:
                    statement = select(User).where(User.id == user_id)
                    result = await session.execute(statement)
                    user = result.scalars().first()
            else:
                statement = select(User).where(User.id == user_id)
                result = await self.db_session.execute(statement)
                user = result.scalars().first()

            return user
        except Exception as e:
            logger.error("Error retrieving user by ID", user_id=user_id, error=str(e))
            raise
```

### 2. Async/Await Optimization

```python
# Real async implementation from codebase
class JWTService(ITokenService, BaseInfrastructureService):
    async def create_access_token(self, user: User, family_id: Optional[str] = None) -> AccessToken:
        """Creates a new JWT access token for a user."""
        operation = "create_access_token"
        
        try:
            # Validate required parameters
            if not user or not user.is_active:
                raise AuthenticationError("User must be active for token creation")
            
            # Generate unique token ID
            jti = TokenId.generate().value
            
            # Calculate expiration time
            expires_in = self._get_config_value("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
            exp_time = datetime.now(timezone.utc) + timedelta(minutes=expires_in)
            
            # Create token payload
            payload = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "iss": settings.JWT_ISSUER,
                "aud": settings.JWT_AUDIENCE,
                "exp": int(exp_time.timestamp()),
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "jti": jti
            }
            
            if family_id:
                payload["family_id"] = family_id
            
            # Sign token with RS256 algorithm
            token_string = jwt.encode(
                payload,
                settings.JWT_PRIVATE_KEY.get_secret_value(),
                algorithm="RS256"
            )
            
            return AccessToken(token=token_string, claims=payload)
            
        except Exception as e:
            raise self._handle_infrastructure_error(error=e, operation=operation, user_id=user.id if user else None)
```

## 🐛 Debugging and Troubleshooting

### 1. Debugging Tools

```python
# Real debugging setup from codebase
import structlog

logger = structlog.get_logger(__name__)

class BaseAuthenticationService(ABC):
    def __init__(self, event_publisher: Optional[IEventPublisher] = None):
        self._event_publisher = event_publisher
        self._metrics = ServiceMetrics()
        self._logger = structlog.get_logger(self.__class__.__name__)
        
        self._logger.info(
            f"{self.__class__.__name__} initialized",
            service_type="domain_service",
            base_class="BaseAuthenticationService"
        )
    
    @asynccontextmanager
    async def _operation_context(self, context: ServiceContext):
        """Context manager for service operations with consistent logging and error handling."""
        start_time = time.time()
        operation_logger = self._create_operation_logger(context)
        
        try:
            operation_logger.info(
                f"{context.operation} operation started",
                correlation_id=context.correlation_id,
                client_ip=self._mask_ip(context.client_ip),
                user_agent_length=len(context.user_agent) if context.user_agent else 0
            )
            
            yield context
            
            # Log successful completion
            response_time_ms = (time.time() - start_time) * 1000
            self._metrics.update_metrics(True, response_time_ms)
            
            operation_logger.info(
                f"{context.operation} operation completed successfully",
                correlation_id=context.correlation_id,
                response_time_ms=round(response_time_ms, 2)
            )
            
        except Exception as e:
            # Log unexpected errors
            response_time_ms = (time.time() - start_time) * 1000
            self._metrics.update_metrics(False, response_time_ms)
            
            operation_logger.error(
                f"{context.operation} operation failed with unexpected error",
                correlation_id=context.correlation_id,
                error_type=type(e).__name__,
                error_message=str(e),
                response_time_ms=round(response_time_ms, 2)
            )
            
            raise AuthenticationError("Service unavailable") from e
```

### 2. Common Issues and Solutions

#### Database Connection Issues
```bash
# Check database connectivity
python -c "from src.infrastructure.database import get_db; print('DB OK')"

# Check connection pool
python -c "from src.infrastructure.database import engine; print(engine.pool.status())"

# Run database health check
make check-health
```

#### Authentication Issues
```bash
# Test JWT token generation
python -c "from src.infrastructure.services.authentication import JWTService; print('JWT OK')"

# Verify token validation
python -c "from src.domain.services.authentication import AuthService; print('Auth OK')"

# Check rate limiting
python -c "from src.core.rate_limiting import get_limiter; print('Rate Limiting OK')"
```

#### Performance Issues
```bash
# Profile slow queries
export SQLALCHEMY_ECHO=true
pytest tests/unit/ -v

# Monitor memory usage
python -m memory_profiler src/main.py

# Check rate limiting performance
pytest tests/performance/rate_limiting/
```

## 🔄 Continuous Integration

### 1. GitHub Actions Workflow

```yaml
# Real CI workflow from codebase
name: CI/CD Pipeline

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: cedrina_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'
    
    - name: Install dependencies
      run: |
        pip install poetry
        poetry install
    
    - name: Run tests
      run: |
        poetry run pytest --cov=src --cov-report=xml --cov-fail-under=50
    
    - name: Run linting
      run: |
        poetry run flake8 src/ tests/
        poetry run black --check src/ tests/
        poetry run isort --check-only src/ tests/
    
    - name: Run type checking
      run: |
        poetry run mypy src/
    
    - name: Run security checks
      run: |
        poetry run bandit -r src/
        poetry run safety check
```

### 2. Code Review Process

#### Automated Checks
- [ ] All tests pass (unit, integration, feature, security)
- [ ] Code coverage > 50% (95%+ for critical components)
- [ ] No linting errors
- [ ] Type checking passes
- [ ] Security scan clean
- [ ] Performance tests pass

#### Manual Review
- [ ] Code follows DDD principles
- [ ] SOLID principles maintained
- [ ] Documentation updated
- [ ] Security implications considered
- [ ] Performance impact assessed
- [ ] Rate limiting implemented
- [ ] Input validation added
- [ ] Error handling comprehensive

## 📚 Additional Resources

- **[Architecture Overview](../architecture/overview.md)** - System architecture and design principles
- **[Domain Design](../architecture/domain-design.md)** - Domain-Driven Design implementation
- **[Testing Strategy](../architecture/testing-strategy.md)** - Comprehensive testing approach
- **[Security Architecture](../architecture/security-architecture.md)** - Security implementation details
- **[API Development](api-development.md)** - API design and implementation
- **[Database Migrations](database-migrations.md)** - Schema evolution and migrations
- **[Performance Optimization](performance.md)** - Performance tuning and monitoring
- **[TDD Workflow](tdd-workflow.md)** - Test-Driven Development practices
- **[DDD Implementation](ddd-implementation.md)** - Domain-Driven Design patterns

## 🎯 Best Practices Summary

### Development Workflow
1. **TDD First**: Always write tests before implementation
2. **Domain Focus**: Keep business logic in domain layer
3. **Security First**: Implement security at every layer
4. **Performance Aware**: Consider performance implications
5. **Documentation**: Keep documentation current

### Code Quality
1. **SOLID Principles**: Follow SOLID principles strictly
2. **Clean Code**: Write readable, maintainable code
3. **Type Safety**: Use comprehensive type hints
4. **Error Handling**: Implement proper error handling
5. **Logging**: Use structured logging with correlation IDs

### Testing Strategy
1. **Test Pyramid**: Follow 70-20-10 test distribution
2. **Real-World Scenarios**: Test production-like conditions
3. **Security Testing**: Include security tests in CI/CD
4. **Performance Testing**: Monitor performance regressions
5. **Property-Based Testing**: Use for edge case discovery

### Security Practices
1. **Input Validation**: Validate all inputs thoroughly
2. **Rate Limiting**: Implement rate limiting for all endpoints
3. **Audit Logging**: Log all security-relevant events
4. **Token Security**: Implement secure token management
5. **Data Protection**: Encrypt sensitive data

---

*Last updated: January 2025* 