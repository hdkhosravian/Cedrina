# Testing Strategy

This document describes the comprehensive testing strategy implemented in Cedrina, following advanced Test-Driven Development (TDD) principles and enterprise-grade testing standards.

## 🎯 Testing Philosophy

Cedrina follows a **Test-Driven Development (TDD)** approach with the following principles:

- **Test-First Development**: Write tests before implementing functionality
- **Red-Green-Refactor Cycle**: Fail → Pass → Improve
- **Comprehensive Coverage**: 95%+ coverage for critical components
- **Real-World Scenarios**: Tests mirror production conditions
- **Fast Execution**: Unit tests run in sub-millisecond time
- **Isolated Dependencies**: No external dependencies in unit tests

## 🏗️ Test Pyramid

### Unit Tests (70-80%)
**Purpose**: Test individual components in isolation.

**Characteristics**:
- **Speed**: Sub-millisecond execution
- **Isolation**: No external dependencies
- **Focus**: Single responsibility testing
- **Coverage**: Business logic and domain rules

**Examples**:
```python
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

### Integration Tests (15-20%)
**Purpose**: Test component interactions and external integrations.

**Characteristics**:
- **Database Integration**: Real database operations
- **External Services**: OAuth, email service testing
- **Repository Testing**: Data persistence validation
- **Middleware Testing**: Authentication, rate limiting

**Examples**:
```python
@pytest.mark.asyncio
async def test_user_registration_with_email_confirmation(async_client, monkeypatch):
    """Test complete user registration flow with email confirmation."""
    # Mock email service
    mock_email_service = AsyncMock()
    monkeypatch.setattr("src.infrastructure.services.email_confirmation_email_service.EmailConfirmationEmailService.send_confirmation_email", mock_email_service)
    
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

### Feature Tests (5-10%)
**Purpose**: Test end-to-end business scenarios.

**Characteristics**:
- **Real API Calls**: Full HTTP request/response testing
- **Business Workflows**: Complete user journeys
- **Production-Like**: Real database and external services
- **BDD Style**: Given-When-Then structure

**Examples**:
```python
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

### End-to-End Tests (<5%)
**Purpose**: Test full system workflows in production-like environment.

**Characteristics**:
- **Complete System**: All components working together
- **External Integrations**: Real OAuth providers, email services
- **Performance Testing**: Load and stress testing
- **Security Testing**: Penetration testing and vulnerability assessment

## 🧪 Advanced Testing Techniques

### Property-Based Testing
**Purpose**: Systematically explore edge cases and invariants.

**Implementation**: Using Hypothesis library
```python
from hypothesis import given, strategies as st

@given(st.text(min_size=3, max_size=50, alphabet=st.characters(whitelist_categories=('L', 'N')))
def test_username_validation_property(username):
    """Test username validation with property-based testing."""
    try:
        Username(username)
        # Valid username should not raise exception
    except ValueError:
        # Invalid username should raise ValueError
        pass
```

### Chaos Testing
**Purpose**: Test system resilience under failure conditions.

**Examples**:
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

### Performance Testing
**Purpose**: Validate system performance under load.

**Implementation**: Using Locust for load testing
```python
from locust import HttpUser, task, between

class AuthenticationUser(HttpUser):
    wait_time = between(1, 3)
    
    @task(3)
    def login(self):
        self.client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "SecurePass123!"
        })
    
    @task(1)
    def register(self):
        self.client.post("/api/v1/auth/register", json={
            "username": f"user_{random.randint(1, 1000)}",
            "email": f"user_{random.randint(1, 1000)}@example.com",
            "password": "SecurePass123!"
        })
```

### Security Testing
**Purpose**: Validate security controls and threat detection.

**Examples**:
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

## 🔧 Testing Infrastructure

### Test Configuration
```python
# pyproject.toml
[tool.pytest.ini_options]
minversion = "6.0"
addopts = [
    "-ra",
    "-q",
    "--disable-warnings",
    "--cov=src",
    "--cov-report=html",
    "--cov-report=term",
    "--asyncio-mode=auto"
]
testpaths = ["tests"]
python_files = ["tests.py", "test_*.py", "*_tests.py"]
python_functions = ["test_*"]
pythonpath = ["src"]
asyncio_mode = "auto"
env_files = [".env"]
```

### Test Categories
```python
markers = [
    "unit: mark a test as a unit test",
    "integration: mark a test as an integration test",
    "performance: mark a test as a performance test",
    "feature: Feature tests",
    "slow: Slow running tests",
    "security: Security tests",
    "auth: Authentication tests",
    "rate_limiting: Rate limiting tests"
]
```

### Test Fixtures
```python
@pytest.fixture
def mock_user_repository():
    """Create mock user repository."""
    repository = AsyncMock()
    repository.get_by_id = AsyncMock()
    repository.save = AsyncMock()
    return repository

@pytest.fixture
def mock_event_publisher():
    """Create mock event publisher."""
    publisher = AsyncMock()
    publisher.publish = AsyncMock()
    return publisher

@pytest.fixture
def mock_user():
    """Create test user with proper password hash."""
    user = User(
        id=1,
        username="testuser",
        email="test@example.com",
        is_active=True,
        role=Role.USER,
        email_confirmed=True
    )
    user.set_password("OldStr0ng!Key")
    return user
```

## 📊 Test Coverage

### Coverage Requirements
- **Critical Components**: 95%+ coverage
- **Domain Logic**: 100% coverage
- **Security Components**: 100% coverage
- **API Endpoints**: 90%+ coverage

### Coverage Categories
```python
# Coverage configuration
cov_fail_under = 50  # Minimum coverage threshold
cov_report = ["html", "term"]  # Coverage report formats
cov_source = ["src"]  # Source directories to measure
```

### Coverage Exclusions
```python
# Exclude from coverage measurement
cov_exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if self.debug:",
    "if settings.DEBUG",
    "raise AssertionError",
    "raise NotImplementedError",
]
```

## 🚀 Test Execution

### Running Tests
```bash
# Run all tests
make test

# Run specific test categories
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/feature/ -v

# Run with coverage
pytest --cov=src --cov-report=html

# Run performance tests
pytest tests/performance/ -v

# Run security tests
pytest tests/security/ -v
```

### CI/CD Integration
```yaml
# GitHub Actions workflow
- name: Run tests
  run: |
    make test
    pytest --cov=src --cov-report=xml
    coverage report --fail-under=50
```

## 🎯 Testing Best Practices

### Test Design Principles
1. **Single Responsibility**: Each test validates one behavior
2. **Clear Naming**: Descriptive test names following Given-When-Then
3. **Arrange-Act-Assert**: Clear test structure
4. **Isolation**: Tests don't depend on each other
5. **Fast Execution**: Unit tests run in milliseconds

### Test Data Management
1. **Factory Pattern**: Use factories for test data creation
2. **Unique Data**: Ensure test data doesn't conflict
3. **Cleanup**: Proper test data cleanup
4. **Realistic Data**: Use realistic but safe test data

### Mocking Strategy
1. **External Dependencies**: Mock external services
2. **Database Operations**: Mock for unit tests, use real DB for integration
3. **Time-Dependent Code**: Mock time for deterministic tests
4. **Random Values**: Mock random generators for reproducibility

### Error Testing
1. **Exception Testing**: Test error conditions and edge cases
2. **Boundary Testing**: Test input boundaries and limits
3. **Invalid Input**: Test with malformed or invalid data
4. **Security Testing**: Test security vulnerabilities and threats

## 📈 Test Metrics

### Quality Metrics
- **Test Coverage**: Percentage of code covered by tests
- **Test Execution Time**: Time to run test suite
- **Test Reliability**: Flaky test detection and prevention
- **Test Maintainability**: Test code quality and maintainability

### Business Metrics
- **Feature Completeness**: Percentage of features tested
- **Bug Detection**: Number of bugs caught by tests
- **Regression Prevention**: Number of regressions prevented
- **Deployment Confidence**: Confidence level for deployments

## 🎯 Benefits

### Quality Assurance
- **Early Bug Detection**: Catch bugs during development
- **Regression Prevention**: Prevent regressions with comprehensive tests
- **Refactoring Safety**: Safe refactoring with test coverage
- **Documentation**: Tests serve as living documentation

### Developer Experience
- **Fast Feedback**: Quick test execution for rapid development
- **Confidence**: High confidence in code changes
- **Debugging**: Tests help identify and fix issues
- **Learning**: Tests demonstrate expected behavior

### Production Readiness
- **Reliability**: Comprehensive testing ensures system reliability
- **Performance**: Performance tests validate system performance
- **Security**: Security tests validate security controls
- **Monitoring**: Tests validate monitoring and alerting

---

*Last updated: January 2025* 