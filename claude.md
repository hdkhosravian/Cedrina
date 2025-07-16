# Advanced CLAUDE.md for Cedrina FastAPI Project and Beyond

## Project Overview
- **Project Name:** Cedrina (or dynamically detected for other projects)
- **Description:** A production-ready Python template for building scalable, secure, and maintainable REST APIs and WebSocket applications, typically using FastAPI. Cedrina (and similar projects) follows clean architecture and Domain-Driven Design (DDD), providing enterprise-grade features: robust authentication (JWT, OAuth2, sessions), async/await with PostgreSQL/Redis, internationalization (i18n), advanced security (rate limiting, input validation, audit logging, zero-trust), structured logging, observability with OpenTelemetry and Prometheus, containerized workflows, and a test suite targeting 95%+ coverage for critical components.
- **Goals:**
  - Deliver a modular, extensible foundation for enterprise-grade APIs and services.
  - Ensure strict separation of concerns via clean architecture and DDD.
  - Prioritize security, performance, scalability, and developer experience.
  - Support multilingual applications, real-time features, and high-traffic scenarios.
  - Adapt dynamically to project-specific structures and requirements.

## Technology Stack
- **Programming Language:** Python 3.11+ (PEP 8 compliant, type hints mandatory)
- **Web Framework:** FastAPI (primary), with support for Django, Flask, or custom frameworks
- **Database:** PostgreSQL 15+ (async queries via `asyncpg`, connection pooling, `SERIALIZABLE` isolation)
- **ORM:** SQLModel (SQLAlchemy + Pydantic) or SQLAlchemy
- **Cache/Queue:** Redis (caching, rate limiting, async tasks via `aioredis`)
- **Dependency Management:** Poetry (preferred) or pip
- **Testing Framework:** Pytest (with `pytest-asyncio`, `pytest-mock`, `hypothesis`, `pytest-bdd`)
- **Code Quality Tools:** `black` (formatting), `ruff`, `isort` (imports), `flake8`, `pylint` (linting), `mypy` (type checking), `pydocstyle` (docstrings)
- **Containerization:** Docker, Docker Compose, Kubernetes (optional)
- **Migrations:** Alembic (database schema migrations)
- **Permissions:** Casbin (RBAC/ABAC) or custom authorization
- **Observability:** Prometheus (metrics), OpenTelemetry (tracing), structured JSON logging
- **Security:** `python-jose` (JWT), `passlib` (password hashing), `cryptography` (encryption)
- **Other Libraries:** `httpx` (HTTP client), `aioredis`, `jinja2` (templates), `pydantic` (validation), `dependency-injector`

## Repository Structure
Cedrina uses a clean architecture layout with DDD layers, but this configuration adapts dynamically to any project structure by scanning the repository. Typical structure for Cedrina (with fallback for other projects):
- **src/** (or equivalent, e.g., `app/`):
  - **adapters/**: Interfaces to external systems
    - `api/v1/`: REST API endpoints (e.g., `auth/`, `admin/`, `health.py`, `docs.py`)
    - `websockets/`: WebSocket endpoints (e.g., `health.py`)
  - **core/**: Application configuration and lifecycle
    - `application.py`: FastAPI app factory
    - `initialization.py`: Environment setup
    - `lifecycle.py`: Startup/shutdown events
    - `middleware.py`: CORS, rate limiting, i18n, security middleware
    - `dependencies/`: Dependency injection (e.g., FastAPI `Depends`)
    - `exceptions.py`: Custom exceptions
    - `handlers.py`: Exception handlers
    - `config/`: Pydantic settings
    - `rate_limiting/`: Rate limiter (Redis or in-memory)
    - `logging/`: Structured JSON logging
    - `metrics.py`: Prometheus/OpenTelemetry integration
  - **domain/**: DDD business logic
    - `entities/`: Entities (e.g., `User`, `Session`) with SQLModel
    - `value_objects/`: Immutable objects (e.g., `Email`, `Role`) with Pydantic
    - `services/`: Domain services (e.g., `AuthService`)
    - `events/`: Domain events (e.g., `UserRegistered`)
    - `interfaces/`: Repository/service contracts (e.g., `abc.ABC`)
    - `validation/`: Validation helpers
    - `security/`: Security utilities (e.g., JWT validation)
  - **infrastructure/**: External system implementations
    - `database/`: SQLModel/`asyncpg` connections
    - `repositories/`: SQLModel repository implementations
    - `services/`: External service adapters (e.g., email, OAuth)
    - `dependency_injection/`: Wiring (e.g., `dependency-injector`)
    - `redis.py`: Redis client
  - **permissions/**: Authorization (e.g., Casbin-based RBAC/ABAC)
    - `enforcer.py`: Permission enforcement
    - `dependencies.py`: Permission dependencies
    - `policies.py`: Policy definitions
    - `config.py`: Authorization configuration
  - **utils/**: Shared utilities (e.g., `i18n.py`, `security.py`)
  - **templates/**: Jinja2 templates (e.g., for emails)
  - **main.py**: Application entry point
- **tests/**: Test suite
  - **unit/**: Unit tests mirroring `src/` structure
  - **integration/**: API and database interaction tests
  - **feature/**: End-to-end workflow tests (e.g., `pytest-bdd`)
  - **performance/**: Load and stress tests (e.g., `locust`)
  - **security/**: Security-focused tests (e.g., OWASP Top 10)
  - **factories/**: Test data factories (e.g., `UserFactory`)
- **alembic/**: Database migrations
- **locales/**: Translation files for i18n
- **scripts/**: Helper scripts (e.g., data seeding, linting)
- **docs/**: Documentation (e.g., `security/`, `api/`, `architecture/`)

**Dynamic Detection**: Claude will scan the repository to identify the actual structure (e.g., `src/`, `app/`, or flat layout) and adapt to project-specific naming conventions (e.g., `domain/` vs. `business_logic/`) without rigid assumptions.

## Application Architecture
- **Clean Architecture**: Enforces dependency rule: **Adapters** → **Core** → **Domain** ← **Infrastructure**.
- **Dependency Flow**: Domain layer is independent; adapters use FastAPI; infrastructure uses SQLModel/Redis.
- **Key Principles**:
  - **Modularity**: Strict separation of concerns via DDD layers.
  - **Testability**: Comprehensive test suite with 95%+ coverage for critical paths.
  - **Scalability**: Async/await, PostgreSQL connection pooling, Redis caching, and horizontal scaling support.
  - **Security**: Zero-trust model, JWT validation, rate limiting, audit logging, and OWASP Top 10 compliance.
  - **Observability**: Structured logging, Prometheus metrics, OpenTelemetry tracing.
  - **Maintainability**: PEP 8-compliant code, type safety, and self-documenting APIs.

## Coding Standards
- **PEP 8 Compliance**: Enforce with `black` (formatting), `isort` (imports), `ruff`, `flake8`, `pylint` (linting), and `mypy` (type checking).
- **Type Hints**: Mandatory for all functions, classes, and modules, validated with `mypy --strict`.
- **Clean Code**:
  - **Functions**: Small (<15 lines), single responsibility, intention-revealing names (e.g., `validate_user_credentials`), with type hints and Google-style docstrings.
  - **Classes**: Cohesive, minimal public APIs, use SQLModel/Pydantic, follow SRP.
  - **Error Handling**: Custom exceptions (e.g., `AuthenticationError`) with business-relevant messages; avoid `None` returns or bare `except`.
  - **Comments**: Minimal, rely on self-documenting code; use `pydocstyle`-compliant Google-style docstrings.
  - **Code Smells**: Eliminate duplication, long functions, and complex conditionals during TDD.
- **Refactoring**: Iteratively simplify code, guided by TDD, ensuring all tests remain green.

## Development Methodologies
### Test-Driven Development (TDD)
- **Workflow**:
  1. Write simple, focused `pytest` tests with PEP 8-compliant names (e.g., `test_user_registration_succeeds`).
  2. Implement minimal code to pass tests, adhering to PEP 8, SOLID, and DRY.
  3. Enhance tests for real-world scenarios (e.g., high-concurrency PostgreSQL transactions, Redis failures, invalid JWTs).
  4. Update code to pass enhanced tests, maintaining modularity and clean code.
  5. Refactor iteratively to eliminate code smells, ensuring all tests pass.
  6. Validate with `pytest --cov` for 95%+ coverage on critical components.
- **Test Pyramid**:
  - **Unit Tests (70-80%)**: Validate components (e.g., entities, services) using `pytest-mock`, isolated with in-memory SQLite (`pytest-sqlmodel`) or mocks.
  - **Integration Tests (15-20%)**: Verify FastAPI-SQLModel-Redis interactions, simulating production-like data flows.
  - **Feature Tests (5-10%)**: End-to-end workflows with `pytest-bdd` (Given-When-Then) for stakeholder readability.
  - **Performance Tests (<5%)**: Benchmark critical paths with `pytest-benchmark`, `locust`.
  - **Security Tests**: OWASP Top 10 compliance, penetration testing, and zero-trust validation.
- **Advanced Testing Techniques**:
  - Parameterized tests (`pytest.mark.parametrize`) for multiple input scenarios.
  - Property-based testing (`hypothesis`) for edge cases and invariants.
  - Async testing (`pytest-asyncio`) for FastAPI, `asyncpg`, and `aioredis`.
  - Contract testing (`pact-python`) for API interactions.
  - Chaos testing (simulate PostgreSQL/Redis downtime, network failures).
  - Security testing (SQL injection, XSS, privilege escalation).
- **Commands**:
  ```bash
  pytest tests/unit/ --cov=src/ --cov-report=html  # Unit tests with coverage
  pytest tests/integration/ -m integration         # Integration tests
  pytest tests/feature/ -m feature                # Feature tests
  locust -f tests/performance/load_test.py        # Performance tests
  make test                                       # Run all tests
  make test-cov                                   # Run tests with coverage
  ```

### Testing Rules and Standards
#### Core Testing Principles
- **Production Reality Testing**: Tests must mirror actual production behavior, avoiding idealized scenarios.
- **Exact Status Code Validation**: Assert single, specific HTTP status codes (e.g., `201` for creation, `401` for unauthorized).
- **No Skipped Tests**: Never use `pytest.skip()`; fix root causes instead.
- **Comprehensive Documentation**: Each test must include clear comments/docstrings explaining expected behavior and business context.
- **Unique Test Data**: Use UUIDs for usernames, emails, and other identifiers to prevent conflicts.
- **Security-First Testing**: Validate against OWASP Top 10, zero-trust principles, and advanced threat models.

#### Test Implementation Standards
```python
# ✅ Correct: Production-ready test with unique data and specific assertions
@pytest.mark.asyncio
async def test_user_registration_success(async_client: httpx.AsyncClient, db_session: AsyncSession):
    """Test user registration with valid data, ensuring production behavior."""
    unique_id = uuid.uuid4().hex[:8]
    user_data = {
        "username": f"test_user_{unique_id}",
        "email": f"test_{unique_id}@example.com",
        "password": "SecurePass9!@#"
    }
    response = await async_client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 201, f"Expected 201 Created, got {response.status_code}: {response.text}"
    response_data = response.json()
    assert "user" in response_data, "Response must include user data"
    assert response_data["user"]["username"] == user_data["username"], "Username mismatch"
    assert "tokens" in response_data, "Response must include tokens"

# ❌ Incorrect: Problematic test patterns
@pytest.mark.asyncio
async def test_user_registration_bad(async_client: httpx.AsyncClient):
    """Incorrect test with static data and vague assertions."""
    user_data = {
        "username": "test_user",  # Static data causes conflicts
        "email": "test@example.com",
        "password": "weak"
    }
    response = await async_client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code in [200, 201], "Should succeed somehow"  # Vague status code
    if response.status_code == 409:
        pytest.skip("User exists")  # Skipping is forbidden
```

#### Security Testing Requirements
```python
# ✅ Correct: Security-focused test for input validation
@pytest.mark.asyncio
async def test_sql_injection_prevention(async_client: httpx.AsyncClient):
    """Test prevention of SQL injection in login endpoint."""
    malicious_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --"
    ]
    for payload in malicious_payloads:
        response = await async_client.post(
            "/api/v1/auth/login",
            json={"username": payload, "password": "password"}
        )
        assert response.status_code == 422, f"SQL injection not caught: {payload}"
        response_text = response.text.lower()
        assert not any(kw in response_text for kw in ["syntax error", "postgresql"]), "SQL errors leaked"

# ✅ Correct: Authorization test
@pytest.mark.asyncio
async def test_privilege_escalation_prevention(async_client: httpx.AsyncClient, regular_user_token: str):
    """Test prevention of privilege escalation in admin endpoint."""
    headers = {"Authorization": f"Bearer {regular_user_token}"}
    response = await async_client.get("/api/v1/admin/users", headers=headers)
    assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
```

#### Data Uniqueness Requirements
```python
# ✅ Correct: Unique test data generation
def generate_unique_user_data() -> dict:
    """Generate unique user data for tests."""
    unique_id = uuid.uuid4().hex[:8]
    return {
        "username": f"test_user_{unique_id}",
        "email": f"test_{unique_id}@example.com",
        "password": "SecurePass9!@#"
    }

# ✅ Correct: Safe username generation
def generate_safe_username(base_name: str) -> str:
    """Generate username avoiding blocked substrings."""
    blocked = ["admin", "root", "system", "script"]
    safe_base = base_name
    for term in blocked:
        safe_base = safe_base.replace(term, "user")
    return f"{safe_base}_{uuid.uuid4().hex[:8]}"
```

#### Status Code Validation Rules
```python
# ✅ Correct: Specific status code expectations
assert response.status_code == 201, "Registration must return 201 Created"
assert response.status_code == 409, "Duplicate resource must return 409 Conflict"
assert response.status_code == 422, "Invalid input must return 422 Unprocessable Entity"
assert response.status_code == 401, "Invalid credentials must return 401 Unauthorized"
assert response.status_code == 403, "Insufficient permissions must return 403 Forbidden"
assert response.status_code == 429, "Rate limit exceeded must return 429 Too Many Requests"
```

#### Test Quality Checklist
- [ ] Uses unique test data (e.g., UUIDs for identifiers)
- [ ] Validates exact production behavior
- [ ] Asserts single, specific status codes
- [ ] Includes clear comments/docstrings explaining intent
- [ ] Covers security scenarios (e.g., SQL injection, XSS)
- [ ] Documents vulnerabilities found
- [ ] Runs consistently without skips
- [ ] Uses async/await for FastAPI/PostgreSQL
- [ ] Validates response structure and content
- [ ] Tests success, failure, and edge cases

#### Security Test Categories
1. **Input Validation**:
   - SQL injection (expect 422)
   - XSS attacks (expect 422)
   - Command injection (expect 422)
   - Path traversal (expect 404/403)
2. **Authentication**:
   - Brute force protection (expect 429)
   - Timing attack prevention (use `hmac.compare_digest`)
   - JWT validation (expect 401 for invalid/expired tokens)
   - Session management (expect 401 for expired sessions)
3. **Authorization**:
   - Privilege escalation prevention (expect 403)
   - RBAC/ABAC enforcement (expect 403)
   - Resource access control (expect 404/403)
4. **Rate Limiting**:
   - Request rate limits (expect 429)
   - IP spoofing prevention (expect 429)
   - Distributed attack mitigation (expect 429)

#### Test Maintenance Rules
- Fix root causes instead of skipping tests.
- Document security vulnerabilities in `docs/security/`.
- Refresh test data regularly to avoid conflicts.
- Monitor test performance (e.g., <1s for unit tests).
- Maintain 95%+ coverage for critical paths using `pytest-cov`.

### Domain-Driven Design (DDD)
- **Bounded Contexts**: Dynamically detect contexts (e.g., Authentication, Administration) based on project structure.
- **Ubiquitous Language**: Use consistent terms (e.g., `User`, `Session`) across code, tests, and documentation.
- **Aggregates**: Model with SQLModel, enforcing consistency via PostgreSQL `SERIALIZABLE` isolation or optimistic locking.
- **Entities**: Objects with identities (e.g., `User`) using SQLModel.
- **Value Objects**: Immutable objects (e.g., `Email`) with Pydantic or `dataclasses` (`frozen=True`).
- **Repositories**: Interfaces (`abc.ABC`) with SQLModel/`asyncpg` implementations.
- **Domain Events**: Events (e.g., `UserRegistered`) for async workflows, integrated with message queues (e.g., Redis Streams, Kafka).
- **Domain Services**: Stateless logic (e.g., `AuthService`) for cross-entity operations.
- **Domain Exceptions**: Custom exceptions (e.g., `InvalidTokenError`) with clear messages.

### SOLID Principles
- **SRP**: One responsibility per class/module (e.g., separate routing from business logic).
- **OCP**: Use polymorphism (e.g., `abc.ABC`, Pydantic) for extensibility.
- **LSP**: Ensure type safety with `mypy --strict`.
- **ISP**: Fine-grained interfaces (e.g., protocols) to avoid bloated dependencies.
- **DIP**: Dependency injection with FastAPI `Depends` or `dependency-injector`.

### Design Patterns
- **Factory**: Create service/repository instances dynamically.
- **Strategy**: Pluggable logic (e.g., authentication strategies).
- **Decorator**: Middleware for rate limiting, logging, and security.
- **Observer**: Handle domain events (e.g., via Redis Pub/Sub).
- **Adapter**: Integrate external systems (e.g., OAuth, email services).
- **CQRS** (optional): Separate command and query models for complex domains.

## Test Analysis and Fix Workflow
- **Objective**: Systematically analyze and fix test failures, starting with the smallest unit test directory and progressing to larger directories, ensuring no side effects and consistency across environments.
- **Process**:
  1. **Identify Test Directories**:
     - Scan `tests/` (or equivalent) to list directories (e.g., `tests/unit/`, `tests/integration/`).
     - Prioritize smallest unit test directory based on file count or complexity (e.g., `tests/unit/domain/entities/`).
  2. **Run Tests**:
     - Execute `pytest <directory> --cov=<corresponding_source_path>` (e.g., `pytest tests/unit/domain/entities/ --cov=src/domain/entities`).
     - Capture output and logs for analysis.
  3. **Analyze Failures**:
     - Identify failing tests using `pytest` output and structured logs.
     - Determine if issues are in **test code** (e.g., incorrect assertions, outdated data) or **source code** (e.g., logic errors in `src/domain/entities/`).
     - Use `pytest --pdb`, logs, or `pdb` for debugging.
     - Provide **CoT Reasoning** in Markdown sections (`## Issue Analysis`, `## Solution`, `## Tests`, `## CoT Reasoning`) detailing failure causes and fix strategy.
  4. **Fix Issues**:
     - Apply minimal changes to tests or code, adhering to PEP 8, SOLID, DRY, and clean code principles.
     - Avoid environment-specific conditions (e.g., no `if os.getenv('TEST_ENV')`).
     - Use TDD: Write additional tests for uncovered edge cases before fixing code.
     - Ensure fixes align with DDD bounded contexts and project architecture.
  5. **Dependency Checks**:
     - Use `pydeps --show-deps` to analyze dependencies of modified files.
     - Identify related modules (e.g., `src/domain/services/`, `src/infrastructure/repositories/`) and run their tests to ensure no regressions.
     - Document dependency impacts in **CoT Reasoning**.
  6. **Validate Fixes**:
     - Run `pytest --cov` on the fixed directory to confirm resolution and 95%+ coverage.
     - Run related tests (e.g., `tests/unit/domain/services/`) to verify no side effects.
     - Use `ruff`, `flake8`, `mypy` for code quality and `pg_stat_statements` for query performance.
  7. **Generate TODOs**:
     - Identify the next smallest test directory (e.g., `tests/unit/domain/services/`).
     - Define steps for the next directory (e.g., run tests, analyze failures).
  8. **Proceed Automatically**:
     - Move to the next directory without user input, documenting the TODO in **CoT Reasoning**.
- **Directory Progression**:
  - Start with smallest unit test directory (e.g., `tests/unit/domain/entities/`).
  - Progress to other unit tests (e.g., `tests/unit/domain/services/`, `tests/unit/adapters/`).
  - Move to `tests/integration/`, `tests/feature/`, `tests/performance/`, and `tests/security/`.
- **Change Management**:
  - **Impact Analysis**: Document impacts on performance, scalability, security, and maintainability.
  - **Rollback Plan**: Revert code (`git reset`) or migrations (`alembic downgrade`) if tests fail.
  - **Static Analysis**: Use `ruff`, `flake8`, `mypy`, `pylint` for code quality.
  - **Dynamic Analysis**: Use `pg_stat_statements`, `EXPLAIN ANALYZE` for PostgreSQL queries, and Redis `MONITOR` for cache performance.

## Security Instructions
- **Authentication**:
  - Implement JWT, OAuth2, and session-based auth with `python-jose`, `passlib`.
  - Use secure token generation and validation (e.g., HS256/RS256 for JWT).
  - Enforce token expiration and refresh mechanisms.
- **Authorization**:
  - Use Casbin for RBAC/ABAC, enforcing least privilege and zero-trust principles.
  - Validate permissions at the endpoint and domain levels.
- **Input Validation**:
  - Enforce with Pydantic schemas in `adapters/api/v1/*/schemas/`.
  - Prevent SQL injection, XSS, and command injection (expect 422 responses).
- **Rate Limiting**:
  - Implement Redis-based rate limiting in `core/rate_limiting/`.
  - Test for distributed attack mitigation (expect 429 responses).
- **Audit Logging**:
  - Log critical actions (e.g., login, permission changes) in `core/logging/`.
  - Include user ID, timestamp, and action details.
- **Timing Attacks**:
  - Use `hmac.compare_digest` for constant-time comparisons.
  - Test for timing attack vulnerabilities in authentication flows.
- **Vulnerability Testing**:
  - Address OWASP Top 10 (e.g., A01: Broken Access Control, A03: Injection).
  - Perform penetration testing and threat modeling.
  - Document findings in `docs/security/`.

## Observability
- **Logging**:
  - Structured JSON logging in `core/logging/` with context (e.g., user ID, request ID).
  - Use `logging` with custom handlers for traceability.
- **Metrics**:
  - Prometheus metrics in `core/metrics.py` for API latency, error rates, and resource usage.
  - Expose metrics at `/metrics` endpoint.
- **Tracing**:
  - Integrate OpenTelemetry for distributed tracing across FastAPI, PostgreSQL, and Redis.
  - Export traces to Jaeger or similar for analysis.
- **Health Checks**:
  - Implement `/api/v1/health` (REST) and `/ws/health` (WebSocket) endpoints.
  - Test database, Redis, and external service connectivity.

## Internationalization (i18n)
- Use `utils/i18n.py` for multilingual support, integrated with `locales/` translations.
- Apply i18n middleware in `core/middleware.py` for locale-aware responses.
- Test multilingual API responses and error messages.

## Deployment and Maintenance
- **Pre-Deployment**:
  - Run `make test-cov` to ensure 95%+ coverage.
  - Apply migrations with `alembic upgrade head`.
  - Validate `.env` settings (e.g., `SECRET_KEY`, database URLs).
- **Deployment**:
  - Use `docker-compose up -d` or Kubernetes for production.
  - Implement feature flags for gradual rollouts.
- **Post-Deployment**:
  - Monitor Prometheus metrics and OpenTelemetry traces.
  - Check logs for errors and anomalies.
  - Rollback with `alembic downgrade` or `git revert` if needed.
- **Maintenance**:
  - Refresh test data to avoid conflicts.
  - Monitor technical debt in `docs/technical_debt/`.
  - Update dependencies with `poetry update` and validate with tests.

## Feature Development and Refactoring Guidelines
### Pre-Development Analysis
- **Codebase Review**:
  ```bash
  find src/ -name "*.py" | head -20  # List key modules
  grep -r "class.*Service" src/      # Identify service patterns
  grep -r "def.*Repository" src/     # Identify repository patterns
  pydeps src/ --show-deps           # Analyze dependency graph
  ```
- **Documentation Review**:
  - Read `claude.md`, `docs/`, and API specifications.
  - Validate alignment with DDD layers and existing patterns.
- **Impact Assessment**:
  - Evaluate breaking changes, security risks, performance impacts, and dependencies.
  - Document migration and rollback strategies.

### New Feature Implementation
- **Directory Structure**:
  ```python
  src/
  ├── adapters/api/v1/new_feature/
  │   ├── routes.py                 # FastAPI routes
  │   └── schemas/                  # Pydantic schemas
  ├── domain/new_feature/
  │   ├── entities.py               # Domain entities
  │   ├── services.py               # Domain services
  │   ├── interfaces.py             # Contracts
  │   └── events.py                 # Domain events
  ├── infrastructure/new_feature/
  │   ├── repositories.py           # Data access
  │   └── services.py               # External integrations
  ├── tests/new_feature/
  │   ├── test_unit_entities.py     # Unit tests
  │   ├── test_unit_services.py     # Unit tests
  │   ├── test_integration_api.py   # Integration tests
  │   ├── test_security.py          # Security tests
  │   └── test_performance.py       # Performance tests
  ```
- **Code Integration**:
  ```python
  # ✅ Correct: Follow existing patterns
  from fastapi import APIRouter, Depends
  from src.core.dependencies import get_db_session, get_current_user
  from src.domain.new_feature.services import NewFeatureService

  router = APIRouter(prefix="/api/v1/new-feature")
  @router.post("/", response_model=NewFeatureResponse, status_code=201)
  async def create_feature(
      request: NewFeatureRequest,
      user: User = Depends(get_current_user),
      db: AsyncSession = Depends(get_db_session)
  ):
      """Create a new feature with proper dependency injection."""
      service = NewFeatureService(db)
      return await service.create(request, user)
  ```
- **Configuration**:
  ```python
  # ✅ Correct: Extend Pydantic settings
  class Settings(BaseSettings):
      NEW_FEATURE_ENABLED: bool = True
      NEW_FEATURE_RATE_LIMIT: int = 100
      class Config:
          env_file = ".env"
  ```

### Refactoring Guidelines
- **Deprecation Strategy**:
  ```python
  # ✅ Correct: Gradual deprecation
  import warnings
  def old_endpoint(param: str) -> str:
      warnings.warn("old_endpoint is deprecated; use new_endpoint", DeprecationWarning, stacklevel=2)
      return new_endpoint(param)
  ```
- **Migration Checklist**:
  - Identify all usages (`grep -r "old_endpoint" src/`).
  - Maintain backward compatibility during transition.
  - Update tests, documentation, and metrics.
  - Provide rollback strategy (e.g., `git revert`).

### Database Migration Standards
- **Safe Migrations**:
  ```python
  # ✅ Correct: Safe migration with rollback
  def upgrade():
      with op.batch_alter_table("users", schema=None) as batch_op:
          batch_op.add_column(sa.Column("profile_id", sa.Integer, nullable=True))
          batch_op.create_foreign_key("fk_user_profile", "profiles", ["profile_id"], ["id"])
      op.create_index("idx_user_profile", "users", ["profile_id"], postgresql_concurrently=True)

  def downgrade():
      with op.batch_alter_table("users", schema=None) as batch_op:
          batch_op.drop_constraint("fk_user_profile", type_="foreignkey")
          batch_op.drop_column("profile_id")
      op.drop_index("idx_user_profile", table_name="users")
  ```
- **Data Migration**:
  ```python
  # ✅ Correct: Batch data migration
  def upgrade():
      op.create_table("new_sessions", ...)
      connection = op.get_bind()
      result = connection.execute("SELECT id, token FROM old_sessions")
      batch = []
      for row in result:
          batch.append({"user_id": row.id, "session_token": row.token, ...})
          if len(batch) >= 1000:
              connection.execute("INSERT INTO new_sessions ...", batch)
              batch = []
      if batch:
          connection.execute("INSERT INTO new_sessions ...", batch)
  ```

## Performance and Monitoring
- **Performance Benchmarking**:
  ```python
  # ✅ Correct: Benchmark critical paths
  def test_endpoint_performance(benchmark):
      """Benchmark API endpoint latency."""
      benchmark.pedantic(
          endpoint_function, args=(test_data,), iterations=100, rounds=10
      )
      assert benchmark.stats.mean < 0.1  # 100ms SLA
  ```
- **Monitoring**:
  ```python
  # ✅ Correct: Observability with metrics and tracing
  from opentelemetry import trace
  from src.core.metrics import REQUEST_COUNT, REQUEST_DURATION
  from src.core.logging import get_logger

  tracer = trace.get_tracer(__name__)
  logger = get_logger(__name__)

  @router.post("/new-feature")
  async def create_feature(request: NewFeatureRequest):
      with tracer.start_as_current_span("create_feature"):
          start_time = time.time()
          try:
              result = await service.create(request)
              REQUEST_COUNT.labels(method="POST", endpoint="/new-feature", status="201").inc()
              logger.info("Feature created", extra={"feature_id": result.id})
              return result
          except Exception as e:
              REQUEST_COUNT.labels(method="POST", endpoint="/new-feature", status="500").inc()
              logger.error("Feature creation failed", extra={"error": str(e)})
              raise
          finally:
              REQUEST_DURATION.labels(method="POST", endpoint="/new-feature").observe(time.time() - start_time)
  ```

## Documentation Requirements
- **Code Documentation**:
  ```python
  # ✅ Correct: Comprehensive docstrings
  class NewFeatureService:
      """Manages new feature operations following DDD principles.
      
      Args:
          repository: Data access layer for features
          validator: Input validation service
      
      Example:
          >>> service = NewFeatureService(repository, validator)
          >>> feature = await service.create(request)
      """
      async def create(self, request: NewFeatureRequest) -> NewFeature:
          """Create a new feature.
          
          Args:
              request: Validated feature request data
          
          Returns:
              NewFeature: Created feature instance
          
          Raises:
              ValidationError: If input is invalid
              PermissionError: If user lacks permissions
          """
  ```
- **API Documentation**:
  ```python
  # ✅ Correct: Detailed OpenAPI documentation
  @router.post(
      "/new-feature",
      response_model=NewFeatureResponse,
      status_code=201,
      summary="Create new feature",
      description="Creates a new feature with validated input",
      responses={
          201: {"description": "Feature created"},
          422: {"description": "Validation error"},
          429: {"description": "Rate limit exceeded"}
      }
  )
  async def create_feature(request: NewFeatureRequest):
      pass
  ```

## Quality Assurance Checklist
- **Pre-Commit**:
  - [ ] Code passes `black`, `ruff`, `isort`, `flake8`, `mypy`
  - [ ] Tests achieve 95%+ coverage (`pytest --cov`)
  - [ ] Security tests pass (OWASP Top 10, zero-trust)
  - [ ] Performance benchmarks meet SLAs
  - [ ] Documentation updated with examples
  - [ ] Migrations tested and reversible
- **Pre-Release**:
  - [ ] Full test suite passes
  - [ ] Load testing completed (`locust`)
  - [ ] Security audit completed
  - [ ] Rollback strategy tested
  - [ ] Monitoring configured (Prometheus, OpenTelemetry)

## Instructions for Claude
- **Role**: Act as a top 1% senior Python engineer specializing in FastAPI, PostgreSQL, Redis, and clean architecture.
- **Test Workflow**:
  1. Scan `tests/` to identify the smallest unit test directory (e.g., `tests/unit/domain/entities/`).
  2. Run `pytest <directory> --cov=<source_path>` and analyze failures.
  3. Determine test vs. code issues using `pytest --pdb` and logs.
  4. Fix issues with minimal changes, adhering to PEP 8, SOLID, DRY, and clean code.
  5. Check dependencies with `pydeps` and run related tests.
  6. Validate fixes with `pytest --cov` for 95%+ coverage.
  7. Generate TODO for the next directory (e.g., `tests/unit/domain/services/`).
  8. Proceed automatically to the next directory.
- **TDD**: Drive fixes with iterative TDD, writing tests for new edge cases if needed.
- **DDD**: Respect domain structure, maintaining bounded contexts and ubiquitous language.
- **Clean Code**: Enforce PEP 8 with `black`, `ruff`, `isort`, `flake8`, `mypy`.
- **CoT Reasoning**: Provide Markdown sections (`## Issue Analysis`, `## Solution`, `## Tests`, `## CoT Reasoning`) for each fix, detailing issue analysis, fix approach, dependency checks, and trade-offs.
- **Multi-Perspective Analysis**: Consider technical (performance, scalability), business (stakeholder needs), human (developer experience), and operational (deployment) perspectives.
- **Constraints**: No environment-specific conditions; ensure consistency across dev, test, prod.
- **Tools**: Use `pytest`, `SQLModel`, `asyncpg`, `aioredis`, `alembic`, `black`, `ruff`, `isort`, `flake8`, `mypy`, `pydocstyle`, `pydeps`, `locust`, `OpenTelemetry`.

## Quick Start
- Install dependencies: `poetry install`
- Configure `.env` from `.env.development`
- Start services: `make run-dev` or `docker-compose up -d`
- Verify health: `curl http://localhost:8000/api/v1/health`
- Run tests: `make test` or `make test-cov`

## Initial TODO
- **Task**: Analyze and fix tests in the smallest unit test directory.
- **Steps**:
  1. Scan `tests/` to identify the smallest unit test directory (e.g., `tests/unit/domain/entities/`).
  2. Run `pytest tests/unit/domain/entities/ --cov=src/domain/entities`.
  3. Analyze failures, identifying test vs. code issues with `pytest --pdb`.
  4. Apply minimal fixes, ensuring PEP 8, SOLID, DRY compliance.
  5. Check dependencies with `pydeps` and run related tests (e.g., `tests/unit/domain/services/`).
  6. Validate with `pytest --cov` for 95%+ coverage.
  7. Next TODO: Move to the next smallest unit test directory (e.g., `tests/unit/domain/services/`).

## Test Requirements
- **Test Pyramid**:
  - **Unit Tests (70-80%)**: Validate individual components (e.g., entities, services, routes) using `pytest-mock`. Cover edge cases (e.g., invalid inputs, null values), failure modes (e.g., database errors, async timeouts), and invariants. Ensure tests are fast (<1ms), isolated (e.g., in-memory SQLite), and PEP 8-compliant.
  - **Integration Tests (15-20%)**: Verify interactions between FastAPI, SQLModel, Redis, and external services. Simulate production-like data flows and failures (e.g., transaction rollbacks, connection pool exhaustion).
  - **Feature Tests (5-10%)**: Validate end-to-end business scenarios (e.g., user registration, order processing) using `pytest-bdd` with Given-When-Then syntax for stakeholder readability.
  - **Performance Tests (<5%)**: Benchmark critical paths under load (`locust`, `pytest-benchmark`) with thousands of concurrent requests.
  - **Security Tests**: Validate OWASP Top 10 compliance, zero-trust principles, and advanced threat models (e.g., SQL injection, XSS, privilege escalation).
- **Coverage**: Achieve 95%+ coverage for critical components using `pytest-cov`. Report uncovered lines in fixes.
- **Advanced Testing Techniques**:
  - **Parameterized Tests**: Use `pytest.mark.parametrize` for multiple input scenarios (e.g., various user roles).
  - **Property-Based Testing**: Use `hypothesis` to explore edge cases and invariants.
  - **Fuzz Testing**: Inject random/malformed inputs with `hypothesis` or custom fuzzers.
  - **Contract Testing**: Validate API interactions with `pact-python`.
  - **Chaos Testing**: Simulate failures (e.g., PostgreSQL downtime, Redis failover) using `chaos-mesh` or custom scripts.
  - **Async Testing**: Test async code with `pytest-asyncio`.
- **Real-World Scenarios**:
  - **High-Traffic**: Simulate thousands of concurrent API requests or PostgreSQL transactions (`pgbench`, `locust`).
  - **Data Inconsistencies**: Handle corrupted data (e.g., null values, constraint violations).
  - **Concurrent Modifications**: Validate `SERIALIZABLE` isolation or optimistic locking.
  - **Resource Constraints**: Test under low memory, high latency, or limited connections.
  - **Integration Failures**: Simulate database downtime, network timeouts, or API failures.
  - **Scalability**: Test with large datasets (e.g., millions of rows) or high-frequency async tasks.
- **Test Isolation**: Use test doubles (mocks, stubs, spies, fakes) with `pytest-mock` to isolate components.
- **Test Naming**: Use descriptive, PEP 8-compliant names (e.g., `test_reject_invalid_user_email`) with concise docstrings.
- **CI/CD Integration**: Run tests in CI/CD pipelines (e.g., GitHub Actions) with `pytest`, `black`, `ruff`, `isort`, `flake8`.
- **Human Factors**: Ensure clear `pytest` output, readable BDD tests, and fast test suites to reduce developer friction.