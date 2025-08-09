# Advanced CLAUDE.md for Cedrina FastAPI Project

## Project Overview
- **Project Name**: Cedrina (dynamically adapts to other projects)
- **Description**: A production-ready Python template for scalable, secure, and maintainable REST APIs and WebSocket applications using FastAPI. Cedrina follows clean architecture and Domain-Driven Design (DDD), delivering enterprise-grade features: robust authentication (JWT, OAuth2, sessions), async PostgreSQL/Redis, internationalization (i18n), advanced security (zero-trust, rate limiting, audit logging), observability (OpenTelemetry, Prometheus), and a test suite targeting 95%+ coverage for critical components.
- **Goals**:
  - Build modular, extensible APIs and services for enterprise use.
  - Enforce strict separation of concerns via clean architecture and DDD.
  - Prioritize security, performance, scalability, and developer experience.
  - Support multilingual, real-time, and high-traffic scenarios.
  - Dynamically adapt to project-specific structures.

## Technology Stack
- **Language**: Python 3.11+ (PEP 8, mandatory type hints)
- **Framework**: FastAPI (primary), supports Django/Flask
- **Database**: PostgreSQL 15+ (asyncpg, connection pooling, SERIALIZABLE isolation)
- **ORM**: SQLModel (SQLAlchemy + Pydantic) or SQLAlchemy
- **Cache/Queue**: Redis (aioredis for caching, rate limiting, async tasks)
- **Dependencies**: Poetry (preferred) or pip
- **Testing**: Pytest (pytest-asyncio, pytest-mock, hypothesis, pytest-bdd)
- **Code Quality**: black, ruff, isort, flake8, pylint, mypy, pydocstyle
- **Containerization**: Docker, Docker Compose, Kubernetes (optional)
- **Migrations**: Alembic
- **Permissions**: Casbin (RBAC/ABAC) or custom
- **Observability**: Prometheus, OpenTelemetry, structured JSON logging
- **Security**: python-jose (JWT), passlib (hashing), cryptography (encryption)
- **Utilities**: httpx, aioredis, jinja2, pydantic, dependency-injector

## Repository Structure
Cedrina uses clean architecture with DDD layers, dynamically adapting to any project structure via repository scanning.
- **src/** (or app/):
  - **adapters/**: External interfaces
    - `api/v1/`: REST endpoints (e.g., auth/, admin/, health.py)
    - `websockets/`: WebSocket endpoints (e.g., health.py)
  - **core/**: App configuration and lifecycle
    - `application.py`: FastAPI app factory
    - `initialization.py`: Environment setup
    - `lifecycle.py`: Startup/shutdown
    - `middleware.py`: CORS, rate limiting, i18n, security
    - `dependencies/`: Dependency injection
    - `exceptions.py`: Custom exceptions
    - `handlers.py`: Exception handlers
    - `config/`: Pydantic settings
    - `rate_limiting/`: Redis-based rate limiting
    - `logging/`: Structured JSON logging
    - `metrics.py`: Prometheus/OpenTelemetry
  - **domain/**: DDD business logic
    - `entities/`: SQLModel entities (e.g., User)
    - `value_objects/`: Pydantic immutable objects (e.g., Email)
    - `services/`: Domain services (e.g., AuthService)
    - `events/`: Domain events (e.g., UserRegistered)
    - `interfaces/`: Repository/service contracts
    - `validation/`: Validation helpers
    - `security/`: JWT validation
  - **infrastructure/**: External implementations
    - `database/`: SQLModel/asyncpg connections
    - `repositories/`: SQLModel repositories
    - `services/`: External adapters (e.g., email, OAuth)
    - `dependency_injection/`: Wiring
    - `redis.py`: Redis client
  - **permissions/**: Authorization
    - `enforcer.py`: Casbin enforcement
    - `dependencies.py`: Permission dependencies
    - `policies.py`: Policy definitions
    - `config.py`: Authorization config
  - **utils/**: Shared utilities (e.g., i18n.py, security.py)
  - **templates/**: Jinja2 templates
  - **main.py**: Application entry
- **tests/**: Test suite
  - `unit/`: Component tests mirroring src/
  - `integration/`: API/database tests
  - `feature/`: End-to-end workflows (pytest-bdd)
  - `performance/`: Load/stress tests (locust)
  - `security/`: OWASP Top 10 tests
  - `factories/`: Test data factories
- **alembic/**: Database migrations
- **locales/**: i18n translations
- **scripts/**: Helper scripts (e.g., seeding, linting)
- **docs/**: Documentation (security/, api/, architecture/)

**Dynamic Detection**: Claude scans for src/, app/, or flat layouts, adapting to naming conventions (e.g., domain/ vs. business_logic/).

## Application Architecture
- **Clean Architecture**: Adapters → Core → Domain ← Infrastructure.
- **Principles**:
  - **Modularity**: Strict DDD layer separation.
  - **Testability**: 95%+ coverage for critical paths.
  - **Scalability**: Async/await, connection pooling, Redis caching.
  - **Security**: Zero-trust, JWT, rate limiting, audit logging, OWASP compliance.
  - **Observability**: Structured logging, Prometheus, OpenTelemetry.
  - **Maintainability**: PEP 8, type safety, self-documenting APIs.

## Coding Standards
- **PEP 8**: Enforced via black, isort, ruff, flake8, pylint, mypy --strict.
- **Clean Code**:
  - **Functions**: <15 lines, single responsibility, descriptive names, type hints, Google-style docstrings.
  - **Classes**: Cohesive, minimal APIs, SQLModel/Pydantic, SRP.
  - **Error Handling**: Custom exceptions, no None returns, no bare except.
  - **Comments**: Minimal, rely on self-documenting code.
  - **Refactoring**: Eliminate duplication, long functions, complex conditionals via TDD.
- **Code Quality Commands**:
  ```bash
  black src/ tests/  # Format
  isort src/ tests/  # Sort imports
  ruff check .       # Lint
  mypy src/ tests/   # Type check
  pydocstyle src/    # Docstring check
  ```

## Development Methodologies
### Test-Driven Development (TDD)
- **Workflow**:
  1. Write focused pytest tests (e.g., test_user_registration_succeeds).
  2. Implement minimal code to pass tests (PEP 8, SOLID, DRY).
  3. Enhance tests for real-world scenarios (e.g., concurrency, failures).
  4. Update code, refactor iteratively, maintain green tests.
  5. Validate 95%+ coverage with pytest --cov.
- **Test Pyramid**:
  - **Unit (70-80%)**: Isolated tests (pytest-mock, in-memory SQLite).
  - **Integration (15-20%)**: FastAPI-SQLModel-Redis interactions.
  - **Feature (5-10%)**: End-to-end workflows (pytest-bdd).
  - **Performance (<5%)**: Load/stress tests (locust).
  - **Security**: OWASP Top 10, zero-trust, penetration tests.
- **Techniques**:
  - Parameterized tests (pytest.mark.parametrize).
  - Property-based testing (hypothesis).
  - Async testing (pytest-asyncio).
  - Contract testing (pact-python).
  - Chaos testing (e.g., PostgreSQL/Redis downtime).
- **Commands**:
  ```bash
  pytest tests/unit/ --cov=src/ --cov-report=html  # Unit tests
  pytest tests/integration/ -m integration         # Integration tests
  pytest tests/feature/ -m feature                 # Feature tests
  locust -f tests/performance/load_test.py        # Performance tests
  make test                                       # All tests
  make test-cov                                   # Tests with coverage
  ```

### Testing Standards
- **Principles**:
  - Mirror production behavior.
  - Assert single, specific HTTP status codes (e.g., 201, 401).
  - No pytest.skip(); fix root causes.
  - Use UUIDs for unique test data.
  - Comprehensive docstrings explaining business context.
- **Security Tests**:
  - Input validation (SQL injection, XSS, expect 422).
  - Authentication (brute force, expect 429; JWT, expect 401).
  - Authorization (privilege escalation, expect 403).
  - Rate limiting (distributed attacks, expect 429).
- **Example**:
  ```python
  @pytest.mark.asyncio
  async def test_user_registration_success(async_client: httpx.AsyncClient, db_session: AsyncSession):
      """Test user registration with valid data."""
      unique_id = uuid.uuid4().hex[:8]
      user_data = {
          "username": f"test_user_{unique_id}",
          "email": f"test_{unique_id}@example.com",
          "password": "SecurePass9!@#"
      }
      response = await async_client.post("/api/v1/auth/register", json=user_data)
      assert response.status_code == 201, f"Expected 201, got {response.status_code}"
      assert response.json()["user"]["username"] == user_data["username"]
  ```

### Domain-Driven Design (DDD)
- **Bounded Contexts**: Detect contexts (e.g., Authentication, Administration) from structure.
- **Ubiquitous Language**: Consistent terms (e.g., User, Session) across code/tests/docs.
- **Aggregates**: SQLModel entities with SERIALIZABLE isolation or optimistic locking.
- **Entities**: SQLModel objects (e.g., User).
- **Value Objects**: Pydantic/dataclasses (frozen=True, e.g., Email).
- **Repositories**: abc.ABC interfaces with SQLModel/asyncpg.
- **Domain Events**: Redis Streams/Kafka for async workflows.
- **Domain Services**: Stateless logic (e.g., AuthService).
- **Exceptions**: Custom, descriptive (e.g., InvalidTokenError).

### SOLID Principles
- **SRP**: One responsibility per class/module.
- **OCP**: Polymorphism via abc.ABC/Pydantic.
- **LSP**: Type safety with mypy --strict.
- **ISP**: Fine-grained interfaces/protocols.
- **DIP**: Dependency injection (FastAPI Depends, dependency-injector).

### Design Patterns
- **Factory**: Dynamic service/repository creation.
- **Strategy**: Pluggable logic (e.g., auth strategies).
- **Decorator**: Middleware for rate limiting/logging.
- **Observer**: Domain events via Redis Pub/Sub.
- **Adapter**: External integrations (e.g., OAuth, email).
- **CQRS** (optional): Separate command/query models.

## Sub-Agent Integration
- **Agents Directory**: `.claude/agents/`
- **Key Agents**:
  - `project-orchestrator`: Coordinates end-to-end workflows.
  - `system-architect`: Designs clean architecture and DDD layers.
  - `data-architect`: Manages PostgreSQL schemas and Redis.
  - `api-designer`: Develops FastAPI endpoints with Pydantic.
  - `database-schema-designer`: Handles SQLModel/Alembic migrations.
  - `security-analyzer`: Ensures OWASP Top 10 and zero-trust compliance.
  - `test-suite-generator`: Generates pytest tests for 95%+ coverage.
  - `performance-optimizer`: Benchmarks critical paths.
  - `cicd-builder`: Configures CI/CD pipelines.
  - `deployment-ops-manager`: Manages Docker/Kubernetes deployments.
  - `workflow-optimizer`: Optimizes Claude Code for long-term projects.

## Test Analysis and Fix Workflow
- **Objective**: Systematically fix test failures from smallest unit test directory to larger ones, ensuring no side effects and production consistency.
- **Process**:
  1. **Identify**: Scan `tests/` for smallest unit test directory (e.g., `tests/unit/domain/entities/`).
  2. **Run**: `pytest tests/unit/domain/entities/ --cov=src/domain/entities`.
  3. **Analyze**: Use `pytest --pdb` and logs to identify test vs. code issues.
  4. **Fix**: Apply minimal changes (PEP 8, SOLID, DRY).
  5. **Dependencies**: Check with `pydeps src/ --show-deps` and run related tests (e.g., `tests/unit/domain/services/`).
  6. **Validate**: Run `pytest --cov` for 95%+ coverage; use ruff, mypy.
  7. **TODO**: Generate steps for next directory (e.g., `tests/unit/domain/services/`).
  8. **Proceed**: Automatically move to next directory.
- **Change Management**:
  - **Impact**: Document performance, security, scalability impacts.
  - **Rollback**: Use `git reset` or `alembic downgrade` if tests fail.
  - **Analysis**: Use ruff, mypy, pg_stat_statements, Redis MONITOR.

## Security Instructions
- **Authentication**: JWT, OAuth2, sessions with python-jose, passlib; enforce token expiration/refresh.
- **Authorization**: Casbin RBAC/ABAC, least privilege, zero-trust.
- **Input Validation**: Pydantic schemas, prevent SQL injection/XSS (expect 422).
- **Rate Limiting**: Redis-based, test distributed attacks (expect 429).
- **Audit Logging**: Log critical actions (user ID, timestamp, action) in core/logging/.
- **Timing Attacks**: Use hmac.compare_digest for constant-time comparisons.
- **Vulnerability Testing**: OWASP Top 10, penetration testing, document in `docs/security/`.

## Observability
- **Logging**: Structured JSON (core/logging/) with user ID, request ID.
- **Metrics**: Prometheus (core/metrics.py) for latency, errors; expose at /metrics.
- **Tracing**: OpenTelemetry for FastAPI/PostgreSQL/Redis, export to Jaeger.
- **Health Checks**: /api/v1/health (REST), /ws/health (WebSocket).

## Internationalization (i18n)
- Use `utils/i18n.py` with `locales/` translations.
- Apply i18n middleware in `core/middleware.py`.
- Test multilingual responses and errors.

## Deployment and Maintenance
- **Pre-Deployment**:
  - Run `make test-cov` for 95%+ coverage.
  - Apply `alembic upgrade head`.
  - Validate `.env` (e.g., SECRET_KEY, database URLs).
- **Deployment**:
  - Use `docker-compose up -d` or Kubernetes.
  - Implement feature flags for rollouts.
- **Post-Deployment**:
  - Monitor Prometheus metrics, OpenTelemetry traces.
  - Check logs for anomalies.
  - Rollback with `alembic downgrade` or `git revert`.
- **Maintenance**:
  - Refresh test data.
  - Monitor technical debt in `docs/technical_debt/`.
  - Update dependencies with `poetry update`.

## Feature Development
- **Structure**:
  ```python
  src/
  ├── adapters/api/v1/new_feature/
  │   ├── routes.py
  │   └── schemas/
  ├── domain/new_feature/
  │   ├── entities.py
  │   ├── services.py
  │   ├── interfaces.py
  │   └── events.py
  ├── infrastructure/new_feature/
  │   ├── repositories.py
  │   └── services.py
  ├── tests/new_feature/
  │   ├── test_unit_entities.py
  │   ├── test_unit_services.py
  │   ├── test_integration_api.py
  │   ├── test_security.py
  │   └── test_performance.py
  ```
- **Example**:
  ```python
  from fastapi import APIRouter, Depends
  from src.domain.new_feature.services import NewFeatureService

  router = APIRouter(prefix="/api/v1/new-feature")
  @router.post("/", response_model=NewFeatureResponse, status_code=201)
  async def create_feature(
      request: NewFeatureRequest,
      user: User = Depends(get_current_user),
      db: AsyncSession = Depends(get_db_session)
  ):
      """Create a new feature."""
      return await NewFeatureService(db).create(request, user)
  ```

## Documentation Requirements
- **Code**:
  ```python
  class NewFeatureService:
      """Manages new feature operations.
      
      Args:
          db: Async database session.
      
      Example:
          >>> service = NewFeatureService(db)
          >>> feature = await service.create(request)
      """
      async def create(self, request: NewFeatureRequest) -> NewFeature:
          """Create a feature.
          
          Args:
              request: Validated request data.
          
          Returns:
              NewFeature: Created feature.
          
          Raises:
              ValidationError: If input is invalid.
          """
  ```
- **API**:
  ```python
  @router.post(
      "/new-feature",
      response_model=NewFeatureResponse,
      status_code=201,
      summary="Create new feature",
      responses={
          201: {"description": "Feature created"},
          422: {"description": "Validation error"}
      }
  )
  async def create_feature(request: NewFeatureRequest):
      pass
  ```

## Quality Assurance Checklist
- **Pre-Commit**:
  - [ ] Passes black, ruff, isort, flake8, mypy.
  - [ ] 95%+ coverage (pytest --cov).
  - [ ] Security tests pass (OWASP, zero-trust).
  - [ ] Performance benchmarks meet SLAs.
  - [ ] Documentation updated.
  - [ ] Migrations reversible.
- **Pre-Release**:
  - [ ] Full test suite passes.
  - [ ] Load testing completed (locust).
  - [ ] Security audit completed.
  - [ ] Rollback strategy tested.
  - [ ] Monitoring configured.

## Instructions for Claude
- **Role**: Senior Python engineer specializing in FastAPI, PostgreSQL, Redis, clean architecture.
- **Workflow**:
  1. Scan `tests/` for smallest unit test directory (e.g., `tests/unit/domain/entities/`).
  2. Run `pytest <directory> --cov=<source_path>`; analyze failures with `pytest --pdb`.
  3. Fix issues minimally (PEP 8, SOLID, DRY).
  4. Check dependencies with `pydeps src/ --show-deps`; run related tests.
  5. Validate with `pytest --cov` for 95%+ coverage.
  6. Generate TODO for next directory (e.g., `tests/unit/domain/services/`).
  7. Proceed automatically.
- **Constraints**: No environment-specific conditions; ensure dev/test/prod consistency.
- **Tools**: pytest, SQLModel, asyncpg, aioredis, alembic, black, ruff, isort, flake8, mypy, pydeps, locust, OpenTelemetry.
- **CoT Reasoning**: Provide Markdown sections (`## Issue Analysis`, `## Solution`, `## Tests`, `## CoT Reasoning`) for fixes.

## Quick Start
```bash
poetry install                        # Install dependencies
cp .env.development .env             # Configure environment
make run-dev                         # Start services
curl http://localhost:8000/api/v1/health  # Verify health
make test                            # Run tests
make test-cov                        # Run tests with coverage
```

## Initial TODO
- **Task**: Analyze and fix tests in `tests/unit/domain/entities/`.
- **Steps**:
  1. Run `pytest tests/unit/domain/entities/ --cov=src/domain/entities`.
  2. Analyze failures with `pytest --pdb`.
  3. Fix issues (PEP 8, SOLID, DRY).
  4. Check dependencies with `pydeps src/`.
  5. Run related tests (e.g., `tests/unit/domain/services/`).
  6. Validate 95%+ coverage.
  7. Next TODO: Analyze `tests/unit/domain/services/`.