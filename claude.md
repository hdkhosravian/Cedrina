# Advanced CLAUDE.md for Cedrina FastAPI Project

## Project Overview
- **Name**: Cedrina (dynamically adapts to other projects)
- **Description**: A production-ready Python template for scalable, secure REST APIs and WebSocket applications using FastAPI. Cedrina leverages clean architecture and DDD, delivering enterprise-grade features: robust authentication (JWT, OAuth2, sessions), async PostgreSQL/Redis, internationalization (i18n), zero-trust security, rate limiting, audit logging, observability (OpenTelemetry, Prometheus), and 95%+ test coverage for critical components.
- **Goals**:
  - Build modular, extensible APIs/services for enterprise use.
  - Enforce strict separation of concerns via clean architecture and DDD.
  - Ensure security, performance, scalability, and developer experience.
  - Support multilingual, real-time, high-traffic scenarios.
  - Adapt dynamically to project-specific structures.

## Technology Stack
- **Language**: Python 3.11+ (PEP 8, mandatory type hints)
- **Framework**: FastAPI (primary), supports Django/Flask
- **Database**: PostgreSQL 15+ (asyncpg, connection pooling, SERIALIZABLE isolation)
- **ORM**: SQLModel (SQLAlchemy + Pydantic) or SQLAlchemy
- **Cache/Queue**: Redis (aioredis for caching, rate limiting, tasks)
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
- **Commands**:
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
  1. Write focused pytest tests (e.g., `test_user_registration_succeeds`).
  2. Implement minimal code to pass (PEP 8, SOLID, DRY).
  3. Enhance tests for real-world scenarios (e.g., concurrency, failures).
  4. Update code, refactor iteratively, keep tests green.
  5. Validate 95%+ coverage with `pytest --cov`.
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
  - No `pytest.skip()`; fix root causes.
  - Use UUIDs for unique test data.
  - Comprehensive docstrings for business context.
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

## Sub-Agent Integration (dl-ezo/claude-code-sub-agents)
- **Agents Directory**: `.claude/agents/`
- **Agent Detection**: Claude scans `.claude/agents/` for agent definitions, automatically loading all 35 sub-agents for task delegation.
- **Agent Execution**:
  - Use `/agents <agent-name> "<task>"` for specific tasks (e.g., `/agents security-analyzer "Audit auth endpoints"`).
  - Use `/agents project-orchestrator "<project-goal>"` for end-to-end workflows (e.g., `/agents project-orchestrator "Build authentication system with JWT and OAuth2"`).
  - Agents coordinate via `project-orchestrator`, ensuring seamless task delegation and context preservation.

### Agent Categories and Descriptions
The dl-ezo framework provides 35 specialized sub-agents across 6 categories, optimized for Cedrina’s advanced requirements. Each agent adheres to TDD, DDD, SOLID, DRY, PEP 8, and clean code principles.

#### 1. Requirements & Analysis (4 Agents)
- **requirements-analyst**: Translates business needs into technical specifications, creating detailed functional requirements. Use for stakeholder alignment and user story validation.
  - **Example**: `/agents requirements-analyst "Define specs for multi-tenant user management"`
- **user-story-generator**: Produces user stories with acceptance criteria, ensuring stakeholder-readable requirements. Aligns with Cedrina’s feature tests (pytest-bdd).
  - **Example**: `/agents user-story-generator "Create user stories for OAuth2 login flow"`
- **business-process-analyst**: Maps business processes to technical requirements, ideal for complex workflows like Cedrina’s authentication or payment systems.
  - **Example**: `/agents business-process-analyst "Map subscription billing process"`
- **requirements-validator**: Ensures requirements are complete, consistent, and testable, preventing scope creep.
  - **Example**: `/agents requirements-validator "Validate specs for real-time WebSocket notifications"`

#### 2. Design & Architecture (5 Agents)
- **system-architect**: Designs clean architecture and DDD layers, ensuring modularity and scalability for Cedrina’s Adapters → Core → Domain ← Infrastructure flow.
  - **Example**: `/agents system-architect "Design architecture for scalable API"`
- **data-architect**: Creates PostgreSQL schemas and Redis caching strategies, optimizing for Cedrina’s asyncpg and aioredis usage.
  - **Example**: `/agents data-architect "Design schema for user sessions"`
- **interface-designer**: Defines RESTful APIs and WebSocket interfaces with OpenAPI-compliant specs, aligning with Cedrina’s API-first approach.
  - **Example**: `/agents interface-designer "Define API for user management"`
- **security-architect**: Designs zero-trust security frameworks, including JWT, OAuth2, and Casbin RBAC/ABAC, critical for Cedrina’s security requirements.
  - **Example**: `/agents security-architect "Design zero-trust auth system"`
- **design-reviewer**: Validates architecture for scalability, security, and compliance, ensuring Cedrina’s enterprise-grade standards.
  - **Example**: `/agents design-reviewer "Review microservices architecture"`

#### 3. Implementation & Development (10 Agents)
- **code-reviewer**: Assesses code for PEP 8, SOLID, and DRY compliance, ensuring Cedrina’s clean code standards.
  - **Example**: `/agents code-reviewer "Review auth service code"`
- **test-suite-generator**: Generates pytest tests (unit, integration, feature) targeting 95%+ coverage, supporting Cedrina’s TDD workflow.
  - **Example**: `/agents test-suite-generator "Generate tests for user registration"`
- **code-refactoring-specialist**: Improves code structure, reducing technical debt while maintaining green tests, aligning with Cedrina’s refactoring guidelines.
  - **Example**: `/agents code-refactoring-specialist "Refactor auth service"`
- **security-analyzer**: Identifies vulnerabilities (e.g., SQL injection, XSS), ensuring OWASP Top 10 compliance for Cedrina’s security tests.
  - **Example**: `/agents security-analyzer "Audit endpoints for vulnerabilities"`
- **performance-optimizer**: Optimizes code and queries for low latency, critical for Cedrina’s high-traffic APIs and WebSockets.
  - **Example**: `/agents performance-optimizer "Optimize user query performance"`
- **api-designer**: Develops FastAPI endpoints with Pydantic schemas, ensuring RESTful and secure APIs for Cedrina.
  - **Example**: `/agents api-designer "Create auth API endpoints"`
- **documentation-generator**: Produces API docs, code comments, and user guides, aligning with Cedrina’s documentation requirements.
  - **Example**: `/agents documentation-generator "Generate API docs for auth"`
- **dependency-manager**: Resolves package conflicts and optimizes dependencies, supporting Cedrina’s Poetry usage.
  - **Example**: `/agents dependency-manager "Resolve Poetry conflicts"`
- **database-schema-designer**: Designs SQLModel/Alembic schemas and migrations, critical for Cedrina’s PostgreSQL setup.
  - **Example**: `/agents database-schema-designer "Design user schema"`
- **cicd-builder**: Configures CI/CD pipelines (e.g., GitHub Actions), ensuring Cedrina’s automated testing and deployment.
  - **Example**: `/agents cicd-builder "Set up CI/CD for FastAPI app"`

#### 4. Project Management (5 Agents)
- **project-planner**: Creates project plans and timelines, coordinating Cedrina’s complex workflows.
  - **Example**: `/agents project-planner "Plan user management module"`
- **risk-manager**: Identifies and mitigates project risks, critical for Cedrina’s enterprise-grade reliability.
  - **Example**: `/agents risk-manager "Assess risks for OAuth2 integration"`
- **progress-tracker**: Monitors progress and identifies blockers, ensuring Cedrina’s timelines are met.
  - **Example**: `/agents progress-tracker "Track auth system development"`
- **qa-coordinator**: Establishes quality standards and coordinates testing, aligning with Cedrina’s 95%+ coverage goal.
  - **Example**: `/agents qa-coordinator "Coordinate security testing"`
- **stakeholder-communicator**: Manages stakeholder updates, ensuring alignment with Cedrina’s business goals.
  - **Example**: `/agents stakeholder-communicator "Prepare auth system report"`

#### 5. Deployment & Operations (5 Agents)
- **project-orchestrator**: Master coordinator for end-to-end workflows, delegating tasks to specialized agents for Cedrina’s full lifecycle.
  - **Example**: `/agents project-orchestrator "Build authentication system"`
- **deployment-ops-manager**: Handles Docker/Kubernetes deployments and monitoring, critical for Cedrina’s production setup.
  - **Example**: `/agents deployment-ops-manager "Deploy FastAPI app to Kubernetes"`
- **uat-coordinator**: Manages user acceptance testing, ensuring Cedrina’s features meet stakeholder needs.
  - **Example**: `/agents uat-coordinator "Coordinate UAT for user management"`
- **training-change-manager**: Creates training materials and manages adoption, supporting Cedrina’s documentation.
  - **Example**: `/agents training-change-manager "Create auth system training"`
- **project-template-manager**: Manages reusable templates for rapid project setup, streamlining Cedrina’s workflows.
  - **Example**: `/agents project-template-manager "Create FastAPI template"`

#### 6. Meta-Management (6 Agents)
- **context-manager**: Maintains session context for continuity, critical for Cedrina’s long-term projects.
  - **Example**: `/agents context-manager "Preserve auth system context"`
- **session-continuity-manager**: Ensures seamless transitions between Claude Code sessions, supporting Cedrina’s iterative development.
  - **Example**: `/agents session-continuity-manager "Restore session state"`
- **memory-manager**: Optimizes project documentation and memory usage, aligning with Cedrina’s maintainability.
  - **Example**: `/agents memory-manager "Optimize project docs"`
- **workflow-optimizer**: Enhances agent workflows, reducing token usage and improving efficiency for Cedrina.
  - **Example**: `/agents workflow-optimizer "Optimize test workflow"`
- **resource-monitor**: Tracks resource usage (e.g., CPU, memory), ensuring Cedrina’s scalability.
  - **Example**: `/agents resource-monitor "Monitor API resource usage"`
- **agent-creator**: Dynamically creates specialized agents for unique Cedrina requirements.
  - **Example**: `/agents agent-creator "Create agent for WebSocket optimization"`

## Test Analysis and Fix Workflow
- **Objective**: Systematically fix test failures from smallest unit test directory to larger ones, ensuring no side effects and production consistency.
- **Process**:
  1. **Identify**: Scan `tests/` for smallest unit test directory (e.g., `tests/unit/domain/entities/`).
  2. **Run**: `/agents test-suite-generator "Generate tests for entities"`; run `pytest tests/unit/domain/entities/ --cov=src/domain/entities`.
  3. **Analyze**: Use `/agents code-reviewer "Analyze test failures"` with `pytest --pdb`.
  4. **Fix**: Apply minimal changes via `/agents code-refactoring-specialist "Refactor failing code"`, ensuring PEP 8, SOLID, DRY.
  5. **Dependencies**: Check with `pydeps src/ --show-deps`; run related tests (e.g., `tests/unit/domain/services/`) via `/agents test-suite-generator`.
  6. **Validate**: Run `pytest --cov` for 95%+ coverage; use `/agents security-analyzer "Validate security tests"`.
  7. **TODO**: Generate steps for next directory (e.g., `tests/unit/domain/services/`) via `/agents project-planner`.
  8. **Proceed**: Automatically move to next directory with `/agents project-orchestrator`.
- **Change Management**:
  - **Impact**: Document performance, security, scalability via `/agents documentation-generator`.
  - **Rollback**: Use `git reset` or `alembic downgrade` if tests fail.
  - **Analysis**: Use ruff, mypy, pg_stat_statements, Redis MONITOR.

## Security Instructions
- **Authentication**: JWT, OAuth2, sessions with python-jose, passlib; enforce expiration/refresh via `/agents security-architect`.
- **Authorization**: Casbin RBAC/ABAC, least privilege, zero-trust via `/agents security-analyzer`.
- **Input Validation**: Pydantic schemas, prevent SQL injection/XSS (expect 422) via `/agents security-analyzer`.
- **Rate Limiting**: Redis-based, test distributed attacks (expect 429) via `/agents test-suite-generator`.
- **Audit Logging**: Log critical actions in core/logging/ via `/agents documentation-generator`.
- **Timing Attacks**: Use hmac.compare_digest; test via `/agents security-analyzer`.
- **Vulnerability Testing**: OWASP Top 10, penetration testing via `/agents security-analyzer`; document in `docs/security/`.

## Observability
- **Logging**: Structured JSON (core/logging/) with user ID, request ID via `/agents documentation-generator`.
- **Metrics**: Prometheus (core/metrics.py) for latency, errors; expose at /metrics via `/agents performance-optimizer`.
- **Tracing**: OpenTelemetry for FastAPI/PostgreSQL/Redis, export to Jaeger via `/agents performance-optimizer`.
- **Health Checks**: /api/v1/health (REST), /ws/health (WebSocket) via `/agents api-designer`.

## Internationalization (i18n)
- Use `utils/i18n.py` with `locales/` translations.
- Apply i18n middleware in `core/middleware.py` via `/agents interface-designer`.
- Test multilingual responses via `/agents test-suite-generator`.

## Deployment and Maintenance
- **Pre-Deployment**:
  - Run `make test-cov` for 95%+ coverage via `/agents qa-coordinator`.
  - Apply `alembic upgrade head` via `/agents database-schema-designer`.
  - Validate `.env` via `/agents dependency-manager`.
- **Deployment**:
  - Use `docker-compose up -d` or Kubernetes via `/agents deployment-ops-manager`.
  - Implement feature flags via `/agents project-template-manager`.
- **Post-Deployment**:
  - Monitor Prometheus/OpenTelemetry via `/agents resource-monitor`.
  - Check logs for anomalies via `/agents documentation-generator`.
  - Rollback with `alembic downgrade` or `git revert`.
- **Maintenance**:
  - Refresh test data via `/agents test-suite-generator`.
  - Monitor technical debt in `docs/technical_debt/` via `/agents documentation-generator`.
  - Update dependencies with `poetry update` via `/agents dependency-manager`.

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
  2. Run `/agents test-suite-generator "Generate tests for entities"`; execute `pytest <directory> --cov=<source_path>`.
  3. Analyze failures with `/agents code-reviewer "Analyze test failures"` and `pytest --pdb`.
  4. Fix issues via `/agents code-refactoring-specialist "Refactor failing code"`, ensuring PEP 8, SOLID, DRY.
  5. Check dependencies with `pydeps src/ --show-deps`; run related tests via `/agents test-suite-generator`.
  6. Validate with `pytest --cov` for 95%+ coverage; use `/agents security-analyzer`.
  7. Generate TODO for next directory via `/agents project-planner`.
  8. Proceed automatically with `/agents project-orchestrator`.
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
make test-cov                        # Tests with coverage
```

## Initial TODO
- **Task**: Analyze and fix tests in `tests/unit/domain/entities/`.
- **Steps**:
  1. Run `/agents test-suite-generator "Generate tests for entities"`; execute `pytest tests/unit/domain/entities/ --cov=src/domain/entities`.
  2. Analyze failures with `/agents code-reviewer "Analyze test failures"`.
  3. Fix issues via `/agents code-refactoring-specialist "Refactor failing code"`.
  4. Check dependencies with `pydeps src/`.
  5. Run related tests (e.g., `tests/unit/domain/services/`) via `/agents test-suite-generator`.
  6. Validate 95%+ coverage with `pytest --cov`.
  7. Next TODO: Analyze `tests/unit/domain/services/` via `/agents project-orchestrator`.
