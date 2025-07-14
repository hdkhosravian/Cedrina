# Advanced CLAUDE.md for Cedrina FastAPI Project

## Project Overview
- **Project Name:** Cedrina
- **Description:** A production-ready FastAPI template for building scalable, secure, and maintainable REST APIs and WebSocket applications. Cedrina follows clean architecture and Domain-Driven Design (DDD), providing enterprise-grade features such as robust authentication (JWT, OAuth2, sessions), async/await support, internationalization (i18n), security mechanisms (rate limiting, input validation, audit logging), structured logging, metrics for observability, Dockerized workflows, and a comprehensive test suite with 95%+ coverage.
- **Goals:**
  - Deliver a modular, extensible foundation for enterprise APIs.
  - Ensure strict separation of concerns via clean architecture and DDD.
  - Prioritize security, performance, scalability, and developer experience.
  - Support multilingual applications and real-time features via WebSockets.

## Technology Stack
- **Programming Language:** Python 3.11+ (PEP 8 compliant)
- **Web Framework:** FastAPI (for REST APIs and WebSockets)
- **Database:** PostgreSQL 15+ (optimized for async queries, connection pooling)
- **ORM:** SQLModel (combining SQLAlchemy and Pydantic)
- **Cache/Queue:** Redis (for caching, rate limiting, and async tasks)
- **Dependency Management:** Poetry
- **Testing Framework:** Pytest (with `pytest-asyncio`, `pytest-mock`, `hypothesis`)
- **Code Quality Tools:** `black`, `ruff`, `isort`, `flake8`, `pydocstyle`, `mypy`
- **Containerization:** Docker, Docker Compose
- **Migrations:** Alembic
- **Permissions:** Casbin (RBAC/ABAC)
- **Observability:** Prometheus (metrics), structured logging (via `logging`)
- **Other Libraries:** `httpx` (HTTP requests), `aioredis` (Redis async client), `jinja2` (templates), `python-jose` (JWT), `passlib` (password hashing)

## Repository Structure
Cedrina uses a `src/` layout aligned with clean architecture and DDD layers:
- **src/**
  - **adapters/**: Interfaces to external systems
    - `api/v1/`: REST API endpoints
      - `auth/`: Authentication routes, schemas, and utilities
      - `admin/`: Admin endpoints
      - `health.py`: Health check endpoint
      - `docs.py`: API documentation router
    - `websockets/`: WebSocket endpoints
      - `health.py`: WebSocket health check
  - **core/**: Application configuration and lifecycle
    - `application.py`: FastAPI app factory
    - `initialization.py`: Environment setup and logging
    - `lifecycle.py`: Startup/shutdown events
    - `middleware.py`: CORS, rate limiting, i18n middleware
    - `dependencies/`: Dependency injection helpers
    - `exceptions.py`: Custom exceptions
    - `handlers.py`: Exception handlers
    - `config/`: Pydantic settings
    - `rate_limiting/`: Advanced rate limiter
    - `logging/`: Structured logging configuration
    - `metrics.py`: Prometheus metrics
  - **domain/**: DDD business logic
    - `entities/`: Domain entities (e.g., `User`, `Session`)
    - `value_objects/`: Immutable value objects (e.g., `Email`, `Role`)
    - `services/`: Domain services (e.g., authentication, email)
    - `events/`: Domain events (e.g., `UserRegistered`)
    - `interfaces/`: Repository/service contracts
    - `validation/`: Validation helpers
    - `security/`: Security utilities
  - **infrastructure/**: External system implementations
    - `database/`: Database connection helpers (SQLModel, `asyncpg`)
    - `repositories/`: SQLModel repository implementations
    - `services/`: External service adapters (e.g., email, OAuth)
    - `dependency_injection/`: Wiring for infrastructure
    - `redis.py`: Redis client
  - **permissions/**: Casbin-based RBAC/ABAC
    - `enforcer.py`: Permission enforcement
    - `dependencies.py`: Permission dependencies
    - `policies.py`: Policy definitions
    - `config.py`: Casbin configuration
  - **utils/**: Shared utilities
    - `i18n.py`: Internationalization support
    - `security.py`: Security helpers
  - **templates/**: Jinja2 templates (e.g., email)
  - **main.py**: Application entry point
- **tests/**: Unit, integration, feature, and performance tests
- **alembic/**: Database migrations
- **locales/**: Translation files for i18n
- **scripts/**: Helper scripts
- **docs/**: Comprehensive documentation (e.g., `security/`, `api/`)

## Application Architecture
- **Clean Architecture:** Enforces dependency rule: **Adapters** → **Core** → **Domain** ← **Infrastructure**.
- **Dependency Flow:** Domain layer is independent; adapters rely on FastAPI; infrastructure uses SQLModel and Redis.
- **Key Principles:**
  - Modularity: Strict separation of concerns via DDD layers.
  - Testability: Comprehensive test suite with 95%+ coverage.
  - Scalability: Async/await, connection pooling, and Redis caching.
  - Security: JWT validation, rate limiting, audit logging, and timing attack prevention.

## Coding Standards
- **PEP 8 Compliance:** Enforce with `black` (formatting), `isort` (imports), `ruff`, `flake8` (linting).
- **Type Hints:** Mandatory, validated with `mypy`.
- **Clean Code:**
  - Functions: Small (<15 lines), single responsibility, clear names (e.g., `validate_user_credentials`).
  - Classes: Cohesive, minimal public APIs, use SQLModel or Pydantic models.
  - Error Handling: Custom exceptions (e.g., `AuthenticationError`) with clear messages; avoid `None` returns or bare `except`.
  - Comments: Minimal, rely on self-documenting code; use `pydocstyle`-compliant docstrings (Google style).
- **Refactoring:** Eliminate code smells (e.g., duplication, complex conditionals) during TDD iterations.

## Development Methodologies
### Test-Driven Development (TDD)
- **Workflow:**
  1. Write simple, focused `pytest` tests (e.g., `test_user_registration_succeeds`).
  2. Implement minimal code to pass tests, adhering to PEP 8 and clean code.
  3. Enhance tests for real-world scenarios (e.g., high-concurrency, Redis failures, invalid JWTs).
  4. Update code to pass enhanced tests, maintaining SOLID and DRY principles.
  5. Refactor iteratively to improve readability and modularity, keeping tests green.
  6. Validate full test suite (`pytest --cov`) with 95%+ coverage for critical components.
- **Test Pyramid:**
  - **Unit Tests (70-80%):** Validate components (e.g., entities, services) using `pytest-mock`. Fast, isolated (e.g., in-memory SQLite via `pytest-sqlmodel`).
  - **Integration Tests (15-20%):** Verify FastAPI-SQLModel-Redis interactions.
  - **Feature Tests (5-10%):** End-to-end workflows with `pytest-bdd` (Given-When-Then).
  - **Performance Tests (<5%):** Benchmark critical paths with `pytest-benchmark`, `locust`.
- **Advanced Testing Techniques:**
  - Parameterized tests (`pytest.mark.parametrize`)
  - Property-based testing (`hypothesis` for edge cases)
  - Async testing (`pytest-asyncio` for FastAPI, `asyncpg`, `aioredis`)
  - Contract testing (`pact-python` for API interactions)
  - Chaos testing (simulate PostgreSQL/Redis downtime)
- **Commands:** `make test`, `make test-cov`, `pytest -m unit`, `pytest -m integration`.

### Domain-Driven Design (DDD)
- **Bounded Contexts:** Define contexts (e.g., Authentication, Administration, WebSockets).
- **Ubiquitous Language:** Use terms like "User," "Session," "Permission" consistently.
- **Aggregates:** Model aggregates (e.g., `UserAggregate`) with SQLModel, enforcing consistency via PostgreSQL transactions.
- **Entities:** Objects with unique identities (e.g., `User`, `Session`) using SQLModel.
- **Value Objects:** Immutable objects (e.g., `Email`, `Role`) with Pydantic or `dataclasses` (`frozen=True`).
- **Repositories:** Interfaces (`abc.ABC`) implemented with SQLModel/`asyncpg`.
- **Domain Events:** Events (e.g., `UserRegistered`) for async workflows.
- **Domain Services:** Stateless logic (e.g., `AuthService`) for cross-entity operations.
- **Domain Exceptions:** Custom exceptions (e.g., `InvalidTokenError`).

### SOLID Principles
- **Single Responsibility Principle (SRP):** Each class/module has one responsibility (e.g., separate routing from business logic).
- **Open/Closed Principle (OCP):** Use polymorphism (e.g., `abc.ABC`, Pydantic) for extensibility.
- **Liskov Substitution Principle (LSP):** Ensure type safety with `mypy`.
- **Interface Segregation Principle (ISP):** Fine-grained interfaces (e.g., protocols).
- **Dependency Inversion Principle (DIP):** Use dependency injection (FastAPI `Depends`, `dependency-injector`).

### Design Patterns
- **Factory:** Create service/repository instances.
- **Strategy:** Pluggable authentication strategies (e.g., JWT vs. OAuth2).
- **Decorator:** Middleware for rate limiting, logging.
- **Observer:** Handle domain events (e.g., user registration triggers).
- **Adapter:** Integrate external services (e.g., OAuth providers).

## Security Instructions
- **Authentication:** Implement JWT, OAuth2, and session-based auth with `python-jose`, `passlib`.
- **Rate Limiting:** Use `redis`-based rate limiter in `core/rate_limiting/`.
- **Input Validation:** Enforce with Pydantic schemas in `adapters/api/v1/*/schemas/`.
- **Audit Logging:** Log critical actions (e.g., login attempts) in `core/logging/`.
- **Timing Attacks:** Use constant-time comparisons (e.g., `hmac.compare_digest`).
- **Vulnerabilities:** Test for rate-limit bypass and JWT ownership issues (see `docs/security/`).

## Observability
- **Logging:** Structured JSON logging in `core/logging/` for traceability.
- **Metrics:** Prometheus metrics in `core/metrics.py` for API performance.
- **Monitoring:** Health checks at `/api/v1/health` and WebSocket `/ws/health`.

## Internationalization (i18n)
- Use `utils/i18n.py` for multi-language support.
- Store translations in `locales/`.
- Apply i18n middleware in `core/middleware.py`.

## Deployment and Maintenance
- **Pre-Deployment:**
  - Run `make test-cov` to ensure 95%+ coverage.
  - Apply migrations with `alembic upgrade head`.
  - Validate `.env` settings (e.g., `SECRET_KEY`, database credentials).
- **Deployment:** Use `docker-compose up -d` for production.
- **Post-Deployment:**
  - Monitor metrics via Prometheus.
  - Check logs for errors.
  - Rollback migrations with `alembic downgrade`.
- **Change Management:**
  - Use `pydeps` for dependency analysis.
  - Document impacts on performance, scalability, and security.
  - Provide rollback strategies for code and database changes.

## Instructions for Claude
- **Role:** Act as a senior Python engineer in the top 1% of global talent, specializing in FastAPI, PostgreSQL, Redis, and clean architecture.
- **TDD:** Drive development with iterative TDD:
  1. Write failing `pytest` tests with clear, PEP 8-compliant names.
  2. Implement minimal code to pass tests.
  3. Enhance tests for real-world scenarios (e.g., high-traffic, Redis failures, invalid inputs).
  4. Refactor to maintain clean code, SOLID, and DRY principles.
  5. Validate with `pytest --cov` (95%+ coverage).
- **DDD:** Model business logic in `domain/` with bounded contexts, aggregates, and ubiquitous language.
- **Clean Code:** Enforce PEP 8, use type hints, and minimize comments with self-documenting code.
- **Security:** Prioritize secure coding practices (e.g., input validation, timing attack prevention).
- **CoT Reasoning:** Provide step-by-step reasoning in Markdown sections (`## Solution`, `## Tests`, `## CoT Reasoning`) for requirement analysis, test design, domain modeling, and trade-offs.
- **Multi-Perspective Analysis:** Consider technical (performance, scalability), business (stakeholder needs), human (developer experience, usability), and operational (deployment, maintenance) perspectives.
- **Tools:** Use `black`, `ruff`, `isort`, `flake8`, `mypy`, `pydocstyle`, `pytest`, `SQLModel`, `asyncpg`, `aioredis`, `alembic`.

## Quick Start
- Clone repository and install dependencies: `poetry install`.
- Configure `.env` from `.env.development`.
- Start services: `make run-dev` or `docker-compose up -d`.
- Verify health: `curl http://localhost:8000/api/v1/health`.
- Run tests: `make test` or `make test-cov`.

## Additional Guidelines
- **Critical Analysis:** Challenge inefficient suggestions, proposing alternatives aligned with Cedrina’s architecture.
- **No Over-Engineering:** Use design patterns only when they simplify code.
- **Project Structure:** Respect existing `src/` layout, tailoring additions to DDD layers.
- **Performance:** Optimize PostgreSQL queries (`EXPLAIN ANALYZE`), Redis access, and FastAPI routes.
- **Version Control:** Commit `claude.md` to Git for team consistency.