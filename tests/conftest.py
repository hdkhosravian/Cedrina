import os
import sys
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import Request
from pytest_mock import MockerFixture

# Adjust sys.path to include src directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from src.infrastructure.database.database import (
    create_db_and_tables,
)
from src.core.config.settings import settings
from src.domain.entities.user import User
from src.infrastructure.services.authentication.token import TokenService
from src.main import app


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Set up the test database with all tables."""
    # Ensure we're using the test database
    import os
    if not os.environ.get("TEST_MODE"):
        os.environ["TEST_MODE"] = "true"
    
    # Use test database URL if available, otherwise construct it
    from src.core.config.settings import settings
    test_db_url = getattr(settings, "TEST_DATABASE_URL", None)
    if test_db_url:
        os.environ["DATABASE_URL"] = test_db_url
    
    create_db_and_tables()


@pytest.fixture(scope="function", autouse=True)
def clean_database():
    """Clean up database state between tests to ensure complete isolation."""
    yield  # Run the test first

    # Clean up after each test
    try:
        from sqlalchemy import create_engine, text
        from src.core.config.settings import settings

        # Use test database URL
        db_url = getattr(settings, "TEST_DATABASE_URL", settings.DATABASE_URL)
        engine = create_engine(db_url)
        
        with engine.connect() as conn:
            # Start a transaction for cleanup
            trans = conn.begin()
            try:
                # Clean up all test data - more comprehensive cleanup
                cleanup_queries = [
                    # Clean up casbin rules (policies)
                    "DELETE FROM casbin_rule WHERE v0 LIKE '%test%' OR v0 LIKE '%user_%' OR v0 IN ('audit_test_user', 'test_role_cycle', 'test_regular_user_unique') OR v1 LIKE '%test%' OR v1 LIKE '%rate-limit%' OR v1 LIKE '%audit%' OR v1 LIKE '%cycle%'",
                    
                    # Clean up audit logs
                    "DELETE FROM policy_audit_logs WHERE subject LIKE '%test%' OR object LIKE '%test%' OR subject IN ('audit_test_user', 'test_role_cycle')",
                    
                    # Clean up sessions
                    "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username LIKE '%test%' OR email LIKE '%test%')",
                    
                    # Clean up oauth profiles
                    "DELETE FROM oauth_profiles WHERE user_id IN (SELECT id FROM users WHERE username LIKE '%test%' OR email LIKE '%test%')",
                    
                    # Clean up users (this should be last due to foreign key constraints)
                    "DELETE FROM users WHERE username LIKE '%test%' OR email LIKE '%test%' OR username IN ('test_user', 'test_admin', 'test_regular_user')",
                    
                    # Note: casbin_policies cleanup removed due to column structure differences
                ]
                
                for query in cleanup_queries:
                    try:
                        conn.execute(text(query))
                    except Exception as e:
                        # Log but don't fail - some tables might not exist or have different constraints
                        print(f"Cleanup query warning: {e}")
                
                trans.commit()
                
            except Exception as e:
                trans.rollback()
                print(f"Database cleanup transaction failed: {e}")
                # Try individual cleanup without transaction
                for query in cleanup_queries:
                    try:
                        conn.execute(text(query))
                        conn.commit()
                    except Exception as e2:
                        print(f"Individual cleanup query failed: {e2}")

    except Exception as e:
        # Don't fail tests if cleanup fails
        print(f"Database cleanup warning: {e}")
        pass


@pytest_asyncio.fixture(scope="function")
async def async_session():
    """Create an async database session for tests using the test database."""
    # Use test database URL
    db_url = getattr(settings, "TEST_DATABASE_URL", settings.DATABASE_URL)
    
    # Convert sync URL to async URL if needed
    if db_url.startswith("postgresql+psycopg2://"):
        db_url = db_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://")
    
    async_engine = create_async_engine(db_url, echo=False)
    async with AsyncSession(async_engine) as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture(scope="function")
def client():
    with TestClient(app) as client:
        yield client


@pytest.fixture
async def admin_headers(async_client: AsyncClient, admin_user: User):
    token_service = TokenService()
    token = await token_service.create_access_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}
    return headers


@pytest.fixture
def mock_get_current_user(mocker: MockerFixture, admin_user: User):
    async def _mock_get_current_user(request: Request = None):
        return admin_user

    mocker.patch("src.core.dependencies.auth.get_current_user", _mock_get_current_user)
    return _mock_get_current_user


@pytest.fixture
def mock_enforce(mocker: MockerFixture):
    async def _mock_enforce(sub: str, obj: str, act: str, request: Request = None):
        return True

    mocker.patch("src.permissions.enforcer.enforce", _mock_enforce)
    return _mock_enforce


@pytest_asyncio.fixture(scope="function")
async def mock_token_service():
    with patch("src.infrastructure.services.authentication.token.TokenService", autospec=True) as mock:
        yield mock


@pytest_asyncio.fixture(scope="function")
async def mock_async_session():
    with patch("src.infrastructure.database.database.AsyncSessionLocal", autospec=True) as mock:
        yield mock


@pytest_asyncio.fixture(scope="function")
async def mock_user_service():
    with patch(
        "src.domain.services.authentication.user_authentication_service.UserAuthenticationService", autospec=True
    ) as mock:
        yield mock


@pytest.fixture(scope="session", autouse=True)
def configure_rate_limiter():
    """Configure rate limiter for tests with disabled limits to avoid test failures."""
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    from src.main import app

    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    
    # Disable rate limiting for tests
    import os
    os.environ["RATE_LIMIT_ENABLED"] = "false"
    
    return limiter


@pytest.fixture(scope="session", autouse=True)
def ensure_test_database():
    """Ensure the test database is properly set up and isolated."""
    import os
    
    # Set test mode
    os.environ["TEST_MODE"] = "true"
    
    # Ensure we're using the test database
    from src.core.config.settings import settings
    
    # Construct test database URL if not already set
    if not hasattr(settings, "TEST_DATABASE_URL") or not settings.TEST_DATABASE_URL:
        test_db_url = f"postgresql+psycopg2://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB_TEST}?sslmode={settings.POSTGRES_SSL_MODE}"
        os.environ["DATABASE_URL"] = test_db_url
    
    # Verify test database exists and has tables
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(settings.DATABASE_URL)
        with engine.connect() as conn:
            # Check if alembic_version table exists (indicates migrations have been run)
            result = conn.execute(text("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'alembic_version'"))
            if result.scalar() == 0:
                raise Exception("Test database does not have migrations applied. Run 'make db-migrate' first.")
    except Exception as e:
        print(f"Test database setup warning: {e}")
        print("Make sure to run 'make db-migrate' before running tests.")
    
    yield
