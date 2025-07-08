import os
import sys
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import Request, FastAPI
from pytest_mock import MockerFixture
from asgi_lifespan import LifespanManager

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
from src.infrastructure.database.async_db import get_async_db_dependency, engine as async_engine
from src.infrastructure.redis import get_redis
import redis.asyncio as aioredis
from sqlalchemy import text


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


@pytest_asyncio.fixture(scope="function", autouse=True)
async def clean_redis():
    """Clean Redis before each test to ensure complete isolation."""
    redis_url = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/0")
    redis = aioredis.from_url(redis_url, decode_responses=True)
    await redis.flushdb()
    await redis.close()


@pytest_asyncio.fixture(scope="function")
async def async_client(clean_redis):
    """Create an async client with proper async DB session isolation and shared Redis."""
    # Create a fresh async engine for each test to ensure complete isolation
    from src.infrastructure.database.async_db import _build_async_url
    from sqlalchemy.orm import sessionmaker
    
    # Build fresh async URL
    async_url = _build_async_url()
    
    # Create a fresh engine for this test
    from sqlalchemy.ext.asyncio import create_async_engine
    test_engine = create_async_engine(async_url, echo=False, future=True, pool_pre_ping=True)
    
    # Create a fresh session factory
    TestAsyncSessionFactory = sessionmaker(
        bind=test_engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async def get_fresh_async_db():
        """Get a completely fresh async DB session for each test."""
        async with TestAsyncSessionFactory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    # Create a shared Redis client for the test
    redis_url = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/0")
    test_redis = aioredis.from_url(redis_url, decode_responses=True)
    
    async def get_test_redis():
        """Get the same Redis instance used by the test."""
        try:
            yield test_redis
        finally:
            # Don't close here as we need it to persist across requests in the same test
            pass
    
    # Override both dependencies to ensure app and test client use the same instances
    app.dependency_overrides[get_async_db_dependency] = get_fresh_async_db
    app.dependency_overrides[get_redis] = get_test_redis
    
    async with LifespanManager(app):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            yield ac
    
    # Clean up
    app.dependency_overrides.clear()
    await test_redis.aclose()
    await test_engine.dispose()


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


@pytest_asyncio.fixture(scope="function")
async def async_session():
    from src.infrastructure.database.async_db import _build_async_url
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker

    async_url = _build_async_url()
    test_engine = create_async_engine(async_url, echo=False, future=True, pool_pre_ping=True)
    TestAsyncSessionFactory = sessionmaker(
        bind=test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with TestAsyncSessionFactory() as session:
        try:
            yield session
        finally:
            await session.close()
    await test_engine.dispose()
