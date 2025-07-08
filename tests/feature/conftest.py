import pytest
import uuid
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.entities.user import Role, User
from src.infrastructure.database.async_db import get_async_db
from src.main import app

# Remove the custom event_loop fixture and use pytest-asyncio's built-in event loop management


@pytest.fixture(scope="module")
def client():
    # Override the get_current_user dependency for tests
    async def override_get_current_user(
        request=None, token=None, db_session=None, redis_client=None
    ):
        from src.domain.entities.user import Role

        # Debug token value and request headers
        auth_header = None
        if request:
            auth_header = request.headers.get("Authorization", "")
            print(f"Authorization header from request: {auth_header}")
        print(f"Token received: {token}")
        if auth_header and "admin" in auth_header.lower():
            print("Admin token detected from header")
            return User(
                id=2,
                username="admin_user",
                email="admin@example.com",
                hashed_password="hashed_password",
                role=Role.ADMIN,
                department="IT",
                location="NY",
                time_of_day="working_hours",
            )
        elif token and "admin" in token.lower():
            print("Admin token detected from token")
            return User(
                id=2,
                username="admin_user",
                email="admin@example.com",
                hashed_password="hashed_password",
                role=Role.ADMIN,
                department="IT",
                location="NY",
                time_of_day="working_hours",
            )
        else:
            print("Non-admin token detected")
            # Use unique data to avoid conflicts with other tests
            unique = uuid.uuid4().hex[:8]
            return User(
                id=1,
                username=f"testuser_{unique}",
                email=f"test{unique}@example.com",
                hashed_password="hashed_password",
                role=Role.USER,
                department="IT",
                location="NY",
                time_of_day="working_hours",
            )

    from src.core.dependencies.auth import get_current_user

    app.dependency_overrides[get_current_user] = override_get_current_user

    # Mock Casbin enforcer to allow admin actions for feature tests
    from unittest.mock import patch

    def mock_enforce(self, subject, object_name, action, department=None, location=None, time_of_day=None, request=None):
        """Mock enforce function with explicit signature matching ABAC usage."""
        print(f"Mock enforce called with subject: {subject}, object: {object_name}, action: {action}")
        print(f"ABAC attributes - department: {department}, location: {location}, time_of_day: {time_of_day}")
        
        # Check if request object is available to get headers
        auth_header = None
        if request:
            auth_header = request.headers.get("Authorization", "")
            print(f"Authorization header from request in enforce: {auth_header}")
        
        if object_name and "/admin/policies" in str(object_name):
            print("Mock enforce: Allowing access to admin policy endpoints")
            return True
        elif subject == "admin":
            print("Mock enforce: Allowing admin access based on subject")
            return True
        print("Mock enforce: Allowing access to endpoints")
        return True

    # Patch the specific Casbin enforcer method
    patch("casbin.Enforcer.enforce", mock_enforce).start()

    return TestClient(app)


@pytest.fixture(scope="function")
async def db_session():
    async with get_async_db() as session:
        yield session


@pytest.fixture(scope="function")
def regular_user():
    # Use unique data to avoid conflicts with other tests
    unique = uuid.uuid4().hex[:8]
    user = User(
        id=1,
        username=f"testuser_{unique}",
        email=f"test{unique}@example.com",
        hashed_password="hashed_password",
        role=Role.USER,
        department="IT",
        location="NY",
        time_of_day="working_hours",
    )
    return user


@pytest.fixture(scope="function")
def admin_user():
    admin = User(
        id=2,
        username="admin_user",
        email="admin@example.com",
        hashed_password="hashed_password",
        role=Role.ADMIN,
        department="IT",
        location="NY",
        time_of_day="working_hours",
    )
    return admin


@pytest.fixture(scope="function")
def regular_user_headers(regular_user: User):
    # Mock token creation or authentication header
    return {"Authorization": "Bearer token_for_regular_user"}


@pytest.fixture(scope="function")
def admin_user_headers(admin_user: User):
    # Mock token creation or authentication header
    return {"Authorization": f"Bearer token_for_{admin_user.username}"}
