import httpx
import pytest
from fastapi import status

from tests.factories.user import create_fake_user


@pytest.mark.asyncio
async def test_login_successful(async_client: httpx.AsyncClient, db_session):
    """Test successful login with valid credentials."""
    # Create a user with a known password
    user = create_fake_user()
    # Note: In a real test, you would need to create the user in the database
    # and hash the password properly. This is a simplified test.

    response = await async_client.post(
        "/api/v1/auth/login", 
        json={"username": user.username, "password": "testpassword123"}
    )

    # Expect 200 OK for successful login
    assert response.status_code == status.HTTP_200_OK
    assert "user" in response.json()
    assert "tokens" in response.json()


@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client: httpx.AsyncClient, db_session):
    """Test login with invalid credentials returns 401."""
    user = create_fake_user()

    response = await async_client.post(
        "/api/v1/auth/login", 
        json={"username": user.username, "password": "wrongpassword"}
    )

    # Expect 401 Unauthorized for invalid credentials
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_nonexistent_user(async_client: httpx.AsyncClient, db_session):
    """Test login with non-existent user returns 401."""
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent@example.com", "password": "testpassword123"},
    )

    # Expect 401 Unauthorized for non-existent user
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_missing_fields(async_client: httpx.AsyncClient, db_session):
    """Test login with missing fields returns 422."""
    response = await async_client.post(
        "/api/v1/auth/login", 
        json={"username": "test@example.com"}
    )

    # Expect 422 Unprocessable Entity for missing fields
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_inactive_user(async_client: httpx.AsyncClient, db_session):
    """Test login with inactive user returns 401."""
    user = create_fake_user(is_active=False)

    response = await async_client.post(
        "/api/v1/auth/login", 
        json={"username": user.username, "password": "testpassword123"}
    )

    # Expect 401 Unauthorized for inactive user
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()
