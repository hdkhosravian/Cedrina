import httpx
import pytest
import uuid
from fastapi import status

from tests.factories.user import create_fake_user
from src.domain.value_objects.password import _hash_password

@pytest.mark.asyncio
async def test_login_successful(async_client: httpx.AsyncClient, db_session):
    """Test successful login with valid credentials."""
    # Create a user with a known password and valid username
    raw_password = "Str0ngP@ssw0rd"
    
    # Generate unique username to avoid conflicts
    unique_suffix = str(uuid.uuid4())[:8]
    username = f"existinguser_{unique_suffix}"
    email = f"existinguser_{unique_suffix}@example.com"
    
    # Register the user first to ensure they exist in the API's database session
    registration_data = {
        "username": username,
        "email": email,
        "password": raw_password
    }
    
    # Register the user
    registration_response = await async_client.post(
        "/api/v1/auth/register",
        json=registration_data
    )
    
    # Verify registration was successful
    assert registration_response.status_code == status.HTTP_201_CREATED
    
    # Now attempt to login with the same credentials
    response = await async_client.post(
        "/api/v1/auth/login", 
        json={"username": registration_data["username"], "password": raw_password}
    )

    print('===============================================')
    print(response.json())
    print('===============================================')

    # Expect 200 OK for successful login
    assert response.status_code == status.HTTP_200_OK
    assert "user" in response.json()
    assert "tokens" in response.json()


@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client: httpx.AsyncClient, db_session):
    """Test login with invalid credentials returns 401."""
    user = create_fake_user(username="testuser456")

    response = await async_client.post(
        "/api/v1/auth/login", 
        json={"username": user.username, "password": "wrongpassword"}
    )

    # Expect 401 Unauthorized for invalid credentials
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_login_nonexistent_user(async_client: httpx.AsyncClient, db_session):
    """Test login with non-existent user returns 422."""
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent@example.com", "password": "testpassword123"},
    )

    # Expect 422 for validation errors (non-existent user)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
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
    user = create_fake_user(username="inactiveuser", is_active=False)

    response = await async_client.post(
        "/api/v1/auth/login", 
        json={"username": user.username, "password": "testpassword123"}
    )

    # Expect 401 Unauthorized for inactive user
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()
