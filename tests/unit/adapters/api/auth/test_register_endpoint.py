import httpx
import pytest
import uuid
from fastapi import status


def _unique_user_data():
    """Generate unique user data for each test run."""
    unique = uuid.uuid4().hex[:8]
    return {
        "username": f"newuser_{unique}",
        "email": f"newuser{unique}@example.com",
        "password": "SecureP@ssw0rd2024!",
    }


@pytest.mark.asyncio
async def test_register_successful(async_client: httpx.AsyncClient, db_session):
    """Test successful user registration with clean architecture."""
    user_data = _unique_user_data()
    response = await async_client.post(
        "/api/v1/auth/register",
        json=user_data,
    )

    # Test should expect only one specific outcome
    assert response.status_code == status.HTTP_201_CREATED
    response_data = response.json()
    assert "user" in response_data
    assert "tokens" in response_data
    assert response_data["user"]["email"] == user_data["email"]
    assert response_data["user"]["username"] == user_data["username"]
    
    # Verify tokens structure
    tokens = response_data["tokens"]
    assert "access_token" in tokens
    assert "refresh_token" in tokens


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: httpx.AsyncClient, db_session):
    """Test registration with an existing email returns 409 conflict."""
    user_data = _unique_user_data()
    # First, try to register a user
    response1 = await async_client.post(
        "/api/v1/auth/register",
        json=user_data,
    )
    
    # Then try to register another user with the same email but different username
    duplicate_data = user_data.copy()
    duplicate_data["username"] = f"duplicate_{uuid.uuid4().hex[:8]}"
    response2 = await async_client.post(
        "/api/v1/auth/register",
        json=duplicate_data,
    )

    # Test should expect only one specific outcome
    assert response2.status_code == status.HTTP_409_CONFLICT
    assert "detail" in response2.json()


@pytest.mark.asyncio
async def test_register_weak_password(async_client: httpx.AsyncClient, db_session):
    """Test registration with weak password returns 422."""
    user_data = _unique_user_data()
    user_data["password"] = "weak"
    response = await async_client.post(
        "/api/v1/auth/register",
        json=user_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_invalid_email(async_client: httpx.AsyncClient, db_session):
    """Test registration with invalid email format returns 422."""
    user_data = _unique_user_data()
    user_data["email"] = "invalid-email"
    response = await async_client.post(
        "/api/v1/auth/register",
        json=user_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_missing_fields(async_client: httpx.AsyncClient, db_session):
    """Test registration with missing fields returns 422."""
    user_data = _unique_user_data()
    # Remove password and username to test missing fields
    incomplete_data = {"email": user_data["email"]}
    response = await async_client.post(
        "/api/v1/auth/register",
        json=incomplete_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_value_object_validation(async_client: httpx.AsyncClient, db_session):
    """Test registration with value object validation errors."""
    user_data = _unique_user_data()
    user_data["username"] = "invalid username with spaces"  # Invalid username format
    response = await async_client.post(
        "/api/v1/auth/register",
        json=user_data,
    )

    # Should return 422 for validation errors
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json() 