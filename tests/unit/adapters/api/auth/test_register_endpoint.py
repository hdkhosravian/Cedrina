import httpx
import pytest
import uuid
import time
import random
from unittest.mock import AsyncMock, patch
from fastapi import status


def _unique_user_data():
    """Generate unique user data for each test run with enhanced uniqueness."""
    # Use timestamp, random number, and uuid for maximum uniqueness
    timestamp = int(time.time() * 1000000)  # microseconds
    random_part = random.randint(100000, 999999)
    uuid_part = uuid.uuid4().hex[:8]
    
    unique = f"{timestamp}_{random_part}_{uuid_part}"
    return {
        "username": f"testuser_{unique}",
        "email": f"testuser{unique}@example.com",
        "password": "SecureP@ssw0rd2024!",
    }


@pytest.mark.asyncio
async def test_register_successful(async_client: httpx.AsyncClient, async_session):
    """Test successful user registration with clean architecture."""
    # Mock the database session to avoid event loop issues
    mock_session = AsyncMock()
    mock_session.execute.return_value.scalars.return_value.first.return_value = None  # No existing user
    
    with patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_username", return_value=None), \
         patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_email", return_value=None), \
         patch("src.infrastructure.repositories.user_repository.UserRepository.save") as mock_save:
        
        user_data = _unique_user_data()
        
        # Mock the save method to return a user with the actual data
        from src.domain.entities.user import User
        mock_user = User(
            id=1,
            username=user_data["username"],
            email=user_data["email"],
            hashed_password="hashed_password",
            role="user",
            is_active=True,
            email_confirmed=True
        )
        mock_save.return_value = mock_user
        
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
async def test_register_duplicate_email(async_client: httpx.AsyncClient, async_session):
    """Test registration with an existing email returns 409 conflict."""
    user_data = _unique_user_data()
    
    # Mock the database to simulate existing user
    with patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_username", return_value=None), \
         patch("src.infrastructure.repositories.user_repository.UserRepository.get_by_email") as mock_get_by_email:
        
        # Mock existing user for duplicate email scenario
        from src.domain.entities.user import User
        existing_user = User(
            id=1,
            username="existinguser",
            email=user_data["email"],
            hashed_password="hashed_password",
            role="user",
            is_active=True,
            email_confirmed=True
        )
        mock_get_by_email.return_value = existing_user
        
        response = await async_client.post(
            "/api/v1/auth/register",
            json=user_data,
        )
        
        # Should return 409 conflict for duplicate email
        assert response.status_code == status.HTTP_409_CONFLICT
        assert "detail" in response.json()


@pytest.mark.asyncio
async def test_register_weak_password(async_client: httpx.AsyncClient, async_session):
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
async def test_register_invalid_email(async_client: httpx.AsyncClient, async_session):
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
async def test_register_missing_fields(async_client: httpx.AsyncClient, async_session):
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
async def test_register_value_object_validation(async_client: httpx.AsyncClient, async_session):
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