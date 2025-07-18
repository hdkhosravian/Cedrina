
import pytest
from unittest.mock import Mock, AsyncMock
import uuid

from src.domain.entities.user import User
from src.domain.services.email_confirmation.email_confirmation_service import (
    EmailConfirmationService,
)
from src.infrastructure.repositories.user_repository import UserRepository
from src.infrastructure.services.email_confirmation_token_service import (
    EmailConfirmationTokenService,
)
from src.domain.value_objects.security_context import SecurityContext


@pytest.mark.asyncio
async def test_confirm_email_integration(async_session):
    """Test the email confirmation flow from service to database."""
    # Arrange
    user_repo = UserRepository(async_session)
    token_service = EmailConfirmationTokenService()
    event_publisher = AsyncMock()
    service = EmailConfirmationService(user_repo, token_service, event_publisher)

    unique_id = uuid.uuid4()
    user = User(
        username=f"testuser_{unique_id}",
        email=f"test_{unique_id}@example.com",
        password_hash="hashed_password",
    )
    await user_repo.save(user)
    await async_session.commit()

    security_context = SecurityContext.create_for_request(
        client_ip="127.0.0.1",
        user_agent="pytest-integration"
    )
    token = await token_service.generate_token(user, security_context)
    user.email_confirmation_token = token.value
    await user_repo.save(user)
    await async_session.commit()

    # Act
    confirmed_user = await service.confirm_email(token.value, "en")

    # Assert
    assert confirmed_user.is_active is True
    assert confirmed_user.email_confirmed is True

    # Verify the user in the database
    db_user = await user_repo.get_by_id(user.id)
    assert db_user.is_active is True
    assert db_user.email_confirmed is True
    assert db_user.email_confirmation_token is None
