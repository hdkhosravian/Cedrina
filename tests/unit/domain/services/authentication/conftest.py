import pytest
from unittest.mock import AsyncMock
from src.domain.services.authentication.user_registration_service import UserRegistrationService
from src.domain.value_objects.email import Email
from src.domain.value_objects.password import Password
from src.domain.value_objects.username import Username

@pytest.fixture
def mock_user_repository():
    repository = AsyncMock()
    repository.get_by_username = AsyncMock()
    repository.get_by_email = AsyncMock()
    repository.save = AsyncMock()
    return repository

@pytest.fixture
def mock_event_publisher():
    publisher = AsyncMock()
    publisher.publish = AsyncMock()
    return publisher

@pytest.fixture
def mock_confirmation_token_service():
    service = AsyncMock()
    service.generate_token = AsyncMock()
    return service

@pytest.fixture
def mock_confirmation_email_service():
    service = AsyncMock()
    service.send_confirmation_email = AsyncMock()
    return service

@pytest.fixture
def service(mock_user_repository, mock_event_publisher, mock_confirmation_token_service, mock_confirmation_email_service):
    return UserRegistrationService(
        user_repository=mock_user_repository,
        event_publisher=mock_event_publisher,
        confirmation_token_service=mock_confirmation_token_service,
        confirmation_email_service=mock_confirmation_email_service
    )

@pytest.fixture
def valid_username():
    return Username("testuser")

@pytest.fixture
def valid_email():
    return Email("test@example.com")

@pytest.fixture
def valid_password():
    return Password("MyStr0ng#P@ssw0rd", language="en") 