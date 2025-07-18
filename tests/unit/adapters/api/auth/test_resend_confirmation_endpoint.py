import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_resend_confirmation_validation_error(async_client: AsyncClient):
    response = await async_client.post("/api/v1/auth/resend-confirmation", json={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_resend_confirmation_success(
    async_client: AsyncClient, mock_email_confirmation_request_service
):
    payload = {"email": "test@example.com"}
    response = await async_client.post("/api/v1/auth/resend-confirmation", json=payload)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "message" in data
    
    # Verify the service was called with the expected parameters
    call_args = mock_email_confirmation_request_service.resend_confirmation_email.call_args
    assert call_args is not None
    # Check that email and language are passed correctly
    assert "email" in call_args.kwargs
    assert "language" in call_args.kwargs
    assert call_args.kwargs["language"] == "en"
