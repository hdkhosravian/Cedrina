"""HTTP endpoint for resending email confirmation tokens."""

from fastapi import APIRouter, Depends, Request, status

from src.infrastructure.dependency_injection.auth_dependencies import (
    get_email_confirmation_request_service,
)
from src.adapters.api.v1.auth.schemas.requests import ResendConfirmationRequest
from src.adapters.api.v1.auth.schemas import MessageResponse
from src.utils.i18n import get_request_language, get_translated_message

router = APIRouter()


@router.post("", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def resend_confirmation(
    request: Request,
    payload: ResendConfirmationRequest,
    service=Depends(get_email_confirmation_request_service),
):
    """Resend a confirmation email to the provided address if necessary."""

    language = get_request_language(request)
    await service.resend_confirmation_email(payload.email, language)
    return MessageResponse(message=get_translated_message("confirmation_email_sent", language))
