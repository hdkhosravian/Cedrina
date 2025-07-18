"""Email confirmation email sender."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from src.core.config.settings import settings
from src.domain.entities.user import User
from src.domain.interfaces.authentication.email_confirmation import IEmailConfirmationEmailService
from src.domain.value_objects.confirmation_token import ConfirmationToken
from src.domain.value_objects.security_context import SecurityContext
from src.common.i18n import get_translated_message
from src.infrastructure.services.base_service import BaseInfrastructureService


class EmailConfirmationEmailService(IEmailConfirmationEmailService, BaseInfrastructureService):
    """Render and deliver email confirmation messages."""

    def __init__(self) -> None:
        """Initialize email confirmation email service."""
        super().__init__(service_name="EmailConfirmationEmailService")
        
        template_dir = Path(settings.EMAIL_TEMPLATES_DIR)
        self._jinja = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
        
        # Add custom filters for email formatting
        self._jinja.filters['format_datetime'] = self._format_datetime_filter

    def _format_datetime_filter(self, value, format_string="%Y-%m-%d %H:%M:%S"):
        """Jinja2 filter for formatting datetime objects.
        
        Args:
            value: Datetime object or string
            format_string: Format string for datetime
            
        Returns:
            str: Formatted datetime string
        """
        from datetime import datetime
        
        if value is None:
            return ""
        
        if value == "now":
            return datetime.now().strftime(format_string)
        
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                return dt.strftime(format_string)
            except ValueError:
                return value
        
        if hasattr(value, 'strftime'):
            return value.strftime(format_string)
        
        return str(value)

    async def send_confirmation_email(
        self, user: User, token: ConfirmationToken, security_context: SecurityContext, language: str = "en"
    ) -> bool:
        """Send a confirmation email to the user.

        Args:
            user: Recipient of the confirmation email.
            token: Confirmation token to embed in the message.
            security_context: Validated security context for audit trails.
            language: Preferred language for the email template.

        Returns:
            ``True`` if the email was sent or queued successfully.
        """
        operation = "send_confirmation_email"
        
        try:
            # Validate security context
            self._validate_security_context(security_context, operation)
            
            base_url = self._get_config_value("FRONTEND_URL", "http://localhost:3000")
            confirm_url = f"{base_url}/confirm-email?token={token.value}"
            subject = get_translated_message("email_confirmation_subject", language)

            context = {"user": user, "confirm_url": confirm_url}

            template_html = f"email_confirmation_{language}.html"
            template_txt = f"email_confirmation_{language}.txt"
            html_content = self._jinja.get_template(template_html).render(context)
            text_content = self._jinja.get_template(template_txt).render(context)

            self._log_success(
                operation=operation,
                user_id=user.id,
                to=user.email,
                subject=subject,
                url=confirm_url,
                language=language,
                correlation_id=security_context.correlation_id
            )
            
            return True
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id,
                language=language,
                correlation_id=security_context.correlation_id if security_context else None
            )
