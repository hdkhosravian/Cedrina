"""Service for email confirmation tokens."""
from src.domain.entities.user import User
from src.domain.interfaces.authentication.email_confirmation import IEmailConfirmationTokenService
from src.domain.value_objects.confirmation_token import ConfirmationToken
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.services.base_service import BaseInfrastructureService


class EmailConfirmationTokenService(IEmailConfirmationTokenService, BaseInfrastructureService):
    """Create and validate email confirmation tokens."""

    def __init__(self):
        """Initialize email confirmation token service."""
        super().__init__(service_name="EmailConfirmationTokenService")

    async def generate_token(self, user: User, security_context: SecurityContext) -> ConfirmationToken:
        """Generate a new token and assign it to the user.
        
        Args:
            user: User entity for token generation
            security_context: Validated security context for audit trails
            
        Returns:
            ConfirmationToken: Generated confirmation token
        """
        operation = "generate_token"
        
        try:
            # Validate security context
            self._validate_security_context(security_context, operation)
            
            token = ConfirmationToken.generate()
            user.email_confirmation_token = token.value
            
            self._log_success(
                operation=operation,
                user_id=user.id,
                correlation_id=security_context.correlation_id
            )
            
            return token
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id,
                correlation_id=security_context.correlation_id
            )

    def validate_token(self, user: User, token: str) -> bool:
        """Check whether the provided token matches the user's token."""
        operation = "validate_token"
        
        try:
            is_valid = user.email_confirmation_token == token
            
            self._log_success(
                operation=operation,
                user_id=user.id,
                is_valid=is_valid
            )
            
            return is_valid
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )

    def invalidate_token(self, user: User) -> None:
        """Remove the stored confirmation token from the user entity."""
        operation = "invalidate_token"
        
        try:
            user.email_confirmation_token = None
            
            self._log_success(
                operation=operation,
                user_id=user.id
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
                user_id=user.id
            )
