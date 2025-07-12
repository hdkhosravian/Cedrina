"""Email Confirmation Checker for Unified Authentication Service.

This module contains the email confirmation checker that encapsulates
email confirmation logic to ensure consistent behavior across
authentication methods.
"""

from src.domain.entities.user import User


class EmailConfirmationChecker:
    """Checks email confirmation requirements for user authentication.
    
    This class encapsulates email confirmation logic to ensure
    consistent behavior across authentication methods.
    """
    
    def __init__(self):
        """Initialize email confirmation checker."""
        self._email_confirmation_enabled = self._load_email_confirmation_setting()
    
    def _load_email_confirmation_setting(self) -> bool:
        """Load email confirmation setting from configuration.
        
        Returns:
            bool: Whether email confirmation is enabled
        """
        try:
            from src.core.config.settings import settings
            return settings.EMAIL_CONFIRMATION_ENABLED
        except ImportError:
            # Fallback if settings not available
            return False
    
    def is_confirmation_required(self, user: User) -> bool:
        """Check if email confirmation is required for the user.
        
        Args:
            user: User entity to check
            
        Returns:
            bool: True if email confirmation is required
        """
        return self._email_confirmation_enabled and not user.email_confirmed 