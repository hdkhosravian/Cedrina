"""Authentication Domain Services.

This module provides domain services related to authentication following
Domain-Driven Design principles. These services encapsulate business logic
around user authentication, registration, and security.

Authentication Domain Services:
- UserAuthenticationService: Handles user login and authentication
- UserRegistrationService: Handles user registration with validation
- UserLogoutService: Handles user logout and session management
- PasswordChangeService: Handles password changes for authenticated users
- OAuthAuthenticationService: Handles OAuth-based authentication
- ErrorClassificationService: Classifies errors using Strategy pattern

These services are pure domain logic without infrastructure dependencies.
"""

from .user_authentication_service import UserAuthenticationService
from .user_registration_service import UserRegistrationService
from .user_logout_service import UserLogoutService
from .password_change_service import PasswordChangeService
from .oauth_service import OAuthAuthenticationService
from .error_classification_service import ErrorClassificationService

__all__ = [
    "UserAuthenticationService",
    "UserRegistrationService", 
    "UserLogoutService",
    "PasswordChangeService",
    "OAuthAuthenticationService",
    "ErrorClassificationService",
] 