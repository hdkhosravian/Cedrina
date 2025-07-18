"""Authentication Services Package.

This package contains all authentication-related domain services
including user authentication, OAuth integration, and security services.

Services:
- UnifiedAuthenticationService: Main authentication service with modular components
- UserRegistrationService: User registration and account creation
- PasswordChangeService: Password change functionality
- UserLogoutService: User logout and session management
- TokenFamilyManagementService: Token family security management
- SecurityAssessmentService: Security assessment and threat detection
- ErrorClassificationService: Error classification and standardization
- UserValidationService: User validation and security checks
- BaseAuthenticationService: Base authentication functionality
"""

from .unified import UnifiedAuthenticationService
from .user_registration_service import UserRegistrationService
from .password_change_service import PasswordChangeService
from .user_logout_service import UserLogoutService
from .token_family_management_service import TokenFamilyManagementService
from .security_assessment_service import SecurityAssessmentService
from .error_classification_service import ErrorClassificationService
from .user_validation_service import UserValidationService
from .base_authentication_service import BaseAuthenticationService

__all__ = [
    "UnifiedAuthenticationService",
    "UserRegistrationService", 
    "PasswordChangeService",
    "UserLogoutService",
    "TokenFamilyManagementService",
    "SecurityAssessmentService",
    "ErrorClassificationService",
    "UserValidationService",
    "BaseAuthenticationService",
] 