"""Domain layer components.

This module provides centralized access to domain layer components
following Domain-Driven Design principles.
"""

from .entities import User, TokenFamily, OAuthProfile, Session
from .value_objects import (
    TokenId,
    SecurityContext,
    TokenFamilyStatus,
    TokenUsageEvent,
    TokenUsageRecord,
    TokenCreationRequest,
    TokenRefreshRequest,
    TokenValidationRequest,
    TokenRevocationRequest,
    TokenPair,
    TokenValidationResult,
    SecurityAssessment,
    SecurityThreatLevel,
    SecurityIncident,
)
from .interfaces import (
    # Repository interfaces
    IUserRepository,
    IOAuthProfileRepository,
    ITokenFamilyRepository,
    
    # Authentication interfaces
    IUserAuthenticationService,
    IUserRegistrationService,
    IUserLogoutService,
    IPasswordChangeService,
    IPasswordResetTokenService,
    IPasswordResetEmailService,
    IPasswordResetRequestService,
    IPasswordResetService,
    IOAuthService,
    IErrorClassificationService,
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
    IEmailConfirmationRequestService,
    IEmailConfirmationService,
    
    # Token management interfaces
    ITokenService,
    ISessionService,
    
    # Security interfaces
    IPasswordEncryptionService,
    IRateLimitingService,
    
    # Infrastructure interfaces
    IEventPublisher,
    ICacheService,
)

__all__ = [
    # Domain entities
    "User",
    "TokenFamily", 
    "OAuthProfile",
    "Session",
    
    # Domain value objects
    "TokenId",
    "SecurityContext",
    "TokenFamilyStatus",
    "TokenUsageEvent",
    "TokenUsageRecord",
    "TokenCreationRequest",
    "TokenRefreshRequest",
    "TokenValidationRequest",
    "TokenRevocationRequest",
    "TokenPair",
    "TokenValidationResult",
    "SecurityAssessment",
    "SecurityThreatLevel",
    "SecurityIncident",
    
    # Domain interfaces
    "IUserRepository",
    "IOAuthProfileRepository",
    "ITokenFamilyRepository",
    "IUserAuthenticationService",
    "IUserRegistrationService",
    "IUserLogoutService",
    "IPasswordChangeService",
    "IPasswordResetTokenService",
    "IPasswordResetEmailService",
    "IPasswordResetRequestService",
    "IPasswordResetService",
    "IOAuthService",
    "IErrorClassificationService",
    "IEmailConfirmationTokenService",
    "IEmailConfirmationEmailService",
    "IEmailConfirmationRequestService",
    "IEmailConfirmationService",
    "ITokenService",
    "ISessionService",
    "IPasswordEncryptionService",
    "IRateLimitingService",
    "IEventPublisher",
    "ICacheService",
]
