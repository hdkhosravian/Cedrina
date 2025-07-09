"""Authentication and Authorization Dependency Injection.

This module provides dependency injection factories for authentication and authorization
services following clean architecture principles. All services are injected through
interfaces to maintain loose coupling and enable easy testing.

Key Features:
- Domain-driven design with interface-based injection
- Database-only token and session management
- Advanced security patterns with token family integration
- Comprehensive error handling and logging
- Event-driven architecture for audit trails

Architecture:
- Domain Layer: Pure business logic with interfaces
- Infrastructure Layer: Concrete implementations
- Dependency Injection: Interface-based service resolution
- Event Publishing: Domain event handling for security monitoring
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from src.domain.interfaces import (
    IUserRepository,
    IOAuthProfileRepository,
    ITokenFamilyRepository,
    IEventPublisher,
    IUserAuthenticationService,
    IUserRegistrationService,
    IUserLogoutService,
    IPasswordChangeService,
    IOAuthService,
    ITokenService,
    IRateLimitingService,
    IPasswordResetTokenService,
    IPasswordResetEmailService,
    IPasswordResetRequestService,
    IPasswordResetService,
    IEmailConfirmationTokenService,
    IEmailConfirmationEmailService,
    IEmailConfirmationRequestService,
    IEmailConfirmationService,
    IUserRegistrationService,
    IErrorClassificationService,
    IPasswordEncryptionService,
)
from src.domain.interfaces.authentication.token_validation import IEnhancedTokenValidationService
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.domain.services.authentication.oauth_service import OAuthAuthenticationService
from src.domain.services.authentication.password_change_service import (
    PasswordChangeService,
)
from src.domain.services.authentication.user_authentication_security_service import (
    UserAuthenticationSecurityService,
)
from src.domain.services.authentication.user_logout_service import (
    UserLogoutService,
)
from src.domain.services.authentication.user_registration_service import (
    UserRegistrationService,
)
from src.domain.services.password_reset.password_reset_request_service import (
    PasswordResetRequestService,
)
from src.domain.services.password_reset.password_reset_service import (
    PasswordResetService,
)
from src.core.rate_limiting.password_reset_service import (
    RateLimitingService,
)
from src.infrastructure.database.async_db import get_async_db_dependency
from src.infrastructure.repositories.user_repository import UserRepository
from src.infrastructure.repositories.oauth_profile_repository import OAuthProfileRepository
from src.infrastructure.repositories.token_family_repository import TokenFamilyRepository
from src.infrastructure.services.event_publisher import InMemoryEventPublisher
from src.infrastructure.services.password_reset_email_service import (
    PasswordResetEmailService,
)
from src.infrastructure.services.password_reset_token_service import (
    PasswordResetTokenService,
)
from src.infrastructure.services.email_confirmation_token_service import (
    EmailConfirmationTokenService,
)
from src.infrastructure.services.email_confirmation_email_service import (
    EmailConfirmationEmailService,
)
from src.domain.services.email_confirmation.email_confirmation_request_service import (
    EmailConfirmationRequestService,
)
from src.domain.services.email_confirmation.email_confirmation_service import (
    EmailConfirmationService,
)
from src.domain.services.authentication import (
    ErrorClassificationService,
)
from src.domain.services.authentication.enhanced_token_validation_service import (
    EnhancedTokenValidationService,
)
from src.infrastructure.services.authentication import (
    PasswordEncryptionService,
)
from src.infrastructure.services.authentication.unified_session_service import UnifiedSessionService
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Type aliases for dependency injection
# ---------------------------------------------------------------------------

AsyncDB = Annotated[AsyncSession, Depends(get_async_db_dependency)]

# ---------------------------------------------------------------------------
# Infrastructure Layer Dependencies
# ---------------------------------------------------------------------------


def get_user_repository(db: AsyncDB) -> IUserRepository:
    """Factory that returns user repository implementation.
    
    This factory creates a concrete implementation of the user repository
    interface, providing data access abstraction for domain services.
    
    Args:
        db: Database session dependency from FastAPI
        
    Returns:
        IUserRepository: Clean user repository implementation
        
    Note:
        The repository is created with a database session, following
        dependency injection principles. This allows for easy testing
        and configuration changes.
    """
    return UserRepository(db)


def get_oauth_profile_repository(db: AsyncDB) -> IOAuthProfileRepository:
    """Factory that returns OAuth profile repository implementation.
    
    This factory creates a concrete implementation of the OAuth profile repository
    interface, providing data access abstraction for OAuth authentication services.
    
    Args:
        db: Database session dependency from FastAPI
        
    Returns:
        IOAuthProfileRepository: Clean OAuth profile repository implementation
        
    Note:
        This repository follows clean architecture principles and provides
        secure, efficient data access for OAuth profile management.
    """
    return OAuthProfileRepository(db)


def get_token_family_repository(db: AsyncDB) -> ITokenFamilyRepository:
    """Factory that returns token family repository implementation.
    
    This factory creates the token family repository with its database
    dependency, following dependency injection principles.
    
    Args:
        db: Database session dependency for data access
        
    Returns:
        ITokenFamilyRepository: Token family repository implementation
        
    Note:
        The token family repository provides encrypted storage and
        security features for token family management.
    """
    return TokenFamilyRepository(db)


def get_event_publisher() -> IEventPublisher:
    """Factory that returns event publisher implementation.
    
    This factory creates an event publisher for domain events, supporting
    audit trails and security monitoring.
    
    Returns:
        IEventPublisher: Event publisher for domain events
        
    Note:
        In production, this could be configured to return:
        - Redis pub/sub implementation for distributed systems
        - RabbitMQ implementation for message queuing
        - Kafka implementation for event streaming
        - Database implementation for audit trails
        Currently returns in-memory implementation for development
    """
    return InMemoryEventPublisher()


def get_token_service(
    db: AsyncDB,
) -> ITokenService:
    """Factory that returns domain-driven token service implementation.
    
    This factory creates the new domain token service that implements
    advanced token family security patterns while eliminating Redis
    dependencies for a unified database approach.
    
    Args:
        db: Database session dependency for unified storage
        
    Returns:
        ITokenService: Domain-driven token service implementation
        
    Note:
        The new domain token service provides:
        - Token family security with reuse detection
        - Database-only storage for consistency and simplicity
        - Advanced threat detection and response
        - Comprehensive audit trails and forensic analysis
        - Sub-millisecond performance for high-throughput applications
        - Encrypted token data for enhanced security
    """
    # Create domain token service with database-only approach
    return DomainTokenService(db_session=db)


# ---------------------------------------------------------------------------
# Domain Service Dependencies
# ---------------------------------------------------------------------------


def get_user_authentication_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IUserAuthenticationService:
    """Factory that returns enhanced user authentication service with security logging.
    
    This factory creates the enhanced domain authentication service with its
    dependencies, following dependency injection principles. The enhanced service
    includes comprehensive security logging, error standardization, and information
    disclosure prevention.
    
    Args:
        user_repository: User repository dependency for data access
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IUserAuthenticationService: Enhanced authentication service with security features
        
    Note:
        The enhanced authentication service implements enterprise-grade security:
        - Zero-trust data masking for audit trails
        - Consistent error responses to prevent enumeration
        - Standardized timing to prevent timing attacks
        - Comprehensive security event logging
        - Risk-based authentication analysis
    """
    return UserAuthenticationSecurityService(
        user_repository=user_repository,
        event_publisher=event_publisher,
    )


def get_email_confirmation_token_service() -> IEmailConfirmationTokenService:
    return EmailConfirmationTokenService()


def get_email_confirmation_email_service() -> IEmailConfirmationEmailService:
    return EmailConfirmationEmailService()


def get_user_registration_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
    confirmation_token_service: IEmailConfirmationTokenService = Depends(get_email_confirmation_token_service),
    confirmation_email_service: IEmailConfirmationEmailService = Depends(get_email_confirmation_email_service),
) -> IUserRegistrationService:
    """Factory that returns clean user registration service.
    
    This factory creates the domain registration service with its
    dependencies, following dependency injection principles.
    
    Args:
        user_repository: User repository dependency for data access
        event_publisher: Event publisher dependency for domain events
        confirmation_token_service: Email confirmation token service
        confirmation_email_service: Email confirmation email service
        
    Returns:
        IUserRegistrationService: Clean registration service
        
    Note:
        The registration service implements clean architecture principles:
        - Domain-driven design with rich domain models
        - Event-driven architecture for audit trails
        - Comprehensive validation and error handling
        - Security-first approach with data masking
    """
    return UserRegistrationService(
        user_repository=user_repository,
        event_publisher=event_publisher,
        confirmation_token_service=confirmation_token_service,
        confirmation_email_service=confirmation_email_service,
    )


def get_oauth_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    oauth_profile_repository: IOAuthProfileRepository = Depends(get_oauth_profile_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IOAuthService:
    """Factory that returns OAuth authentication service.
    
    This factory creates the OAuth authentication service with its
    dependencies, following dependency injection principles.
    
    Args:
        user_repository: User repository dependency for data access
        oauth_profile_repository: OAuth profile repository dependency
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IOAuthService: OAuth authentication service
        
    Note:
        The OAuth service provides secure integration with external providers:
        - Google, Microsoft, and Facebook OAuth support
        - Secure token exchange and validation
        - Profile synchronization and management
        - Comprehensive audit logging
    """
    return OAuthAuthenticationService(
        user_repository=user_repository,
        oauth_profile_repository=oauth_profile_repository,
        event_publisher=event_publisher,
    )


def get_user_logout_service(
    token_service: ITokenService = Depends(get_token_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IUserLogoutService:
    """Factory that returns user logout service.
    
    This factory creates the logout service with its dependencies,
    following dependency injection principles.
    
    Args:
        token_service: Token service dependency for token revocation
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IUserLogoutService: User logout service
        
    Note:
        The logout service provides secure session termination:
        - Immediate token revocation and blacklisting
        - Session cleanup and activity tracking
        - Comprehensive audit logging
        - Cross-device logout support
    """
    return UserLogoutService(
        token_service=token_service,
        event_publisher=event_publisher,
    )


def get_password_change_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> IPasswordChangeService:
    """Factory that returns password change service.
    
    This factory creates the password change service with its
    dependencies, following dependency injection principles.
    
    Args:
        user_repository: User repository dependency for data access
        event_publisher: Event publisher dependency for domain events
        
    Returns:
        IPasswordChangeService: Password change service
        
    Note:
        The password change service provides secure password management:
        - Defense-in-depth password encryption
        - Password policy enforcement
        - Comprehensive audit logging
        - Cross-session invalidation
    """
    return PasswordChangeService(
        user_repository=user_repository,
        event_publisher=event_publisher,
    )


def get_password_reset_rate_limiting_service() -> IRateLimitingService:
    """Factory that returns rate limiting service for password resets.
    
    This factory creates the rate limiting service to prevent
    abuse of password reset functionality.
    
    Returns:
        IRateLimitingService: Rate limiting service for password resets
        
    Note:
        The rate limiting service provides abuse prevention:
        - Per-email address rate limiting
        - Configurable limits and timeouts
        - Comprehensive monitoring and alerting
        - Automatic cleanup of expired data
    """
    return RateLimitingService()


def get_password_reset_token_service(
    rate_limiting_service: IRateLimitingService = Depends(get_password_reset_rate_limiting_service),
) -> IPasswordResetTokenService:
    """Factory that returns enhanced password reset token service.
    
    This factory creates the password reset token service with
    rate limiting integration for enhanced security.
    
    Args:
        rate_limiting_service: Rate limiting service dependency
        
    Returns:
        IPasswordResetTokenService: Enhanced token service for password resets
        
    Note:
        The enhanced token service includes:
        - Rate limiting per email address to prevent abuse
        - Unpredictable token format with mixed character sets
        - Cryptographically secure random generation
        - Constant-time validation to prevent timing attacks
        - Security metrics and monitoring capabilities
    """
    return PasswordResetTokenService(
        rate_limiting_service=rate_limiting_service
    )


def get_password_reset_email_service() -> IPasswordResetEmailService:
    """Factory that returns password reset email service.
    
    This factory creates the email service for sending password reset
    emails with internationalization support.
    
    Returns:
        IPasswordResetEmailService: Email service for password resets
        
    Note:
        The email service supports multiple languages and secure
        email delivery with proper template rendering.
    """
    return PasswordResetEmailService()


def get_password_reset_request_service(
    db: AsyncDB,
    rate_limiting_service: IRateLimitingService = Depends(get_password_reset_rate_limiting_service),
    token_service: IPasswordResetTokenService = Depends(get_password_reset_token_service),
    email_service: IPasswordResetEmailService = Depends(get_password_reset_email_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> PasswordResetRequestService:
    user_repository = UserRepository(db)
    return PasswordResetRequestService(
        user_repository=user_repository,
        rate_limiting_service=rate_limiting_service,
        token_service=token_service,
        email_service=email_service,
        event_publisher=event_publisher,
    )


def get_email_confirmation_request_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    token_service: IEmailConfirmationTokenService = Depends(get_email_confirmation_token_service),
    email_service: IEmailConfirmationEmailService = Depends(get_email_confirmation_email_service),
) -> EmailConfirmationRequestService:
    return EmailConfirmationRequestService(
        user_repository=user_repository,
        token_service=token_service,
        email_service=email_service,
    )


def get_email_confirmation_service(
    user_repository: IUserRepository = Depends(get_user_repository),
    token_service: IEmailConfirmationTokenService = Depends(get_email_confirmation_token_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> EmailConfirmationService:
    return EmailConfirmationService(
        user_repository=user_repository,
        token_service=token_service,
        event_publisher=event_publisher,
    )


def get_password_reset_service(
    db: AsyncDB,
    token_service: IPasswordResetTokenService = Depends(get_password_reset_token_service),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> PasswordResetService:
    user_repository = UserRepository(db)
    return PasswordResetService(
        user_repository=user_repository,
        token_service=token_service,
        event_publisher=event_publisher,
    )


# Additional Dependency Factories
# ---------------------------------------------------------------------------

def get_error_classification_service() -> IErrorClassificationService:
    """Factory that returns error classification service following Strategy pattern.
    
    This factory creates the error classification service that uses the Strategy pattern
    to classify different types of domain errors into appropriate HTTP exceptions.
    
    Returns:
        IErrorClassificationService: Error classification service for clean error handling
        
    Note:
        The error classification service includes:
        - Strategy Pattern for different error classification approaches
        - Single Responsibility for error classification logic
        - Consistent error responses across all endpoints
        - Separation of concerns between domain and HTTP concerns
    """
    return ErrorClassificationService()


def get_password_encryption_service() -> IPasswordEncryptionService:
    """Factory that returns password encryption service for defense-in-depth security.
    
    This factory creates the password hash encryption service that adds an additional
    security layer beyond bcrypt hashing for defense-in-depth security.
    
    Returns:
        IPasswordEncryptionService: Password encryption service for enhanced security
        
    Note:
        The password encryption service provides:
        - AES-256-GCM encryption for password hashes
        - Key separation from database credentials
        - Migration compatibility for legacy unencrypted hashes
        - Constant-time operations to prevent timing attacks
    """
    return PasswordEncryptionService()


def get_session_service(
    db: AsyncDB,
    token_family_repository: ITokenFamilyRepository = Depends(get_token_family_repository),
    event_publisher: IEventPublisher = Depends(get_event_publisher),
) -> UnifiedSessionService:
    """Factory that returns unified session service with token family integration.
    
    This factory creates the unified session service that uses database-only
    storage with token family integration for enhanced security.
    
    Args:
        db: Database session dependency for unified storage
        token_family_repository: Token family repository for security integration
        event_publisher: Event publisher for domain events
        
    Returns:
        UnifiedSessionService: Unified session service with token family integration
        
    Note:
        The unified session service provides:
        - Database-only storage eliminates Redis complexity
        - Token family integration for security correlation
        - Comprehensive session lifecycle management
        - Activity tracking and inactivity timeout
        - Concurrent session limits with cleanup
        - Audit trail generation for compliance
    """
    return UnifiedSessionService(
        db_session=db,
        token_family_repository=token_family_repository,
        event_publisher=event_publisher
    )


def get_enhanced_token_validation_service(
    db: AsyncDB,
) -> IEnhancedTokenValidationService:
    """Factory that returns enhanced token validation service with advanced security.
    
    This factory creates the enhanced token validation service with comprehensive
    security features for token pairing validation and threat detection.
    
    Args:
        db: Database session dependency for unified storage
        
    Returns:
        IEnhancedTokenValidationService: Enhanced token validation service
        
    Note:
        The enhanced validation service provides:
        - Token pairing validation (access + refresh must have same JTI)
        - Cross-user attack prevention
        - Session consistency validation
        - Security threat detection and classification
        - Performance metrics and monitoring
        - Database-only approach for improved consistency
    """
    # Note: Enhanced token validation now uses the unified domain token service
    # which includes all necessary session management capabilities
    token_service = DomainTokenService(db_session=db)
    return EnhancedTokenValidationService(token_service=token_service)


# Type aliases for dependency injection
UserAuthenticationServiceDep = Annotated[IUserAuthenticationService, Depends(get_user_authentication_service)]
UserRegistrationServiceDep = Annotated[IUserRegistrationService, Depends(get_user_registration_service)]
UserLogoutServiceDep = Annotated[IUserLogoutService, Depends(get_user_logout_service)]
PasswordChangeServiceDep = Annotated[IPasswordChangeService, Depends(get_password_change_service)]
OAuthServiceDep = Annotated[IOAuthService, Depends(get_oauth_service)]
TokenServiceDep = Annotated[ITokenService, Depends(get_token_service)]
ErrorClassificationServiceDep = Annotated[IErrorClassificationService, Depends(get_error_classification_service)]
PasswordEncryptionServiceDep = Annotated[IPasswordEncryptionService, Depends(get_password_encryption_service)]
EnhancedTokenValidationServiceDep = Annotated[IEnhancedTokenValidationService, Depends(get_enhanced_token_validation_service)]
