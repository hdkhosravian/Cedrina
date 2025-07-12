"""Unified Authentication Domain Service (Refactored).

This service now delegates all logic to modular components in
src/domain/services/authentication/unified/ for maintainability and
clean code, while preserving the public interface for backward compatibility.
"""

from typing import Dict, Any, Optional, Tuple, Union
from src.domain.interfaces.repositories import IUserRepository, IOAuthProfileRepository
from src.common.events import IEventPublisher
from src.common.authentication import IUserAuthenticationService, IOAuthService
from src.domain.interfaces.authentication.user_authentication import IUserAuthenticationService as DomainUserAuthenticationService
from src.domain.interfaces.authentication.oauth import IOAuthService as DomainOAuthService
from src.domain.value_objects.username import Username
from src.domain.value_objects.oauth_provider import OAuthProvider
from src.domain.value_objects.oauth_token import OAuthToken
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.password import LoginPassword, Password
from src.domain.entities.user import User
from src.domain.entities.oauth_profile import OAuthProfile

from .unified.context import AuthenticationContext, AuthenticationMetrics
from .unified.flow_executor import AuthenticationFlowExecutor
from .unified.email_confirmation_checker import EmailConfirmationChecker
from .unified.oauth_handler import OAuthAuthenticationHandler
from .unified.event_handler import AuthenticationEventHandler
from src.domain.security.error_standardization import error_standardization_service
from src.domain.security.logging_service import secure_logging_service
from src.common.exceptions import AuthenticationError, ValidationError
from src.common.i18n import get_translated_message

import time
import structlog

logger = structlog.get_logger(__name__)

class UnifiedAuthenticationService(
    IUserAuthenticationService, IOAuthService, DomainUserAuthenticationService, DomainOAuthService
):
    """Unified authentication service with enterprise-grade security features (refactored).
    Now delegates all logic to modular components in unified/.
    """
    def __init__(
        self,
        user_repository: IUserRepository,
        oauth_profile_repository: Optional[IOAuthProfileRepository] = None,
        event_publisher: Optional[IEventPublisher] = None,
    ):
        self._user_repository = user_repository
        self._oauth_profile_repository = oauth_profile_repository
        self._event_publisher = event_publisher
        self._secure_logger = secure_logging_service
        self._error_standardizer = error_standardization_service
        self._flow_executor = AuthenticationFlowExecutor(self._secure_logger, self._error_standardizer)
        self._email_confirmation_checker = EmailConfirmationChecker()
        self._oauth_handler = OAuthAuthenticationHandler(oauth_profile_repository) if oauth_profile_repository else None
        self._event_handler = AuthenticationEventHandler(event_publisher, self._secure_logger)
        self._auth_metrics = AuthenticationMetrics()
        logger.info(
            "UnifiedAuthenticationService initialized (refactored)",
            service_type="domain_service",
            responsibilities=[
                "user_authentication",
                "oauth_integration",
                "security_monitoring",
                "threat_detection",
                "audit_trail"
            ]
        )

    async def authenticate_user(
        self,
        username: "Username",
        password: "LoginPassword",
        security_context_or_language: Union[SecurityContext, str] = "en",
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> "User":
        request_start_time = time.time()
        if isinstance(security_context_or_language, SecurityContext):
            security_context = security_context_or_language
            context = AuthenticationContext(
                client_ip=security_context.client_ip,
                user_agent=security_context.user_agent,
                correlation_id=security_context.correlation_id or "",
                language=language
            )
        else:
            context = AuthenticationContext(
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id,
                language=security_context_or_language
            )
        async def _perform_user_authentication() -> User:
            return await self._authenticate_user_internal(username, password, context)
        result = await self._flow_executor.execute(
            _perform_user_authentication,
            context,
            request_start_time,
            oauth=False
        )
        duration_ms = (time.time() - request_start_time) * 1000
        self._auth_metrics = self._auth_metrics.update_success(duration_ms, oauth=False)
        return result

    async def authenticate_with_oauth(
        self,
        provider: "OAuthProvider",
        token: "OAuthToken",
        security_context_or_language: Union[SecurityContext, str] = "en",
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> Tuple["User", "OAuthProfile"]:
        if not self._oauth_handler:
            raise AuthenticationError("OAuth authentication not configured")
        request_start_time = time.time()
        if isinstance(security_context_or_language, SecurityContext):
            security_context = security_context_or_language
            context = AuthenticationContext(
                client_ip=security_context.client_ip,
                user_agent=security_context.user_agent,
                correlation_id=security_context.correlation_id or "",
                language=language
            )
        else:
            context = AuthenticationContext(
                client_ip=client_ip,
                user_agent=user_agent,
                correlation_id=correlation_id,
                language=security_context_or_language
            )
        async def _perform_oauth_authentication() -> Tuple[User, OAuthProfile]:
            return await self._authenticate_oauth_internal(provider, token, context)
        result = await self._flow_executor.execute(
            _perform_oauth_authentication,
            context,
            request_start_time,
            oauth=True
        )
        duration_ms = (time.time() - request_start_time) * 1000
        self._auth_metrics = self._auth_metrics.update_success(duration_ms, oauth=True)
        return result

    async def _authenticate_user_internal(
        self,
        username: "Username",
        password: "LoginPassword",
        context: AuthenticationContext
    ) -> User:
        self._secure_logger.log_authentication_attempt(
            username=str(username),
            success=False,
            correlation_id=context.correlation_id,
            ip_address=context.client_ip,
            user_agent=context.user_agent,
            risk_indicators=[]
        )
        user = await self._user_repository.get_by_username(str(username))
        if not user or not await self.verify_password(user, password):
            await self._event_handler.handle_authentication_failure(
                username=username,
                failure_reason="invalid_credentials",
                context=context
            )
            error_response = await self._error_standardizer.create_authentication_error_response(
                actual_failure_reason="invalid_credentials",
                username=str(username),
                correlation_id=context.correlation_id,
                language=context.language,
                request_start_time=time.time()
            )
            raise AuthenticationError(error_response["detail"])
        if not user.is_active:
            await self._event_handler.handle_authentication_failure(
                username=username,
                failure_reason="account_inactive",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("account_inactive", context.language)
            )
        if self._email_confirmation_checker.is_confirmation_required(user):
            await self._event_handler.handle_authentication_failure(
                username=username,
                failure_reason="email_confirmation_required",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("email_confirmation_required", context.language)
            )
        await self._event_handler.handle_authentication_success(user, context)
        return user

    async def _authenticate_oauth_internal(
        self,
        provider: OAuthProvider,
        token: OAuthToken,
        context: AuthenticationContext
    ) -> Tuple[User, OAuthProfile]:
        if not await self._oauth_handler.validate_oauth_token(provider, token):
            await self._event_handler.handle_oauth_failure(
                provider=provider,
                failure_reason="invalid_token",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("oauth_token_invalid", context.language)
            )
        user_info = await self._oauth_handler.fetch_oauth_user_info(provider, token)
        if not user_info:
            await self._event_handler.handle_oauth_failure(
                provider=provider,
                failure_reason="user_info_fetch_failed",
                context=context
            )
            raise AuthenticationError(
                get_translated_message("oauth_user_info_failed", context.language)
            )
        user, oauth_profile = await self._oauth_handler.link_or_create_oauth_user(
            provider, user_info, context
        )
        await self._event_handler.handle_oauth_success(user, oauth_profile, context)
        return user, oauth_profile

    async def verify_password(self, user: "User", password: "Password") -> bool:
        try:
            if not user or not user.hashed_password or not password:
                return False
            return password.verify_against_hash(user.hashed_password)
        except Exception as e:
            logger.error(
                "Password verification error",
                user_id=user.id if user else None,
                error=str(e)
            )
            return False

    async def validate_oauth_state(self, state: str, stored_state: str, language: str = "en") -> bool:
        try:
            if len(state) != len(stored_state):
                return False
            result = 0
            for a, b in zip(state, stored_state):
                result |= ord(a) ^ ord(b)
            return result == 0
        except Exception as e:
            logger.error(
                "OAuth state validation error",
                error=str(e)
            )
            return False

    def get_auth_metrics(self) -> Dict[str, Any]:
        return {
            "total_authentications": self._auth_metrics.total_authentications,
            "successful_authentications": self._auth_metrics.successful_authentications,
            "failed_authentications": self._auth_metrics.failed_authentications,
            "oauth_authentications": self._auth_metrics.oauth_authentications,
            "security_incidents": self._auth_metrics.security_incidents,
            "average_auth_time_ms": self._auth_metrics.average_auth_time_ms,
        } 