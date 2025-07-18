"""Unified Authentication Service Package.

This package contains the modularized unified authentication service
with separate components for different responsibilities.
"""

from .unified_authentication_service import UnifiedAuthenticationService
from .context import AuthenticationContext, AuthenticationMetrics
from .flow_executor import AuthenticationFlowExecutor
from .email_confirmation_checker import EmailConfirmationChecker
from .oauth_handler import OAuthAuthenticationHandler
from .event_handler import AuthenticationEventHandler

__all__ = [
    "UnifiedAuthenticationService",
    "AuthenticationContext",
    "AuthenticationMetrics", 
    "AuthenticationFlowExecutor",
    "EmailConfirmationChecker",
    "OAuthAuthenticationHandler",
    "AuthenticationEventHandler",
] 