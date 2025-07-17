"""Middleware configuration for the FastAPI application.

This module handles the configuration and registration of all middleware
components including CORS, rate limiting, and language handling.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.middleware import SlowAPIMiddleware

from src.core.config.settings import settings
from src.core.rate_limiting.ratelimiter import get_limiter
from src.common.i18n import extract_language_from_request


def configure_middleware(app: FastAPI) -> None:
    """Configure all middleware for the FastAPI application.
    
    Args:
        app (FastAPI): The FastAPI application instance
    """
    # Initialize and attach the rate limiter to app state
    # This must be done before adding the SlowAPIMiddleware
    app.state.limiter = get_limiter()
    
    # Language middleware (first for request preprocessing)
    app.middleware("http")(set_language_middleware)

    # Rate limiting middleware (early to block bad requests quickly)
    app.add_middleware(SlowAPIMiddleware)
    
    # CORS middleware configuration (last for response headers)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


async def set_language_middleware(request: Request, call_next):
    """Middleware for handling language preferences in requests.

    This middleware:
    1. Extracts language preference from request headers or query parameters
    2. Sets the language for the current request
    3. Adds language information to response headers

    Args:
        request (Request): The incoming request
        call_next: The next middleware or route handler

    Returns:
        Response: The response with language headers
    """
    # Extract language from request for I18N
    lang = extract_language_from_request(request)
    request.state.language = lang
    response = await call_next(request)
    response.headers["Content-Language"] = lang
    return response 