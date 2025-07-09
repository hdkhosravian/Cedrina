"""API Documentation Endpoints

This module provides custom endpoints for API documentation with access control. These endpoints serve the
Swagger UI and ReDoc interfaces for exploring the API's OpenAPI schema, as well as the raw OpenAPI JSON schema
itself. Access to these documentation endpoints is restricted to users with the 'admin' role to prevent
unauthorized users from viewing detailed API structures, which could expose sensitive implementation details.

The permission checks are enforced using the Casbin access control system, ensuring that only authorized
personnel can access these resources. This is particularly important in production environments where API
documentation should not be publicly accessible.

**Environment-based Access Control:**
- Development and Test: No permission checks required
- Production and Staging: Admin permissions required

Endpoints:
    - /docs: Serves the Swagger UI for interactive API documentation.
    - /redoc: Serves the ReDoc interface for a more readable API documentation view.
    - /openapi.json: Provides the raw OpenAPI JSON schema for the API.
"""

from fastapi import APIRouter, Depends
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html

from src.core.config.settings import settings
from src.core.dependencies.auth import get_current_admin_user

router = APIRouter()


def get_docs_dependencies():
    """Get the appropriate dependencies for docs endpoints based on environment.
    
    Returns:
        List of dependencies - empty for development/test, admin dependency for production/staging.
    """
    # Check if we're in production or staging environment
    if settings.APP_ENV in ["production", "staging"]:
        return [Depends(get_current_admin_user)]
    # For development and test environments, no permission check required
    return []


# Create the dependencies at module level based on current environment
_docs_dependencies = get_docs_dependencies()


@router.get("/docs", dependencies=_docs_dependencies)
async def get_documentation():
    """Custom endpoint for Swagger UI documentation.

    This endpoint serves the Swagger UI, an interactive interface for exploring and testing the API based on its
    OpenAPI schema. Access control varies by environment:
    - Development/Test: No permission checks required
    - Production/Staging: Admin permissions required

    Returns:
        HTMLResponse: The Swagger UI HTML page configured to load the OpenAPI schema from /openapi.json.

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden) in production/staging.
    """
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API Documentation")


@router.get("/redoc", dependencies=_docs_dependencies)
async def get_redoc_documentation():
    """Custom endpoint for ReDoc documentation.

    This endpoint serves the ReDoc interface, a clean and readable alternative to Swagger UI for viewing API
    documentation based on the OpenAPI schema. Access control varies by environment:
    - Development/Test: No permission checks required
    - Production/Staging: Admin permissions required

    Returns:
        HTMLResponse: The ReDoc HTML page configured to load the OpenAPI schema from /openapi.json.

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden) in production/staging.
    """
    return get_redoc_html(openapi_url="/openapi.json", title="API Documentation")


@router.get("/openapi.json", dependencies=_docs_dependencies)
async def get_openapi_json():
    """Custom endpoint for OpenAPI JSON schema.

    This endpoint provides the raw OpenAPI JSON schema for the API, which is used by documentation tools like
    Swagger UI and ReDoc to generate interactive documentation. Access control varies by environment:
    - Development/Test: No permission checks required
    - Production/Staging: Admin permissions required

    Returns:
        Dict: The OpenAPI schema as a JSON-compatible dictionary, describing all API endpoints, parameters,
              responses, and schemas.

    Raises:
        HTTPException: If the user does not have the required permissions (HTTP 403 Forbidden) in production/staging.
    """
    from src.main import app  # Import app to access OpenAPI schema

    # Return the OpenAPI schema as-is - FastAPI will automatically include
    return app.openapi()
