# Environment-based Documentation Permissions

This document explains how the `/docs`, `/redoc`, and `/openapi.json` endpoints handle permissions based on the environment setting.

## Overview

The documentation endpoints (`/docs`, `/redoc`, and `/openapi.json`) have different permission requirements depending on the environment:

- **Development and Test**: No permission checks required
- **Production and Staging**: Admin permissions required

## Implementation

The permission logic is implemented in `src/adapters/api/v1/docs.py` using the `get_docs_dependencies()` function:

```python
def get_docs_dependencies():
    """Get the appropriate dependencies for docs endpoints based on environment."""
    if settings.APP_ENV in ["production", "staging"]:
        return [Depends(get_current_admin_user)]
    return []
```

## Environment Configuration

The system uses the `APP_ENV` setting from `src/core/config/app.py`:

- `APP_ENV = "development"` - No permission checks
- `APP_ENV = "test"` - No permission checks  
- `APP_ENV = "staging"` - Admin permissions required
- `APP_ENV = "production"` - Admin permissions required

## Usage

### Development Environment
```bash
# Set environment to development
export APP_ENV=development

# Start the application
make run-dev

# Access docs without authentication
curl http://localhost:8000/docs
curl http://localhost:8000/redoc
curl http://localhost:8000/openapi.json
```

### Production Environment
```bash
# Set environment to production
export APP_ENV=production

# Start the application
make run-prod

# Access docs requires admin authentication
curl -H "Authorization: Bearer <admin_token>" http://localhost:8000/docs
curl -H "Authorization: Bearer <admin_token>" http://localhost:8000/redoc
curl -H "Authorization: Bearer <admin_token>" http://localhost:8000/openapi.json
```

## Security Benefits

This approach provides several security benefits:

1. **Development Convenience**: Developers can easily access API documentation during development without authentication
2. **Production Security**: Sensitive API documentation is protected in production environments
3. **Environment Isolation**: Different environments can have different security requirements
4. **Zero Configuration**: No manual configuration needed - behavior is automatically determined by environment

## Testing

The implementation includes comprehensive tests in `tests/unit/adapters/api/v1/test_docs_environment_permissions.py` that verify:

- No authentication required in development/test environments
- Admin authentication required in production/staging environments
- Correct dependency injection based on environment setting
- Proper handling of different environment values

## Policy Configuration

The Casbin policy file (`src/permissions/policy.csv`) has been updated to remove the static admin-only policies for docs endpoints, since permissions are now handled at the endpoint level based on environment.

## Migration Notes

If you're upgrading from a previous version:

1. The `/docs`, `/redoc`, and `/openapi.json` endpoints will now be accessible without authentication in development environments
2. These endpoints will still require admin authentication in production/staging environments
3. No changes to existing authentication or authorization systems are required
4. The behavior is automatically determined by the `APP_ENV` setting 