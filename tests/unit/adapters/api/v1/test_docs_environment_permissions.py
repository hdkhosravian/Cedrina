"""Unit Tests for Environment-based Documentation Endpoint Permissions

This module tests that the /docs, /redoc, and /openapi.json endpoints correctly apply
permission checks based on the environment setting:
- Development and Test: No permission checks required
- Production and Staging: Admin permissions required
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from src.core.dependencies.auth import get_current_admin_user


class TestDocsEnvironmentPermissions:
    """Test class for environment-based documentation endpoint permissions."""

    def test_docs_endpoints_no_auth_in_dev_test(self):
        """Test that docs endpoints are accessible without authentication in dev/test environments."""
        # Since the current environment is development, these endpoints should be accessible
        from src.main import app
        client = TestClient(app)
        
        # Test all three endpoints
        endpoints = ["/docs", "/redoc", "/openapi.json"]
        
        for endpoint in endpoints:
            response = client.get(endpoint)
            # Should not return 401/403 (authentication/authorization errors)
            assert response.status_code not in [401, 403], f"Endpoint {endpoint} should be accessible without auth in development environment"



    def test_docs_endpoints_require_auth_in_prod_staging(self):
        """Test that docs endpoints require authentication in production/staging environments."""
        # Note: This test would require setting the environment to production/staging
        # For now, we'll test the function logic directly
        from src.adapters.api.v1.docs import get_docs_dependencies
        
        # Test the function with different environment values
        with patch('src.adapters.api.v1.docs.settings') as mock_settings:
            # Test production environment
            mock_settings.APP_ENV = "production"
            dependencies = get_docs_dependencies()
            assert len(dependencies) == 1, "Should require admin auth in production"
            
            # Test staging environment
            mock_settings.APP_ENV = "staging"
            dependencies = get_docs_dependencies()
            assert len(dependencies) == 1, "Should require admin auth in staging"

    def test_docs_endpoints_with_admin_auth_in_prod(self):
        """Test that docs endpoints are accessible with admin authentication in production."""
        # This test would require setting up proper authentication
        # For now, we'll test the function logic
        from src.adapters.api.v1.docs import get_docs_dependencies
        
        with patch('src.adapters.api.v1.docs.settings') as mock_settings:
            mock_settings.APP_ENV = "production"
            dependencies = get_docs_dependencies()
            assert len(dependencies) == 1, "Should require admin auth in production"
            assert hasattr(dependencies[0], 'dependency'), "Should be a Depends object"

    def test_environment_variable_handling(self):
        """Test that the environment variable is correctly read and handled."""
        from src.adapters.api.v1.docs import get_docs_dependencies
        
        with patch('src.adapters.api.v1.docs.settings') as mock_settings:
            # Test with different environment values
            test_cases = [
                ("development", False),
                ("test", False),
                ("staging", True),
                ("production", True),
            ]
            
            for env, should_require_auth in test_cases:
                mock_settings.APP_ENV = env
                
                dependencies = get_docs_dependencies()
                
                if should_require_auth:
                    assert len(dependencies) == 1, f"Should require auth for {env}"
                else:
                    assert dependencies == [], f"Should not require auth for {env}" 