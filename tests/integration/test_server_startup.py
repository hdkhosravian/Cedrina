"""Integration Test for Server Startup

This module contains integration tests to verify that the FastAPI server can start correctly
without encountering import errors, configuration issues, or other startup failures.
These tests simulate running the server with Uvicorn to ensure the application loads properly.

Tests:
    - test_server_startup: Verifies that the server can start and respond to a basic request.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.core.rate_limiting.ratelimiter import get_limiter
from src.main import app


def test_server_startup():
    """Test server startup sequence."""
    # Test that the app can start and respond to requests
    app.state.limiter = get_limiter()  # Ensure limiter is attached for the test
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health", headers={"Authorization": "Bearer fake-token"})
            assert response.status_code == 401, f"Expected 401 for invalid token, got {response.status_code}"
    except RuntimeError as e:
        pytest.fail(f"Server startup failed: {e}")


@pytest.mark.asyncio
async def test_server_startup_alternative():
    """Test that the server can start successfully and respond to requests.

    This test simulates starting the server with Uvicorn in a controlled environment
    and checks if it can handle a basic request (e.g., to the root endpoint if available
    or a known endpoint). It ensures there are no import errors or configuration issues
    during startup.
    """
    # Use TestClient to interact with the app directly without starting a full server
    # This avoids port conflicts and focuses on app initialization
    client = TestClient(app)

    # Test a simple request to verify the app is loaded correctly
    # Assuming there's a root endpoint or a simple endpoint to test
    try:
        response = client.get("/api/v1/health", headers={"Authorization": "Bearer fake-token"})
        # We expect 401 for invalid token
        assert response.status_code == 401, f"Expected 401 for invalid token, got {response.status_code}"
    except Exception as e:
        pytest.fail(f"Server startup test failed with exception: {e!s}")
    finally:
        # Ensure any background tasks or resources are cleaned up if needed
        pass
