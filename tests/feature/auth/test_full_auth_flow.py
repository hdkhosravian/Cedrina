import pytest
import uuid
import time
import json
import asyncio
from httpx import AsyncClient

from src.main import app


@pytest.mark.asyncio
class TestFullAuthFlow:
    def _unique_user(self):
        # Use timestamp + uuid to ensure uniqueness across test runs and parallel execution
        timestamp = str(int(time.time() * 1000))
        uid = str(uuid.uuid4())[:8]
        unique_id = f"{timestamp}_{uid}"
        return {
            "username": f"user_{unique_id}",
            "email": f"user_{unique_id}@test.com",
            "password": "Str0ng!Passw0rd"
        }

    @pytest.mark.asyncio
    async def test_registration_login_logout_flow(self, async_client):
        user = self._unique_user()
        print("Registering user:", user)
        # Register
        resp = await async_client.post("/api/v1/auth/register", json=user)
        if resp.status_code != 201:
            print("Registration failed:", resp.status_code, resp.text)
        assert resp.status_code == 201
        
        # Login
        login_resp = await async_client.post("/api/v1/auth/login", json={
            "username": user["username"],
            "password": user["password"]
        })
        assert login_resp.status_code == 200
        tokens = login_resp.json()["tokens"]
        access_token = tokens["access_token"]
        
        # Logout
        headers = {"Authorization": f"Bearer {access_token}"}
        logout_resp = await async_client.post("/api/v1/auth/logout", headers=headers)
        assert logout_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_registration_duplicate_and_weak_password(self, async_client):
        user = self._unique_user()
        print("Registering user:", user)
        # Register first time
        resp1 = await async_client.post("/api/v1/auth/register", json=user)
        if resp1.status_code != 201:
            print("Registration failed:", resp1.status_code, resp1.text)
        assert resp1.status_code == 201
        # Register duplicate
        resp2 = await async_client.post("/api/v1/auth/register", json=user)
        assert resp2.status_code == 409
        
        # Test weak password
        weak_user = self._unique_user()
        weak_user["password"] = "weak"
        resp3 = await async_client.post("/api/v1/auth/register", json=weak_user)
        assert resp3.status_code == 422

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, async_client):
        # Invalid user
        resp1 = await async_client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "password"
        })
        assert resp1.status_code == 401
        
        # Register valid user first
        user = self._unique_user()
        reg_resp = await async_client.post("/api/v1/auth/register", json=user)
        assert reg_resp.status_code == 201
        
        # Wrong password
        resp2 = await async_client.post("/api/v1/auth/login", json={
            "username": user["username"],
            "password": "wrongpassword"
        })
        assert resp2.status_code == 401

    @pytest.mark.asyncio
    async def test_password_change_flow(self, async_client):
        user = self._unique_user()
        print("Registering user:", user)
        # Register
        reg_resp = await async_client.post("/api/v1/auth/register", json=user)
        if reg_resp.status_code != 201:
            print("Registration failed:", reg_resp.status_code, reg_resp.text)
            assert False, f"Registration failed: {reg_resp.status_code} {reg_resp.text}"
        
        # Login to get token
        login_resp = await async_client.post("/api/v1/auth/login", json={
            "username": user["username"],
            "password": user["password"]
        })
        assert login_resp.status_code == 200
        tokens = login_resp.json()["tokens"]
        access_token = tokens["access_token"]
        
        # Change password
        headers = {"Authorization": f"Bearer {access_token}"}
        change_resp = await async_client.put("/api/v1/auth/change-password", 
            headers=headers,
            json={
                "old_password": user["password"],
                "new_password": "NewStr0ng!Passw0rd"
            }
        )
        assert change_resp.status_code == 200
        
        # Login with new password
        new_login_resp = await async_client.post("/api/v1/auth/login", json={
            "username": user["username"],
            "password": "NewStr0ng!Passw0rd"
        })
        assert new_login_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_logout_with_invalid_token(self, async_client):
        headers = {"Authorization": "Bearer invalidtoken"}
        resp = await async_client.post("/api/v1/auth/logout", headers=headers)
        assert resp.status_code == 401 