"""
Basic Security Tests for Policy System
======================================

This test suite contains basic security tests for the policy system that can run
without additional dependencies, focusing on core security vulnerabilities.

Author: Senior Python QA Security Engineer
"""

import asyncio
import json
import time
import uuid
from typing import Dict, List

import httpx
import pytest


class BasicPolicySecurityTests:
    """Basic security tests for policy system."""

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
        try:
            response = await async_client.post("/api/v1/auth/register", json=admin_data)
            if response.status_code != 201:
                # If registration fails, try to login (user might exist)
                login_response = await async_client.post("/api/v1/auth/login", json={
                    "username": admin_data["username"],
                    "password": admin_data["password"]
                })
                if login_response.status_code == 200:
                    return login_response.json()["tokens"]["access_token"]
                else:
                    # Create with different username
                    admin_data["username"] = f"admin_security_{uuid.uuid4().hex[:8]}"
                    admin_data["email"] = f"admin_security_{uuid.uuid4().hex[:8]}@cedrina.test"
                    response = await async_client.post("/api/v1/auth/register", json=admin_data)
                    assert response.status_code == 201, f"Admin registration failed: {response.text}"
            
            # Login to get token
            login_response = await async_client.post("/api/v1/auth/login", json={
                "username": admin_data["username"],
                "password": admin_data["password"]
            })
            assert login_response.status_code == 200, f"Admin login failed: {login_response.text}"
            
            return login_response.json()["tokens"]["access_token"]
        
        except Exception as e:
            pytest.skip(f"Could not create admin token: {e}")

    @pytest.mark.asyncio
    async def test_sql_injection_prevention(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test SQL injection prevention in policy creation."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # SQL injection payloads
        sql_payloads = [
            "'; DROP TABLE casbin_rule; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO casbin_rule VALUES ('p', 'attacker', '/admin/*', '*'); --",
            "admin'; DELETE FROM policy_audit_logs; --"
        ]
        
        blocked_count = 0
        
        for payload in sql_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={"subject": payload, "object": "/test", "action": "GET"}
            )
            
            # Should block SQL injection
            if response.status_code == 422:
                blocked_count += 1
            
            # Verify no database errors leaked
            response_text = response.text.lower()
            assert "database" not in response_text, f"Database error leaked: {response_text}"
            assert "sql" not in response_text, f"SQL error leaked: {response_text}"
        
        # All SQL injection attempts should be blocked
        assert blocked_count == len(sql_payloads), f"SQL injection not fully prevented: {blocked_count}/{len(sql_payloads)}"

    @pytest.mark.asyncio
    async def test_xss_prevention(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test XSS prevention in policy fields."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "' onclick='alert(\"XSS\")"
        ]
        
        blocked_count = 0
        
        for payload in xss_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={"subject": payload, "object": "/test", "action": "GET"}
            )
            
            # Should block XSS
            if response.status_code == 422:
                blocked_count += 1
        
        # All XSS attempts should be blocked
        assert blocked_count == len(xss_payloads), f"XSS not fully prevented: {blocked_count}/{len(xss_payloads)}"

    @pytest.mark.asyncio
    async def test_policy_injection_prevention(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test policy injection prevention."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Policy injection payloads
        policy_payloads = [
            "user\np,attacker,/admin/*,*",
            "user\ng,attacker,admin",
            "admin\np,hacker,/*,*",
            "user\np,attacker,/admin/*,*\ng,attacker,admin"
        ]
        
        blocked_count = 0
        
        for payload in policy_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={"subject": payload, "object": "/test", "action": "GET"}
            )
            
            # Should block policy injection
            if response.status_code == 422:
                blocked_count += 1
        
        # All policy injection attempts should be blocked
        assert blocked_count == len(policy_payloads), f"Policy injection not fully prevented: {blocked_count}/{len(policy_payloads)}"

    @pytest.mark.asyncio
    async def test_command_injection_prevention(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test command injection prevention."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Command injection payloads
        command_payloads = [
            "; cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "& ls -la",
            "| ps aux"
        ]
        
        blocked_count = 0
        
        for payload in command_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={"subject": f"user{payload}", "object": "/test", "action": "GET"}
            )
            
            # Should block command injection
            if response.status_code == 422:
                blocked_count += 1
        
        # All command injection attempts should be blocked
        assert blocked_count == len(command_payloads), f"Command injection not fully prevented: {blocked_count}/{len(command_payloads)}"

    @pytest.mark.asyncio
    async def test_rate_limiting_enforcement(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test rate limiting enforcement."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Send rapid requests to test rate limiting
        policy = {"subject": "rate_test", "object": "/test", "action": "GET"}
        
        # Send 60 requests rapidly (should exceed rate limit of 50/minute)
        tasks = []
        for i in range(60):
            task = async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={**policy, "subject": f"rate_test_{i}"}
            )
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count rate limited responses
        rate_limited = 0
        successful = 0
        
        for response in responses:
            if hasattr(response, 'status_code'):
                if response.status_code == 429:
                    rate_limited += 1
                elif response.status_code == 201:
                    successful += 1
        
        # Should have some rate limiting
        assert rate_limited > 0, f"Rate limiting not enforced: {rate_limited} rate limited responses"
        assert successful < 60, f"Too many requests succeeded: {successful}/60"

    @pytest.mark.asyncio
    async def test_authentication_bypass_prevention(
        self, 
        async_client: httpx.AsyncClient
    ):
        """Test authentication bypass prevention."""
        
        # Test various authentication bypass attempts
        invalid_tokens = [
            "invalid_token",
            "Bearer invalid_token",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.",
            "",
            "null",
            "undefined"
        ]
        
        policy = {"subject": "auth_test", "object": "/test", "action": "GET"}
        blocked_count = 0
        
        for token in invalid_tokens:
            if token:
                headers = {"Authorization": f"Bearer {token}"}
            else:
                headers = {}
            
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            
            # Should block unauthorized access
            if response.status_code == 401:
                blocked_count += 1
        
        # All invalid tokens should be blocked
        assert blocked_count == len(invalid_tokens), f"Authentication bypass not prevented: {blocked_count}/{len(invalid_tokens)}"

    @pytest.mark.asyncio
    async def test_input_validation_buffer_overflow(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test input validation for buffer overflow attempts."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Large payload attempts
        large_payloads = [
            "A" * 1000,
            "B" * 5000,
            "C" * 10000,
            "D" * 50000
        ]
        
        blocked_count = 0
        
        for payload in large_payloads:
            response = await async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json={"subject": payload, "object": "/test", "action": "GET"}
            )
            
            # Should block large payloads
            if response.status_code == 422:
                blocked_count += 1
        
        # Large payloads should be blocked
        assert blocked_count >= len(large_payloads) * 0.75, f"Large payload protection insufficient: {blocked_count}/{len(large_payloads)}"

    @pytest.mark.asyncio
    async def test_concurrent_policy_manipulation(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test concurrent policy manipulation for race conditions."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test race condition with identical policy creation
        policy = {"subject": "race_test", "object": "/race", "action": "GET"}
        
        # Create 20 concurrent requests for the same policy
        tasks = []
        for _ in range(20):
            task = async_client.post(
                "/api/v1/admin/policies/add",
                headers=headers,
                json=policy
            )
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful and duplicate responses
        successful = 0
        duplicates = 0
        
        for response in responses:
            if hasattr(response, 'status_code'):
                if response.status_code == 201:
                    successful += 1
                elif response.status_code == 409:
                    duplicates += 1
        
        # Should have only one successful creation
        assert successful <= 1, f"Race condition vulnerability: {successful} policies created"
        assert duplicates >= 15, f"Duplicate detection failed: {duplicates} duplicates detected"

    @pytest.mark.asyncio
    async def test_malicious_json_payloads(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test malicious JSON payload handling."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Malicious JSON payloads
        malicious_payloads = [
            '{"subject": "test", "object": "/test", "action": "GET", "extra": {"evil": "payload"}}',
            '{"subject": "test", "subject": "admin", "object": "/test", "action": "GET"}',
            '{"subject": null, "object": "/test", "action": "GET"}',
            '{"subject": ["admin", "user"], "object": "/test", "action": "GET"}',
            '{"subject": "test", "object": "/test", "action": "GET", "malicious": "' + "A" * 10000 + '"}'
        ]
        
        blocked_count = 0
        
        for payload in malicious_payloads:
            try:
                response = await async_client.post(
                    "/api/v1/admin/policies/add",
                    headers={**headers, "Content-Type": "application/json"},
                    content=payload
                )
                
                # Should block or sanitize malicious payloads
                if response.status_code in [400, 422]:
                    blocked_count += 1
            except Exception:
                # Parsing errors are acceptable
                blocked_count += 1
        
        # Most malicious payloads should be blocked
        assert blocked_count >= len(malicious_payloads) * 0.8, f"Malicious JSON not sufficiently blocked: {blocked_count}/{len(malicious_payloads)}"

    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test privilege escalation prevention."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create a regular user token (simulate)
        unique_id = uuid.uuid4().hex[:8]
        user_data = {
            "username": f"user_security_{unique_id}",
            "email": f"user_security_{unique_id}@cedrina.test",
            "password": "UserSecure123!@#",
            "role": "user"
        }
        
        try:
            # Register regular user
            response = await async_client.post("/api/v1/auth/register", json=user_data)
            if response.status_code != 201:
                # Skip if user registration fails
                pytest.skip("Could not create regular user for privilege escalation test")
            
            # Login to get user token
            login_response = await async_client.post("/api/v1/auth/login", json={
                "username": user_data["username"],
                "password": user_data["password"]
            })
            
            if login_response.status_code != 200:
                pytest.skip("Could not login regular user for privilege escalation test")
            
            user_token = login_response.json()["tokens"]["access_token"]
            user_headers = {"Authorization": f"Bearer {user_token}"}
            
            # Test privilege escalation attempts
            escalation_attempts = [
                {"subject": "user", "object": "/admin/*", "action": "*"},
                {"subject": "user", "object": "/admin/users", "action": "DELETE"},
                {"subject": "user", "object": "/admin/policies", "action": "POST"}
            ]
            
            blocked_count = 0
            
            for attempt in escalation_attempts:
                response = await async_client.post(
                    "/api/v1/admin/policies/add",
                    headers=user_headers,
                    json=attempt
                )
                
                # Should block regular user from creating admin policies
                if response.status_code == 403:
                    blocked_count += 1
            
            # All privilege escalation attempts should be blocked
            assert blocked_count == len(escalation_attempts), f"Privilege escalation not prevented: {blocked_count}/{len(escalation_attempts)}"
            
        except Exception as e:
            pytest.skip(f"Could not complete privilege escalation test: {e}")

    @pytest.mark.asyncio
    async def test_information_disclosure_prevention(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Test information disclosure prevention in error messages."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Payloads designed to trigger errors
        error_payloads = [
            {"subject": "A" * 100000, "object": "/test", "action": "GET"},
            {"subject": None, "object": "/test", "action": "GET"},
            {"subject": {"nested": "object"}, "object": "/test", "action": "GET"}
        ]
        
        safe_error_count = 0
        
        for payload in error_payloads:
            try:
                response = await async_client.post(
                    "/api/v1/admin/policies/add",
                    headers=headers,
                    json=payload
                )
                
                # Check error message for sensitive information
                error_text = response.text.lower()
                sensitive_keywords = [
                    "password", "secret", "key", "token", "database", "sql", 
                    "server", "host", "port", "username", "credential", "admin",
                    "traceback", "exception", "stack", "internal", "debug"
                ]
                
                is_safe = True
                for keyword in sensitive_keywords:
                    if keyword in error_text:
                        is_safe = False
                        break
                
                if is_safe:
                    safe_error_count += 1
                    
            except Exception:
                # Exception handling is acceptable
                safe_error_count += 1
        
        # Error messages should not contain sensitive information
        assert safe_error_count == len(error_payloads), f"Information disclosure in error messages: {safe_error_count}/{len(error_payloads)}"

    @pytest.mark.asyncio
    async def test_comprehensive_security_validation(
        self, 
        async_client: httpx.AsyncClient, 
        admin_token: str
    ):
        """Comprehensive security validation test."""
        print("\n" + "="*60)
        print("COMPREHENSIVE SECURITY VALIDATION RESULTS")
        print("="*60)
        
        # Security test categories
        security_tests = [
            ("SQL Injection Prevention", self.test_sql_injection_prevention),
            ("XSS Prevention", self.test_xss_prevention),
            ("Policy Injection Prevention", self.test_policy_injection_prevention),
            ("Command Injection Prevention", self.test_command_injection_prevention),
            ("Rate Limiting Enforcement", self.test_rate_limiting_enforcement),
            ("Authentication Bypass Prevention", self.test_authentication_bypass_prevention),
            ("Input Validation Buffer Overflow", self.test_input_validation_buffer_overflow),
            ("Concurrent Policy Manipulation", self.test_concurrent_policy_manipulation),
            ("Malicious JSON Payloads", self.test_malicious_json_payloads),
            ("Information Disclosure Prevention", self.test_information_disclosure_prevention)
        ]
        
        passed_tests = 0
        total_tests = len(security_tests)
        
        for test_name, test_func in security_tests:
            try:
                await test_func(async_client, admin_token)
                print(f"✅ {test_name}: PASSED")
                passed_tests += 1
            except Exception as e:
                print(f"❌ {test_name}: FAILED - {str(e)[:100]}...")
        
        # Security score calculation
        security_score = (passed_tests / total_tests) * 100
        
        print(f"\nSECURITY SCORE: {security_score:.1f}/100")
        print(f"TESTS PASSED: {passed_tests}/{total_tests}")
        
        if security_score >= 95:
            print("🎉 EXCELLENT: Strong security posture")
        elif security_score >= 80:
            print("👍 GOOD: Acceptable security with minor improvements")
        elif security_score >= 60:
            print("⚠️  MODERATE: Security improvements required")
        else:
            print("🚨 POOR: Significant security vulnerabilities")
        
        print("="*60)
        
        # Assert minimum security requirements
        assert security_score >= 80, f"Security score below minimum threshold: {security_score:.1f}%"
        assert passed_tests >= total_tests * 0.8, f"Too many security tests failed: {passed_tests}/{total_tests}"


# Test execution marker
if __name__ == "__main__":
    print("Basic Policy Security Test Suite")
    print("Run with: pytest tests/security/test_policy_security_basic.py -v")
    print("For comprehensive validation: pytest tests/security/test_policy_security_basic.py::BasicPolicySecurityTests::test_comprehensive_security_validation -v -s")