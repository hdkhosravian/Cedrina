"""
Unit Tests for Token Lifecycle Management Service.

This test suite validates the TokenLifecycleManagementService following
Test-Driven Development (TDD) principles and comprehensive security testing.

Test Categories:
1. Token Pair Creation Tests - Validates secure token creation with family patterns
2. Token Refresh Tests - Validates secure refresh with reuse detection
3. Token Validation Tests - Validates zero-trust token validation
4. Security Incident Tests - Validates threat detection and response
5. Performance Tests - Validates sub-millisecond response requirements
6. Edge Case Tests - Validates error handling and boundary conditions

Security Test Focus:
- Token reuse detection and family-wide revocation
- Advanced threat pattern analysis and response
- Zero-trust validation with comprehensive security checks
- Security context validation and enrichment
- Audit trail generation and forensic analysis

Test Quality Standards:
- Fast execution (sub-millisecond unit tests)
- Isolated dependencies through mocking
- Comprehensive edge case coverage
- Security-focused validation
- Clear test documentation and intent
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from src.core.exceptions import AuthenticationError, SecurityViolationError, ValidationError
from src.domain.entities.user import User, Role
from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.services.authentication.token_lifecycle_management_service import (
    TokenLifecycleManagementService,
    TokenPair,
    TokenCreationRequest,
    TokenRefreshRequest,
    SecurityThreatLevel,
    SecurityAssessment
)
from src.domain.events.authentication_events import (
    TokenFamilyCreatedEvent,
    TokenRefreshedEvent,
    TokenReuseDetectedEvent,
    TokenFamilyCompromisedEvent,
    SecurityIncidentEvent
)


class TestTokenLifecycleManagementService:
    """
    Test suite for TokenLifecycleManagementService domain service.
    
    This test suite validates the core business logic of token lifecycle management
    including security patterns, family management, and threat detection.
    """
    
    @pytest.fixture
    def mock_token_family_repository(self):
        """Mock token family repository for isolated testing."""
        repository = AsyncMock()
        repository.create_token_family = AsyncMock()
        repository.get_by_family_id = AsyncMock()
        repository.is_token_revoked = AsyncMock(return_value=False)
        repository.rotate_tokens = AsyncMock()
        repository.compromise_family = AsyncMock()
        return repository
    
    @pytest.fixture
    def mock_event_publisher(self):
        """Mock event publisher for isolated testing."""
        publisher = AsyncMock()
        publisher.publish = AsyncMock()
        return publisher
    
    @pytest.fixture
    def service(self, mock_token_family_repository, mock_event_publisher):
        """Create service instance with mocked dependencies."""
        return TokenLifecycleManagementService(
            token_family_repository=mock_token_family_repository,
            event_publisher=mock_event_publisher
        )
    
    @pytest.fixture
    def test_user(self):
        """Create test user entity."""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            role=Role.USER,
            is_active=True
        )
    
    @pytest.fixture
    def security_context(self):
        """Create test security context."""
        return SecurityContext.create_for_request(
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0 (Test Browser)",
            correlation_id="test-correlation-123"
        )
    
    @pytest.fixture
    def token_creation_request(self, test_user, security_context):
        """Create token creation request for testing."""
        return TokenCreationRequest(
            user=test_user,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
    
    # === Token Pair Creation Tests ===
    
    @pytest.mark.asyncio
    async def test_create_token_pair_with_family_security_success(
        self,
        service,
        token_creation_request,
        mock_token_family_repository,
        mock_event_publisher
    ):
        """
        BUSINESS RULE TEST: Token pair creation should establish family security.
        
        This test validates that token pair creation follows the domain business rules:
        1. Security context is assessed for threats
        2. Token family is established with secure metadata
        3. Cryptographically secure tokens are generated
        4. Family association is created for security correlation
        5. Domain events are published for monitoring
        """
        # Act
        result = await service.create_token_pair_with_family_security(token_creation_request)
        
        # Assert: Token pair is created successfully
        assert isinstance(result, TokenPair)
        assert result.access_token is not None
        assert result.refresh_token is not None
        assert result.family_id is not None
        assert result.token_type == "bearer"
        assert result.expires_in == 900  # 15 minutes
        
        # Assert: Token family is created in repository
        mock_token_family_repository.create_token_family.assert_called_once()
        created_family = mock_token_family_repository.create_token_family.call_args[0][0]
        assert isinstance(created_family, TokenFamily)
        assert created_family.user_id == token_creation_request.user.id
        assert created_family.status == TokenFamilyStatus.ACTIVE
        
        # Assert: Domain event is published
        mock_event_publisher.publish.assert_called_once()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, TokenFamilyCreatedEvent)
        assert published_event.user_id == token_creation_request.user.id
        assert published_event.family_id == result.family_id
    
    @pytest.mark.asyncio
    async def test_create_token_pair_rejects_critical_security_threat(
        self,
        service,
        token_creation_request,
        mock_event_publisher
    ):
        """
        SECURITY TEST: Token creation should reject critical security threats.
        
        This test validates that the service properly detects and rejects
        token creation attempts when critical security threats are detected.
        """
        # Arrange: Mock critical threat detection
        with patch.object(service, '_assess_security_threat') as mock_assess:
            mock_assess.return_value = SecurityAssessment(
                threat_level=SecurityThreatLevel.CRITICAL,
                confidence_score=0.95,
                indicators=["malicious_ip", "suspicious_user_agent"],
                recommended_action="block_request"
            )
            
            # Act & Assert: Should raise SecurityViolationError
            with pytest.raises(SecurityViolationError, match="Critical security threat detected"):
                await service.create_token_pair_with_family_security(token_creation_request)
            
            # Assert: Security incident event is published
            mock_event_publisher.publish.assert_called()
            published_event = mock_event_publisher.publish.call_args[0][0]
            assert isinstance(published_event, SecurityIncidentEvent)
            assert published_event.threat_level == "critical"
    
    @pytest.mark.asyncio
    async def test_create_token_pair_handles_repository_failure(
        self,
        service,
        token_creation_request,
        mock_token_family_repository
    ):
        """
        ERROR HANDLING TEST: Token creation should handle repository failures gracefully.
        
        This test validates that the service properly handles database failures
        and converts them to appropriate domain exceptions.
        """
        # Arrange: Mock repository failure
        mock_token_family_repository.create_token_family.side_effect = Exception("Database connection failed")
        
        # Act & Assert: Should raise AuthenticationError
        with pytest.raises(AuthenticationError, match="token_creation_failed"):
            await service.create_token_pair_with_family_security(token_creation_request)
    
    # === Token Refresh Tests ===
    
    @pytest.mark.asyncio
    async def test_refresh_tokens_with_family_security_success(
        self,
        service,
        security_context,
        mock_token_family_repository
    ):
        """
        BUSINESS RULE TEST: Token refresh should rotate tokens with family security.
        
        This test validates that token refresh follows the domain business rules:
        1. Refresh token is validated for format and signature
        2. Token family security is verified
        3. Token reuse detection is performed
        4. New token pair is generated with rotation
        5. Old tokens are revoked and new tokens are associated
        """
        # Arrange: Create valid refresh token
        refresh_token = "valid.refresh.token"
        refresh_request = TokenRefreshRequest(
            refresh_token=refresh_token,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        # Mock token family
        test_family = TokenFamily(
            family_id="test-family-id",
            user_id=1,
            status=TokenFamilyStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        mock_token_family_repository.get_by_family_id.return_value = test_family
        
        # Mock token parsing
        with patch.object(service, '_parse_and_validate_refresh_token') as mock_parse:
            mock_parse.return_value = {
                "sub": "1",
                "jti": "test-jti",
                "family_id": "test-family-id"
            }
            
            with patch.object(service, '_validate_user_for_refresh') as mock_user:
                mock_user.return_value = User(id=1, username="test", email="test@example.com", is_active=True)
                
                # Act
                result = await service.refresh_tokens_with_family_security(refresh_request)
        
        # Assert: New token pair is created
        assert isinstance(result, TokenPair)
        assert result.access_token is not None
        assert result.refresh_token is not None
        assert result.family_id == "test-family-id"
        
        # Assert: Tokens are rotated in repository
        mock_token_family_repository.rotate_tokens.assert_called_once()
        
        # Assert: Token reuse detection was performed
        mock_token_family_repository.is_token_revoked.assert_called_once_with(
            "test-family-id", "test-jti"
        )
    
    @pytest.mark.asyncio
    async def test_refresh_tokens_detects_token_reuse(
        self,
        service,
        security_context,
        mock_token_family_repository,
        mock_event_publisher
    ):
        """
        SECURITY TEST: Token refresh should detect and respond to token reuse.
        
        This test validates that the service detects token reuse attacks and
        triggers immediate family-wide revocation as a security response.
        """
        # Arrange: Set up token reuse scenario
        refresh_token = "reused.refresh.token"
        refresh_request = TokenRefreshRequest(
            refresh_token=refresh_token,
            security_context=security_context,
            correlation_id="test-correlation-123"
        )
        
        test_family = TokenFamily(
            family_id="test-family-id",
            user_id=1,
            status=TokenFamilyStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        mock_token_family_repository.get_by_family_id.return_value = test_family
        mock_token_family_repository.is_token_revoked.return_value = True  # Token reuse detected
        
        with patch.object(service, '_parse_and_validate_refresh_token') as mock_parse:
            mock_parse.return_value = {
                "sub": "1",
                "jti": "reused-jti",
                "family_id": "test-family-id"
            }
            
            # Act & Assert: Should raise SecurityViolationError
            with pytest.raises(SecurityViolationError, match="Token reuse detected"):
                await service.refresh_tokens_with_family_security(refresh_request)
        
        # Assert: Family is compromised
        mock_token_family_repository.compromise_family.assert_called_once()
        
        # Assert: Token reuse event is published
        mock_event_publisher.publish.assert_called()
        published_event = mock_event_publisher.publish.call_args[0][0]
        assert isinstance(published_event, TokenReuseDetectedEvent)
        assert published_event.family_id == "test-family-id"
        assert published_event.reused_jti == "reused-jti"
    
    @pytest.mark.asyncio
    async def test_refresh_tokens_rejects_compromised_family(
        self,
        service,
        security_context,
        mock_token_family_repository
    ):
        """
        SECURITY TEST: Token refresh should reject compromised families.
        
        This test validates that the service properly rejects refresh attempts
        from token families that have been marked as compromised.
        """
        # Arrange: Set up compromised family scenario
        refresh_token = "token.from.compromised.family"
        refresh_request = TokenRefreshRequest(
            refresh_token=refresh_token,
            security_context=security_context
        )
        
        compromised_family = TokenFamily(
            family_id="compromised-family-id",
            user_id=1,
            status=TokenFamilyStatus.COMPROMISED,  # Family is compromised
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        mock_token_family_repository.get_by_family_id.return_value = compromised_family
        
        with patch.object(service, '_parse_and_validate_refresh_token') as mock_parse:
            mock_parse.return_value = {
                "sub": "1",
                "jti": "test-jti",
                "family_id": "compromised-family-id"
            }
            
            # Act & Assert: Should raise AuthenticationError for invalid token family
            with pytest.raises(AuthenticationError):
                await service.refresh_tokens_with_family_security(refresh_request)
    
    # === Token Validation Tests ===
    
    @pytest.mark.asyncio
    async def test_validate_token_with_family_security_success(
        self,
        service,
        security_context,
        mock_token_family_repository
    ):
        """
        BUSINESS RULE TEST: Token validation should perform comprehensive security checks.
        
        This test validates that token validation follows domain business rules:
        1. JWT format and signature are validated
        2. Token expiration is checked
        3. Family security status is verified
        4. User account status is validated
        5. Security threat assessment is performed
        """
        # Arrange: Valid access token
        access_token = "valid.access.token"
        
        with patch('jwt.decode') as mock_decode:
            mock_decode.return_value = {
                "sub": "1",
                "jti": "test-jti",
                "family_id": "test-family-id",
                "exp": (datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()
            }
            
            with patch.object(service, '_validate_token_family_security') as mock_family:
                mock_family.return_value = True
                
                with patch.object(service, '_validate_user_is_active') as mock_user:
                    mock_user.return_value = True
                    
                    # Act
                    result = await service.validate_token_with_family_security(
                        access_token, security_context
                    )
        
        # Assert: Token payload is returned
        assert isinstance(result, dict)
        assert result["sub"] == "1"
        assert result["jti"] == "test-jti"
        assert result["family_id"] == "test-family-id"
        
        # Assert: Security validations were performed
        mock_family.assert_called_once_with("test-family-id", "test-jti")
        mock_user.assert_called_once_with(1, "en")
    
    @pytest.mark.asyncio
    async def test_validate_token_rejects_invalid_jwt(
        self,
        service,
        security_context
    ):
        """
        SECURITY TEST: Token validation should reject invalid JWTs.
        
        This test validates that the service properly handles and rejects
        malformed or tampered JWT tokens.
        """
        # Arrange: Invalid JWT token
        invalid_token = "invalid.jwt.token"
        
        with patch('jwt.decode') as mock_decode:
            from jwt import PyJWTError
            mock_decode.side_effect = PyJWTError("Invalid token")
            
            # Act & Assert: Should raise AuthenticationError
            with pytest.raises(AuthenticationError, match="invalid_token"):
                await service.validate_token_with_family_security(
                    invalid_token, security_context
                )
    
    @pytest.mark.asyncio
    async def test_validate_token_rejects_compromised_family(
        self,
        service,
        security_context
    ):
        """
        SECURITY TEST: Token validation should reject tokens from compromised families.
        
        This test validates that tokens from compromised families are immediately
        rejected to prevent further security violations.
        """
        # Arrange: Token from compromised family
        access_token = "token.from.compromised.family"
        
        with patch('jwt.decode') as mock_decode:
            mock_decode.return_value = {
                "sub": "1",
                "jti": "test-jti",
                "family_id": "compromised-family-id"
            }
            
            with patch.object(service, '_validate_token_family_security') as mock_family:
                mock_family.return_value = False  # Family is compromised
                
                with patch.object(service, '_validate_user_is_active') as mock_user:
                    mock_user.return_value = True
                    
                    # Act & Assert: Should raise SecurityViolationError
                    with pytest.raises(SecurityViolationError, match="Token family compromised"):
                        await service.validate_token_with_family_security(
                            access_token, security_context
                        )
    
    # === Performance Tests ===
    
    @pytest.mark.asyncio
    async def test_token_validation_performance_requirement(
        self,
        service,
        security_context
    ):
        """
        PERFORMANCE TEST: Token validation should meet sub-millisecond requirement.
        
        This test validates that token validation operations complete within
        the required performance threshold for high-throughput applications.
        """
        import time
        
        # Arrange: Valid token for performance test
        access_token = "performance.test.token"
        
        with patch('jwt.decode') as mock_decode:
            mock_decode.return_value = {
                "sub": "1",
                "jti": "perf-jti",
                "family_id": "perf-family-id"
            }
            
            with patch.object(service, '_validate_token_family_security') as mock_family:
                mock_family.return_value = True
                
                with patch.object(service, '_validate_user_is_active') as mock_user:
                    mock_user.return_value = True
                    
                    # Act: Measure validation time
                    start_time = time.perf_counter()
                    await service.validate_token_with_family_security(
                        access_token, security_context
                    )
                    end_time = time.perf_counter()
        
        # Assert: Validation completes within performance requirement
        validation_time_ms = (end_time - start_time) * 1000
        assert validation_time_ms < 1.0, f"Token validation took {validation_time_ms:.3f}ms, exceeds 1ms requirement"
    
    # === Edge Case Tests ===
    
    @pytest.mark.asyncio
    async def test_create_token_pair_with_invalid_security_context(
        self,
        service,
        test_user
    ):
        """
        EDGE CASE TEST: Token creation should validate security context.
        
        This test validates that the service properly handles invalid
        security context data and provides appropriate error responses.
        """
        # Arrange: Invalid security context
        with pytest.raises(ValidationError):
            invalid_context = SecurityContext(
                client_ip="",  # Invalid empty IP
                user_agent="Valid User Agent",
                request_timestamp=datetime.now(timezone.utc)
            )
            
            request = TokenCreationRequest(
                user=test_user,
                security_context=invalid_context
            )
            
            # Act: Should fail during security context validation
            await service.create_token_pair_with_family_security(request)
    
    @pytest.mark.asyncio
    async def test_refresh_tokens_with_missing_family_id(
        self,
        service,
        security_context
    ):
        """
        EDGE CASE TEST: Token refresh should handle missing family ID.
        
        This test validates backward compatibility with tokens that don't
        have family IDs while maintaining security standards.
        """
        # Arrange: Token without family ID
        refresh_token = "token.without.family.id"
        refresh_request = TokenRefreshRequest(
            refresh_token=refresh_token,
            security_context=security_context
        )
        
        with patch.object(service, '_parse_and_validate_refresh_token') as mock_parse:
            mock_parse.return_value = {
                "sub": "1",
                "jti": "test-jti"
                # No family_id in payload
            }
            
            # Act & Assert: Should raise AuthenticationError
            with pytest.raises(AuthenticationError, match="invalid_token_family"):
                await service.refresh_tokens_with_family_security(refresh_request)
    
    @pytest.mark.asyncio
    async def test_validate_token_with_expired_token(
        self,
        service,
        security_context
    ):
        """
        EDGE CASE TEST: Token validation should handle expired tokens.
        
        This test validates that expired tokens are properly rejected
        with appropriate error messages.
        """
        # Arrange: Expired token
        expired_token = "expired.access.token"
        
        with patch('jwt.decode') as mock_decode:
            from jwt import ExpiredSignatureError
            mock_decode.side_effect = ExpiredSignatureError("Token has expired")
            
            # Act & Assert: Should raise AuthenticationError
            with pytest.raises(AuthenticationError, match="invalid_token"):
                await service.validate_token_with_family_security(
                    expired_token, security_context
                ) 