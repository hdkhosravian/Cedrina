import pytest
from datetime import datetime, timezone
import uuid
import asyncio
from src.infrastructure.services.authentication.domain_token_service import DomainTokenService
from src.domain.value_objects.token_requests import TokenCreationRequest, TokenRefreshRequest
from src.domain.value_objects.security_context import SecurityContext
from src.domain.entities.user import User, Role
from src.common.exceptions import AuthenticationError, SecurityViolationError
from src.infrastructure.database.session_factory import get_default_session_factory
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

@pytest.fixture(scope="function")
async def isolated_user():
    """Create and persist test user with complete isolation for production scenario testing."""
    # Create unique user to avoid conflicts across tests with enhanced uniqueness
    import time
    import random
    
    timestamp = int(time.time() * 1000000)  # microseconds
    random_part = random.randint(100000, 999999)
    uuid_part = uuid.uuid4().hex[:8]
    unique_suffix = f"{timestamp}_{random_part}_{uuid_part}"
    # Use a much larger range to avoid ID conflicts and ensure uniqueness
    unique_id = abs(hash(unique_suffix)) % 999999999 + 1000000  # Range: 1000000 to 999999999
    
    user = User(
        id=unique_id, 
        username=f"testuser_{unique_suffix}", 
        email=f"test_{unique_suffix}@example.com", 
        role=Role.USER, 
        is_active=True
    )
    
    # Use separate session factory instance for complete isolation
    session_factory = get_default_session_factory()
    
    # Persist user to database with proper error handling and retries
    for attempt in range(5):  # Increase retry attempts
        try:
            # Add incremental delay with jitter to reduce connection pool contention
            if attempt > 0:
                import random
                base_delay = 0.2 * attempt
                jitter = random.uniform(0.05, 0.15)
                await asyncio.sleep(base_delay + jitter)
            
            # Use create_session instead of create_transactional_session for better control
            async with session_factory.create_session() as session:
                try:
                    # Add the user to the session
                    session.add(user)
                    
                    # Flush to check for any immediate errors
                    await session.flush()
                    
                    # Commit the transaction
                    await session.commit()
                    
                    # Refresh to get the persisted state
                    await session.refresh(user)
                    
                    # Success - break out of retry loop
                    break
                    
                except Exception as session_error:
                    # Rollback on any error
                    await session.rollback()
                    raise session_error
                    
        except Exception as e:
            if attempt == 4:  # Last attempt
                # If user creation fails after all retries, skip the test gracefully
                pytest.skip(f"Could not create test user after {attempt + 1} attempts: {e}")
            else:
                # Log the attempt and continue
                print(f"Attempt {attempt + 1} failed: {e}")
                continue
    
    yield user
    
    # Clean up: remove user from database with retry logic
    for attempt in range(5):  # Increase retry attempts for cleanup
        try:
            # Add delay with jitter for cleanup operations
            if attempt > 0:
                import random
                base_delay = 0.15 * attempt
                jitter = random.uniform(0.05, 0.10)
                await asyncio.sleep(base_delay + jitter)
            
            async with session_factory.create_session() as cleanup_session:
                try:
                    await cleanup_session.execute(text("DELETE FROM users WHERE id = :user_id"), {"user_id": user.id})
                    await cleanup_session.commit()
                    break  # Success - exit retry loop
                except Exception as session_error:
                    await cleanup_session.rollback()
                    raise session_error
                    
        except Exception as e:
            if attempt == 4:  # Last attempt
                # Log but don't fail test on cleanup error
                print(f"Warning: Could not clean up test user {user.id} after {attempt + 1} attempts: {e}")
            else:
                # Continue to next attempt
                continue

@pytest.fixture(scope="function")
async def isolated_domain_token_service():
    """Create isolated domain token service with separate session factory."""
    session_factory = get_default_session_factory()
    service = DomainTokenService(session_factory=session_factory)
    
    yield service
    
    # Clean up: remove any token families created during test with retry logic
    for attempt in range(5):  # Increase retry attempts for cleanup
        try:
            # Add delay with jitter for cleanup operations
            if attempt > 0:
                import random
                base_delay = 0.15 * attempt
                jitter = random.uniform(0.05, 0.10)
                await asyncio.sleep(base_delay + jitter)
            
            async with session_factory.create_session() as cleanup_session:
                try:
                    # Clean up recent token families to avoid interference
                    await cleanup_session.execute(
                        text("DELETE FROM token_families WHERE created_at > NOW() - INTERVAL '10 minutes'")
                    )
                    await cleanup_session.commit()
                    break  # Success - exit retry loop
                except Exception as session_error:
                    await cleanup_session.rollback()
                    raise session_error
                    
        except Exception as e:
            if attempt == 4:  # Last attempt
                # Log but don't fail test on cleanup error
                print(f"Warning: Could not clean up token families after {attempt + 1} attempts: {e}")
            else:
                # Continue to next attempt
                continue

@pytest.mark.asyncio
async def test_create_token_pair_with_family_security_success(isolated_domain_token_service, isolated_user):
    """Test creating token pair with family security in real production scenario."""
    correlation_id = f"corr-{uuid.uuid4()}"
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id=correlation_id)
    request = TokenCreationRequest(user=isolated_user, security_context=security_context, correlation_id=correlation_id, language="en")
    
    # Test real production scenario with actual database operations
    result = await isolated_domain_token_service.create_token_pair_with_family_security(request)
    
    # Verify production-level token pair creation
    assert result.access_token
    assert result.refresh_token
    assert result.family_id
    assert result.expires_in > 0
    
    # Verify that token family was actually created in database
    token_family = await isolated_domain_token_service._token_family_repository.get_family_by_id(result.family_id)
    assert token_family is not None
    assert token_family.user_id == isolated_user.id
    assert token_family.status.value == 'active'
    assert len(token_family.active_tokens) > 0

@pytest.mark.asyncio
async def test_create_token_pair_with_family_security_invalid_user(isolated_domain_token_service):
    """Test production scenario with inactive user - should fail at request validation."""
    correlation_id = f"corr-{uuid.uuid4()}"
    unique_id = abs(hash(str(uuid.uuid4()))) % 1000000
    
    # Create inactive user to test real production validation
    user = User(id=unique_id, username=f"inactive_{unique_id}", email=f"inactive_{unique_id}@example.com", role=Role.USER, is_active=False)
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id=correlation_id)
    
    # Test that creating request with inactive user raises ValueError at request creation (production behavior)
    with pytest.raises(ValueError, match="Cannot create tokens for inactive user"):
        TokenCreationRequest(user=user, security_context=security_context, correlation_id=correlation_id, language="en")

@pytest.mark.asyncio
async def test_refresh_tokens_with_family_security_success(isolated_domain_token_service, isolated_user):
    """Test real production scenario for token refresh with family security."""
    correlation_id = f"corr-{uuid.uuid4()}"
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id=correlation_id)
    
    # Step 1: Create initial token pair in production scenario
    creation_request = TokenCreationRequest(user=isolated_user, security_context=security_context, correlation_id=correlation_id, language="en")
    token_pair = await isolated_domain_token_service.create_token_pair_with_family_security(creation_request)
    
    # Step 2: Refresh tokens using the real refresh token (production scenario)
    refresh_request = TokenRefreshRequest(
        refresh_token=token_pair.refresh_token,
        security_context=security_context,
        correlation_id=correlation_id
    )
    result = await isolated_domain_token_service.refresh_tokens_with_family_security(refresh_request)
    
    # Verify production-level token refresh behavior
    assert result.access_token
    assert result.refresh_token
    assert result.family_id == token_pair.family_id
    
    # Verify that refresh token was actually processed in database
    token_family = await isolated_domain_token_service._token_family_repository.get_family_by_id(result.family_id)
    assert token_family is not None
    assert token_family.user_id == isolated_user.id
    assert token_family.status.value == 'active'

@pytest.mark.asyncio
async def test_refresh_tokens_with_family_security_invalid_token(isolated_domain_token_service, isolated_user):
    """Test production scenario with invalid refresh token - should fail with AuthenticationError."""
    correlation_id = f"corr-{uuid.uuid4()}"
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id=correlation_id)
    
    # Test real production scenario with invalid token
    refresh_request = TokenRefreshRequest(
        refresh_token="invalid.token.value",
        security_context=security_context,
        correlation_id=correlation_id
    )
    
    # Should raise AuthenticationError in production scenario
    with pytest.raises(AuthenticationError):
        await isolated_domain_token_service.refresh_tokens_with_family_security(refresh_request)

@pytest.mark.asyncio
async def test_validate_token_with_family_security_success(isolated_domain_token_service, isolated_user):
    """Test real production scenario for token validation with family security."""
    correlation_id = f"corr-{uuid.uuid4()}"
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id=correlation_id)
    
    # Step 1: Create token pair in production scenario
    creation_request = TokenCreationRequest(user=isolated_user, security_context=security_context, correlation_id=correlation_id, language="en")
    token_pair = await isolated_domain_token_service.create_token_pair_with_family_security(creation_request)
    
    # Step 2: Validate the access token in real production scenario
    payload = await isolated_domain_token_service.validate_token_with_family_security(
        access_token=token_pair.access_token,
        security_context=security_context,
        correlation_id=correlation_id
    )
    
    # Verify production-level token validation
    assert payload["sub"] == str(isolated_user.id)
    assert payload["family_id"] == token_pair.family_id
    assert "jti" in payload
    assert "exp" in payload
    assert "iat" in payload

@pytest.mark.asyncio
async def test_validate_token_with_family_security_invalid_token(isolated_domain_token_service, isolated_user):
    """Test production scenario with invalid access token - should fail with AuthenticationError."""
    correlation_id = f"corr-{uuid.uuid4()}"
    security_context = SecurityContext(client_ip="127.0.0.1", user_agent="pytest", request_timestamp=datetime.now(timezone.utc), correlation_id=correlation_id)
    
    # Test real production scenario with invalid token
    with pytest.raises(AuthenticationError):
        await isolated_domain_token_service.validate_token_with_family_security(
            access_token="invalid.token.value",
            security_context=security_context,
            correlation_id=correlation_id
        )