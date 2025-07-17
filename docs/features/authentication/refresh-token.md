# Token Refresh

Securely refresh JWT tokens using advanced token family security patterns.

## Endpoint

```http
POST /api/v1/auth/refresh
```

## Request

### Headers
```http
Content-Type: application/json
Authorization: Bearer <access_token>
X-Refresh-Token: <refresh_token>
Accept-Language: en|es|ar|fa (optional)
```

### Required Headers

| Header | Format | Description |
|--------|--------|-------------|
| `Authorization` | `Bearer <access_token>` | Current access token (may be expired) |
| `X-Refresh-Token` | `<refresh_token>` | Valid refresh token |
| `Content-Type` | `application/json` | Required content type |

### Request Body
Empty JSON object:
```json
{}
```

### Security Requirements
- **Token Pairing**: Access and refresh tokens must belong to the same session (matching JTI)
- **Session Validation**: Database session must exist and not be revoked
- **Token Family**: Both tokens must belong to the same token family
- **Expiration Check**: Refresh token must not be expired

## Response

### Success Response (200 OK)
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

### Token Response Details
- **New Access Token**: Fresh access token with 15-minute expiration
- **New Refresh Token**: Fresh refresh token with 7-day expiration
- **Token Type**: Always "bearer"
- **Expires In**: Access token lifetime in seconds (900 = 15 minutes)

### Error Responses

#### 401 Unauthorized - Invalid Access Token
```json
{
  "detail": "Invalid token"
}
```

#### 401 Unauthorized - JTI Mismatch
```json
{
  "detail": "Token pair security violation detected"
}
```

#### 401 Unauthorized - Session Revoked
```json
{
  "detail": "Session has been revoked"
}
```

#### 401 Unauthorized - Expired Refresh Token
```json
{
  "detail": "Refresh token has expired"
}
```

#### 401 Unauthorized - Cross-User Attack
```json
{
  "detail": "Security violation: token ownership mismatch"
}
```

#### 422 Unprocessable Entity - Missing Headers
```json
{
  "detail": "Authorization header is missing"
}
```

#### 422 Unprocessable Entity - Invalid Token Format
```json
{
  "detail": "Invalid Authorization header format. Expected: Bearer <token>"
}
```

#### 429 Too Many Requests - Rate Limit
```json
{
  "detail": "Refresh rate limit exceeded. Try again in 45 seconds."
}
```

## Security Features

### Token Family Security
- **JTI Matching**: Access and refresh tokens must have identical JTI claims
- **Family Validation**: Both tokens must belong to the same token family
- **Concurrent Protection**: Prevents concurrent refresh attacks
- **Reuse Detection**: Detects and prevents token reuse attacks

### Session Validation
- **Database Sessions**: Validates session exists and is active
- **Session Tracking**: Updates last activity timestamp
- **Revocation Check**: Ensures session hasn't been revoked via logout
- **User Validation**: Confirms user account is still active

### Security Violations
The system detects and responds to various security violations:

#### JTI Mismatch
```json
{
  "violation": "jti_mismatch",
  "description": "Access and refresh tokens have different JTI values",
  "action": "Both tokens revoked immediately",
  "security_impact": "High - Possible token theft"
}
```

#### Cross-User Attack
```json
{
  "violation": "cross_user_attack", 
  "description": "Tokens belong to different users",
  "action": "All user sessions revoked",
  "security_impact": "Critical - Account compromise"
}
```

#### Token Reuse
```json
{
  "violation": "token_reuse",
  "description": "Refresh token used multiple times",
  "action": "Token family revoked",
  "security_impact": "High - Replay attack"
}
```

## Rate Limiting

### Refresh Protection
- **Limit**: 10 refresh attempts per minute per IP
- **Window**: 1 minute rolling window
- **Family Tracking**: Additional limits per token family
- **Abuse Prevention**: Progressive delays for suspicious activity

### Headers
```http
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1642234567
```

## Examples

### Basic Token Refresh
```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Refresh-Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Complete Authentication Flow with Refresh
```bash
#!/bin/bash

# 1. Login to get initial tokens
echo "🔑 Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hdkhosravian",
    "password": "Str0ngP@ssw0rd1@3"
  }')

ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.tokens.access_token')
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.tokens.refresh_token')

echo "✅ Login successful, tokens obtained"

# 2. Wait for access token to near expiration (optional for demo)
echo "⏱️  Simulating token usage..."

# 3. Refresh tokens
echo "🔄 Refreshing tokens..."
REFRESH_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Refresh-Token: $REFRESH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')

if [ $(echo $REFRESH_RESPONSE | jq -r '.access_token' | wc -c) -gt 50 ]; then
  NEW_ACCESS_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.access_token')
  NEW_REFRESH_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.refresh_token')
  echo "✅ Tokens refreshed successfully"
else
  echo "❌ Token refresh failed:"
  echo $REFRESH_RESPONSE | jq
  exit 1
fi

# 4. Use new access token
echo "🛡️  Using new access token..."
curl -s -X GET "http://localhost:8000/api/v1/protected-resource" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" > /dev/null

echo "✅ Protected resource accessed with new token"

# 5. Logout to revoke all tokens
echo "🚪 Logging out..."
LOGOUT_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN")

echo "✅ Logout: $(echo $LOGOUT_RESPONSE | jq -r '.message')"

# 6. Verify tokens are revoked
echo "🔒 Verifying token revocation..."
REVOKED_TEST=$(curl -s -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  -H "X-Refresh-Token: $NEW_REFRESH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')

if [ "$(echo $REVOKED_TEST | jq -r '.detail')" = "Session has been revoked" ]; then
  echo "✅ SECURITY CONFIRMED: Tokens properly revoked after logout"
else
  echo "❌ SECURITY ISSUE: Tokens still working after logout!"
fi
```

### Security Violation Testing
```bash
# Test JTI mismatch (will fail)
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer <token_from_user_1>" \
  -H "X-Refresh-Token: <token_from_user_2>" \
  -H "Content-Type: application/json" \
  -d '{}'

# Expected response:
# {"detail": "Token pair security violation detected"}
```

### Automated Token Management
```bash
#!/bin/bash

# Function to refresh tokens automatically
refresh_tokens() {
  local current_access="$1"
  local current_refresh="$2"
  
  local response=$(curl -s -X POST "http://localhost:8000/api/v1/auth/refresh" \
    -H "Authorization: Bearer $current_access" \
    -H "X-Refresh-Token: $current_refresh" \
    -H "Content-Type: application/json" \
    -d '{}')
  
  if [ $(echo $response | jq -r '.access_token' | wc -c) -gt 50 ]; then
    echo "NEW_ACCESS=$(echo $response | jq -r '.access_token')"
    echo "NEW_REFRESH=$(echo $response | jq -r '.refresh_token')"
    return 0
  else
    echo "REFRESH_ERROR=$(echo $response | jq -r '.detail')"
    return 1
  fi
}

# Usage example
if refresh_result=$(refresh_tokens "$ACCESS_TOKEN" "$REFRESH_TOKEN"); then
  eval $refresh_result
  echo "Tokens refreshed: $NEW_ACCESS"
else
  eval $refresh_result
  echo "Refresh failed: $REFRESH_ERROR"
fi
```

## Testing

### Successful Refresh Test
```python
async def test_token_refresh_success():
    """Test successful token refresh."""
    # Login first
    login_data = {
        "username": "test_user",
        "password": "SecurePass123!"
    }
    
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    tokens = login_response.json()["tokens"]
    
    # Refresh tokens
    headers = {
        "Authorization": f"Bearer {tokens['access_token']}",
        "X-Refresh-Token": tokens["refresh_token"]
    }
    
    response = await client.post("/api/v1/auth/refresh", headers=headers, json={})
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900
```

### JTI Mismatch Security Test
```python
async def test_refresh_jti_mismatch_security():
    """Test JTI mismatch security violation."""
    # Create two different sessions
    user1_tokens = await login_user("user1")
    user2_tokens = await login_user("user2")
    
    # Try to mix tokens from different sessions
    headers = {
        "Authorization": f"Bearer {user1_tokens['access_token']}",
        "X-Refresh-Token": user2_tokens["refresh_token"]
    }
    
    response = await client.post("/api/v1/auth/refresh", headers=headers, json={})
    
    assert response.status_code == 401
    assert "security violation" in response.json()["detail"].lower()
```

### Session Revocation Test
```python
async def test_refresh_after_logout():
    """Test refresh fails after logout."""
    # Login and get tokens
    tokens = await login_user("test_user")
    
    # Logout to revoke session
    await client.post("/api/v1/auth/logout", 
                     headers={"Authorization": f"Bearer {tokens['access_token']}"})
    
    # Try to refresh tokens - should fail
    headers = {
        "Authorization": f"Bearer {tokens['access_token']}",
        "X-Refresh-Token": tokens["refresh_token"]
    }
    
    response = await client.post("/api/v1/auth/refresh", headers=headers, json={})
    
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"].lower()
```

### Rate Limiting Test
```python
async def test_refresh_rate_limiting():
    """Test refresh rate limiting."""
    tokens = await login_user("test_user")
    
    headers = {
        "Authorization": f"Bearer {tokens['access_token']}",
        "X-Refresh-Token": tokens["refresh_token"]
    }
    
    # Make multiple rapid refresh attempts
    for _ in range(11):  # Exceed 10 per minute limit
        response = await client.post("/api/v1/auth/refresh", headers=headers, json={})
        if response.status_code != 200:
            break
    
    assert response.status_code == 429
    assert "rate limit" in response.json()["detail"].lower()
```

## JWT Token Structure

### Token Claims Comparison
```python
# Access Token Claims
{
  "sub": "123",                    # User ID
  "username": "john_doe",          # Username
  "email": "john@example.com",     # Email
  "role": "user",                  # User role
  "iss": "https://api.cedrina.com", # Issuer
  "aud": "cedrina:api:v1",         # Audience
  "exp": 1642234567,               # Expiration (15 min)
  "iat": 1642233667,               # Issued at
  "jti": "family_abc123",          # JWT ID (matches refresh)
  "family_id": "fam_def456"        # Token family ID
}

# Refresh Token Claims
{
  "sub": "123",                    # User ID (same)
  "iss": "https://api.cedrina.com", # Issuer (same)
  "aud": "cedrina:api:v1",         # Audience (same)
  "exp": 1642838467,               # Expiration (7 days)
  "iat": 1642233667,               # Issued at (same)
  "jti": "family_abc123",          # JWT ID (MUST match access)
  "family_id": "fam_def456"        # Token family ID (same)
}
```

### Security Validation Flow
```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant D as Database
    
    C->>A: POST /auth/refresh
    Note over C,A: Headers: Authorization & X-Refresh-Token
    
    A->>A: Validate JWT format
    A->>A: Decode access token (ignore expiration)
    A->>A: Validate refresh token
    A->>A: Check JTI match
    A->>A: Check user ID match
    
    A->>D: Query session by JTI
    D-->>A: Session details
    
    alt Session not found
        A-->>C: 401 - Session not found
    else Session revoked
        A-->>C: 401 - Session revoked
    else Valid session
        A->>A: Generate new token pair
        A->>D: Update session activity
        D-->>A: Updated
        A-->>C: 200 - New tokens
    end
```

## Troubleshooting

### Common Issues

**401 Unauthorized: "Token pair security violation detected"**
- Ensure access and refresh tokens are from the same login session
- Don't mix tokens from different users or sessions
- Tokens must have matching JTI values

**401 Unauthorized: "Session has been revoked"**
- User has logged out - all tokens are permanently invalid
- Re-authenticate to get new tokens
- Check if logout was triggered by security violation

**422 Unprocessable Entity: "Authorization header is missing"**
- Include Authorization header: `Authorization: Bearer <token>`
- Include X-Refresh-Token header: `X-Refresh-Token: <token>`
- Ensure both headers are present

**429 Rate Limit Exceeded**
- Wait for rate limit window to reset (check X-RateLimit-Reset header)
- Implement exponential backoff
- Don't refresh tokens unnecessarily

### Debug Tips

1. **Decode JWT tokens**: Use jwt.io to inspect token claims
2. **Check JTI values**: Ensure access and refresh tokens have matching JTI
3. **Verify expiration**: Check exp claims in both tokens
4. **Test headers**: Verify all required headers are present
5. **Check session status**: Look for logout events in audit logs

### Best Practices

- **Automatic refresh**: Refresh tokens before access token expires
- **Error handling**: Handle refresh failures gracefully
- **Secure storage**: Store tokens securely on client side
- **Token rotation**: Always use new tokens from refresh response
- **Logout on violation**: Logout immediately on security violations

## Related Endpoints

- **[User Login](login.md)** - Get initial tokens
- **[User Logout](logout.md)** - Revoke all tokens (makes refresh impossible)
- **[Change Password](change-password.md)** - Password change may invalidate sessions

## Configuration

### Token Settings
```bash
# Access token configuration
ACCESS_TOKEN_EXPIRE_MINUTES=15
ACCESS_TOKEN_ALGORITHM=RS256

# Refresh token configuration  
REFRESH_TOKEN_EXPIRE_DAYS=7
REFRESH_TOKEN_ROTATION=true

# Security settings
TOKEN_FAMILY_SECURITY=true
JTI_VALIDATION=strict
SESSION_VALIDATION=required

# Rate limiting
REFRESH_RATE_LIMIT="10/minute"
REFRESH_RATE_LIMIT_STORAGE="memory://"
```