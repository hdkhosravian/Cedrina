# User Logout

Securely end user session and revoke all associated tokens.

## Endpoint

```http
POST /api/v1/auth/logout
```

## Request

### Headers
```http
Content-Type: application/json
Authorization: Bearer <access_token>
Accept-Language: en|es|ar|fa (optional)
```

### Authentication
- **Required**: Valid JWT access token in Authorization header
- **Format**: `Bearer <access_token>`

### Request Body
Empty JSON object:
```json
{}
```

## Response

### Success Response (200 OK)
```json
{
  "message": "Logged out successfully",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Error Responses

#### 401 Unauthorized - Missing Token
```json
{
  "detail": "Authorization header is missing"
}
```

#### 401 Unauthorized - Invalid Token
```json
{
  "detail": "Invalid token"
}
```

#### 401 Unauthorized - Expired Token
```json
{
  "detail": "Token has expired"
}
```

#### 401 Unauthorized - Malformed Token
```json
{
  "detail": "Invalid Authorization header format. Expected: Bearer <token>"
}
```

## Security Features

### Complete Session Revocation
- **Database Sessions**: All database sessions associated with the token are revoked
- **Token Family**: Entire token family is invalidated
- **Refresh Tokens**: All refresh tokens become unusable immediately
- **Access Tokens**: Current access token is blacklisted

### Token Family Security
- **JTI Tracking**: Uses JWT ID (JTI) to identify and revoke related tokens
- **Family Revocation**: All tokens in the same family are revoked simultaneously
- **Immediate Effect**: Revocation takes effect immediately across all services
- **No Grace Period**: No delay between logout and token invalidation

### Audit Logging
- **Security Events**: Logout events are logged for security monitoring
- **User Tracking**: User ID and session details logged
- **IP Address**: Client IP address recorded for security analysis
- **Timestamp**: Precise logout time for audit trails

## Implementation Details

### Logout Process
1. **Token Validation**: Verify access token is valid and not expired
2. **User Identification**: Extract user ID and JTI from token claims
3. **Session Revocation**: Mark database session as revoked with timestamp
4. **Token Family Invalidation**: Revoke entire token family for security
5. **Audit Logging**: Log successful logout event
6. **Response**: Return success message with timestamp

### Database Updates
```sql
-- Sessions table update
UPDATE sessions 
SET revoked_at = NOW(), 
    revoke_reason = 'Logout - Manual revocation'
WHERE jti = '<token_jti>' 
  AND user_id = <user_id>;

-- Token family revocation
UPDATE token_families 
SET status = 'revoked',
    revoked_at = NOW(),
    revoke_reason = 'Manual logout'
WHERE family_id = '<family_id>';
```

## Security Validation

### Post-Logout Token Validation
After logout, attempting to use any tokens from the session will fail:

#### Refresh Token Attempt (Will Fail)
```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer <revoked_access_token>" \
  -H "X-Refresh-Token: <revoked_refresh_token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:
```json
{
  "detail": "Session has been revoked"
}
```

#### Access Protected Resource (Will Fail)
```bash
curl -X GET "http://localhost:8000/api/v1/protected-resource" \
  -H "Authorization: Bearer <revoked_access_token>"
```

Response:
```json
{
  "detail": "Token has been revoked"
}
```

## Examples

### Basic Logout
```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json"
```

### Complete Login-Logout Flow
```bash
#!/bin/bash

# 1. Login to get tokens
echo "Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hdkhosravian",
    "password": "Str0ngP@ssw0rd1@3"
  }')

ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.tokens.access_token')
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.tokens.refresh_token')

echo "✅ Login successful"

# 2. Test refresh token works
echo "Testing refresh token..."
REFRESH_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Refresh-Token: $REFRESH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')

if [ $(echo $REFRESH_RESPONSE | jq -r '.access_token' | wc -c) -gt 50 ]; then
  echo "✅ Refresh token works before logout"
  NEW_ACCESS_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.access_token')
  NEW_REFRESH_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.refresh_token')
else
  echo "❌ Refresh token failed before logout"
  exit 1
fi

# 3. Logout
echo "Logging out..."
LOGOUT_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  -H "Content-Type: application/json")

echo "✅ Logout: $(echo $LOGOUT_RESPONSE | jq -r '.message')"

# 4. Test refresh token fails after logout
echo "Testing refresh token after logout..."
REFRESH_AFTER_LOGOUT=$(curl -s -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  -H "X-Refresh-Token: $NEW_REFRESH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')

if [ "$(echo $REFRESH_AFTER_LOGOUT | jq -r '.detail')" = "Session has been revoked" ]; then
  echo "✅ SECURITY CONFIRMED: Refresh token blocked after logout"
else
  echo "❌ SECURITY ISSUE: Refresh token still works after logout!"
  echo "Response: $REFRESH_AFTER_LOGOUT"
fi
```

### Logout with Language Preference
```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer <access_token>" \
  -H "Accept-Language: es" \
  -H "Content-Type: application/json"
```

Response (Spanish):
```json
{
  "message": "Sesión cerrada exitosamente",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## Testing

### Successful Logout Test
```python
async def test_user_logout_success():
    """Test successful user logout."""
    # Login first
    login_data = {
        "username": "test_user",
        "password": "SecurePass123!"
    }
    
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    access_token = login_response.json()["tokens"]["access_token"]
    
    # Logout
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.post("/api/v1/auth/logout", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "timestamp" in data
    assert "successfully" in data["message"].lower()
```

### Token Revocation Verification Test
```python
async def test_logout_revokes_tokens():
    """Test that logout properly revokes all tokens."""
    # Login and get tokens
    login_data = {
        "username": "test_user",
        "password": "SecurePass123!"
    }
    
    login_response = await client.post("/api/v1/auth/login", json=login_data)
    tokens = login_response.json()["tokens"]
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    
    # Logout
    headers = {"Authorization": f"Bearer {access_token}"}
    await client.post("/api/v1/auth/logout", headers=headers)
    
    # Try to refresh tokens - should fail
    refresh_headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Refresh-Token": refresh_token
    }
    
    response = await client.post("/api/v1/auth/refresh", headers=refresh_headers, json={})
    
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"].lower()
```

### Invalid Token Test
```python
async def test_logout_invalid_token():
    """Test logout with invalid token."""
    headers = {"Authorization": "Bearer invalid_token"}
    response = await client.post("/api/v1/auth/logout", headers=headers)
    
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()
```

### Missing Authorization Test
```python
async def test_logout_missing_authorization():
    """Test logout without authorization header."""
    response = await client.post("/api/v1/auth/logout")
    
    assert response.status_code == 401
    assert "authorization" in response.json()["detail"].lower()
```

## Security Considerations

### Immediate Revocation
- **Database Consistency**: All session records updated atomically
- **No Race Conditions**: Session revocation is immediate and consistent
- **Cross-Service**: Revocation affects all services using the same session store

### Token Security
- **No Token Storage**: Tokens are not stored server-side (only session hashes)
- **Family Revocation**: All related tokens invalidated simultaneously
- **Blacklist Avoidance**: Uses session-based validation instead of token blacklists

### Audit and Monitoring
- **Security Logs**: All logout events logged with full context
- **Suspicious Activity**: Multiple rapid logouts may indicate compromise
- **Session Tracking**: Session duration and activity patterns monitored

## Troubleshooting

### Common Issues

**401 Unauthorized: "Authorization header is missing"**
- Ensure Authorization header is included in request
- Check header format: `Authorization: Bearer <token>`

**401 Unauthorized: "Invalid token"**
- Token may be expired or malformed
- Get new tokens via login
- Check token format and encoding

**401 Unauthorized: "Token has expired"**
- Access token has exceeded its lifetime (15 minutes default)
- Use refresh token to get new access token
- If refresh token also expired, re-authenticate

### Debug Tips

1. **Verify token format**: Ensure proper Bearer token format
2. **Check token expiration**: Decode JWT to check exp claim
3. **Test with curl**: Use curl to isolate client issues
4. **Review logs**: Check application logs for detailed error messages
5. **Validate headers**: Ensure all required headers are present

### Best Practices

- **Logout on app close**: Always logout when application closes
- **Automatic logout**: Implement automatic logout on inactivity
- **Secure storage**: Clear tokens from client storage after logout
- **Error handling**: Handle logout failures gracefully
- **User feedback**: Provide clear logout confirmation to users

## Related Endpoints

- **[User Login](login.md)** - Authenticate and get tokens
- **[Token Refresh](refresh-token.md)** - Refresh expired tokens (will fail after logout)
- **[Change Password](change-password.md)** - Change password (requires authentication)

## Configuration

### Session Settings
```bash
# Session management
SESSION_EXPIRE_DAYS=7
SESSION_CLEANUP_INTERVAL_HOURS=24

# Token settings
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Security settings
LOGOUT_REVOKE_ALL_SESSIONS=true
LOGOUT_AUDIT_LOGGING=true
```