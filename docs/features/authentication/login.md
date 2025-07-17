# User Login

Authenticate a user and receive JWT tokens for API access.

## Endpoint

```http
POST /api/v1/auth/login
```

## Request

### Headers
```http
Content-Type: application/json
Accept-Language: en|es|ar|fa (optional)
```

### Request Body
```json
{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

### Field Specifications

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `username` | string | ✅ | 3-50 chars, alphanumeric + `_-` | Username or email address |
| `password` | string | ✅ | User's current password | Account password |

### Authentication Methods
- **Username + Password**: Standard authentication
- **Email + Password**: Can use email address as username
- **Case-Insensitive**: Username matching is case-insensitive

## Response

### Success Response (200 OK)
```json
{
  "user": {
    "id": 123,
    "username": "john_doe",
    "email": "john@example.com",
    "full_name": "John Doe",
    "is_active": true,
    "created_at": "2025-01-15T10:30:00Z",
    "updated_at": "2025-01-15T11:45:00Z",
    "roles": ["user"]
  },
  "tokens": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

### Token Details
- **Access Token**: Used for API authentication (15 minutes default)
- **Refresh Token**: Used to obtain new access tokens (7 days default)
- **Token Type**: Always "Bearer"
- **Expires In**: Access token lifetime in seconds

### Error Responses

#### 401 Unauthorized - Invalid Credentials
```json
{
  "detail": "Invalid username or password"
}
```

#### 401 Unauthorized - Account Not Confirmed
```json
{
  "detail": "Please confirm your email address before logging in"
}
```

#### 401 Unauthorized - Account Inactive
```json
{
  "detail": "Account has been deactivated"
}
```

#### 422 Unprocessable Entity - Missing Fields
```json
{
  "detail": "Username and password are required"
}
```

#### 422 Unprocessable Entity - Invalid Username
```json
{
  "detail": "Username contains invalid characters"
}
```

#### 429 Too Many Requests - Rate Limit
```json
{
  "detail": "Too many login attempts. Try again in 60 seconds."
}
```

## Rate Limiting

### Login Protection
- **Limit**: 5 login attempts per minute per IP address
- **Window**: 1 minute
- **Brute Force Protection**: Progressive delays after failed attempts
- **Account Lockout**: Temporary lockout after multiple failures

### Headers
```http
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 2
X-RateLimit-Reset: 1642234567
```

## Security Features

### Authentication Security
- **Constant-Time Comparison**: Prevents timing attacks using `hmac.compare_digest`
- **Password Hashing**: bcrypt with configurable rounds
- **Session Management**: Database-only session tracking
- **Token Security**: RS256 JWT signing with asymmetric keys

### Brute Force Protection
- **Progressive Delays**: Increasing delays after failed attempts
- **IP-Based Limiting**: Rate limits per IP address
- **Account Protection**: Temporary lockouts for suspicious activity
- **Audit Logging**: All login attempts logged with security context

### Input Validation
- **SQL Injection Prevention**: Parameterized queries
- **Username Sanitization**: Character validation and filtering
- **Length Validation**: Prevents buffer overflow attacks
- **Encoding Validation**: UTF-8 validation for international characters

## JWT Token Structure

### Access Token Claims
```json
{
  "sub": "123",
  "username": "john_doe",
  "email": "john@example.com",
  "role": "user",
  "iss": "https://api.cedrina.com",
  "aud": "cedrina:api:v1",
  "exp": 1642234567,
  "iat": 1642233667,
  "jti": "token_family_id",
  "family_id": "family_uuid"
}
```

### Refresh Token Claims
```json
{
  "sub": "123",
  "iss": "https://api.cedrina.com",
  "aud": "cedrina:api:v1",
  "exp": 1642838467,
  "iat": 1642233667,
  "jti": "token_family_id",
  "family_id": "family_uuid"
}
```

### Token Security Features
- **JTI Matching**: Access and refresh tokens share the same JTI
- **Token Family**: All tokens belong to a security family
- **Rotation**: New tokens issued on refresh
- **Revocation**: Immediate invalidation on logout

## Examples

### Basic Login
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePass123!"
  }'
```

### Login with Email
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### Login with Language Preference
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -H "Accept-Language: es" \
  -d '{
    "username": "juan",
    "password": "MiPassword123!"
  }'
```

### Using Access Token
```bash
curl -X GET "http://localhost:8000/api/v1/protected-endpoint" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Complete Authentication Flow

```bash
#!/bin/bash

# 1. Login and capture tokens
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hdkhosravian",
    "password": "Str0ngP@ssw0rd1@3"
  }')

# 2. Extract tokens
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.tokens.access_token')
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.tokens.refresh_token')

echo "Login successful! Tokens obtained."

# 3. Use access token
curl -X GET "http://localhost:8000/api/v1/protected-resource" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# 4. Refresh tokens when needed
REFRESH_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Refresh-Token: $REFRESH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')

# 5. Extract new tokens
NEW_ACCESS_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.access_token')
NEW_REFRESH_TOKEN=$(echo $REFRESH_RESPONSE | jq -r '.refresh_token')

echo "Tokens refreshed successfully!"

# 6. Logout when done
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN"

echo "Logged out successfully!"
```

## Testing

### Successful Login Test
```python
async def test_user_login_success():
    """Test successful user login."""
    # First create a user
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "SecurePass123!"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Then login
    login_data = {
        "username": user_data["username"],
        "password": user_data["password"]
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    
    assert response.status_code == 200
    data = response.json()
    assert "user" in data
    assert "tokens" in data
    assert data["tokens"]["token_type"] == "Bearer"
    assert "access_token" in data["tokens"]
    assert "refresh_token" in data["tokens"]
```

### Invalid Credentials Test
```python
async def test_login_invalid_credentials():
    """Test login with invalid credentials."""
    login_data = {
        "username": "nonexistent_user",
        "password": "wrong_password"
    }
    
    response = await client.post("/api/v1/auth/login", json=login_data)
    
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()
```

### Rate Limiting Test
```python
async def test_login_rate_limiting():
    """Test login rate limiting protection."""
    login_data = {
        "username": "test_user",
        "password": "wrong_password"
    }
    
    # Make multiple failed attempts
    for _ in range(6):  # Exceed 5 attempt limit
        response = await client.post("/api/v1/auth/login", json=login_data)
    
    assert response.status_code == 429
    assert "rate limit" in response.json()["detail"].lower()
```

### Security Validation Test
```python
async def test_login_security_validation():
    """Test login input security validation."""
    # Test SQL injection attempt
    sql_injection_data = {
        "username": "'; DROP TABLE users; --",
        "password": "password"
    }
    
    response = await client.post("/api/v1/auth/login", json=sql_injection_data)
    
    # Should be handled gracefully, not cause server error
    assert response.status_code in [401, 422]
    
    # Test XSS attempt
    xss_data = {
        "username": "<script>alert('xss')</script>",
        "password": "password"
    }
    
    response = await client.post("/api/v1/auth/login", json=xss_data)
    assert response.status_code in [401, 422]
```

## Troubleshooting

### Common Issues

**401 Unauthorized: "Invalid username or password"**
- Verify credentials are correct
- Check if username exists in the system
- Ensure password hasn't been changed
- Try using email address instead of username

**401 Unauthorized: "Please confirm your email address"**
- Check email inbox for confirmation link
- Use resend confirmation endpoint if needed
- Contact support if email not received

**429 Rate Limit Exceeded**
- Wait for rate limit window to reset
- Check `X-RateLimit-Reset` header for reset time
- Implement exponential backoff in client applications

**422 Validation Error: "Username contains invalid characters"**
- Remove spaces from username
- Use only letters, numbers, underscores, and hyphens
- Try using email address instead

### Debug Tips

1. **Check account status**: Verify account is active and confirmed
2. **Test credentials**: Try logging in via web interface
3. **Review logs**: Check application logs for detailed error messages
4. **Verify rate limits**: Check if rate limiting is blocking requests
5. **Test with curl**: Use curl commands to isolate client issues

### Security Considerations

- **Never log passwords**: Passwords are never stored in logs
- **Use HTTPS**: Always use HTTPS in production
- **Secure storage**: Store tokens securely on client side
- **Token expiration**: Handle token expiration gracefully
- **Logout on suspicious activity**: Implement logout on security violations

## Related Endpoints

- **[User Registration](registration.md)** - Create new account
- **[Token Refresh](refresh-token.md)** - Refresh expired tokens
- **[User Logout](logout.md)** - End session and revoke tokens
- **[Change Password](change-password.md)** - Update account password
- **[Forgot Password](forgot-password.md)** - Reset forgotten password