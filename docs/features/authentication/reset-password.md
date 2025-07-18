# Reset Password

Complete password reset using secure token received via email.

## Endpoint

```http
POST /api/v1/auth/reset-password
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
  "token": "a1b2c3d4e5f6789abc123def456789abcdef0123456789abcdef0123456789ab",
  "new_password": "NewSecurePassword123!"
}
```

### Field Specifications

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `token` | string | ✅ | 8-64 chars, hex format | Password reset token from email |
| `new_password` | string | ✅ | See password policy | New password meeting security requirements |

### Password Policy
New password must meet these requirements:
- **Minimum length**: 8 characters
- **Uppercase letter**: At least 1 (A-Z)
- **Lowercase letter**: At least 1 (a-z)
- **Digit**: At least 1 (0-9)
- **Special character**: At least 1 (!@#$%^&*)

## Response

### Success Response (200 OK)
```json
{
  "message": "Password reset successfully",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Error Responses

#### 400 Bad Request - Invalid Token
```json
{
  "detail": "Invalid or expired reset token"
}
```

#### 400 Bad Request - Token Already Used
```json
{
  "detail": "Reset token has already been used"
}
```

#### 401 Unauthorized - Expired Token
```json
{
  "detail": "Reset token has expired"
}
```

#### 404 Not Found - Token Not Found
```json
{
  "detail": "Reset token not found"
}
```

#### 422 Unprocessable Entity - Invalid Password
```json
{
  "detail": "Password must contain at least one uppercase letter"
}
```

#### 422 Unprocessable Entity - Invalid Token Format
```json
{
  "detail": "Invalid token format"
}
```

#### 429 Too Many Requests - Rate Limit
```json
{
  "detail": "Password reset rate limit exceeded. Try again in 30 minutes."
}
```

## Security Features

### Token Validation
- **Format Verification**: Validates token format and length
- **Hash Verification**: Compares against hashed token in database
- **Expiration Check**: Ensures token hasn't expired (24 hours default)
- **Single Use**: Token becomes invalid after successful use
- **User Association**: Verifies token belongs to valid user account

### Password Security
- **Strength Validation**: Enforces comprehensive password policy
- **Hash Generation**: Uses bcrypt with configurable rounds
- **Immediate Effect**: Password change takes effect immediately
- **Session Invalidation**: All existing sessions remain valid (by design)

### Abuse Prevention
- **Rate Limiting**: 5 reset attempts per hour per IP
- **Token Cleanup**: Expired tokens automatically removed
- **Audit Logging**: All reset attempts logged with full context
- **IP Tracking**: Client IP addresses logged for security analysis

### Input Validation
- **Token Format**: Validates hex format and length constraints
- **SQL Injection**: Parameterized queries prevent injection
- **XSS Prevention**: Input sanitization and validation
- **Length Validation**: Prevents buffer overflow attacks

## Rate Limiting

### Protection Limits
- **Requests**: 5 password reset attempts per hour
- **Scope**: Per IP address
- **Window**: 1 hour rolling window
- **Recovery**: Full recovery after window expires

### Headers
```http
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1642234567
```

## Examples

### Basic Password Reset
```bash
curl -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "a1b2c3d4e5f6789abc123def456789abcdef0123456789abcdef0123456789ab",
    "new_password": "NewSecurePassword123!"
  }'
```

### Complete Password Recovery Flow
```bash
#!/bin/bash

echo "🔄 Complete Password Recovery Flow"

# Step 1: Request password reset
echo "1️⃣ Requesting password reset..."
FORGOT_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }')

echo "✅ $(echo $FORGOT_RESPONSE | jq -r '.message')"

# Step 2: Simulate receiving token via email
# In real scenario, user gets this from email link
echo "2️⃣ User receives reset token via email..."
RESET_TOKEN="example_secure_token_from_email"
echo "Token received: ${RESET_TOKEN:0:20}..."

# Step 3: Reset password with token
echo "3️⃣ Resetting password..."
RESET_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"$RESET_TOKEN\",
    \"new_password\": \"NewSecurePassword123!\"
  }")

if [ "$(echo $RESET_RESPONSE | jq -r '.message')" != "null" ]; then
  echo "✅ $(echo $RESET_RESPONSE | jq -r '.message')"
else
  echo "❌ Password reset failed:"
  echo $RESET_RESPONSE | jq
  exit 1
fi

# Step 4: Verify old password no longer works
echo "4️⃣ Testing old password (should fail)..."
OLD_LOGIN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john@example.com",
    "password": "OldPassword123!"
  }')

if [ "$(echo $OLD_LOGIN | jq -r '.detail')" != "null" ]; then
  echo "✅ Old password correctly rejected"
else
  echo "❌ Security issue: Old password still works!"
fi

# Step 5: Verify new password works
echo "5️⃣ Testing new password (should work)..."
NEW_LOGIN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john@example.com",
    "password": "NewSecurePassword123!"
  }')

if [ "$(echo $NEW_LOGIN | jq -r '.tokens.access_token')" != "null" ]; then
  echo "✅ New password login successful"
  echo "🎉 Password recovery flow completed successfully!"
else
  echo "❌ New password login failed"
fi
```

### Password Reset with Language Preference
```bash
curl -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -H "Accept-Language: es" \
  -d '{
    "token": "a1b2c3d4e5f6...",
    "new_password": "NuevaContraseña123!"
  }'
```

Response (Spanish):
```json
{
  "message": "Contraseña restablecida exitosamente",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Token Reuse Prevention Test
```bash
#!/bin/bash

RESET_TOKEN="example_token"
NEW_PASSWORD="SecurePassword123!"

echo "🔒 Testing token reuse prevention..."

# First use - should succeed
echo "1️⃣ First password reset attempt..."
FIRST_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"$RESET_TOKEN\",
    \"new_password\": \"$NEW_PASSWORD\"
  }")

echo "First attempt: $(echo $FIRST_RESPONSE | jq -r '.message // .detail')"

# Second use - should fail
echo "2️⃣ Second password reset attempt (token reuse)..."
SECOND_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"$RESET_TOKEN\",
    \"new_password\": \"AnotherPassword456!\"
  }")

if [ "$(echo $SECOND_RESPONSE | jq -r '.detail')" != "null" ]; then
  echo "✅ Token reuse correctly prevented: $(echo $SECOND_RESPONSE | jq -r '.detail')"
else
  echo "❌ Security issue: Token was reused!"
fi
```

## Testing

### Successful Password Reset Test
```python
async def test_reset_password_success():
    """Test successful password reset."""
    # Create user and request reset
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "OriginalPass123!"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    await client.post("/api/v1/auth/forgot-password", 
                     json={"email": user_data["email"]})
    
    # Get reset token from database (in real scenario, from email)
    reset_token = await get_latest_reset_token(user_data["email"])
    
    # Reset password
    reset_data = {
        "token": reset_token,
        "new_password": "NewPassword123!"
    }
    
    response = await client.post("/api/v1/auth/reset-password", json=reset_data)
    
    assert response.status_code == 200
    assert "successfully" in response.json()["message"].lower()
    
    # Verify new password works
    login_response = await client.post("/api/v1/auth/login", json={
        "username": user_data["username"],
        "password": "NewPassword123!"
    })
    
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()["tokens"]
```

### Invalid Token Test
```python
async def test_reset_password_invalid_token():
    """Test password reset with invalid token."""
    reset_data = {
        "token": "invalid_token_123",
        "new_password": "NewPassword123!"
    }
    
    response = await client.post("/api/v1/auth/reset-password", json=reset_data)
    
    assert response.status_code in [400, 404]
    assert "invalid" in response.json()["detail"].lower() or \
           "not found" in response.json()["detail"].lower()
```

### Expired Token Test
```python
async def test_reset_password_expired_token():
    """Test password reset with expired token."""
    # Create user and reset token
    user_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    expired_token = await create_expired_reset_token(user_email)
    
    reset_data = {
        "token": expired_token,
        "new_password": "NewPassword123!"
    }
    
    response = await client.post("/api/v1/auth/reset-password", json=reset_data)
    
    assert response.status_code in [400, 401]
    assert "expired" in response.json()["detail"].lower()
```

### Token Reuse Prevention Test
```python
async def test_reset_password_token_reuse_prevention():
    """Test that tokens cannot be reused."""
    # Setup user and get reset token
    user_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    reset_token = await setup_password_reset(user_email)
    
    # First use - should succeed
    reset_data = {
        "token": reset_token,
        "new_password": "FirstPassword123!"
    }
    
    first_response = await client.post("/api/v1/auth/reset-password", 
                                     json=reset_data)
    assert first_response.status_code == 200
    
    # Second use - should fail
    reset_data["new_password"] = "SecondPassword456!"
    second_response = await client.post("/api/v1/auth/reset-password",
                                      json=reset_data)
    
    assert second_response.status_code == 400
    assert "used" in second_response.json()["detail"].lower()
```

### Password Policy Test
```python
async def test_reset_password_weak_password():
    """Test password policy enforcement during reset."""
    reset_token = await setup_password_reset("test@example.com")
    
    weak_passwords = [
        "weak",                    # Too short
        "alllowercase123",         # No uppercase
        "ALLUPPERCASE123",         # No lowercase
        "NoNumbers!@#",            # No digits
        "NoSpecialChars123",       # No special characters
    ]
    
    for weak_password in weak_passwords:
        reset_data = {
            "token": reset_token,
            "new_password": weak_password
        }
        
        response = await client.post("/api/v1/auth/reset-password", 
                                   json=reset_data)
        
        assert response.status_code == 422
        assert "password" in response.json()["detail"].lower()
```

### Rate Limiting Test
```python
async def test_reset_password_rate_limiting():
    """Test reset password rate limiting."""
    reset_data = {
        "token": "fake_token",
        "new_password": "Password123!"
    }
    
    # Make requests up to rate limit
    for i in range(6):
        response = await client.post("/api/v1/auth/reset-password",
                                   json=reset_data)
        
        if i < 5:  # First 5 attempts
            assert response.status_code in [400, 404]  # Invalid token
        else:  # 6th attempt should be rate limited
            assert response.status_code == 429
            assert "rate limit" in response.json()["detail"].lower()
```

## Token Management

### Token Lifecycle
1. **Generation**: Created during forgot password request
2. **Storage**: Hashed and stored in database with expiration
3. **Validation**: Verified against database hash
4. **Usage**: Single use only, marked as used
5. **Cleanup**: Expired tokens automatically removed

### Database Schema
```sql
CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    ip_address INET,
    user_agent TEXT,
    
    CONSTRAINT chk_expires_future CHECK (expires_at > created_at)
);

-- Indexes for performance
CREATE INDEX idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_expires ON password_reset_tokens(expires_at);
CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens(user_id);
```

### Token Validation Process
```python
async def validate_reset_token(token: str) -> dict:
    """
    Validate password reset token.
    
    Returns:
        dict: Validation result with user info or error
    """
    # Hash the provided token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Query database
    result = await db.execute(
        "SELECT user_id, expires_at, used_at FROM password_reset_tokens "
        "WHERE token_hash = %s",
        (token_hash,)
    )
    
    token_record = result.fetchone()
    
    if not token_record:
        return {"error": "Token not found", "code": 404}
    
    user_id, expires_at, used_at = token_record
    
    # Check if already used
    if used_at:
        return {"error": "Token already used", "code": 400}
    
    # Check expiration
    if datetime.utcnow() > expires_at:
        return {"error": "Token expired", "code": 401}
    
    return {"user_id": user_id, "valid": True}
```

### Token Cleanup
```python
async def cleanup_expired_tokens():
    """Remove expired password reset tokens."""
    await db.execute(
        "DELETE FROM password_reset_tokens "
        "WHERE expires_at < NOW() OR used_at IS NOT NULL"
    )
```

## Security Considerations

### Token Security
- **Hash Storage**: Only hashed tokens stored in database
- **Single Use**: Tokens invalidated after successful use
- **Time Limits**: Tokens expire after 24 hours
- **Cryptographic**: Uses SHA-256 for hashing

### Password Security
- **Immediate Effect**: Password change is immediate
- **Secure Hashing**: New password hashed with bcrypt
- **Policy Enforcement**: Strong password requirements
- **No Plaintext**: Passwords never stored in plaintext

### Session Management
- **Existing Sessions**: Current sessions remain valid (by design)
- **Manual Logout**: Users should manually logout other devices
- **Security Notification**: Consider notifying users of password change

### Audit and Monitoring
- **Event Logging**: All reset attempts logged
- **IP Tracking**: Client IP addresses recorded
- **Failure Analysis**: Failed attempts monitored for patterns
- **Security Alerts**: Suspicious activity flagged

## Troubleshooting

### Common Issues

**400 Bad Request: "Invalid or expired reset token"**
- Check if token is correct from email
- Verify token hasn't expired (24 hours)
- Ensure token hasn't been used already

**422 Validation Error: Password policy violations**
- Ensure password meets all requirements
- Check for minimum 8 characters
- Include uppercase, lowercase, digit, and special character

**429 Rate Limit Exceeded**
- Wait for rate limit window to reset
- Check X-RateLimit-Reset header for reset time
- Use valid tokens to avoid wasting attempts

**404 Not Found: "Reset token not found"**
- Verify token was copied correctly from email
- Check if token has been deleted due to expiration
- Request new password reset if needed

### Debug Tips

1. **Check token format**: Ensure token is 64-character hex string
2. **Verify email**: Confirm reset email was received
3. **Test expiration**: Check if token is within 24-hour window
4. **Review logs**: Check application logs for detailed errors
5. **Test password**: Verify new password meets policy requirements

### Best Practices

- **Quick use**: Use reset tokens promptly after receiving
- **Secure environment**: Reset password on trusted device
- **Strong passwords**: Use password managers for strong passwords
- **Email security**: Ensure email account is secure
- **Multiple resets**: Request new token if first attempt fails

## Related Endpoints

- **[Forgot Password](forgot-password.md)** - Request password reset token
- **[Change Password](change-password.md)** - Change password when logged in
- **[User Login](login.md)** - Login with new password

## Configuration

### Reset Settings
```bash
# Token settings
PASSWORD_RESET_TOKEN_EXPIRE_HOURS=24
PASSWORD_RESET_TOKEN_CLEANUP_HOURS=48
PASSWORD_RESET_TOKEN_LENGTH=64

# Rate limiting
RESET_PASSWORD_RATE_LIMIT="5/hour"
RESET_PASSWORD_RATE_LIMIT_STORAGE="memory://"

# Password policy
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true

# Security settings
RESET_INVALIDATE_SESSIONS=false
RESET_AUDIT_LOGGING=true
RESET_IP_TRACKING=true
```