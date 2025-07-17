# Forgot Password

Initiate password reset process by sending a secure reset token via email.

## Endpoint

```http
POST /api/v1/auth/forgot-password
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
  "email": "john@example.com"
}
```

### Field Specifications

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `email` | string | ✅ | Valid email format | Email address associated with account |

## Response

### Success Response (200 OK)
**Note**: Always returns success to prevent email enumeration attacks

```json
{
  "message": "If your email is registered, you will receive password reset instructions",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Security Response Behavior
- **Always 200 OK**: Returns success regardless of whether email exists
- **Consistent timing**: Response time is consistent to prevent email enumeration
- **No user information**: Response doesn't reveal if email is registered
- **Generic message**: Same message for existing and non-existing emails

### Error Responses

#### 422 Unprocessable Entity - Invalid Email
```json
{
  "detail": "Invalid email format"
}
```

#### 422 Unprocessable Entity - Missing Email
```json
{
  "detail": "Email is required"
}
```

#### 429 Too Many Requests - Rate Limit
```json
{
  "detail": "Too many password reset requests. Try again in 45 minutes."
}
```

## Security Features

### Email Enumeration Prevention
- **Consistent Response**: Same response for valid and invalid emails
- **Timing Protection**: Response time is consistent regardless of email existence
- **Generic Messages**: No indication whether email is registered
- **Silent Failure**: Invalid emails fail silently

### Rate Limiting
- **Strict Limits**: 3 requests per hour per IP address
- **User Protection**: Prevents abuse and spam
- **Long Window**: 1-hour rate limit window
- **Progressive Delays**: Increasing delays for repeated requests

### Token Security
- **Cryptographically Secure**: Uses secure random token generation
- **Time-Limited**: Tokens expire after 24 hours (configurable)
- **Single Use**: Each token can only be used once
- **Database Storage**: Tokens securely stored with expiration

### Input Validation
- **Email Format**: RFC-compliant email validation
- **Injection Prevention**: SQL injection and XSS protection
- **Length Validation**: Prevents buffer overflow attacks
- **Encoding Validation**: UTF-8 validation for international emails

## Email Reset Process

### Complete Flow
1. **User requests reset** → `POST /auth/forgot-password`
2. **System validates email** → Checks if email exists (silently)
3. **Token generated** → Secure random token created
4. **Email sent** → Reset instructions sent to email
5. **User clicks link** → Link contains secure token
6. **Password reset** → `POST /auth/reset-password` with token
7. **Account secured** → Old password invalidated

### Email Template
```html
Subject: Password Reset Request

Hello,

You recently requested to reset your password. Click the link below to reset it:

https://app.cedrina.com/reset-password?token=a1b2c3d4e5f6...

This link expires in 24 hours for security.

If you didn't request this reset, please ignore this email.

Best regards,
Cedrina Team
```

### Reset Link Format
```
https://app.cedrina.com/reset-password?token=<secure_token>
```

## Rate Limiting

### Protection Limits
- **Requests**: 3 password reset requests per hour
- **Scope**: Per IP address (not per email)
- **Window**: 1 hour rolling window
- **Recovery**: Full recovery after window expires

### Headers
```http
X-RateLimit-Limit: 3
X-RateLimit-Remaining: 1
X-RateLimit-Reset: 1642234567
```

### Rate Limit Response
```json
{
  "detail": "Password reset rate limit exceeded. Try again in 45 minutes."
}
```

## Examples

### Basic Password Reset Request
```bash
curl -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }'
```

### Password Reset with Language Preference
```bash
curl -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -H "Accept-Language: es" \
  -d '{
    "email": "juan@example.com"
  }'
```

Response (Spanish):
```json
{
  "message": "Si tu email está registrado, recibirás instrucciones para restablecer tu contraseña",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Complete Password Reset Flow
```bash
#!/bin/bash

echo "🔑 Starting password reset flow..."

# 1. Request password reset
echo "📧 Requesting password reset..."
RESET_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }')

echo "✅ $(echo $RESET_RESPONSE | jq -r '.message')"

# 2. Simulate user checking email and getting token
# In real scenario, user would click link in email
echo "📬 User checks email and gets reset token..."
RESET_TOKEN="example_secure_token_from_email"

# 3. Reset password with token
echo "🔄 Resetting password with token..."
NEW_PASSWORD_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"$RESET_TOKEN\",
    \"new_password\": \"NewSecurePassword123!\"
  }")

echo "✅ Password reset completed"

# 4. Test login with new password
echo "🔓 Testing login with new password..."
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john@example.com",
    "password": "NewSecurePassword123!"
  }')

if [ "$(echo $LOGIN_RESPONSE | jq -r '.tokens.access_token')" != "null" ]; then
  echo "✅ Login successful with new password"
else
  echo "❌ Login failed with new password"
fi
```

### Rate Limiting Test
```bash
#!/bin/bash

echo "🚦 Testing rate limiting..."

for i in {1..4}; do
  echo "Request $i:"
  RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "test@example.com"
    }')
  
  if [ $i -le 3 ]; then
    echo "✅ $(echo $RESPONSE | jq -r '.message')"
  else
    echo "🚫 $(echo $RESPONSE | jq -r '.detail')"
  fi
  
  sleep 1
done
```

## Testing

### Successful Reset Request Test
```python
async def test_forgot_password_success():
    """Test successful password reset request."""
    # Create a user first
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "OriginalPass123!"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Request password reset
    reset_data = {"email": user_data["email"]}
    response = await client.post("/api/v1/auth/forgot-password", json=reset_data)
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "timestamp" in data
    assert "receive" in data["message"].lower()
```

### Email Enumeration Prevention Test
```python
async def test_forgot_password_email_enumeration_prevention():
    """Test that response is same for existing and non-existing emails."""
    # Test with non-existing email
    fake_email_data = {"email": "nonexistent@example.com"}
    fake_response = await client.post("/api/v1/auth/forgot-password", 
                                    json=fake_email_data)
    
    # Test with existing email
    real_user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "TestPass123!"
    }
    
    await client.post("/api/v1/auth/register", json=real_user_data)
    
    real_email_data = {"email": real_user_data["email"]}
    real_response = await client.post("/api/v1/auth/forgot-password",
                                    json=real_email_data)
    
    # Both should return 200 with similar message
    assert fake_response.status_code == 200
    assert real_response.status_code == 200
    assert fake_response.json()["message"] == real_response.json()["message"]
```

### Rate Limiting Test
```python
async def test_forgot_password_rate_limiting():
    """Test rate limiting enforcement."""
    email_data = {"email": "test@example.com"}
    
    # Make requests up to the limit
    for i in range(4):
        response = await client.post("/api/v1/auth/forgot-password", 
                                   json=email_data)
        
        if i < 3:  # First 3 should succeed
            assert response.status_code == 200
        else:  # 4th should be rate limited
            assert response.status_code == 429
            assert "rate limit" in response.json()["detail"].lower()
```

### Input Validation Test
```python
async def test_forgot_password_input_validation():
    """Test input validation."""
    # Test invalid email format
    invalid_emails = [
        {"email": "not-an-email"},
        {"email": "missing@"},
        {"email": "@missing-domain"},
        {"email": ""},
    ]
    
    for email_data in invalid_emails:
        response = await client.post("/api/v1/auth/forgot-password",
                                   json=email_data)
        assert response.status_code == 422
        assert "email" in response.json()["detail"].lower()
    
    # Test missing email field
    response = await client.post("/api/v1/auth/forgot-password", json={})
    assert response.status_code == 422
```

### Security Validation Test
```python
async def test_forgot_password_security_validation():
    """Test security input validation."""
    # Test SQL injection attempt
    sql_injection_data = {"email": "test'; DROP TABLE users; --@example.com"}
    response = await client.post("/api/v1/auth/forgot-password",
                               json=sql_injection_data)
    
    # Should be handled gracefully
    assert response.status_code in [200, 422]
    
    # Test XSS attempt
    xss_data = {"email": "<script>alert('xss')</script>@example.com"}
    response = await client.post("/api/v1/auth/forgot-password",
                               json=xss_data)
    
    assert response.status_code in [200, 422]
```

## Token Generation and Storage

### Token Characteristics
- **Length**: 64 characters (hex-encoded)
- **Entropy**: 256 bits of cryptographic randomness
- **Uniqueness**: Guaranteed unique across all reset tokens
- **Expiration**: 24 hours from generation (configurable)

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
    user_agent TEXT
);

CREATE INDEX idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_expires ON password_reset_tokens(expires_at);
```

### Token Generation Code
```python
import secrets
import hashlib
from datetime import datetime, timedelta

def generate_reset_token() -> tuple[str, str]:
    """
    Generate secure password reset token.
    
    Returns:
        tuple: (raw_token, hashed_token)
    """
    # Generate 32 bytes (256 bits) of randomness
    raw_token = secrets.token_hex(32)
    
    # Hash for database storage
    hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
    
    return raw_token, hashed_token

# Usage
raw_token, token_hash = generate_reset_token()
expiry = datetime.utcnow() + timedelta(hours=24)

# Store in database
store_reset_token(user_id, token_hash, expiry)

# Send raw_token in email (never store this)
send_reset_email(user_email, raw_token)
```

## Email Service Integration

### Email Configuration
```python
# Email settings
EMAIL_RESET_SUBJECT = "Password Reset Request"
EMAIL_RESET_TEMPLATE = "password_reset.html"
EMAIL_RESET_FROM = "noreply@cedrina.com"
EMAIL_RESET_EXPIRES_HOURS = 24

# SMTP configuration
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TLS = True
SMTP_USERNAME = "your-email@gmail.com"
SMTP_PASSWORD = "app-password"
```

### Email Template Variables
```html
<!DOCTYPE html>
<html>
<head>
    <title>Password Reset</title>
</head>
<body>
    <h1>Password Reset Request</h1>
    
    <p>Hello {{ user.username }},</p>
    
    <p>You recently requested to reset your password for your Cedrina account.</p>
    
    <p>Click the button below to reset your password:</p>
    
    <a href="{{ reset_url }}" 
       style="background: #007bff; color: white; padding: 10px 20px; 
              text-decoration: none; border-radius: 5px;">
        Reset Password
    </a>
    
    <p>Or copy and paste this link into your browser:</p>
    <p>{{ reset_url }}</p>
    
    <p>This link will expire in {{ expires_hours }} hours for security.</p>
    
    <p>If you didn't request this password reset, please ignore this email.</p>
    
    <p>Best regards,<br>The Cedrina Team</p>
</body>
</html>
```

## Troubleshooting

### Common Issues

**422 Validation Error: "Invalid email format"**
- Ensure email address is properly formatted
- Check for typos in email address
- Verify email contains @ symbol and domain

**429 Rate Limit Exceeded**
- Wait for rate limit window to reset (1 hour)
- Check X-RateLimit-Reset header for exact time
- Use only valid email addresses to avoid wasting attempts

**Email not received**
- Check spam/junk folder
- Verify email address is correct
- Check if email service is working
- Wait a few minutes for email delivery

### Debug Tips

1. **Check email logs**: Review email service logs for delivery status
2. **Verify email settings**: Test SMTP configuration
3. **Test rate limits**: Check if rate limiting is blocking requests
4. **Review application logs**: Look for error messages
5. **Test with known emails**: Use existing account emails for testing

### Best Practices

- **Clear instructions**: Provide clear steps to users
- **Multiple attempts**: Allow reasonable number of reset attempts
- **Email validation**: Verify email addresses during registration
- **Backup contacts**: Consider phone number backup for critical accounts
- **Security education**: Educate users about phishing attempts

## Security Considerations

### Email Security
- **Secure transport**: Use TLS for email transmission
- **Link expiration**: Links expire after reasonable time
- **One-time use**: Each token can only be used once
- **No sensitive data**: Never include passwords in emails

### Token Security
- **Cryptographic randomness**: Use secure random generation
- **Hash storage**: Only store hashed tokens in database
- **Expiration**: Tokens expire automatically
- **Cleanup**: Remove expired tokens from database

### Abuse Prevention
- **Rate limiting**: Strict limits prevent abuse
- **Email enumeration**: Responses don't reveal email existence
- **Consistent timing**: Response time doesn't reveal information
- **Audit logging**: All attempts logged for security monitoring

## Related Endpoints

- **[Reset Password](reset-password.md)** - Complete password reset with token
- **[Change Password](change-password.md)** - Change password when logged in
- **[User Login](login.md)** - Login with new password after reset

## Configuration

### Reset Settings
```bash
# Password reset token settings
PASSWORD_RESET_TOKEN_EXPIRE_HOURS=24
PASSWORD_RESET_TOKEN_LENGTH=64
PASSWORD_RESET_MAX_ATTEMPTS=3

# Rate limiting
FORGOT_PASSWORD_RATE_LIMIT="3/hour"
FORGOT_PASSWORD_RATE_LIMIT_STORAGE="memory://"

# Email settings
PASSWORD_RESET_EMAIL_TEMPLATE="password_reset.html"
PASSWORD_RESET_FROM_EMAIL="noreply@cedrina.com"
PASSWORD_RESET_SUBJECT="Password Reset Request"

# Security settings
EMAIL_ENUMERATION_PREVENTION=true
CONSISTENT_RESPONSE_TIMING=true
RESET_TOKEN_CLEANUP_HOURS=48
```