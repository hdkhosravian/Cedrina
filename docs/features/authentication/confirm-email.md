# Email Confirmation

Confirm user email address using secure token received via email.

## Endpoint

```http
GET /api/v1/auth/confirm-email
```

## Request

### URL Format
```
GET /api/v1/auth/confirm-email?token=<confirmation_token>
```

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | ✅ | Email confirmation token from email |

### Headers
```http
Accept-Language: en|es|ar|fa (optional)
```

## Response

### Success Response (200 OK)
```json
{
  "message": "Email confirmed successfully",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Error Responses

#### 400 Bad Request - Invalid Token
```json
{
  "detail": "Invalid confirmation token"
}
```

#### 400 Bad Request - Token Already Used
```json
{
  "detail": "Email has already been confirmed"
}
```

#### 401 Unauthorized - Expired Token
```json
{
  "detail": "Confirmation token has expired"
}
```

#### 404 Not Found - Token Not Found
```json
{
  "detail": "Confirmation token not found"
}
```

#### 422 Unprocessable Entity - Missing Token
```json
{
  "detail": "Confirmation token is required"
}
```

## Security Features

### Token Validation
- **Format Verification**: Validates token format and structure
- **Hash Verification**: Compares against stored hash in database
- **Expiration Check**: Ensures token hasn't expired (24 hours default)
- **Single Use**: Token becomes invalid after successful confirmation
- **User Association**: Verifies token belongs to valid user account

### Account Activation
- **Status Update**: Sets `is_active=true` and `email_confirmed=true`
- **Timestamp Recording**: Records confirmation timestamp
- **Immediate Effect**: Account becomes usable immediately
- **Login Enabled**: User can login after confirmation

### Security Logging
- **Confirmation Events**: All attempts logged with full context
- **IP Tracking**: Client IP addresses recorded
- **Success/Failure**: Both successful and failed attempts logged
- **Timestamp Precision**: Exact confirmation time recorded

## Email Confirmation Flow

### Complete Process
1. **User registers** → Account created with `is_active=false`
2. **Email sent** → Confirmation email with secure token
3. **User clicks link** → Redirected to confirmation endpoint
4. **Token validated** → System verifies token authenticity
5. **Account activated** → `is_active=true`, user can login
6. **Success redirect** → User redirected to login or dashboard

### Email Template
```html
Subject: Confirm Your Email Address

Hello {{ user.username }},

Welcome to Cedrina! Please confirm your email address by clicking the link below:

<a href="{{ confirmation_url }}">Confirm Email Address</a>

Or copy and paste this link into your browser:
{{ confirmation_url }}

This link expires in {{ expires_hours }} hours for security.

If you didn't create this account, please ignore this email.

Best regards,
The Cedrina Team
```

### Confirmation Link Format
```
https://app.cedrina.com/confirm-email?token=<secure_token>
```

## Examples

### Email Confirmation Link (from email)
```
GET https://api.cedrina.com/api/v1/auth/confirm-email?token=a1b2c3d4e5f6789abc123def456789abcdef0123456789abcdef0123456789ab
```

### Manual API Call
```bash
curl -X GET "http://localhost:8000/api/v1/auth/confirm-email?token=a1b2c3d4e5f6789abc123def456789abcdef0123456789abcdef0123456789ab"
```

### Complete Registration + Confirmation Flow
```bash
#!/bin/bash

echo "🚀 Complete Registration and Email Confirmation Flow"

# Step 1: Register user
echo "1️⃣ Registering new user..."
REGISTER_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser123",
    "email": "newuser@example.com",
    "password": "SecurePass123!"
  }')

USER_ID=$(echo $REGISTER_RESPONSE | jq -r '.user.id')
IS_ACTIVE=$(echo $REGISTER_RESPONSE | jq -r '.user.is_active')
TOKENS=$(echo $REGISTER_RESPONSE | jq -r '.tokens')

echo "✅ User registered - ID: $USER_ID, Active: $IS_ACTIVE, Tokens: $TOKENS"

if [ "$IS_ACTIVE" = "false" ] && [ "$TOKENS" = "null" ]; then
  echo "📧 Email confirmation required"
  
  # Step 2: Simulate getting confirmation token from email
  echo "2️⃣ User receives confirmation email..."
  CONFIRMATION_TOKEN="example_confirmation_token_from_email"
  
  # Step 3: Confirm email
  echo "3️⃣ Confirming email address..."
  CONFIRM_RESPONSE=$(curl -s -X GET "http://localhost:8000/api/v1/auth/confirm-email?token=$CONFIRMATION_TOKEN")
  
  if [ "$(echo $CONFIRM_RESPONSE | jq -r '.message')" != "null" ]; then
    echo "✅ $(echo $CONFIRM_RESPONSE | jq -r '.message')"
  else
    echo "❌ Email confirmation failed:"
    echo $CONFIRM_RESPONSE | jq
    exit 1
  fi
  
  # Step 4: Test login after confirmation
  echo "4️⃣ Testing login after confirmation..."
  LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "newuser123",
      "password": "SecurePass123!"
    }')
  
  if [ "$(echo $LOGIN_RESPONSE | jq -r '.tokens.access_token')" != "null" ]; then
    echo "✅ Login successful after email confirmation"
    echo "🎉 Registration and confirmation flow completed!"
  else
    echo "❌ Login failed after confirmation"
  fi
  
else
  echo "✅ User active immediately (email confirmation disabled)"
fi
```

### Confirmation with Language Preference
```bash
curl -X GET "http://localhost:8000/api/v1/auth/confirm-email?token=a1b2c3d4..." \
  -H "Accept-Language: es"
```

Response (Spanish):
```json
{
  "message": "Correo electrónico confirmado exitosamente",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Browser Redirect Flow
```html
<!-- Example frontend handling -->
<script>
// Parse token from URL
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');

if (token) {
  // Confirm email via API
  fetch(`/api/v1/auth/confirm-email?token=${token}`)
    .then(response => response.json())
    .then(data => {
      if (data.message) {
        // Success - redirect to login
        alert(data.message);
        window.location.href = '/login';
      } else {
        // Error - show message
        alert(data.detail);
      }
    })
    .catch(error => {
      console.error('Confirmation failed:', error);
      alert('Email confirmation failed. Please try again.');
    });
} else {
  alert('Invalid confirmation link');
}
</script>
```

## Testing

### Successful Email Confirmation Test
```python
async def test_confirm_email_success():
    """Test successful email confirmation."""
    # Create user with email confirmation required
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "SecurePass123!"
    }
    
    # Register user (should be inactive)
    register_response = await client.post("/api/v1/auth/register", json=user_data)
    assert register_response.json()["user"]["is_active"] is False
    assert register_response.json()["tokens"] is None
    
    # Get confirmation token from database
    confirmation_token = await get_latest_confirmation_token(user_data["email"])
    
    # Confirm email
    response = await client.get(f"/api/v1/auth/confirm-email?token={confirmation_token}")
    
    assert response.status_code == 200
    assert "confirmed" in response.json()["message"].lower()
    
    # Verify user is now active
    user = await get_user_by_email(user_data["email"])
    assert user.is_active is True
    assert user.email_confirmed is True
```

### Invalid Token Test
```python
async def test_confirm_email_invalid_token():
    """Test email confirmation with invalid token."""
    response = await client.get("/api/v1/auth/confirm-email?token=invalid_token")
    
    assert response.status_code in [400, 404]
    assert "invalid" in response.json()["detail"].lower() or \
           "not found" in response.json()["detail"].lower()
```

### Expired Token Test
```python
async def test_confirm_email_expired_token():
    """Test email confirmation with expired token."""
    # Create user and expired confirmation token
    user_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    expired_token = await create_expired_confirmation_token(user_email)
    
    response = await client.get(f"/api/v1/auth/confirm-email?token={expired_token}")
    
    assert response.status_code in [400, 401]
    assert "expired" in response.json()["detail"].lower()
```

### Token Reuse Prevention Test
```python
async def test_confirm_email_token_reuse():
    """Test that confirmation tokens cannot be reused."""
    # Setup user and confirmation token
    user_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    confirmation_token = await setup_email_confirmation(user_email)
    
    # First use - should succeed
    first_response = await client.get(
        f"/api/v1/auth/confirm-email?token={confirmation_token}"
    )
    assert first_response.status_code == 200
    
    # Second use - should fail
    second_response = await client.get(
        f"/api/v1/auth/confirm-email?token={confirmation_token}"
    )
    assert second_response.status_code == 400
    assert "already" in second_response.json()["detail"].lower()
```

### Missing Token Test
```python
async def test_confirm_email_missing_token():
    """Test email confirmation without token parameter."""
    response = await client.get("/api/v1/auth/confirm-email")
    
    assert response.status_code == 422
    assert "required" in response.json()["detail"].lower()
```

## Token Management

### Token Lifecycle
1. **Generation**: Created during user registration
2. **Storage**: Hashed and stored in database with expiration
3. **Email Delivery**: Sent via confirmation email
4. **Validation**: Verified against database hash
5. **Usage**: Single use only, marked as used
6. **Cleanup**: Expired tokens automatically removed

### Database Schema
```sql
CREATE TABLE email_confirmation_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    confirmed_at TIMESTAMP NULL,
    ip_address INET,
    user_agent TEXT,
    
    CONSTRAINT chk_expires_future CHECK (expires_at > created_at)
);

-- Indexes for performance
CREATE INDEX idx_email_confirmation_tokens_hash ON email_confirmation_tokens(token_hash);
CREATE INDEX idx_email_confirmation_tokens_expires ON email_confirmation_tokens(expires_at);
CREATE INDEX idx_email_confirmation_tokens_user ON email_confirmation_tokens(user_id);
```

### Token Generation
```python
import secrets
import hashlib
from datetime import datetime, timedelta

def generate_confirmation_token() -> tuple[str, str]:
    """
    Generate secure email confirmation token.
    
    Returns:
        tuple: (raw_token, hashed_token)
    """
    # Generate 32 bytes (256 bits) of randomness
    raw_token = secrets.token_hex(32)
    
    # Hash for database storage
    hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
    
    return raw_token, hashed_token

# Usage
raw_token, token_hash = generate_confirmation_token()
expiry = datetime.utcnow() + timedelta(hours=24)

# Store in database
store_confirmation_token(user_id, token_hash, expiry)

# Send raw_token in email (never store this)
send_confirmation_email(user_email, raw_token)
```

### Token Validation Process
```python
async def validate_confirmation_token(token: str) -> dict:
    """
    Validate email confirmation token.
    
    Returns:
        dict: Validation result with user info or error
    """
    # Hash the provided token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Query database
    result = await db.execute(
        "SELECT user_id, expires_at, confirmed_at FROM email_confirmation_tokens "
        "WHERE token_hash = %s",
        (token_hash,)
    )
    
    token_record = result.fetchone()
    
    if not token_record:
        return {"error": "Token not found", "code": 404}
    
    user_id, expires_at, confirmed_at = token_record
    
    # Check if already used
    if confirmed_at:
        return {"error": "Email already confirmed", "code": 400}
    
    # Check expiration
    if datetime.utcnow() > expires_at:
        return {"error": "Token expired", "code": 401}
    
    return {"user_id": user_id, "valid": True}
```

## Account Activation Process

### User Status Updates
```python
async def activate_user_account(user_id: int, token_hash: str) -> bool:
    """
    Activate user account after email confirmation.
    
    Args:
        user_id: ID of user to activate
        token_hash: Hash of confirmation token
        
    Returns:
        bool: True if activation successful
    """
    async with db.transaction():
        # Update user status
        await db.execute(
            "UPDATE users SET is_active = true, email_confirmed = true, "
            "email_confirmed_at = NOW() WHERE id = %s",
            (user_id,)
        )
        
        # Mark token as used
        await db.execute(
            "UPDATE email_confirmation_tokens SET confirmed_at = NOW() "
            "WHERE token_hash = %s",
            (token_hash,)
        )
        
        return True
```

### Status Check Helper
```python
def check_user_confirmation_status(user_id: int) -> dict:
    """Check user email confirmation status."""
    user = get_user_by_id(user_id)
    
    return {
        "user_id": user_id,
        "is_active": user.is_active,
        "email_confirmed": user.email_confirmed,
        "email_confirmed_at": user.email_confirmed_at,
        "requires_confirmation": not user.email_confirmed
    }
```

## Frontend Integration

### React Component Example
```jsx
import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

function EmailConfirmation() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState('confirming');
  const [message, setMessage] = useState('');
  const navigate = useNavigate();
  
  useEffect(() => {
    const token = searchParams.get('token');
    
    if (!token) {
      setStatus('error');
      setMessage('Invalid confirmation link');
      return;
    }
    
    // Confirm email via API
    fetch(`/api/v1/auth/confirm-email?token=${token}`)
      .then(response => response.json())
      .then(data => {
        if (data.message) {
          setStatus('success');
          setMessage(data.message);
          // Redirect to login after 3 seconds
          setTimeout(() => navigate('/login'), 3000);
        } else {
          setStatus('error');
          setMessage(data.detail);
        }
      })
      .catch(error => {
        setStatus('error');
        setMessage('Email confirmation failed. Please try again.');
      });
  }, [searchParams, navigate]);
  
  return (
    <div className="confirmation-page">
      {status === 'confirming' && (
        <div>Confirming your email address...</div>
      )}
      
      {status === 'success' && (
        <div className="success">
          <h2>Email Confirmed!</h2>
          <p>{message}</p>
          <p>Redirecting to login...</p>
        </div>
      )}
      
      {status === 'error' && (
        <div className="error">
          <h2>Confirmation Failed</h2>
          <p>{message}</p>
          <button onClick={() => navigate('/resend-confirmation')}>
            Resend Confirmation Email
          </button>
        </div>
      )}
    </div>
  );
}
```

## Troubleshooting

### Common Issues

**400 Bad Request: "Invalid confirmation token"**
- Check if token was copied correctly from email
- Verify token format (should be 64-character hex string)
- Ensure no extra characters or spaces

**400 Bad Request: "Email has already been confirmed"**
- Account is already active and confirmed
- Try logging in with your credentials
- No further action needed

**401 Unauthorized: "Confirmation token has expired"**
- Token expired after 24 hours
- Request new confirmation email via resend endpoint
- Complete confirmation within time limit

**404 Not Found: "Confirmation token not found"**
- Token may have been deleted or never existed
- Request new confirmation email
- Check if account was already confirmed

### Debug Tips

1. **Check email delivery**: Verify email was received and not in spam
2. **Copy full link**: Ensure entire confirmation URL is copied
3. **Test quickly**: Use confirmation link within 24 hours
4. **Check network**: Ensure stable internet connection
5. **Review logs**: Check application logs for detailed errors

### Best Practices

- **Quick confirmation**: Confirm email address soon after registration
- **Secure email**: Ensure email account is secure and accessible
- **Link handling**: Don't share confirmation links with others
- **Multiple attempts**: Request new email if first attempt fails
- **Browser compatibility**: Use modern browser for best experience

## Security Considerations

### Token Security
- **Hash Storage**: Only hashed tokens stored in database
- **Single Use**: Tokens invalidated after successful confirmation
- **Time Limits**: Tokens expire after 24 hours
- **Cryptographic**: Uses SHA-256 for hashing

### Email Security
- **Secure Transport**: Use TLS for email transmission
- **Link Security**: Confirmation links are single-use
- **No Sensitive Data**: Emails don't contain passwords or sensitive info
- **Phishing Protection**: Educate users about legitimate emails

### Account Security
- **Activation Control**: Inactive accounts cannot login
- **Immediate Effect**: Confirmation activates account immediately
- **Status Tracking**: Confirmation status and timestamp recorded
- **Audit Trail**: All confirmation attempts logged

## Related Endpoints

- **[User Registration](registration.md)** - Create account that requires confirmation
- **[Resend Confirmation](resend-confirmation.md)** - Request new confirmation email
- **[User Login](login.md)** - Login after email confirmation

## Configuration

### Email Confirmation Settings
```bash
# Email confirmation
EMAIL_CONFIRMATION_REQUIRED=true
EMAIL_CONFIRMATION_TOKEN_EXPIRE_HOURS=24
EMAIL_CONFIRMATION_FROM_EMAIL="noreply@cedrina.com"

# Email template
EMAIL_CONFIRMATION_SUBJECT="Confirm Your Email Address"
EMAIL_CONFIRMATION_TEMPLATE="email_confirmation.html"

# Frontend URLs
FRONTEND_URL="https://app.cedrina.com"
EMAIL_CONFIRMATION_SUCCESS_URL="/login"
EMAIL_CONFIRMATION_ERROR_URL="/resend-confirmation"

# Security settings
EMAIL_CONFIRMATION_TOKEN_LENGTH=64
EMAIL_CONFIRMATION_AUDIT_LOGGING=true
EMAIL_CONFIRMATION_IP_TRACKING=true
```