# Resend Email Confirmation

Request a new email confirmation when the original confirmation email was not received or expired.

## Endpoint

```http
POST /api/v1/auth/resend-confirmation
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
| `email` | string | ✅ | Valid email format | Email address of unconfirmed account |

## Response

### Success Response (200 OK)
**Note**: Always returns success to prevent email enumeration attacks

```json
{
  "message": "If your email is registered and unconfirmed, a new confirmation email has been sent",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Security Response Behavior
- **Always 200 OK**: Returns success regardless of email status
- **Consistent Timing**: Response time is consistent to prevent enumeration
- **Generic Message**: Same message for all scenarios
- **No Information Disclosure**: Doesn't reveal if email is registered or confirmed

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
  "detail": "Too many confirmation requests. Try again in 15 minutes."
}
```

## Security Features

### Email Enumeration Prevention
- **Consistent Response**: Same response for all email addresses
- **Timing Protection**: Response time consistent regardless of email status
- **Generic Messages**: No indication of email registration status
- **Silent Operation**: Invalid emails and already confirmed accounts handled silently

### Rate Limiting
- **Request Limits**: 5 requests per 15 minutes per IP address
- **Abuse Prevention**: Prevents spam and email flooding
- **Progressive Delays**: Increasing delays for repeated requests
- **IP-Based Tracking**: Rate limits applied per client IP

### Token Management
- **Token Invalidation**: Previous unused tokens are invalidated
- **Fresh Tokens**: Each request generates new secure token
- **Expiration Reset**: New 24-hour expiration period
- **Single Active Token**: Only one valid confirmation token per user

### Input Validation
- **Email Format**: RFC-compliant email validation
- **Injection Prevention**: SQL injection and XSS protection
- **Length Validation**: Prevents buffer overflow attacks
- **Encoding Validation**: UTF-8 validation for international emails

## Resend Conditions

### When Email is Sent
Email confirmation is sent only when:
1. **Email is registered**: Account exists with this email
2. **Account is unconfirmed**: User has not confirmed email yet
3. **Rate limit not exceeded**: Within allowed request limits
4. **Email service available**: SMTP service is operational

### When Email is NOT Sent (Silent)
- **Email not registered**: No account with this email exists
- **Account already confirmed**: Email is already confirmed
- **Rate limit exceeded**: Too many recent requests
- **Invalid email format**: Email format is invalid

## Examples

### Basic Resend Request
```bash
curl -X POST "http://localhost:8000/api/v1/auth/resend-confirmation" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }'
```

### Resend with Language Preference
```bash
curl -X POST "http://localhost:8000/api/v1/auth/resend-confirmation" \
  -H "Content-Type: application/json" \
  -H "Accept-Language: es" \
  -d '{
    "email": "juan@example.com"
  }'
```

Response (Spanish):
```json
{
  "message": "Si tu email está registrado y no confirmado, se ha enviado un nuevo email de confirmación",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Complete Resend Flow
```bash
#!/bin/bash

echo "📧 Email Confirmation Resend Flow"

# Step 1: Register user (email confirmation required)
echo "1️⃣ Registering user with email confirmation required..."
REGISTER_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser123",
    "email": "testuser@example.com",
    "password": "SecurePass123!"
  }')

IS_ACTIVE=$(echo $REGISTER_RESPONSE | jq -r '.user.is_active')
TOKENS=$(echo $REGISTER_RESPONSE | jq -r '.tokens')

echo "✅ User registered - Active: $IS_ACTIVE, Tokens: $TOKENS"

if [ "$IS_ACTIVE" = "false" ] && [ "$TOKENS" = "null" ]; then
  echo "📧 Email confirmation required"
  
  # Step 2: Simulate missed or expired first email
  echo "2️⃣ Simulating missed/expired confirmation email..."
  sleep 2
  
  # Step 3: Request resend
  echo "3️⃣ Requesting new confirmation email..."
  RESEND_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/resend-confirmation" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "testuser@example.com"
    }')
  
  echo "✅ $(echo $RESEND_RESPONSE | jq -r '.message')"
  
  # Step 4: Simulate receiving new confirmation email
  echo "4️⃣ User receives new confirmation email..."
  NEW_CONFIRMATION_TOKEN="new_example_token_from_email"
  
  # Step 5: Confirm email with new token
  echo "5️⃣ Confirming email with new token..."
  CONFIRM_RESPONSE=$(curl -s -X GET "http://localhost:8000/api/v1/auth/confirm-email?token=$NEW_CONFIRMATION_TOKEN")
  
  if [ "$(echo $CONFIRM_RESPONSE | jq -r '.message')" != "null" ]; then
    echo "✅ $(echo $CONFIRM_RESPONSE | jq -r '.message')"
    echo "🎉 Resend and confirmation flow completed!"
  else
    echo "❌ Email confirmation failed with new token"
  fi
  
else
  echo "✅ User active immediately (email confirmation disabled)"
fi
```

### Rate Limiting Test
```bash
#!/bin/bash

echo "🚦 Testing resend rate limiting..."

EMAIL="test@example.com"

for i in {1..6}; do
  echo "Request $i:"
  RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/resend-confirmation" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$EMAIL\"}")
  
  if [ $i -le 5 ]; then
    echo "✅ $(echo $RESPONSE | jq -r '.message')"
  else
    echo "🚫 $(echo $RESPONSE | jq -r '.detail')"
  fi
  
  sleep 1
done
```

## Testing

### Successful Resend Test
```python
async def test_resend_confirmation_success():
    """Test successful confirmation email resend."""
    # Create user with email confirmation required
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "SecurePass123!"
    }
    
    register_response = await client.post("/api/v1/auth/register", json=user_data)
    assert register_response.json()["user"]["is_active"] is False
    
    # Request resend
    resend_data = {"email": user_data["email"]}
    response = await client.post("/api/v1/auth/resend-confirmation", json=resend_data)
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "timestamp" in data
    assert "confirmation" in data["message"].lower()
```

### Email Enumeration Prevention Test
```python
async def test_resend_confirmation_email_enumeration_prevention():
    """Test that response is same for existing and non-existing emails."""
    # Test with non-existing email
    fake_email_data = {"email": "nonexistent@example.com"}
    fake_response = await client.post("/api/v1/auth/resend-confirmation",
                                    json=fake_email_data)
    
    # Test with existing unconfirmed email
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "TestPass123!"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    real_email_data = {"email": user_data["email"]}
    real_response = await client.post("/api/v1/auth/resend-confirmation",
                                    json=real_email_data)
    
    # Both should return 200 with similar message
    assert fake_response.status_code == 200
    assert real_response.status_code == 200
    assert fake_response.json()["message"] == real_response.json()["message"]
```

### Already Confirmed Email Test
```python
async def test_resend_confirmation_already_confirmed():
    """Test resend for already confirmed email."""
    # Create and confirm user
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "TestPass123!"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Confirm email
    confirmation_token = await get_latest_confirmation_token(user_data["email"])
    await client.get(f"/api/v1/auth/confirm-email?token={confirmation_token}")
    
    # Try to resend confirmation for already confirmed email
    resend_data = {"email": user_data["email"]}
    response = await client.post("/api/v1/auth/resend-confirmation", json=resend_data)
    
    # Should still return 200 (no information disclosure)
    assert response.status_code == 200
    assert "message" in response.json()
```

### Rate Limiting Test
```python
async def test_resend_confirmation_rate_limiting():
    """Test rate limiting enforcement."""
    email_data = {"email": "test@example.com"}
    
    # Make requests up to the limit
    for i in range(6):
        response = await client.post("/api/v1/auth/resend-confirmation",
                                   json=email_data)
        
        if i < 5:  # First 5 should succeed
            assert response.status_code == 200
        else:  # 6th should be rate limited
            assert response.status_code == 429
            assert "rate limit" in response.json()["detail"].lower()
```

### Input Validation Test
```python
async def test_resend_confirmation_input_validation():
    """Test input validation."""
    # Test invalid email formats
    invalid_emails = [
        {"email": "not-an-email"},
        {"email": "missing@"},
        {"email": "@missing-domain"},
        {"email": ""},
    ]
    
    for email_data in invalid_emails:
        response = await client.post("/api/v1/auth/resend-confirmation",
                                   json=email_data)
        assert response.status_code == 422
        assert "email" in response.json()["detail"].lower()
    
    # Test missing email field
    response = await client.post("/api/v1/auth/resend-confirmation", json={})
    assert response.status_code == 422
```

## Token Management

### Token Invalidation Process
When a resend request is made:

1. **Previous Token Cleanup**: All unused confirmation tokens for the user are invalidated
2. **New Token Generation**: Fresh secure token generated
3. **Database Update**: New token stored with 24-hour expiration
4. **Email Dispatch**: New confirmation email sent

### Database Operations
```sql
-- Invalidate previous tokens
UPDATE email_confirmation_tokens 
SET invalidated_at = NOW()
WHERE user_id = ? AND confirmed_at IS NULL AND invalidated_at IS NULL;

-- Insert new token
INSERT INTO email_confirmation_tokens 
(user_id, token_hash, created_at, expires_at)
VALUES (?, ?, NOW(), NOW() + INTERVAL '24 hours');
```

### Token Lifecycle Management
```python
async def handle_resend_confirmation(email: str) -> bool:
    """
    Handle confirmation email resend.
    
    Args:
        email: Email address to send confirmation to
        
    Returns:
        bool: True if email was sent (or should appear to be sent)
    """
    # Find user by email
    user = await get_user_by_email(email)
    
    if not user or user.email_confirmed:
        # Return success for security (no information disclosure)
        return True
    
    # Invalidate old tokens
    await invalidate_user_confirmation_tokens(user.id)
    
    # Generate new token
    raw_token, token_hash = generate_confirmation_token()
    
    # Store new token
    await store_confirmation_token(user.id, token_hash)
    
    # Send email
    await send_confirmation_email(user.email, user.username, raw_token)
    
    return True
```

## Email Service Integration

### Resend Email Template
```html
<!DOCTYPE html>
<html>
<head>
    <title>Email Confirmation - Resent</title>
</head>
<body>
    <h1>Confirm Your Email Address</h1>
    
    <p>Hello {{ user.username }},</p>
    
    <p>You requested a new email confirmation link for your Cedrina account.</p>
    
    <p>Click the button below to confirm your email address:</p>
    
    <a href="{{ confirmation_url }}" 
       style="background: #007bff; color: white; padding: 10px 20px; 
              text-decoration: none; border-radius: 5px;">
        Confirm Email Address
    </a>
    
    <p>Or copy and paste this link into your browser:</p>
    <p>{{ confirmation_url }}</p>
    
    <p>This link will expire in {{ expires_hours }} hours for security.</p>
    
    <p><strong>Note:</strong> This replaces any previous confirmation links, 
       which are no longer valid.</p>
    
    <p>If you didn't request this, please ignore this email.</p>
    
    <p>Best regards,<br>The Cedrina Team</p>
</body>
</html>
```

### Email Configuration
```python
# Resend-specific email settings
EMAIL_RESEND_SUBJECT = "Confirm Your Email Address - New Link"
EMAIL_RESEND_TEMPLATE = "email_confirmation_resend.html"
EMAIL_RESEND_FROM = "noreply@cedrina.com"

# Rate limiting for email sending
EMAIL_RESEND_RATE_LIMIT = "5/15min"
EMAIL_RESEND_DAILY_LIMIT = 20
```

## Frontend Integration

### React Resend Component
```jsx
import React, { useState } from 'react';

function ResendConfirmation() {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('idle'); // idle, sending, sent, error
  const [message, setMessage] = useState('');
  
  const handleResend = async (e) => {
    e.preventDefault();
    setStatus('sending');
    
    try {
      const response = await fetch('/api/v1/auth/resend-confirmation', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setStatus('sent');
        setMessage(data.message);
      } else {
        setStatus('error');
        setMessage(data.detail);
      }
    } catch (error) {
      setStatus('error');
      setMessage('Failed to send confirmation email. Please try again.');
    }
  };
  
  return (
    <div className="resend-confirmation">
      <h2>Resend Email Confirmation</h2>
      
      {status === 'idle' && (
        <form onSubmit={handleResend}>
          <div>
            <label htmlFor="email">Email Address:</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <button type="submit">Resend Confirmation Email</button>
        </form>
      )}
      
      {status === 'sending' && (
        <div>Sending confirmation email...</div>
      )}
      
      {status === 'sent' && (
        <div className="success">
          <h3>Email Sent!</h3>
          <p>{message}</p>
          <p>Please check your email inbox and spam folder.</p>
        </div>
      )}
      
      {status === 'error' && (
        <div className="error">
          <h3>Error</h3>
          <p>{message}</p>
          <button onClick={() => setStatus('idle')}>Try Again</button>
        </div>
      )}
    </div>
  );
}
```

## Troubleshooting

### Common Issues

**422 Validation Error: "Invalid email format"**
- Ensure email address is properly formatted
- Check for typos in email address
- Verify email contains @ symbol and domain

**429 Rate Limit Exceeded**
- Wait for rate limit window to reset (15 minutes)
- Check X-RateLimit-Reset header for exact time
- Limit resend requests to avoid hitting limits

**Email not received after resend**
- Check spam/junk folder thoroughly
- Verify email address is correct
- Wait a few minutes for email delivery
- Check if email service is operational

**Previous confirmation link still works**
- Old tokens are invalidated when new ones are sent
- Use only the most recent confirmation email
- Clear browser cache if experiencing issues

### Debug Tips

1. **Check email logs**: Review email service logs for delivery status
2. **Verify rate limits**: Check if rate limiting is blocking requests
3. **Test email delivery**: Use email testing tools
4. **Review application logs**: Look for error messages
5. **Check token status**: Verify token invalidation in database

### Best Practices

- **Limit requests**: Only resend when actually needed
- **Check spam**: Always check spam folder for emails
- **Wait between requests**: Don't rapidly resend confirmations
- **Use latest email**: Use only the most recent confirmation email
- **Clear instructions**: Provide clear guidance to users

## Security Considerations

### Anti-Abuse Measures
- **Rate limiting**: Strict limits prevent email flooding
- **IP tracking**: Monitor suspicious patterns
- **Token invalidation**: Previous tokens become invalid
- **Audit logging**: All requests logged for security analysis

### Privacy Protection
- **No information disclosure**: Responses don't reveal account status
- **Consistent behavior**: Same response for all email addresses
- **Timing consistency**: Response times don't reveal information
- **Email enumeration prevention**: Cannot determine if email is registered

### Email Security
- **Token uniqueness**: Each resend creates unique token
- **Secure transport**: Use TLS for email transmission
- **Link expiration**: All links expire after 24 hours
- **Single use**: Each token can only be used once

## Related Endpoints

- **[User Registration](registration.md)** - Create account requiring confirmation
- **[Email Confirmation](confirm-email.md)** - Confirm email with token
- **[User Login](login.md)** - Login after email confirmation

## Configuration

### Resend Settings
```bash
# Rate limiting
RESEND_CONFIRMATION_RATE_LIMIT="5/15min"
RESEND_CONFIRMATION_DAILY_LIMIT=20
RESEND_CONFIRMATION_IP_LIMIT="10/hour"

# Email settings
RESEND_CONFIRMATION_SUBJECT="Confirm Your Email Address - New Link"
RESEND_CONFIRMATION_TEMPLATE="email_confirmation_resend.html"
RESEND_CONFIRMATION_FROM="noreply@cedrina.com"

# Security settings
RESEND_EMAIL_ENUMERATION_PREVENTION=true
RESEND_CONSISTENT_RESPONSE_TIMING=true
RESEND_TOKEN_INVALIDATION=true

# Token management
RESEND_TOKEN_EXPIRE_HOURS=24
RESEND_TOKEN_CLEANUP_HOURS=48
RESEND_MAX_ACTIVE_TOKENS_PER_USER=1
```