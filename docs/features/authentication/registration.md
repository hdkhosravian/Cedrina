# User Registration

Register a new user account with email verification support.

## Endpoint

```http
POST /api/v1/auth/register
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
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

### Field Specifications

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `username` | string | ✅ | 3-50 chars, alphanumeric + `_-` only | Unique username identifier |
| `email` | string | ✅ | Valid email format | Unique email address |
| `password` | string | ✅ | See password policy below | User password |

### Password Policy
- **Minimum length**: 8 characters
- **Required characters**: 
  - At least 1 uppercase letter (A-Z)
  - At least 1 lowercase letter (a-z)
  - At least 1 digit (0-9)
  - At least 1 special character (!@#$%^&*)

## Response

### Success Response (201 Created)

When email confirmation is **not required**:
```json
{
  "user": {
    "id": 123,
    "username": "john_doe",
    "email": "john@example.com",
    "full_name": null,
    "is_active": true,
    "created_at": "2025-01-15T10:30:00Z",
    "updated_at": null,
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

When email confirmation **is required**:
```json
{
  "user": {
    "id": 123,
    "username": "john_doe",
    "email": "john@example.com",
    "full_name": null,
    "is_active": false,
    "created_at": "2025-01-15T10:30:00Z",
    "updated_at": null,
    "roles": ["user"]
  },
  "tokens": null
}
```

### Error Responses

#### 400 Bad Request
```json
{
  "detail": "Invalid input data"
}
```

#### 409 Conflict
```json
{
  "detail": "Username already exists"
}
```
```json
{
  "detail": "Email already registered"
}
```

#### 422 Unprocessable Entity
```json
{
  "detail": "Password must contain at least one uppercase letter"
}
```
```json
{
  "detail": "Username can only contain letters, numbers, underscores and hyphens"
}
```
```json
{
  "detail": "Invalid email format"
}
```

#### 429 Too Many Requests
```json
{
  "detail": "Registration rate limit exceeded. Try again in 45 seconds."
}
```

## Rate Limiting

- **Limit**: 3 registrations per minute per IP address
- **Window**: 1 minute
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## Security Features

### Input Validation
- **SQL Injection Prevention**: Parameterized queries and input sanitization
- **XSS Prevention**: HTML encoding and validation
- **Username Validation**: Alphanumeric + underscore/hyphen only, no spaces
- **Email Validation**: RFC-compliant email format validation
- **Password Strength**: Enforced password policy with multiple character types

### Duplicate Prevention
- **Username Uniqueness**: Case-insensitive duplicate checking
- **Email Uniqueness**: Case-insensitive duplicate checking
- **Concurrent Registration**: Database constraints prevent race conditions

### Audit Logging
All registration attempts are logged with:
- User details (masked sensitive data)
- IP address and user agent
- Success/failure status
- Correlation ID for tracking

## Email Confirmation Flow

When `EMAIL_CONFIRMATION_REQUIRED=true`:

1. **User registers** → Account created with `is_active=false`
2. **Email sent** → Confirmation email with secure token
3. **User clicks link** → `GET /api/v1/auth/confirm-email?token=<token>`
4. **Account activated** → `is_active=true`, user can login

### Email Confirmation Settings
```bash
EMAIL_CONFIRMATION_REQUIRED=true
EMAIL_CONFIRMATION_TOKEN_EXPIRE_HOURS=24
```

## Examples

### Basic Registration
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_smith",
    "email": "alice@example.com",
    "password": "MySecure123!"
  }'
```

### Registration with Language Preference
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -H "Accept-Language: es" \
  -d '{
    "username": "juan_perez",
    "email": "juan@example.com", 
    "password": "MiPassword123!"
  }'
```

### Response (Spanish)
```json
{
  "user": {
    "id": 124,
    "username": "juan_perez",
    "email": "juan@example.com",
    "is_active": false
  },
  "tokens": null
}
```

## Testing

### Valid Registration Test
```python
async def test_user_registration_success():
    """Test successful user registration."""
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "SecurePass123!"
    }
    
    response = await client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 201
    data = response.json()
    assert data["user"]["username"] == user_data["username"]
    assert data["user"]["email"] == user_data["email"]
    assert data["user"]["is_active"] is True  # When email confirmation disabled
    assert "tokens" in data
```

### Invalid Password Test
```python
async def test_registration_weak_password():
    """Test registration with weak password."""
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "weak"  # Fails password policy
    }
    
    response = await client.post("/api/v1/auth/register", json=user_data)
    
    assert response.status_code == 422
    assert "password" in response.json()["detail"].lower()
```

### Duplicate Username Test
```python
async def test_registration_duplicate_username():
    """Test registration with existing username."""
    # First registration
    user_data = {
        "username": "duplicate_user",
        "email": "first@example.com",
        "password": "SecurePass123!"
    }
    await client.post("/api/v1/auth/register", json=user_data)
    
    # Attempt duplicate username
    duplicate_data = {
        "username": "duplicate_user",  # Same username
        "email": "second@example.com",
        "password": "SecurePass123!"
    }
    
    response = await client.post("/api/v1/auth/register", json=duplicate_data)
    
    assert response.status_code == 409
    assert "username" in response.json()["detail"].lower()
```

## Troubleshooting

### Common Issues

**422 Validation Error: "Password too weak"**
- Ensure password contains uppercase, lowercase, digit, and special character
- Check minimum length requirement (8 characters)

**409 Conflict: "Username already exists"**
- Try a different username
- Usernames are case-insensitive

**409 Conflict: "Email already registered"**
- Check if account already exists
- Use password reset if forgotten

**422 Validation Error: "Username contains invalid characters"**
- Only letters, numbers, underscores, and hyphens allowed
- No spaces or special characters in username

### Debug Tips

1. **Check password strength**: Use password validation regex
2. **Verify email format**: Use email validation tools
3. **Test rate limits**: Wait between registration attempts
4. **Check logs**: Review application logs for detailed error messages

## Related Endpoints

- **[Email Confirmation](confirm-email.md)** - Activate account after registration
- **[Resend Confirmation](resend-confirmation.md)** - Resend confirmation email
- **[User Login](login.md)** - Login after successful registration