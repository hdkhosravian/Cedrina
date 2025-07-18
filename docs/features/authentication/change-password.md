# Change Password

Update user account password with current password verification.

## Endpoint

```http
PUT /api/v1/auth/change-password
```

## Request

### Headers
```http
Content-Type: application/json
Authorization: Bearer <access_token>
Accept-Language: en|es|ar|fa (optional)
```

### Authentication
- **Required**: Valid JWT access token
- **User Context**: Must be authenticated user

### Request Body
```json
{
  "old_password": "CurrentPass123!",
  "new_password": "NewSecurePass456!"
}
```

### Field Specifications

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `old_password` | string | ✅ | Current account password for verification |
| `new_password` | string | ✅ | New password meeting security policy |

### Password Policy
New password must meet these requirements:
- **Minimum length**: 8 characters
- **Uppercase letter**: At least 1 (A-Z)
- **Lowercase letter**: At least 1 (a-z)
- **Digit**: At least 1 (0-9)
- **Special character**: At least 1 (!@#$%^&*)
- **Not same as old**: Cannot reuse current password

## Response

### Success Response (200 OK)
```json
{
  "message": "Password changed successfully",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Error Responses

#### 400 Bad Request - Invalid Old Password
```json
{
  "detail": "Current password is incorrect"
}
```

#### 400 Bad Request - Password Reuse
```json
{
  "detail": "New password cannot be the same as the current password"
}
```

#### 401 Unauthorized - Missing Token
```json
{
  "detail": "Authorization header is missing"
}
```

#### 401 Unauthorized - Invalid Token
```json
{
  "detail": "Invalid or expired token"
}
```

#### 422 Unprocessable Entity - Weak Password
```json
{
  "detail": "Password must contain at least one uppercase letter"
}
```

#### 422 Unprocessable Entity - Missing Fields
```json
{
  "detail": "Both old_password and new_password are required"
}
```

#### 422 Unprocessable Entity - Password Too Short
```json
{
  "detail": "Password must be at least 8 characters long"
}
```

## Security Features

### Password Verification
- **Current Password Check**: Verifies old password before allowing change
- **Constant-Time Comparison**: Uses `hmac.compare_digest` to prevent timing attacks
- **Secure Hashing**: bcrypt with configurable rounds for new password
- **Reuse Prevention**: Prevents using the same password

### Input Validation
- **Comprehensive Policy**: Enforces strong password requirements
- **Injection Prevention**: SQL injection and XSS protection
- **Length Validation**: Prevents buffer overflow attacks
- **Character Validation**: Ensures proper encoding

### Session Security
- **Authentication Required**: Must be logged in to change password
- **Token Validation**: Verifies JWT signature and expiration
- **User Context**: Can only change own password
- **Session Continuity**: Current session remains valid after password change

### Audit Logging
- **Security Events**: Password change attempts logged
- **User Tracking**: User ID and timestamp recorded
- **IP Address**: Client IP logged for security analysis
- **Success/Failure**: Both successful and failed attempts logged

## Examples

### Basic Password Change
```bash
curl -X PUT "http://localhost:8000/api/v1/auth/change-password" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "OldSecurePass123!",
    "new_password": "NewSecurePass456!"
  }'
```

### Complete Flow Example
```bash
#!/bin/bash

# 1. Login to get access token
echo "🔑 Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "CurrentPass123!"
  }')

ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.tokens.access_token')

if [ "$ACCESS_TOKEN" = "null" ]; then
  echo "❌ Login failed"
  exit 1
fi

echo "✅ Login successful"

# 2. Change password
echo "🔄 Changing password..."
CHANGE_RESPONSE=$(curl -s -X PUT "http://localhost:8000/api/v1/auth/change-password" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "CurrentPass123!",
    "new_password": "NewSecurePass456!"
  }')

if [ "$(echo $CHANGE_RESPONSE | jq -r '.message')" != "null" ]; then
  echo "✅ $(echo $CHANGE_RESPONSE | jq -r '.message')"
else
  echo "❌ Password change failed:"
  echo $CHANGE_RESPONSE | jq
  exit 1
fi

# 3. Verify old password no longer works
echo "🔒 Testing old password (should fail)..."
OLD_LOGIN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "CurrentPass123!"
  }')

if [ "$(echo $OLD_LOGIN | jq -r '.detail')" != "null" ]; then
  echo "✅ Old password correctly rejected"
else
  echo "❌ Security issue: Old password still works!"
fi

# 4. Verify new password works
echo "🔓 Testing new password (should work)..."
NEW_LOGIN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "NewSecurePass456!"
  }')

if [ "$(echo $NEW_LOGIN | jq -r '.tokens.access_token')" != "null" ]; then
  echo "✅ New password works correctly"
else
  echo "❌ New password login failed"
fi
```

### Password Change with Language Preference
```bash
curl -X PUT "http://localhost:8000/api/v1/auth/change-password" \
  -H "Authorization: Bearer <access_token>" \
  -H "Accept-Language: es" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "ContraseñaActual123!",
    "new_password": "NuevaContraseña456!"
  }'
```

Response (Spanish):
```json
{
  "message": "Contraseña cambiada exitosamente",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## Testing

### Successful Password Change Test
```python
async def test_change_password_success():
    """Test successful password change."""
    # Create and login user
    user_data = {
        "username": f"test_user_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "OldPassword123!"
    }
    
    await client.post("/api/v1/auth/register", json=user_data)
    login_response = await client.post("/api/v1/auth/login", json={
        "username": user_data["username"],
        "password": user_data["password"]
    })
    
    access_token = login_response.json()["tokens"]["access_token"]
    
    # Change password
    change_data = {
        "old_password": "OldPassword123!",
        "new_password": "NewPassword456!"
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.put("/api/v1/auth/change-password", 
                              headers=headers, json=change_data)
    
    assert response.status_code == 200
    assert "successfully" in response.json()["message"].lower()
```

### Invalid Old Password Test
```python
async def test_change_password_wrong_old_password():
    """Test password change with incorrect old password."""
    # Setup user and login
    access_token = await get_user_access_token()
    
    change_data = {
        "old_password": "WrongOldPassword!",
        "new_password": "NewPassword456!"
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.put("/api/v1/auth/change-password",
                              headers=headers, json=change_data)
    
    assert response.status_code == 400
    assert "incorrect" in response.json()["detail"].lower()
```

### Password Reuse Prevention Test
```python
async def test_change_password_same_password():
    """Test prevention of password reuse."""
    access_token = await get_user_access_token()
    current_password = "CurrentPass123!"
    
    change_data = {
        "old_password": current_password,
        "new_password": current_password  # Same password
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.put("/api/v1/auth/change-password",
                              headers=headers, json=change_data)
    
    assert response.status_code == 400
    assert "same" in response.json()["detail"].lower()
```

### Weak Password Policy Test
```python
async def test_change_password_weak_password():
    """Test password policy enforcement."""
    access_token = await get_user_access_token()
    
    weak_passwords = [
        "weak",                    # Too short
        "alllowercase123",         # No uppercase
        "ALLUPPERCASE123",         # No lowercase
        "NoNumbers!@#",            # No digits
        "NoSpecialChars123",       # No special characters
    ]
    
    for weak_password in weak_passwords:
        change_data = {
            "old_password": "CurrentPass123!",
            "new_password": weak_password
        }
        
        headers = {"Authorization": f"Bearer {access_token}"}
        response = await client.put("/api/v1/auth/change-password",
                                  headers=headers, json=change_data)
        
        assert response.status_code == 422
        assert "password" in response.json()["detail"].lower()
```

### Security Validation Test
```python
async def test_change_password_security_validation():
    """Test security input validation."""
    access_token = await get_user_access_token()
    
    # Test SQL injection in password
    sql_injection_data = {
        "old_password": "CurrentPass123!",
        "new_password": "'; DROP TABLE users; --"
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.put("/api/v1/auth/change-password",
                              headers=headers, json=sql_injection_data)
    
    # Should be handled gracefully
    assert response.status_code in [400, 422]
    
    # Test XSS in password
    xss_data = {
        "old_password": "CurrentPass123!",
        "new_password": "<script>alert('xss')</script>"
    }
    
    response = await client.put("/api/v1/auth/change-password",
                              headers=headers, json=xss_data)
    
    assert response.status_code in [400, 422]
```

### Authentication Required Test
```python
async def test_change_password_authentication_required():
    """Test that authentication is required."""
    change_data = {
        "old_password": "OldPass123!",
        "new_password": "NewPass456!"
    }
    
    # No Authorization header
    response = await client.put("/api/v1/auth/change-password", json=change_data)
    
    assert response.status_code == 401
    assert "authorization" in response.json()["detail"].lower()
```

## Password Strength Validation

### Strength Checker Function
```python
import re

def validate_password_strength(password: str) -> list[str]:
    """
    Validate password strength and return list of violations.
    
    Returns:
        List of error messages, empty if password is valid
    """
    errors = []
    
    # Length check
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    # Uppercase check
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    # Lowercase check
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    # Digit check
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    # Special character check
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    return errors

# Usage example
password = "NewPassword123!"
errors = validate_password_strength(password)
if errors:
    print("Password violations:", errors)
else:
    print("Password is strong")
```

### Password Strength Examples

| Password | Strength | Issues |
|----------|----------|--------|
| `password123` | ❌ Weak | No uppercase, no special chars |
| `Password123` | ❌ Weak | No special characters |
| `Password!` | ❌ Weak | No digits |
| `PASSWORD123!` | ❌ Weak | No lowercase |
| `Pass123!` | ❌ Weak | Too short (7 chars) |
| `Password123!` | ✅ Strong | Meets all requirements |
| `MySecureP@ssw0rd2024!` | ✅ Very Strong | Long with mixed characters |

## Troubleshooting

### Common Issues

**400 Bad Request: "Current password is incorrect"**
- Verify you're using the correct current password
- Check for typing errors or caps lock
- Ensure password hasn't been changed recently

**400 Bad Request: "New password cannot be the same"**
- Choose a different password than your current one
- Password reuse is prevented for security

**422 Validation Error: Password policy violations**
- Ensure password meets all requirements:
  - At least 8 characters
  - Contains uppercase and lowercase letters
  - Contains at least one digit
  - Contains at least one special character

**401 Unauthorized: Missing or invalid token**
- Ensure you're logged in with a valid access token
- Token may have expired - refresh or re-login
- Check Authorization header format

### Debug Tips

1. **Test password strength**: Use the validation function above
2. **Check current password**: Verify current password via login
3. **Review logs**: Check application logs for detailed errors
4. **Test with curl**: Use curl to isolate client issues
5. **Verify token**: Decode JWT to check expiration and claims

### Best Practices

- **Strong passwords**: Use password managers for strong, unique passwords
- **Regular changes**: Change passwords periodically
- **Secure storage**: Don't store passwords in plaintext
- **Two-factor auth**: Consider enabling 2FA for additional security
- **Monitor activity**: Watch for suspicious login attempts

## Security Considerations

### Password Storage
- **Never plaintext**: Passwords are never stored in plaintext
- **Bcrypt hashing**: Uses bcrypt with configurable rounds
- **Salt generation**: Unique salt for each password
- **Timing safety**: Constant-time comparisons prevent timing attacks

### Session Security
- **No forced logout**: Current session remains valid after password change
- **Other sessions**: Other active sessions remain valid
- **Manual logout**: User should manually logout/login for other devices

### Audit and Monitoring
- **Event logging**: All password changes logged
- **Failure tracking**: Failed attempts monitored for security
- **IP tracking**: Client IP addresses logged
- **Anomaly detection**: Unusual patterns flagged for review

## Related Endpoints

- **[Forgot Password](forgot-password.md)** - Reset password when forgotten
- **[Reset Password](reset-password.md)** - Complete password reset flow
- **[User Login](login.md)** - Login with new password
- **[User Logout](logout.md)** - End current session

## Configuration

### Password Policy Settings
```bash
# Password requirements
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true

# Security settings
PASSWORD_HISTORY_COUNT=5
PASSWORD_REUSE_PREVENTION=true
PASSWORD_COMPLEXITY_SCORING=true

# Hashing configuration
BCRYPT_ROUNDS=12
PASSWORD_HASH_ALGORITHM=bcrypt
```