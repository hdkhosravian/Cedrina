# OAuth Authentication

Authenticate using Google, Microsoft, or Facebook OAuth providers.

## Endpoint

```http
POST /api/v1/auth/oauth
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
  "provider": "google",
  "token": {
    "access_token": "ya29.a0AfH6SMC...",
    "expires_at": 1640995200,
    "id_token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "1//04...",
    "token_type": "Bearer"
  }
}
```

### Field Specifications

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string | ✅ | OAuth provider: `google`, `microsoft`, `facebook` |
| `token.access_token` | string | ✅ | OAuth access token from provider |
| `token.expires_at` | integer | ✅ | Unix timestamp when token expires |
| `token.id_token` | string | ❌ | OpenID Connect ID token (if available) |
| `token.refresh_token` | string | ❌ | OAuth refresh token |
| `token.token_type` | string | ❌ | Token type (defaults to "Bearer") |

## Response

### Success Response (200 OK)
```json
{
  "user": {
    "id": 123,
    "username": "john_doe",
    "email": "john@example.com",
    "is_active": true,
    "email_confirmed": true,
    "role": "user"
  },
  "provider": "google",
  "oauth_profile_id": 456,
  "tokens": {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
}
```

### Error Responses

#### 400 Bad Request - Invalid Token
```json
{
  "detail": "Invalid or expired OAuth token"
}
```

#### 400 Bad Request - Provider Error
```json
{
  "detail": "Failed to authenticate with Google"
}
```

#### 422 Unprocessable Entity - Invalid Provider
```json
{
  "detail": "Unsupported OAuth provider"
}
```

## Supported Providers

### Google OAuth
- **Provider ID**: `google`
- **Scopes**: `openid email profile`
- **Configuration**: Requires `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`

### Microsoft OAuth
- **Provider ID**: `microsoft`
- **Scopes**: `openid email profile`
- **Configuration**: Requires `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET`

### Facebook OAuth
- **Provider ID**: `facebook`
- **Scopes**: `email public_profile`
- **Configuration**: Requires `FACEBOOK_CLIENT_ID` and `FACEBOOK_CLIENT_SECRET`

## OAuth Flow

1. **Frontend OAuth**: User authenticates with provider (Google/Microsoft/Facebook)
2. **Token Exchange**: Frontend sends OAuth token to `/api/v1/auth/oauth`
3. **Token Validation**: System validates token with provider
4. **User Resolution**: Links existing user or creates new account
5. **JWT Generation**: Returns access/refresh tokens for session

## Examples

### Google OAuth Authentication
```bash
curl -X POST "http://localhost:8000/api/v1/auth/oauth" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "token": {
      "access_token": "ya29.a0AfH6SMC...",
      "expires_at": 1640995200
    }
  }'
```

### Microsoft OAuth Authentication
```bash
curl -X POST "http://localhost:8000/api/v1/auth/oauth" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "microsoft",
    "token": {
      "access_token": "EwAoA8l6BAAU...",
      "expires_at": 1640995200,
      "id_token": "eyJ0eXAiOiJKV1Q..."
    }
  }'
```

### Facebook OAuth Authentication
```bash
curl -X POST "http://localhost:8000/api/v1/auth/oauth" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "facebook",
    "token": {
      "access_token": "EAAG...",
      "expires_at": 1640995200
    }
  }'
```

## Testing

### Successful OAuth Test
```python
async def test_oauth_authentication_success():
    """Test successful OAuth authentication."""
    oauth_data = {
        "provider": "google",
        "token": {
            "access_token": "valid_google_token",
            "expires_at": int(time.time()) + 3600
        }
    }
    
    response = await client.post("/api/v1/auth/oauth", json=oauth_data)
    
    assert response.status_code == 200
    data = response.json()
    assert "user" in data
    assert "tokens" in data
    assert data["provider"] == "google"
```

### Invalid Provider Test
```python
async def test_oauth_invalid_provider():
    """Test OAuth with invalid provider."""
    oauth_data = {
        "provider": "invalid_provider",
        "token": {
            "access_token": "token",
            "expires_at": int(time.time()) + 3600
        }
    }
    
    response = await client.post("/api/v1/auth/oauth", json=oauth_data)
    assert response.status_code == 422
```

## Security Features

### Token Security
- **Encryption**: OAuth tokens encrypted with AES-256
- **Expiration**: Validates token expiration
- **Provider Validation**: Verifies tokens with actual providers
- **ID Token Verification**: Validates OpenID Connect tokens

### User Security
- **Account Linking**: Links OAuth accounts to existing users by email
- **Profile Storage**: Stores encrypted OAuth profile data
- **Audit Logging**: Logs all OAuth authentication attempts

## Configuration

### Environment Variables
```bash
# Google OAuth
GOOGLE_CLIENT_ID="your_google_client_id"
GOOGLE_CLIENT_SECRET="your_google_client_secret"

# Microsoft OAuth
MICROSOFT_CLIENT_ID="your_microsoft_client_id"
MICROSOFT_CLIENT_SECRET="your_microsoft_client_secret"

# Facebook OAuth
FACEBOOK_CLIENT_ID="your_facebook_client_id"
FACEBOOK_CLIENT_SECRET="your_facebook_client_secret"

# Token encryption
PGCRYPTO_KEY="your_encryption_key"
```

## Related Endpoints

- **[User Login](login.md)** - Alternative username/password authentication
- **[User Registration](registration.md)** - Create account without OAuth
- **[Refresh Token](refresh-token.md)** - Refresh JWT tokens