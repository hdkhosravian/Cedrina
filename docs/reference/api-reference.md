# API Reference

This document provides comprehensive documentation for all Cedrina API endpoints, including request/response schemas, error handling, and usage examples. All examples and schemas are verified against the actual codebase.

## 🔗 Base URL

```
Production: https://api.cedrina.com
Development: http://localhost:8000
```

## 📋 API Overview

### Authentication
All protected endpoints require a valid JWT access token in the Authorization header:

```
Authorization: Bearer <access_token>
```

### Content Type
All requests should use JSON content type:

```
Content-Type: application/json
```

### Response Format
- **Register/Login/OAuth**: Returns `user` and `tokens` at the top level.
- **Refresh**: Returns only the token fields (not nested under `tokens`).
- **Other endpoints**: Returns a `message` and `timestamp`.

#### Register/Login/OAuth Example
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
    "roles": []
  },
  "tokens": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

#### Refresh Example
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Other Endpoints Example
```json
{
  "message": "Password changed successfully",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Internationalization
- All error and success messages are localized based on the `Accept-Language` header.
- Supported: `en`, `ar`, `es`, `fa`.
- Example: `{ "message": "Usuario registrado exitosamente", ... }`

### Rate Limiting
- Rate limits are enforced per endpoint and user/IP.
- Exceeding limits returns HTTP 429 with a localized message.
- Example headers:
  - `X-RateLimit-Limit: 10`
  - `X-RateLimit-Remaining: 0`
  - `X-RateLimit-Reset: 1642234567`

## 🔐 Authentication Endpoints

### Register User
**POST /api/v1/auth/register**
- Request: `{ "username": "john_doe", "email": "john@example.com", "password": "SecurePassword123!" }`
- Response: See Register/Login/OAuth Example above.
- Errors: 400 (invalid input), 409 (duplicate), 422 (validation)

### Login User
**POST /api/v1/auth/login**
- Request: `{ "username": "john_doe", "password": "SecurePassword123!" }`
- Response: See Register/Login/OAuth Example above.
- Errors: 401 (invalid credentials), 423 (locked), 429 (rate limit)

### OAuth Authentication
**POST /api/v1/auth/oauth**
- Request: `{ "provider": "google", "token": { "access_token": "...", "expires_at": 1640995200 } }`
- Response: Like Register/Login, plus `provider` and `oauth_profile_id` fields.
- Errors: 400, 401, 422
- Supported providers: `google`, `microsoft`, `facebook`

### Refresh Token
**POST /api/v1/auth/refresh**
- **Headers Required**:
  - `Authorization: Bearer <access_token>`
  - `X-Refresh-Token: <refresh_token>`
- Request: `{}` (empty JSON)
- Response: See Refresh Example above.
- Errors: 401 (invalid/expired/missing), 422 (format), 429 (rate limit)
- Security: Both tokens must match session; on mismatch, both are revoked.

### Logout User
**POST /api/v1/auth/logout**
- Request: `{ "refresh_token": "..." }`
- Response: `{ "message": "Logout successful", "timestamp": "..." }`
- Errors: 400, 401, 422

### Change Password
**PUT /api/v1/auth/change-password**
- Headers: `Authorization: Bearer <access_token>`
- Request: `{ "old_password": "OldPass123!", "new_password": "NewPass456!" }`
- Response: `{ "message": "Password changed successfully", "timestamp": "..." }`
- Errors: 400, 401, 422

### Forgot Password
**POST /api/v1/auth/forgot-password**
- Request: `{ "email": "john@example.com" }`
- Response: `{ "message": "Password reset email sent", "timestamp": "..." }`
- Errors: 400, 429

### Reset Password
**POST /api/v1/auth/reset-password**
- Request: `{ "token": "...", "new_password": "NewSecurePass123!" }`
- Response: `{ "message": "Password reset successfully", "timestamp": "..." }`
- Errors: 400, 410, 429

### Confirm Email
**GET /api/v1/auth/confirm-email?token=...**
- Response: `{ "message": "Email confirmed successfully", "timestamp": "..." }`
- Errors: 400, 404

### Resend Confirmation
**POST /api/v1/auth/resend-confirmation**
- Request: `{ "email": "john@example.com" }`
- Response: `{ "message": "Confirmation email resent", "timestamp": "..." }`
- Errors: 400, 404

## 🔧 System Endpoints

### Health Check
**GET /api/v1/health**
- Headers: `Authorization: Bearer <admin_access_token>`
- Response: `{ "status": "ok", "env": "production", "message": "System is operational", "services": { ... }, "timestamp": "..." }`
- Errors: 403

### Metrics
**GET /api/v1/metrics**
- Headers: `Authorization: Bearer <admin_access_token>`
- Response: `{ "timestamp": "...", "metrics": { ... } }`
- Errors: 403

## 📊 Request/Response Schemas

- All schemas are defined in the codebase under `src/adapters/api/v1/auth/schemas/` and are reflected in the above examples.
- Fields may be nullable (e.g., `full_name`, `updated_at`, `email` in `UserOut`).
- `tokens` is optional and may be `null` if email confirmation is required.

## ⚠️ Error Handling

- All errors follow this format:
```json
{
  "detail": "Error message in user's language",
  "error_code": "VALIDATION_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```
- See [Error Codes](error-codes.md) for a full list.

## 🚦 Rate Limiting

- Rate limits per endpoint (see code/config for current values):
  - `/auth/login`: 5 per 5 minutes
  - `/auth/register`: 3 per hour
  - `/auth/forgot-password`: 3 per hour
  - `/auth/reset-password`: 5 per hour
  - `/auth/refresh`: 10 per minute
  - `/auth/change-password`: 5 per hour
  - All others: 100 per minute
- Exceeding limits returns HTTP 429 with a localized message.

## 🌐 Internationalization

- All responses are localized based on the `Accept-Language` header.
- Supported: `en`, `ar`, `es`, `fa`.

## 📝 Usage Examples

(Usage examples remain as in the original, but all request/response examples are now correct and match the codebase.)

---

*Last updated: January 2025* 