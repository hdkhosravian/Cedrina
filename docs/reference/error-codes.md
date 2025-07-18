# Error Codes Reference

This document provides a comprehensive reference for all error codes used in the Cedrina system, including their meanings, causes, and resolution strategies. All codes and examples are verified against the actual codebase.

## 📋 Error Code Overview

Cedrina uses a structured error handling system with consistent error codes across all endpoints. Each error includes:

- **Error Code**: Unique identifier for the error type
- **HTTP Status**: Appropriate HTTP status code
- **Message**: Human-readable, localized error message
- **Details**: Additional context for debugging

## 🔐 Authentication Errors

### AUTHENTICATION_ERROR
**HTTP Status**: `401 Unauthorized`
**Description**: General authentication failure
**Causes**: Invalid credentials, locked/inactive account
**Resolution**: Verify credentials, check account status, use password reset
**Example**:
```json
{
  "detail": "Invalid username or password",
  "error_code": "AUTHENTICATION_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### INVALID_CREDENTIALS
**HTTP Status**: `401 Unauthorized`
**Description**: Invalid username or password during login
**Causes**: Incorrect username/password, locked/inactive account
**Resolution**: Verify credentials, check account status, use password reset
**Example**:
```json
{
  "detail": "Invalid username or password",
  "error_code": "INVALID_CREDENTIALS",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### SECURITY_VIOLATION
**HTTP Status**: `401 Unauthorized`
**Description**: Security violation detected (e.g., token family compromise)
**Causes**: Token family compromise, cross-user token attack, manipulation
**Resolution**: Re-authenticate, contact support, check for suspicious activity
**Example**:
```json
{
  "detail": "Security violation detected",
  "error_code": "SECURITY_VIOLATION",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### SESSION_LIMIT_EXCEEDED
**HTTP Status**: `423 Locked`
**Description**: User has exceeded maximum concurrent sessions
**Causes**: Too many active sessions, session policy enforcement
**Resolution**: Logout from other devices, contact support
**Example**:
```json
{
  "detail": "Maximum concurrent sessions exceeded",
  "error_code": "SESSION_LIMIT_EXCEEDED",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 📝 Validation Errors

### VALIDATION_ERROR
**HTTP Status**: `400 Bad Request`
**Description**: Request data fails validation rules
**Causes**: Invalid input, missing/invalid fields, type errors
**Resolution**: Check request format and required fields
**Example**:
```json
{
  "detail": "Invalid input data",
  "error_code": "VALIDATION_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### PASSWORD_POLICY_ERROR
**HTTP Status**: `400 Bad Request`
**Description**: Password does not meet security policy
**Causes**: Too short, lacks complexity, reuse
**Resolution**: Use a strong, unique password
**Example**:
```json
{
  "detail": "Password must be at least 8 characters long and contain uppercase, lowercase, number, and symbol",
  "error_code": "PASSWORD_POLICY_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### PASSWORD_VALIDATION_ERROR
**HTTP Status**: `400 Bad Request`
**Description**: Password validation failed
**Causes**: Format issues, policy violation, reuse
**Resolution**: Check password requirements
**Example**:
```json
{
  "detail": "Password validation failed",
  "error_code": "PASSWORD_VALIDATION_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### INVALID_OLD_PASSWORD
**HTTP Status**: `401 Unauthorized`
**Description**: Current password provided is incorrect
**Causes**: Incorrect current password, recent change
**Resolution**: Verify current password, use password reset
**Example**:
```json
{
  "detail": "Current password is incorrect",
  "error_code": "INVALID_OLD_PASSWORD",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### PASSWORD_REUSE_ERROR
**HTTP Status**: `400 Bad Request`
**Description**: New password cannot reuse recent passwords
**Causes**: Password matches one of the last N passwords
**Resolution**: Choose a new, unique password
**Example**:
```json
{
  "detail": "Password cannot reuse any of the last 5 passwords",
  "error_code": "PASSWORD_REUSE_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### TOKEN_FORMAT_ERROR
**HTTP Status**: `422 Unprocessable Entity`
**Description**: Token format is invalid
**Causes**: Not a valid JWT, corrupted, invalid characters
**Resolution**: Ensure token is complete and valid
**Example**:
```json
{
  "detail": "Invalid JWT format: must have exactly 3 parts separated by dots",
  "error_code": "TOKEN_FORMAT_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 👥 User Management Errors

### USER_NOT_FOUND
**HTTP Status**: `404 Not Found`
**Description**: Requested user does not exist
**Causes**: Invalid user ID, deleted user
**Resolution**: Verify user ID, check if user exists
**Example**:
```json
{
  "detail": "User not found",
  "error_code": "USER_NOT_FOUND",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### USER_ALREADY_EXISTS
**HTTP Status**: `409 Conflict`
**Description**: Username or email already exists
**Causes**: Username/email taken, duplicate registration
**Resolution**: Choose a different username/email, use password reset
**Example**:
```json
{
  "detail": "Username or email already exists",
  "error_code": "USER_ALREADY_EXISTS",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### DUPLICATE_USER_ERROR
**HTTP Status**: `409 Conflict`
**Description**: User already exists with provided credentials
**Causes**: Username/email taken, duplicate registration
**Resolution**: Choose a different username/email, use password reset
**Example**:
```json
{
  "detail": "User already exists",
  "error_code": "DUPLICATE_USER_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### INSUFFICIENT_PERMISSIONS
**HTTP Status**: `403 Forbidden`
**Description**: User lacks required permissions
**Causes**: Insufficient role, resource mismatch
**Resolution**: Contact admin, verify resource ownership
**Example**:
```json
{
  "detail": "Insufficient permissions for this operation",
  "error_code": "INSUFFICIENT_PERMISSIONS",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 🔗 OAuth Errors

### OAUTH_AUTHENTICATION_FAILED
**HTTP Status**: `401 Unauthorized`
**Description**: OAuth provider authentication failed
**Causes**: Invalid/expired token, provider unavailable
**Resolution**: Re-authenticate, check provider status
**Example**:
```json
{
  "detail": "OAuth authentication failed",
  "error_code": "OAUTH_AUTHENTICATION_FAILED",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### OAUTH_PROVIDER_ERROR
**HTTP Status**: `400 Bad Request`
**Description**: OAuth provider returned an error
**Causes**: Provider error, invalid config, rate limiting
**Resolution**: Try again, check provider status, contact support
**Example**:
```json
{
  "detail": "OAuth provider error: rate limit exceeded",
  "error_code": "OAUTH_PROVIDER_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 🔄 Token Management Errors

### TOKEN_EXPIRED
**HTTP Status**: `401 Unauthorized`
**Description**: JWT access token has expired
**Causes**: Token expired, clock skew
**Resolution**: Use refresh token, re-authenticate
**Example**:
```json
{
  "detail": "Access token has expired",
  "error_code": "TOKEN_EXPIRED",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### TOKEN_INVALID
**HTTP Status**: `401 Unauthorized`
**Description**: JWT token format is invalid or malformed
**Causes**: Not a valid JWT, corrupted, invalid characters
**Resolution**: Ensure token is valid, re-authenticate
**Example**:
```json
{
  "detail": "Invalid JWT format: must have exactly 3 parts separated by dots",
  "error_code": "TOKEN_INVALID",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 📧 Email and Confirmation Errors

### EMAIL_SERVICE_ERROR
**HTTP Status**: `500 Internal Server Error`
**Description**: Email service is unavailable or failed
**Causes**: SMTP unavailable, config error, template error
**Resolution**: Try again, check email service, contact support
**Example**:
```json
{
  "detail": "Email service temporarily unavailable",
  "error_code": "EMAIL_SERVICE_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### TEMPLATE_RENDER_ERROR
**HTTP Status**: `500 Internal Server Error`
**Description**: Email template rendering failed
**Causes**: Template syntax error, missing variables
**Resolution**: Contact support, check template config
**Example**:
```json
{
  "detail": "Email template rendering failed",
  "error_code": "TEMPLATE_RENDER_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### FORGOT_PASSWORD_ERROR
**HTTP Status**: `400 Bad Request`
**Description**: Password reset request failed
**Causes**: Email not found, account locked, rate limit, email error
**Resolution**: Verify email, check account, wait for rate limit, contact support
**Example**:
```json
{
  "detail": "Password reset request failed",
  "error_code": "FORGOT_PASSWORD_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### PASSWORD_RESET_ERROR
**HTTP Status**: `400 Bad Request`
**Description**: Password reset operation failed
**Causes**: Invalid/expired token, policy violation, already used
**Resolution**: Request new reset, ensure password meets requirements
**Example**:
```json
{
  "detail": "Password reset failed",
  "error_code": "PASSWORD_RESET_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 🚦 Rate Limiting Errors

### RATE_LIMIT_EXCEEDED
**HTTP Status**: `429 Too Many Requests`
**Description**: Rate limit exceeded for the endpoint
**Causes**: Too many requests, brute force, abuse
**Resolution**: Wait for window reset, reduce frequency
**Example**:
```json
{
  "detail": "Rate limit exceeded. Please try again later.",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 🔧 System Errors

### DATABASE_ERROR
**HTTP Status**: `500 Internal Server Error`
**Description**: Database operation failed
**Causes**: Connection issues, query errors, constraint violations
**Resolution**: Try again, contact support, check DB status
**Example**:
```json
{
  "detail": "Database operation failed",
  "error_code": "DATABASE_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### ENCRYPTION_ERROR
**HTTP Status**: `500 Internal Server Error`
**Description**: Data encryption operation failed
**Causes**: Key issues, algorithm errors, data corruption
**Resolution**: Contact support, check encryption config
**Example**:
```json
{
  "detail": "A critical error occurred during data encryption",
  "error_code": "ENCRYPTION_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### DECRYPTION_ERROR
**HTTP Status**: `500 Internal Server Error`
**Description**: Data decryption operation failed
**Causes**: Key issues, algorithm errors, data corruption
**Resolution**: Contact support, check decryption config
**Example**:
```json
{
  "detail": "A critical error occurred during data decryption",
  "error_code": "DECRYPTION_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### GENERIC_ERROR
**HTTP Status**: `500 Internal Server Error`
**Description**: Generic application error
**Causes**: Unhandled exceptions, resource issues, config problems
**Resolution**: Try again, contact support, check system status
**Example**:
```json
{
  "detail": "An unexpected error occurred",
  "error_code": "GENERIC_ERROR",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 📊 Error Response Format

### Standard Error Response
All error responses follow this consistent format:
```json
{
  "detail": "Human-readable error message",
  "error_code": "ERROR_CODE",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Validation Error Response
For validation errors, additional details may be included:
```json
{
  "detail": "Validation failed",
  "error_code": "VALIDATION_ERROR",
  "errors": {
    "username": ["Username must be between 3 and 50 characters"],
    "email": ["Invalid email format"],
    "password": ["Password must be at least 8 characters long"]
  },
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## 🔍 Error Handling Best Practices

### Client-Side Handling
1. **Check HTTP Status Code**: Always check the HTTP status code first
2. **Parse Error Code**: Use the `error_code` for specific handling
3. **Display User-Friendly Messages**: Use the `detail` field for user display
4. **Log for Debugging**: Log full error response for debugging
5. **Implement Retry Logic**: For transient errors (5xx status codes)

### Server-Side Handling
1. **Consistent Error Format**: Always return errors in the standard format
2. **Appropriate Status Codes**: Use correct HTTP status codes
3. **Security Considerations**: Don't expose sensitive information in errors
4. **Internationalization**: Provide localized error messages
5. **Logging**: Log all errors for monitoring and debugging

## 📈 Error Monitoring

### Key Metrics to Track
- **Error Rate**: Percentage of requests that result in errors
- **Error Distribution**: Breakdown by error type and endpoint
- **Response Time**: Impact of errors on response times
- **User Impact**: Number of users affected by errors

### Monitoring Queries
```sql
-- Error rate by endpoint
SELECT 
    endpoint,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as errors,
    ROUND(COUNT(CASE WHEN status_code >= 400 THEN 1 END) * 100.0 / COUNT(*), 2) as error_rate
FROM security_events 
WHERE event_type = 'api_request'
GROUP BY endpoint
ORDER BY error_rate DESC;

-- Most common error codes
SELECT 
    error_code,
    COUNT(*) as occurrences
FROM security_events 
WHERE event_type = 'api_error'
GROUP BY error_code
ORDER BY occurrences DESC;
```

## 🔗 Related Documentation

- **[API Reference](api-reference.md)** - API endpoint documentation
- **[Troubleshooting Guide](../getting-started/troubleshooting.md)** - Common issues and solutions
- **[Security Guide](../security/overview.md)** - Security best practices
- **[Monitoring Guide](performance-benchmarks.md)** - Performance and monitoring

---

*Last updated: January 2025* 